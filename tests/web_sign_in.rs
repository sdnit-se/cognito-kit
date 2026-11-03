//! Web sign-in through managed login, as the browser, Cognito and an
//! attacker replaying a callback each see it.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cognito_kit::{AuthorizeOptions, ClientSecret, LoginError, ManagedLogin, RefreshToken};
use serde_json::json;
use sha2::{Digest, Sha256};
use support::{CLIENT, FakeCognito, LOGIN, access_claims, id_claims, sign};
use url::Url;

const CALLBACK: &str = "https://app.example.com/callback";

fn login(cognito: &FakeCognito) -> ManagedLogin {
    cognito
        .pool()
        .managed_login(
            LOGIN.parse().unwrap(),
            CLIENT.parse().unwrap(),
            CALLBACK.parse().unwrap(),
        )
        .client_secret(ClientSecret::new("s3cret"))
        .build()
        .unwrap()
}

fn query(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs().into_owned().collect()
}

/// A token endpoint that answers a code exchange as Cognito does, with an ID
/// token carrying `nonce`.
fn answer_with_nonce(cognito: &FakeCognito, nonce: Arc<Mutex<String>>) {
    cognito.on_token(move |form| {
        let id_token = sign("k1", &id_claims(CLIENT, Some(&nonce.lock().unwrap())));
        let access_token = sign("k1", &access_claims("https://api.example.com", "openid email"));
        let refresh_token = if form["grant_type"] == "refresh_token" {
            "rotated"
        } else {
            "first"
        };
        (
            200,
            json!({ "id_token": id_token, "access_token": access_token, "refresh_token": refresh_token,
                      "expires_in": 3600, "token_type": "Bearer" }),
        )
    });
}

#[tokio::test]
async fn signs_in_with_pkce_state_and_nonce() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let login = login(&cognito);
    let (url, pending) = login.authorize(&AuthorizeOptions::default().identity_provider("Google"));

    assert_eq!(url.origin().ascii_serialization(), LOGIN);
    assert_eq!(url.path(), "/oauth2/authorize");
    let sent = query(&url);
    assert_eq!(sent["response_type"], "code");
    assert_eq!(sent["client_id"], CLIENT);
    assert_eq!(sent["redirect_uri"], CALLBACK);
    assert_eq!(sent["code_challenge_method"], "S256");
    assert_eq!(sent["identity_provider"], "Google");
    assert!(sent["scope"].split(' ').any(|s| s == "openid"));

    answer_with_nonce(&cognito, Arc::new(Mutex::new(sent["nonce"].clone())));
    let callback = format!("code=abc123&state={}", sent["state"]);
    let signed_in = login.callback::<()>(pending, &callback).await.unwrap();
    assert_eq!(signed_in.claims.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        signed_in.tokens.refresh_token.as_ref().map(RefreshToken::secret),
        Some("first")
    );

    let (path, form, authorization) = cognito.requests().pop().unwrap();
    assert_eq!(path, "/oauth2/token");
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "abc123");
    assert_eq!(form["redirect_uri"], CALLBACK);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
    assert_eq!(
        challenge, sent["code_challenge"],
        "Cognito checks the verifier against the challenge"
    );
    let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT}:s3cret")));
    assert_eq!(
        authorization,
        Some(basic),
        "a confidential client authenticates with HTTP Basic"
    );
}

#[tokio::test]
async fn refuses_a_callback_with_another_sign_in_state() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let login = login(&cognito);
    let (_, pending) = login.authorize(&AuthorizeOptions::default());
    let (other, _) = login.authorize(&AuthorizeOptions::default());

    let forged = format!("code=abc123&state={}", query(&other)["state"]);
    assert!(matches!(
        login.callback::<()>(pending.clone(), &forged).await,
        Err(LoginError::State)
    ));
    assert!(matches!(
        login.callback::<()>(pending, "code=abc123").await,
        Err(LoginError::State)
    ));
    assert!(
        cognito.requests().is_empty(),
        "a forged callback never reaches the token endpoint"
    );
}

#[tokio::test]
async fn refuses_an_id_token_from_another_sign_in() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let login = login(&cognito);
    let (url, pending) = login.authorize(&AuthorizeOptions::default());
    answer_with_nonce(&cognito, Arc::new(Mutex::new("a-replayed-nonce".to_owned())));

    let callback = format!("code=abc123&state={}", query(&url)["state"]);
    assert!(matches!(
        login.callback::<()>(pending, &callback).await,
        Err(LoginError::Nonce)
    ));
}

#[tokio::test]
async fn reports_a_refused_sign_in() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let login = login(&cognito);
    let (url, pending) = login.authorize(&AuthorizeOptions::default());
    let callback = format!(
        "error=access_denied&error_description=PreTokenGeneration+failed&state={}",
        query(&url)["state"]
    );
    let error = login.callback::<()>(pending, &callback).await.unwrap_err();
    assert!(matches!(error, LoginError::Denied(e) if e.error == "access_denied"));
}

#[tokio::test]
async fn refreshes_and_reports_a_spent_refresh_token() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let login = login(&cognito);
    answer_with_nonce(&cognito, Arc::default());
    let refreshed = login.refresh::<()>(&RefreshToken::new("first")).await.unwrap();
    assert_eq!(
        refreshed.tokens.refresh_token.as_ref().map(RefreshToken::secret),
        Some("rotated")
    );
    let (_, form, _) = cognito.requests().pop().unwrap();
    assert_eq!(
        (form["grant_type"].as_str(), form["refresh_token"].as_str()),
        ("refresh_token", "first")
    );

    cognito.on_token(|_| {
        (
            400,
            json!({ "error": "invalid_grant", "error_description": "Refresh Token has been revoked" }),
        )
    });
    let error = login
        .refresh::<()>(&RefreshToken::new("first"))
        .await
        .unwrap_err();
    assert!(matches!(error, LoginError::Refused(e) if e.is_invalid_grant()));
}

#[tokio::test]
async fn signs_out_through_managed_login() {
    let cognito = FakeCognito::default();
    let login = login(&cognito);
    let url = login.logout_url(&"https://app.example.com/".parse().unwrap());
    assert_eq!(url.origin().ascii_serialization(), LOGIN);
    assert_eq!(url.path(), "/logout");
    let sent = query(&url);
    assert_eq!(
        (sent["client_id"].as_str(), sent["logout_uri"].as_str()),
        (CLIENT, "https://app.example.com/")
    );

    login.revoke(&RefreshToken::new("first")).await.unwrap();
    let (path, form, _) = cognito.requests().pop().unwrap();
    assert_eq!(
        (path.as_str(), form["token"].as_str()),
        ("/oauth2/revoke", "first")
    );
}

#[test]
fn never_prints_secrets() {
    let printed = format!(
        "{:?} {:?}",
        ClientSecret::new("s3cret"),
        RefreshToken::new("first")
    );
    assert!(!printed.contains("s3cret") && !printed.contains("first"));
}

#[test]
fn its_futures_can_run_on_any_thread() {
    fn send<T: Send>(_: T) {}
    let cognito = FakeCognito::default();
    let login = login(&cognito);
    let (_, pending) = login.authorize(&AuthorizeOptions::default());
    send(login.callback::<()>(pending, ""));
    send(login.refresh::<()>(&RefreshToken::new("first")));
    send(login.revoke(&RefreshToken::new("first")));
    let verifier = cognito
        .pool()
        .access_tokens()
        .client(CLIENT.parse().unwrap())
        .build()
        .unwrap();
    send(verifier.verify::<()>(""));
}
