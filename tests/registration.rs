//! What an attacker, or an operator watching the pool, would notice about
//! client registration: where codes may go, which documents count, which
//! tokens pass, and how app clients are kept in check.

mod front;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cognito_kit::registration::{BoxFuture, Registrar, Registration, RegistrationStore};
use cognito_kit::test_kit::{FakeCognito, MemoryStore};
use cognito_kit::{BoxError, ClientId};

use front::{
    Authorization, DRAFTS, Documents, MCP, ORIGIN, call_mcp, get, json, location, open_server, post_form,
    post_json, serve, server, sign_in,
};
use http::StatusCode;
use serde_json::json;
use url::Url;

const CLAUDE: &str = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

fn claude_document(redirect_uris: &[&str]) -> String {
    json!({
        "client_id": CLAUDE, "client_name": "Claude", "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
    .to_string()
}

fn authorize_url(client_id: &str, redirect_uri: &str, pkce: bool) -> String {
    let mut url = Url::parse(&format!("{ORIGIN}/oauth2/authorize")).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", DRAFTS)
        .append_pair("state", "s")
        .append_pair("resource", MCP);
    if pkce {
        url.query_pairs_mut()
            .append_pair("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .append_pair("code_challenge_method", "S256");
    }
    url.into()
}

fn registration(redirect_uris: &[&str]) -> serde_json::Value {
    json!({ "client_name": "app", "redirect_uris": redirect_uris, "token_endpoint_auth_method": "none" })
}

const REGISTER: &str = "https://portal.example.com/oauth2/register";

#[tokio::test]
async fn refuses_a_document_that_does_not_list_the_redirect_uri() {
    let server = open_server();
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    for redirect_uri in ["https://claude.ai/api/mcp/other", "https://evil.example/callback"] {
        let answer = get(&server.front, &authorize_url(CLAUDE, redirect_uri, true)).await;
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{redirect_uri}");
        assert_eq!(location(&answer), None, "never redirected to an unregistered URI");
    }
}

#[tokio::test]
async fn refuses_a_document_served_for_another_client_id() {
    let server = open_server();
    let other = claude_document(&[CLAUDE_CALLBACK]).replace(CLAUDE, "https://claude.ai/oauth/other");
    server.documents.serve(CLAUDE, &other);
    let answer = get(&server.front, &authorize_url(CLAUDE, CLAUDE_CALLBACK, true)).await;
    assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
    assert!(server.cognito.app_clients().is_empty());
}

#[tokio::test]
async fn fetches_no_document_from_a_host_it_does_not_trust() {
    let server = open_server();
    let url = "https://evil.example/client.json";
    let document = json!({ "client_id": url, "redirect_uris": ["http://localhost/callback"] }).to_string();
    server.documents.serve(url, &document);
    let answer = get(
        &server.front,
        &authorize_url(url, "http://localhost:5000/callback", true),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.documents.fetches(), 0);
    for client_id in [
        "http://claude.ai/oauth/x",
        "https://claude.ai/",
        "https://claude.ai/a/../b",
        "https://claude.ai/x?y=1",
        "https://user@claude.ai/x",
    ] {
        let answer = get(&server.front, &authorize_url(client_id, CLAUDE_CALLBACK, true)).await;
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{client_id}");
    }
    assert_eq!(server.documents.fetches(), 0);
}

#[tokio::test]
async fn sends_codes_only_to_the_device_or_a_trusted_host() {
    let server = open_server();
    for refused in [
        "https://evil.example/callback",
        "http://evil.example/callback",
        "javascript:alert(1)",
        "microsoft-edge:https://evil.example/callback",
        "cursor://anysphere.cursor-mcp/oauth/callback",
        "https://claude.ai/callback#fragment",
    ] {
        let answer = post_json(&server.front, REGISTER, &registration(&[refused])).await;
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{refused}");
        assert!(json(&answer)["error"].as_str().unwrap().starts_with("invalid_"));
    }
    assert!(server.cognito.app_clients().is_empty());
    for accepted in [
        "http://127.0.0.1:8765/callback",
        "https://claude.ai/api/mcp/auth_callback",
    ] {
        let answer = post_json(&server.front, REGISTER, &registration(&[accepted])).await;
        assert_eq!(answer.status(), StatusCode::CREATED, "{accepted}");
    }

    // A document from a trusted host may list other hosts; they aren't registered.
    server.documents.serve(
        CLAUDE,
        &claude_document(&[CLAUDE_CALLBACK, "https://evil.example/callback"]),
    );
    let tokens = sign_in(
        &server,
        &Authorization {
            client_id: CLAUDE,
            redirect_uri: CLAUDE_CALLBACK,
            scope: DRAFTS,
            resource: Some(MCP),
            extra: &[],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        call_mcp(&server, tokens["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    let evil = get(
        &server.front,
        &authorize_url(CLAUDE, "https://evil.example/callback", true),
    )
    .await;
    assert_eq!(location(&evil), None);
    let callbacks: Vec<String> = server
        .cognito
        .app_clients()
        .into_iter()
        .flat_map(|a| a.callback_urls)
        .collect();
    assert!(
        !callbacks.iter().any(|c| c.contains("evil.example")),
        "{callbacks:?}"
    );
}

#[tokio::test]
async fn a_host_taken_off_the_trusted_list_gets_no_more_codes() {
    let server = open_server();
    let registered = json(&post_json(&server.front, REGISTER, &registration(&[CLAUDE_CALLBACK])).await);
    let url = authorize_url(registered["client_id"].as_str().unwrap(), CLAUDE_CALLBACK, true);
    assert_eq!(get(&server.front, &url).await.status(), StatusCode::FOUND);

    // The operator stops trusting claude.ai and restarts the server.
    let registrar = Registrar::builder(server.cognito.clone(), server.store.clone())
        .dynamic_registration()
        .client_hosts(["chatgpt.com"])
        .build()
        .unwrap();
    let server = serve(server.cognito, server.store, server.documents, registrar);
    let answer = get(&server.front, &url).await;
    assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
    assert_eq!(location(&answer), None, "never redirected to the untrusted host");
}

#[tokio::test]
async fn without_trusted_hosts_only_codes_that_stay_on_the_device_are_allowed() {
    let server = server(|b, documents| b.fetcher(documents).dynamic_registration());
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    let web = get(&server.front, &authorize_url(CLAUDE, CLAUDE_CALLBACK, true)).await;
    assert_eq!(web.status(), StatusCode::BAD_REQUEST);
    let native = "https://cli.example/client.json";
    let document = json!({ "client_id": native, "redirect_uris": ["http://127.0.0.1/callback"] }).to_string();
    server.documents.serve(native, &document);
    let answer = get(
        &server.front,
        &authorize_url(native, "http://127.0.0.1:7777/callback", true),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::FOUND, "{}", answer.body());
    let registered = post_json(
        &server.front,
        REGISTER,
        &registration(&["https://claude.ai/callback"]),
    )
    .await;
    assert_eq!(json(&registered)["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn refuses_a_token_from_an_app_client_it_did_not_register() {
    let server = open_server();
    let stranger = server
        .cognito
        .add_client("someone else's", &["https://elsewhere.example/callback"]);
    let token = server.cognito.access_token(&stranger, Some(MCP), DRAFTS);
    assert_eq!(call_mcp(&server, &token).await, StatusCode::UNAUTHORIZED);

    let registered = json(
        &post_json(
            &server.front,
            REGISTER,
            &registration(&["http://127.0.0.1:9000/cb"]),
        )
        .await,
    );
    let client: ClientId = registered["client_id"].as_str().unwrap().parse().unwrap();
    let token = server.cognito.access_token(&client, Some(MCP), DRAFTS);
    server
        .store
        .edit(client.as_str(), |r| r.created_at -= 2 * 24 * 3600);
    server.registrar.cleanup().await.unwrap();
    assert_eq!(
        call_mcp(&server, &token).await,
        StatusCode::UNAUTHORIZED,
        "a removed registration's tokens stop working"
    );
}

#[tokio::test]
async fn a_registered_client_must_not_authenticate_and_must_use_pkce() {
    let server = open_server();
    let registered = json(
        &post_json(
            &server.front,
            REGISTER,
            &registration(&["http://127.0.0.1:9000/cb"]),
        )
        .await,
    );
    let client_id = registered["client_id"].as_str().unwrap();
    let form = [
        ("grant_type", "authorization_code"),
        ("code", "x"),
        ("client_id", client_id),
        ("client_secret", "guess"),
    ];
    let answer = post_form(&server.front, &format!("{ORIGIN}/oauth2/token"), &form).await;
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&answer)["error"], "invalid_client");

    let answer = get(
        &server.front,
        &authorize_url(client_id, "http://127.0.0.1:9000/cb", false),
    )
    .await;
    let back = location(&answer).expect("the error goes back to the client");
    assert!(
        back.as_str()
            .starts_with("http://127.0.0.1:9000/cb?error=invalid_request")
    );
}

#[tokio::test]
async fn keeps_room_for_the_app_clients_you_manage() {
    let server = server(|b, _| b.dynamic_registration().max_registrations(1));
    let first = post_json(
        &server.front,
        REGISTER,
        &registration(&["http://127.0.0.1:9000/cb"]),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = post_json(
        &server.front,
        REGISTER,
        &registration(&["http://127.0.0.1:9001/cb"]),
    )
    .await;
    assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&second)["error"], "temporarily_unavailable");

    // Cognito's own quota answers the same way.
    let server = open_server();
    server.cognito.limit_app_clients(0);
    let refused = post_json(
        &server.front,
        REGISTER,
        &registration(&["http://127.0.0.1:9000/cb"]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn two_first_sign_ins_at_once_leave_one_app_client() {
    let server = open_server();
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    let url = authorize_url(CLAUDE, CLAUDE_CALLBACK, true);
    let (a, b) = tokio::join!(get(&server.front, &url), get(&server.front, &url));
    assert_eq!((a.status(), b.status()), (StatusCode::FOUND, StatusCode::FOUND));
    assert_eq!(server.cognito.app_clients().len(), 1);
    assert_eq!(
        location(&a)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "client_id"),
        location(&b)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "client_id")
    );
}

#[tokio::test]
async fn cleanup_removes_what_nobody_uses() {
    let server = open_server();
    let register = |uri: &'static str| {
        let front = server.front.clone();
        async move {
            json(&post_json(&front, REGISTER, &registration(&[uri])).await)["client_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let active = register("http://127.0.0.1:9000/cb").await;
    let abandoned = register("http://127.0.0.1:9001/cb").await;
    let idle = register("http://127.0.0.1:9002/cb").await;
    server.store.edit(&active, |r| r.last_used = Some(r.created_at));
    server.store.edit(&abandoned, |r| r.created_at -= 2 * 24 * 3600);
    server
        .store
        .edit(&idle, |r| r.last_used = Some(r.created_at - 40 * 24 * 3600));
    let orphan = server
        .cognito
        .add_client("cognito-kit left behind", &["http://127.0.0.1:9003/cb"]);
    server
        .cognito
        .age_app_client(&orphan, Duration::from_secs(2 * 3600));
    let young = server
        .cognito
        .add_client("cognito-kit being stored", &["http://127.0.0.1:9004/cb"]);
    let yours = server
        .cognito
        .add_client("claude", &["https://claude.ai/api/mcp/auth_callback"]);
    server
        .cognito
        .age_app_client(&yours, Duration::from_secs(90 * 24 * 3600));

    let report = server.registrar.cleanup().await.unwrap();
    assert_eq!((report.unused, report.idle, report.orphans), (1, 1, 1));
    let left: Vec<String> = server
        .cognito
        .app_clients()
        .into_iter()
        .map(|a| a.id.to_string())
        .collect();
    assert!(
        left.contains(&active) && left.contains(&young.to_string()) && left.contains(&yours.to_string()),
        "{left:?}"
    );
    assert_eq!(left.len(), 3);
}

#[tokio::test]
async fn the_relay_sends_a_code_only_back_to_the_device() {
    use base64::Engine;
    let server = open_server();
    let relay = |state: &str| format!("{ORIGIN}/oauth2/callback?code=stolen&state={state}");
    let encode =
        |value: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
    for state in [
        encode(json!({ "r": "https://evil.example/callback", "s": "x" })),
        encode(json!({ "r": "http://evil.example/callback" })),
        encode(json!({ "r": "javascript:alert(1)" })),
        "not-ours".to_owned(),
    ] {
        let answer = get(&server.front, &relay(&state)).await;
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{state}");
        assert_eq!(location(&answer), None);
    }
    let home = get(
        &server.front,
        &relay(&encode(
            json!({ "r": "http://127.0.0.1:8765/callback", "s": "x" }),
        )),
    )
    .await;
    assert_eq!(
        location(&home).unwrap().as_str(),
        "http://127.0.0.1:8765/callback?code=stolen&state=x"
    );
}

#[tokio::test]
async fn stale_writes_leave_a_newer_registration() {
    let server = open_server();
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    let url = authorize_url(CLAUDE, CLAUDE_CALLBACK, true);
    get(&server.front, &url).await;
    let first = server.store.registrations().remove(0);
    server.store.remove(&first).await.unwrap();
    // The next sign-in registers the document again, with a new app client.
    assert_eq!(get(&server.front, &url).await.status(), StatusCode::FOUND);
    // A refresh that read the first registration stores its fetch late,
    // and a cleanup that listed it removes it late.
    let mut refreshed = first.clone();
    refreshed.redirect_uris = vec!["https://claude.ai/api/mcp/old_callback".into()];
    server.store.update(&refreshed).await.unwrap();
    server.store.remove(&first).await.unwrap();
    let left = server.store.registrations();
    assert_eq!(left.len(), 1);
    assert_ne!(left[0].app_client, first.app_client);
    assert_eq!(left[0].redirect_uris, [CLAUDE_CALLBACK]);
}

#[test]
fn refuses_at_startup_a_name_prefix_that_cognito_would_refuse() {
    let build = |prefix: &str| {
        Registrar::builder(FakeCognito::new(), MemoryStore::new())
            .dynamic_registration()
            .name_prefix(prefix)
            .build()
    };
    assert!(build("team/portal").is_err());
    assert!(build("portal-2 eu").is_ok());
}

#[tokio::test]
async fn leaves_an_app_client_managed_by_hand_to_cognito() {
    let server = open_server();
    // A confidential client without PKCE, as an operator may have set one up.
    let url = authorize_url("3hand4managed5client6", "https://app.example.com/callback", false);
    let answer = get(&server.front, &url).await;
    assert_eq!(answer.status(), StatusCode::FOUND);
    let to = location(&answer).expect("sent on to Cognito");
    assert_ne!(to.host_str(), Url::parse(ORIGIN).unwrap().host_str());
    assert_eq!(to.path(), "/oauth2/authorize");
    let sent: std::collections::BTreeMap<String, String> = to.query_pairs().into_owned().collect();
    assert_eq!(sent["client_id"], "3hand4managed5client6");
    assert_eq!(sent["redirect_uri"], "https://app.example.com/callback");
    assert!(!sent.contains_key("code_challenge"), "{sent:?}");
    assert!(
        server.cognito.app_clients().is_empty(),
        "no app client made for it"
    );
}

/// A store with faults: a token request that uses `used_after_list` right
/// after a cleanup lists the registrations, and touches that fail while
/// `touch_fails` is set.
#[derive(Default)]
struct Faulty {
    store: MemoryStore,
    used_after_list: Option<String>,
    touch_fails: Arc<AtomicBool>,
}

impl RegistrationStore for Faulty {
    fn get<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        self.store.get(client_id)
    }
    fn get_by_app_client<'a>(
        &'a self,
        app_client: &'a ClientId,
    ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        self.store.get_by_app_client(app_client)
    }
    fn insert(&self, registration: Registration) -> BoxFuture<'_, Result<Registration, BoxError>> {
        self.store.insert(registration)
    }
    fn update<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>> {
        self.store.update(registration)
    }
    fn touch<'a>(&'a self, client_id: &'a str, at: u64) -> BoxFuture<'a, Result<(), BoxError>> {
        if self.touch_fails.load(Ordering::SeqCst) {
            return Box::pin(async { Err("throttled".into()) });
        }
        self.store.touch(client_id, at)
    }
    fn remove<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>> {
        self.store.remove(registration)
    }
    fn list(&self) -> BoxFuture<'_, Result<Vec<Registration>, BoxError>> {
        Box::pin(async {
            let listed = self.store.list().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if let Some(client) = &self.used_after_list {
                self.store.touch(client, now).await?;
            }
            listed
        })
    }
}

#[tokio::test]
async fn cleanup_keeps_a_client_used_while_it_ran() {
    let server = open_server();
    let answer = post_json(
        &server.front,
        REGISTER,
        &registration(&["http://127.0.0.1:9000/cb"]),
    )
    .await;
    let client = json(&answer)["client_id"].as_str().unwrap().to_owned();
    server
        .store
        .edit(&client, |r| r.last_used = Some(r.created_at - 40 * 24 * 3600));
    let registrar = Registrar::builder(
        server.cognito.clone(),
        Faulty {
            store: server.store.clone(),
            used_after_list: Some(client.clone()),
            ..Faulty::default()
        },
    )
    .dynamic_registration()
    .build()
    .unwrap();

    let report = registrar.cleanup().await.unwrap();
    assert_eq!((report.unused, report.idle, report.orphans), (0, 0, 0));
    assert_eq!(server.cognito.app_clients().len(), 1, "its app client stays");
    assert_eq!(server.store.registrations().len(), 1);
}

#[tokio::test]
async fn cleanup_keeps_a_client_whose_first_use_failed_to_record() {
    let cognito = FakeCognito::new();
    let store = MemoryStore::new();
    let touch_fails = Arc::new(AtomicBool::new(true));
    let faulty = Faulty {
        store: store.clone(),
        touch_fails: touch_fails.clone(),
        ..Faulty::default()
    };
    let registrar = Registrar::builder(cognito.clone(), faulty)
        .dynamic_registration()
        .build()
        .unwrap();
    let server = serve(cognito, store, Documents::default(), registrar);
    let redirect_uri = "http://127.0.0.1:9000/cb";
    let answer = post_json(&server.front, REGISTER, &registration(&[redirect_uri])).await;
    let client = json(&answer)["client_id"].as_str().unwrap().to_owned();
    let auth = Authorization {
        client_id: &client,
        redirect_uri,
        scope: DRAFTS,
        resource: Some(MCP),
        extra: &[],
    };
    sign_in(&server, &auth).await.unwrap();
    // The store failed to record that use, and is back for the next.
    touch_fails.store(false, Ordering::SeqCst);
    sign_in(&server, &auth).await.unwrap();

    server.store.edit(&client, |r| r.created_at -= 2 * 24 * 3600);
    let report = server.registrar.cleanup().await.unwrap();
    assert_eq!(report.unused, 0, "a client in use is not unused");
    assert_eq!(server.store.registrations().len(), 1);
}
