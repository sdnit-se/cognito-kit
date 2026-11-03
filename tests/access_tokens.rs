//! What a client or an attacker sees when a Cognito-protected service checks
//! its bearer tokens.

mod support;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cognito_kit::{AccessClaims, AccessTokenVerifier, Rejection, UserPool};
use http::StatusCode;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use support::{CLIENT, FakeCognito, KEYS, access_claims, id_claims, now, sign};

const MCP: &str = "https://portal.example.com/mcp";
const DRAFTS: &str = "https://portal.example.com/mcp/drafts";
const KEY_AGE: Duration = Duration::from_millis(50);

fn verifier(pool: &UserPool) -> AccessTokenVerifier {
    pool.access_tokens()
        .client(CLIENT.parse().unwrap())
        .resource(MCP.parse().unwrap())
        .scope(DRAFTS.parse().unwrap())
        .build()
        .unwrap()
}

async fn check(token: &str) -> Result<AccessClaims, Rejection> {
    verifier(&FakeCognito::publishing(&["k1"]).pool())
        .verify(token)
        .await
}

#[derive(serde::Deserialize)]
struct Tenant {
    #[serde(rename = "custom:tenant")]
    tenant: String,
}

#[tokio::test]
async fn accepts_a_valid_token_and_types_its_claims() {
    let mut claims = access_claims(MCP, &format!("openid {DRAFTS}"));
    claims["custom:tenant"] = json!("acme");
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let claims: AccessClaims<Tenant> = verifier(&pool).verify(&sign("k1", &claims)).await.unwrap();
    assert_eq!(claims.sub.as_str(), "6f1c2e7a-0000-4000-8000-000000000001");
    assert_eq!(claims.client_id.as_str(), CLIENT);
    assert_eq!(claims.groups, ["editors"]);
    assert!(claims.scopes.contains(&DRAFTS.parse().unwrap()));
    assert_eq!(claims.custom.tenant, "acme");
}

#[tokio::test]
async fn refuses_a_token_from_another_pool() {
    let mut claims = access_claims(MCP, DRAFTS);
    claims["iss"] = json!("https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_OtherPool");
    assert!(matches!(
        check(&sign("k1", &claims)).await,
        Err(Rejection::Issuer)
    ));
}

#[tokio::test]
async fn refuses_a_token_for_another_resource_or_none() {
    let other = access_claims("https://evil.example.com/mcp", DRAFTS);
    assert!(matches!(
        check(&sign("k1", &other)).await,
        Err(Rejection::Audience)
    ));

    let mut no_aud = access_claims(MCP, DRAFTS);
    no_aud.as_object_mut().unwrap().remove("aud");
    assert!(matches!(
        check(&sign("k1", &no_aud)).await,
        Err(Rejection::Audience)
    ));
}

#[tokio::test]
async fn refuses_an_id_token_as_an_access_token() {
    let mut claims = id_claims(CLIENT, None);
    claims["aud"] = json!(MCP);
    assert!(matches!(
        check(&sign("k1", &claims)).await,
        Err(Rejection::TokenUse)
    ));
}

#[tokio::test]
async fn refuses_a_token_issued_to_another_app_client() {
    let mut claims = access_claims(MCP, DRAFTS);
    claims["client_id"] = json!("customerportalclient");
    assert!(matches!(
        check(&sign("k1", &claims)).await,
        Err(Rejection::Client)
    ));
}

#[tokio::test]
async fn answers_a_missing_scope_with_403() {
    let rejection = check(&sign("k1", &access_claims(MCP, "openid email")))
        .await
        .unwrap_err();
    assert!(matches!(&rejection, Rejection::Scope(s) if s.as_str() == DRAFTS));
    assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn refuses_an_expired_token_beyond_the_leeway() {
    let mut claims = access_claims(MCP, DRAFTS);
    claims["exp"] = json!(now() - 120);
    assert!(matches!(
        check(&sign("k1", &claims)).await,
        Err(Rejection::Expired)
    ));

    claims["exp"] = json!(now() - 30);
    assert!(
        check(&sign("k1", &claims)).await.is_ok(),
        "within the 60 s leeway"
    );
}

#[tokio::test]
async fn refetches_keys_for_an_unknown_kid_at_most_once_per_cooldown() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let verifier = verifier(&cognito.pool().refetch_cooldown(Duration::from_secs(3600)));
    let rotated = sign("k2", &access_claims(MCP, DRAFTS));

    verifier
        .verify::<()>(&sign("k1", &access_claims(MCP, DRAFTS)))
        .await
        .unwrap();
    cognito.publish(&["k1", "k2"]);
    for _ in 0..5 {
        assert!(matches!(
            verifier.verify::<()>(&rotated).await,
            Err(Rejection::UnknownKey)
        ));
    }
    assert_eq!(
        cognito.jwks_fetches(),
        1,
        "forged key ids must not trigger fetches"
    );
}

#[tokio::test]
async fn accepts_a_rotated_key_once_the_cooldown_has_passed() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let verifier = verifier(&cognito.pool().refetch_cooldown(Duration::ZERO));
    verifier
        .verify::<()>(&sign("k1", &access_claims(MCP, DRAFTS)))
        .await
        .unwrap();
    cognito.publish(&["k1", "k2"]);
    verifier
        .verify::<()>(&sign("k2", &access_claims(MCP, DRAFTS)))
        .await
        .unwrap();
    assert_eq!(cognito.jwks_fetches(), 2);
}

#[tokio::test]
async fn stops_accepting_a_withdrawn_key_once_the_keys_are_stale() {
    let cognito = FakeCognito::publishing(&["k1", "k2"]);
    let pool = cognito
        .pool()
        .refetch_cooldown(Duration::ZERO)
        .max_key_age(KEY_AGE);
    let verifier = verifier(&pool);
    let token = sign("k2", &access_claims(MCP, DRAFTS));
    verifier.verify::<()>(&token).await.unwrap();
    cognito.publish(&["k1"]);
    tokio::time::sleep(KEY_AGE * 2).await;
    assert!(matches!(
        verifier.verify::<()>(&token).await,
        Err(Rejection::UnknownKey)
    ));
}

#[tokio::test]
async fn never_trusts_stale_keys_while_cognito_is_unreachable() {
    let cognito = FakeCognito::publishing(&["k1"]);
    let pool = cognito
        .pool()
        .refetch_cooldown(Duration::ZERO)
        .max_key_age(KEY_AGE);
    let verifier = verifier(&pool);
    let token = sign("k1", &access_claims(MCP, DRAFTS));
    verifier.verify::<()>(&token).await.unwrap();
    cognito.fail_jwks_with(500);
    tokio::time::sleep(KEY_AGE * 2).await;
    let rejection = verifier.verify::<()>(&token).await.unwrap_err();
    assert_eq!(rejection.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn answers_503_when_the_keys_cannot_be_fetched() {
    let cognito = FakeCognito::default();
    cognito.fail_jwks_with(500);
    let rejection = verifier(&cognito.pool())
        .verify::<()>(&sign("k1", &access_claims(MCP, DRAFTS)))
        .await;
    assert_eq!(rejection.unwrap_err().status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn refuses_an_unsigned_token() {
    let encode = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let header = encode(json!({ "alg": "none", "kid": "k1", "typ": "JWT" }));
    let token = format!("{header}.{}.", encode(access_claims(MCP, DRAFTS)));
    assert_eq!(
        check(&token).await.unwrap_err().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refuses_hs256_signed_with_the_public_key() {
    let header = Header {
        kid: Some("k1".to_owned()),
        ..Header::new(Algorithm::HS256)
    };
    let secret = EncodingKey::from_secret(KEYS[0].public_pem.as_bytes());
    let token = jsonwebtoken::encode(&header, &access_claims(MCP, DRAFTS), &secret).unwrap();
    assert!(matches!(check(&token).await, Err(Rejection::Algorithm)));
}

#[tokio::test]
async fn refuses_a_token_whose_signature_was_tampered_with() {
    let token = sign("k1", &access_claims(MCP, "openid"));
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let (header, _) = signed.split_once('.').unwrap();
    let forged = format!(
        "{header}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(access_claims(MCP, DRAFTS).to_string())
    );
    assert!(matches!(check(&forged).await, Err(Rejection::Signature)));
}

#[tokio::test]
async fn needs_at_least_one_app_client() {
    let pool = FakeCognito::default().pool();
    assert!(pool.access_tokens().build().is_err());
}

#[tokio::test]
async fn checks_id_tokens_for_their_own_app_client() {
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let id_tokens = pool.id_tokens(CLIENT.parse().unwrap());
    let claims = id_tokens
        .verify::<()>(&sign("k1", &id_claims(CLIENT, None)))
        .await
        .unwrap();
    assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
    assert!(claims.email_verified);
    assert_eq!(claims.identities[0].provider_name, "Google");

    let for_other = sign("k1", &id_claims("someotherclient", None));
    assert!(matches!(
        id_tokens.verify::<()>(&for_other).await,
        Err(Rejection::Audience)
    ));
    let access = sign("k1", &access_claims(CLIENT, DRAFTS));
    assert!(matches!(
        id_tokens.verify::<()>(&access).await,
        Err(Rejection::TokenUse)
    ));
}
