//! The OAuth front as an MCP client walks it: a 401, the challenge's
//! `resource_metadata`, the protected resource document, the authorization
//! server document, and the checks on the token it comes back with.

mod support;

use cognito_kit::{AccessTokenVerifier, OAuthFront, UserPool};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::Value;
use support::{CLIENT, FakeCognito, LOGIN, access_claims, sign};
use url::Url;

const MCP: &str = "https://portal.example.com/mcp";
const DRAFTS: &str = "https://portal.example.com/mcp/drafts";

fn front(pool: &UserPool, resource: &str) -> OAuthFront {
    let verifier = pool
        .access_tokens()
        .client(CLIENT.parse().unwrap())
        .resource(resource.parse().unwrap())
        .scope(DRAFTS.parse().unwrap())
        .build()
        .unwrap();
    OAuthFront::new(verifier, LOGIN.parse().unwrap()).unwrap()
}

fn get(front: &OAuthFront, url: &str) -> Value {
    let response = front
        .respond(&Method::GET, Url::parse(url).unwrap().path())
        .expect("a document");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_str(response.body()).unwrap()
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// The `WWW-Authenticate` parameters, in a map.
fn challenge_params(response: &http::Response<String>) -> Vec<(String, String)> {
    let value = response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
    let params = value.strip_prefix("Bearer ").expect("a Bearer challenge");
    params
        .split(", ")
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap();
            (k.to_owned(), v.trim_matches('"').to_owned())
        })
        .collect()
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn leads_a_client_from_a_401_to_cognito() {
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let front = front(&pool, MCP);

    let response = front
        .verifier()
        .authenticate::<()>(&HeaderMap::new())
        .await
        .unwrap_err()
        .response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let params = challenge_params(&response);
    assert_eq!(
        param(&params, "error"),
        None,
        "RFC 6750: no error code without credentials"
    );
    assert_eq!(param(&params, "scope"), Some(DRAFTS));

    let resource = get(&front, param(&params, "resource_metadata").unwrap());
    assert_eq!(resource["resource"], MCP);
    assert_eq!(resource["scopes_supported"], serde_json::json!([DRAFTS]));
    assert_eq!(
        resource["bearer_methods_supported"],
        serde_json::json!(["header"])
    );
    assert_eq!(
        get(
            &front,
            "https://portal.example.com/.well-known/oauth-protected-resource"
        ),
        resource,
        "clients that miss the header look at the root"
    );

    let issuer = resource["authorization_servers"][0].as_str().unwrap();
    let server = get(
        &front,
        &format!("{issuer}/.well-known/oauth-authorization-server"),
    );
    assert_eq!(server["issuer"], issuer, "RFC 8414 section 3.3");
    assert_eq!(
        server["authorization_endpoint"],
        format!("{LOGIN}/oauth2/authorize")
    );
    assert_eq!(server["token_endpoint"], format!("{LOGIN}/oauth2/token"));
    assert_eq!(server["revocation_endpoint"], format!("{LOGIN}/oauth2/revoke"));
    assert_eq!(
        server["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        server["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none"])
    );
    assert_eq!(server["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(
        server["grant_types_supported"],
        serde_json::json!(["authorization_code", "refresh_token"])
    );

    let token = sign("k1", &access_claims(MCP, &format!("openid {DRAFTS}")));
    let claims = front
        .verifier()
        .authenticate::<()>(&bearer(&token))
        .await
        .unwrap();
    assert_eq!(claims.client_id.as_str(), CLIENT);
}

#[tokio::test]
async fn tells_a_client_with_a_bad_token_to_sign_in_again() {
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let front = front(&pool, MCP);
    let token = sign("k1", &access_claims("https://elsewhere.example.com/mcp", DRAFTS));
    let response = front
        .verifier()
        .authenticate::<()>(&bearer(&token))
        .await
        .unwrap_err()
        .response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let params = challenge_params(&response);
    assert_eq!(param(&params, "error"), Some("invalid_token"));
    assert!(param(&params, "resource_metadata").is_some());
}

#[tokio::test]
async fn asks_for_the_missing_scope_with_403() {
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let front = front(&pool, MCP);
    let token = sign("k1", &access_claims(MCP, "openid email"));
    let response = front
        .verifier()
        .authenticate::<()>(&bearer(&token))
        .await
        .unwrap_err()
        .response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let params = challenge_params(&response);
    assert_eq!(param(&params, "error"), Some("insufficient_scope"));
    assert_eq!(param(&params, "scope"), Some(DRAFTS));
}

#[tokio::test]
async fn names_a_server_at_the_root_without_a_trailing_slash() {
    let pool = FakeCognito::publishing(&["k1"]).pool();
    let front = front(&pool, "https://mcp.example.com");
    let resource = get(
        &front,
        "https://mcp.example.com/.well-known/oauth-protected-resource",
    );
    assert_eq!(resource["resource"], "https://mcp.example.com");
    let token = sign("k1", &access_claims("https://mcp.example.com", DRAFTS));
    front.verifier().verify::<()>(&token).await.unwrap();
}

#[tokio::test]
async fn needs_a_verifier_that_protects_a_resource() {
    let pool = FakeCognito::default().pool();
    let plain: AccessTokenVerifier = pool
        .access_tokens()
        .client(CLIENT.parse().unwrap())
        .build()
        .unwrap();
    assert!(OAuthFront::new(plain, LOGIN.parse().unwrap()).is_err());
}

#[tokio::test]
async fn answers_only_its_own_paths() {
    let pool = FakeCognito::default().pool();
    let front = front(&pool, MCP);
    assert!(front.respond(&Method::GET, "/mcp").is_none());
    assert!(
        front
            .respond(&Method::POST, "/.well-known/oauth-authorization-server")
            .is_none()
    );
    assert!(
        front
            .respond(&Method::GET, "/.well-known/openid-configuration")
            .is_none()
    );
}
