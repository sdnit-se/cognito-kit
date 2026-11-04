//! Each assistant's OAuth flow, as it documents or ships it, replayed
//! against the front: from the MCP URL alone to a tool call, a refresh, and
//! a reused refresh token refused. No client id is typed anywhere.
//!
//! The metadata documents are the assistants' own, fetched on 2026-11-04.
//! Behavior comes from Anthropic's and OpenAI's documentation, the shipped
//! Claude Code 2.1.310 and Codex 0.164.0, Executor's source, and the
//! portal's prototype C runs.

mod front;

use std::collections::BTreeMap;

use front::{
    Authorization, DRAFTS, MCP, ORIGIN, Server, call_mcp, get, json, open_server, post_form, post_json,
    sign_in,
};
use http::StatusCode;
use serde_json::{Value, json};

const CLAUDE: &str = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const CLAUDE_DOCUMENT: &str = r#"{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#;

const CLAUDE_CODE: &str = "https://claude.ai/oauth/claude-code-client-metadata";
const CLAUDE_CODE_DOCUMENT: &str = r#"{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#;

// ChatGPT's document for a server without RFC 9207 `iss`, which Cognito
// doesn't send: one per connector, with the connector's callback.
const CHATGPT: &str = "https://chatgpt.com/oauth/mcp/client.json";
const CHATGPT_DOCUMENT: &str = r#"{"client_id":"https://chatgpt.com/oauth/mcp/client.json","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector/oauth/mcp"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"ChatGPT","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png","token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://chatgpt.com/oauth/jwks.json"}"#;

// Codex has a document per server, named by an id it derives from the
// server, with that id in its callback path.
const CODEX: &str = "https://chatgpt.com/oauth/codex/EL3FpU2s_bzX/client.json";
const CODEX_DOCUMENT: &str = r#"{"client_id":"https://chatgpt.com/oauth/codex/EL3FpU2s_bzX/client.json","client_uri":"https://chatgpt.com/codex","application_type":"native","redirect_uris":["http://127.0.0.1/callback/EL3FpU2s_bzX","http://localhost/callback/EL3FpU2s_bzX"],"token_endpoint_auth_method":"none","token_endpoint_auth_methods_supported":["none"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"Codex","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png"}"#;

const EXECUTOR_LOCAL: &str = "https://executor.sh/api/oauth/client-id-metadata/local.json";
const EXECUTOR_LOCAL_DOCUMENT: &str = r#"{"client_id":"https://executor.sh/api/oauth/client-id-metadata/local.json","client_name":"Executor Local","client_uri":"https://executor.sh","redirect_uris":["http://127.0.0.1/api/oauth/callback","http://localhost/api/oauth/callback","http://[::1]/api/oauth/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"native"}"#;

const EXECUTOR: &str = "https://executor.sh/api/oauth/client-id-metadata.json";
const EXECUTOR_DOCUMENT: &str = r#"{"client_id":"https://executor.sh/api/oauth/client-id-metadata.json","client_name":"Executor","client_uri":"https://executor.sh","redirect_uris":["https://executor.sh/api/oauth/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"web"}"#;

/// What every assistant does first: call the MCP URL, follow the 401 to the
/// protected resource document, and read the authorization server's.
/// Claude on the web reads the root document when a proxy drops
/// `WWW-Authenticate`, as Lambda function URLs do.
async fn discover(server: &Server, root_only: bool) -> (Value, Value) {
    let challenge = server
        .front
        .verifier()
        .authenticate::<()>(&http::HeaderMap::new())
        .await
        .unwrap_err()
        .response();
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    let header = challenge.headers()[http::header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    let from_header = header
        .split("resource_metadata=\"")
        .nth(1)
        .unwrap()
        .trim_end_matches('"');
    let resource_url = if root_only {
        format!("{ORIGIN}/.well-known/oauth-protected-resource")
    } else {
        from_header.to_owned()
    };
    let resource = json(&get(&server.front, &resource_url).await);
    assert_eq!(resource["resource"], MCP);
    let issuer = resource["authorization_servers"][0].as_str().unwrap();
    let metadata = json(
        &get(
            &server.front,
            &format!("{issuer}/.well-known/oauth-authorization-server"),
        )
        .await,
    );
    assert_eq!(metadata["issuer"], issuer);
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"]),
        "ChatGPT refuses a server without S256"
    );
    assert!(
        metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("none"))
    );
    (resource, metadata)
}

fn scopes(resource: &Value, extra: &[&str]) -> String {
    let mut scopes: Vec<String> = extra.iter().map(|s| (*s).to_owned()).collect();
    for scope in resource["scopes_supported"].as_array().unwrap() {
        scopes.push(scope.as_str().unwrap().to_owned());
    }
    scopes.join(" ")
}

async fn refresh(server: &Server, client_id: &str, token: &str) -> http::Response<String> {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", client_id),
        ("resource", MCP),
    ];
    post_form(&server.front, &format!("{ORIGIN}/oauth2/token"), &form).await
}

/// Uses the tokens as the assistant does: a tool call, then a refresh with
/// `resource`, then the old refresh token again, which rotation refuses.
async fn use_tokens(server: &Server, client_id: &str, tokens: &Value) {
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(call_mcp(server, access).await, StatusCode::OK);
    let old = tokens["refresh_token"].as_str().unwrap();
    let refreshed = refresh(server, client_id, old).await;
    assert_eq!(refreshed.status(), StatusCode::OK, "{}", refreshed.body());
    let refreshed = json(&refreshed);
    assert_ne!(refreshed["refresh_token"], tokens["refresh_token"], "rotation");
    assert_eq!(
        call_mcp(server, refreshed["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    let reused = refresh(server, client_id, old).await;
    assert_eq!(json(&reused)["error"], "invalid_grant");
}

/// A client with a metadata document: its URL is its client id.
async fn connect_with_document(server: &Server, client_id: &str, redirect_uri: &str, scope: &str) -> Value {
    sign_in(
        server,
        &Authorization {
            client_id,
            redirect_uri,
            scope,
            resource: Some(MCP),
            extra: &[],
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{client_id} via {redirect_uri}: {e}"))
}

#[tokio::test]
async fn claude_connects_from_the_url_alone() {
    let server = open_server();
    server.documents.serve(CLAUDE, CLAUDE_DOCUMENT);
    let (resource, metadata) = discover(&server, true).await;
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    let tokens = connect_with_document(
        &server,
        CLAUDE,
        "https://claude.ai/api/mcp/auth_callback",
        &scopes(&resource, &["openid", "email"]),
    )
    .await;
    use_tokens(&server, CLAUDE, &tokens).await;
}

#[tokio::test]
async fn chatgpt_connects_from_the_url_alone() {
    let server = open_server();
    server.documents.serve(CHATGPT, CHATGPT_DOCUMENT);
    let (resource, metadata) = discover(&server, false).await;
    // ChatGPT picks CIMD when offered, and `none` from the methods both
    // sides support, though its document prefers private_key_jwt.
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    assert_eq!(
        metadata.get("authorization_response_iss_parameter_supported"),
        None
    );
    let tokens = connect_with_document(
        &server,
        CHATGPT,
        "https://chatgpt.com/connector/oauth/mcp",
        &scopes(&resource, &["openid"]),
    )
    .await;
    use_tokens(&server, CHATGPT, &tokens).await;
}

#[tokio::test]
async fn claude_code_connects_from_the_url_alone_on_any_port() {
    let server = open_server();
    server.documents.serve(CLAUDE_CODE, CLAUDE_CODE_DOCUMENT);
    let (resource, _) = discover(&server, false).await;
    let scope = scopes(&resource, &[]);
    // Claude Code listens on a port the system picks, unless pinned with
    // --callback-port, and signs in again on a new one later.
    for port in [49152, 61234] {
        let redirect_uri = format!("http://localhost:{port}/callback");
        let tokens = connect_with_document(&server, CLAUDE_CODE, &redirect_uri, &scope).await;
        use_tokens(&server, CLAUDE_CODE, &tokens).await;
    }
    let apps = server.cognito.app_clients();
    assert_eq!(apps.len(), 1, "one app client for every Claude Code user");
    assert_eq!(
        apps[0].callback_urls,
        [format!("{ORIGIN}/oauth2/callback")],
        "ports never reach Cognito"
    );
}

#[tokio::test]
async fn codex_connects_from_the_url_alone() {
    let server = open_server();
    server.documents.serve(CODEX, CODEX_DOCUMENT);
    let (resource, _) = discover(&server, false).await;
    // Codex listens on an ephemeral port, a new one for each sign-in.
    for port in [50321, 41877] {
        let redirect_uri = format!("http://127.0.0.1:{port}/callback/EL3FpU2s_bzX");
        let tokens = connect_with_document(&server, CODEX, &redirect_uri, &scopes(&resource, &[])).await;
        use_tokens(&server, CODEX, &tokens).await;
    }
}

#[tokio::test]
async fn executor_connects_from_the_url_alone() {
    let server = open_server();
    server.documents.serve(EXECUTOR_LOCAL, EXECUTOR_LOCAL_DOCUMENT);
    server.documents.serve(EXECUTOR, EXECUTOR_DOCUMENT);
    let (resource, _) = discover(&server, false).await;
    // Executor asks only for the resource's own scopes, so no ID token.
    let scope = scopes(&resource, &[]);
    let local = connect_with_document(
        &server,
        EXECUTOR_LOCAL,
        "http://127.0.0.1:4312/api/oauth/callback",
        &scope,
    )
    .await;
    assert!(local.get("id_token").is_none());
    use_tokens(&server, EXECUTOR_LOCAL, &local).await;
    let ipv6 = connect_with_document(
        &server,
        EXECUTOR_LOCAL,
        "http://[::1]:4312/api/oauth/callback",
        &scope,
    )
    .await;
    use_tokens(&server, EXECUTOR_LOCAL, &ipv6).await;
    let cloud = connect_with_document(
        &server,
        EXECUTOR,
        "https://executor.sh/api/oauth/callback",
        &scope,
    )
    .await;
    use_tokens(&server, EXECUTOR, &cloud).await;
}

/// A client without a metadata document registers itself, as Claude Code
/// and Executor do when a server offers only Dynamic Client Registration,
/// and ChatGPT does when its builder picks it.
async fn connect_by_registration(server: &Server, registration: Value, redirect_uri: &str, scope: &str) {
    let (_, metadata) = discover(server, false).await;
    let endpoint = metadata["registration_endpoint"]
        .as_str()
        .expect("a registration endpoint");
    let registered = post_json(&server.front, endpoint, &registration).await;
    assert_eq!(registered.status(), StatusCode::CREATED, "{}", registered.body());
    let registered = json(&registered);
    assert_eq!(registered["token_endpoint_auth_method"], "none");
    let client_id = registered["client_id"].as_str().unwrap();
    let tokens = sign_in(
        server,
        &Authorization {
            client_id,
            redirect_uri,
            scope,
            resource: Some(MCP),
            extra: &[],
        },
    )
    .await
    .unwrap();
    use_tokens(server, client_id, &tokens).await;
}

#[tokio::test]
async fn claude_code_registers_when_no_document_is_offered() {
    let server = front::server(|b, _| b.dynamic_registration());
    let (_, metadata) = discover(&server, false).await;
    assert_eq!(metadata.get("client_id_metadata_document_supported"), None);
    let registration = json!({
        "client_name": "Claude Code (portal)",
        "redirect_uris": ["http://localhost:53121/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": DRAFTS,
    });
    connect_by_registration(&server, registration, "http://localhost:53121/callback", DRAFTS).await;
}

#[tokio::test]
async fn chatgpt_registers_when_its_builder_picks_registration() {
    let server = open_server();
    let registration = json!({
        "client_name": "ChatGPT",
        "redirect_uris": ["https://chatgpt.com/connector/oauth/abc123"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    connect_by_registration(
        &server,
        registration,
        "https://chatgpt.com/connector/oauth/abc123",
        &format!("openid {DRAFTS}"),
    )
    .await;
}

#[tokio::test]
async fn every_assistant_gets_its_own_app_client_and_none_is_typed() {
    let server = open_server();
    let documents: BTreeMap<&str, (&str, &str)> = [
        (
            CLAUDE,
            (CLAUDE_DOCUMENT, "https://claude.ai/api/mcp/auth_callback"),
        ),
        (
            CLAUDE_CODE,
            (CLAUDE_CODE_DOCUMENT, "http://localhost:50000/callback"),
        ),
        (
            CHATGPT,
            (CHATGPT_DOCUMENT, "https://chatgpt.com/connector/oauth/mcp"),
        ),
        (
            CODEX,
            (CODEX_DOCUMENT, "http://127.0.0.1:50001/callback/EL3FpU2s_bzX"),
        ),
        (
            EXECUTOR_LOCAL,
            (
                EXECUTOR_LOCAL_DOCUMENT,
                "http://127.0.0.1:4312/api/oauth/callback",
            ),
        ),
    ]
    .into();
    for (url, (document, redirect_uri)) in &documents {
        server.documents.serve(url, document);
        connect_with_document(&server, url, redirect_uri, DRAFTS).await;
    }
    let apps = server.cognito.app_clients();
    assert_eq!(apps.len(), documents.len());
    assert!(apps.iter().all(|a| a.name.starts_with("cognito-kit ")));
}
