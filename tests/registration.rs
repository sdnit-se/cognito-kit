//! What an attacker, or an operator watching the pool, would notice about
//! client registration: where codes may go, which documents count, which
//! tokens pass, and how app clients are kept in check.

mod front;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use cognito_kit::registration::{
    AdminError, AppClients, BoxFuture, FetchDocument, FetchError, Registrar, Registration, RegistrationStore,
};
use cognito_kit::test_kit::{FakeCognito, MemoryStore};
use cognito_kit::{BoxError, ClientId, OAuthFront};
use tokio::sync::{Notify, SetOnce};

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

fn claude(redirect_uri: &str) -> Authorization<'_> {
    Authorization {
        client_id: CLAUDE,
        redirect_uri,
        scope: DRAFTS,
        resource: Some(MCP),
        extra: &[],
    }
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

/// Spends the rest of a server's app-client writes for the minute.
async fn spend(front: &OAuthFront) {
    loop {
        let answer = post_json(front, REGISTER, &registration(&["http://127.0.0.1:9000/cb"])).await;
        if answer.status() != StatusCode::CREATED {
            assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
            return;
        }
    }
}

/// Whether a sign-in finished, or got 503 so that the client tries again,
/// rather than reaching Cognito with a callback it lacks.
fn signed_in_or_retry(signed_in: &Result<serde_json::Value, String>) -> bool {
    signed_in.is_ok() || signed_in.as_ref().is_err_and(|e| e.starts_with("503"))
}

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

    // Its app client still lists the host, and Cognito's authorize is
    // public, so cleanup removes it.
    let report = server.registrar.cleanup().await.unwrap();
    assert_eq!(report.untrusted, 1);
    assert!(server.cognito.app_clients().is_empty());
    assert!(server.store.registrations().is_empty());
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

#[tokio::test]
async fn the_next_refresh_repairs_an_interrupted_one() {
    let server = open_server();
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    // A refresh stored the document and stopped before Cognito got it.
    let app_client = server.store.registrations().remove(0).app_client;
    let lost = ["https://claude.ai/api/mcp/old_callback".to_owned()];
    server
        .cognito
        .set_callback_urls(&app_client, &lost)
        .await
        .unwrap();
    server.store.edit(CLAUDE, |r| r.fetched_at -= 600);
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
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
    // Cut short in a name, cleanup wouldn't know its app clients.
    assert!(build(&"p".repeat(65)).is_err());
    assert!(build(&"p".repeat(64)).is_ok());
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
/// after a cleanup lists the registrations, touches that fail while
/// `touch_fails` is set, and updates in the `order` given.
#[derive(Clone, Default)]
struct Faulty {
    store: MemoryStore,
    used_after_list: Option<String>,
    touch_fails: Arc<AtomicBool>,
    order: Option<Arc<Order>>,
}

/// An update of a registration listing `then` waits until one listing
/// `first` is written.
struct Order {
    first: String,
    then: String,
    written: SetOnce<()>,
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
        let lists = |uri: &String| registration.redirect_uris.contains(uri);
        Box::pin(async move {
            if let Some(order) = self.order.as_ref().filter(|o| lists(&o.then)) {
                order.written.wait().await;
            }
            let written = self.store.update(registration).await;
            if let Some(order) = self.order.as_ref().filter(|o| lists(&o.first)) {
                let _ = order.written.set(());
            }
            written
        })
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

/// Answers fetches with these documents in turn, and with the last one from
/// then on.
struct Versions(Mutex<VecDeque<String>>);

impl FetchDocument for Versions {
    fn fetch<'a>(&'a self, _: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        let mut left = self.0.lock().unwrap();
        let body = if left.len() > 1 {
            left.pop_front()
        } else {
            left.front().cloned()
        };
        Box::pin(async move { Ok(body.expect("a document").into_bytes()) })
    }
}

/// A fake Cognito with faults: a callback write listing `slow`, made once
/// the store lists it too, waits until `release` is notified, and the next
/// callback write fails while `fails` is set.
#[derive(Default)]
struct FaultyCognito {
    cognito: FakeCognito,
    store: MemoryStore,
    slow: Option<String>,
    release: Arc<Notify>,
    fails: Arc<AtomicBool>,
}

impl AppClients for FaultyCognito {
    fn create<'a>(
        &'a self,
        name: &'a str,
        callback_urls: &'a [String],
    ) -> BoxFuture<'a, Result<ClientId, AdminError>> {
        self.cognito.create(name, callback_urls)
    }
    fn set_callback_urls<'a>(
        &'a self,
        client: &'a ClientId,
        urls: &'a [String],
    ) -> BoxFuture<'a, Result<(), AdminError>> {
        if self.fails.swap(false, Ordering::SeqCst) {
            return Box::pin(async { Err(AdminError::Other(Arc::new("TooManyRequestsException".into()))) });
        }
        let slow = self.slow.as_ref().is_some_and(|uri| {
            urls.contains(uri)
                && self
                    .store
                    .registrations()
                    .iter()
                    .any(|r| r.redirect_uris.contains(uri))
        });
        Box::pin(async move {
            if slow {
                self.release.notified().await;
            }
            self.cognito.set_callback_urls(client, urls).await
        })
    }
    fn delete<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<(), AdminError>> {
        self.cognito.delete(client)
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<ClientId>, AdminError>> {
        self.cognito.list(prefix)
    }
    fn created<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<SystemTime, AdminError>> {
        self.cognito.created(client)
    }
}

/// Runs concurrent sign-ins, failing instead of hanging if they never finish.
async fn finish<F: Future>(sign_ins: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), sign_ins)
        .await
        .expect("the sign-ins finish")
}

#[tokio::test]
async fn a_new_redirect_uri_works_after_refreshes_that_overtake_each_other() {
    let old = "https://claude.ai/api/mcp/auth_callback/2";
    let new = "https://claude.ai/api/mcp/auth_callback/3";
    // Two sign-ins refresh Claude's document while it moves its callback, so
    // one fetch gets the old document and the other the new. Both read the
    // store before either writes, the old document is stored first, and its
    // Cognito write lands last.
    let store = MemoryStore::new();
    let release = Arc::new(Notify::new());
    let fake = FakeCognito::new();
    let cognito = FaultyCognito {
        cognito: fake.clone(),
        store: store.clone(),
        slow: Some(old.to_owned()),
        release: release.clone(),
        ..FaultyCognito::default()
    };
    let faulty = Faulty {
        store: store.clone(),
        order: Some(Arc::new(Order {
            first: old.to_owned(),
            then: new.to_owned(),
            written: SetOnce::new(),
        })),
        ..Faulty::default()
    };
    let documents = [CLAUDE_CALLBACK, new, old, new].map(|uri| claude_document(&[uri]));
    let registrar = Registrar::builder(cognito, faulty)
        .fetcher(Versions(Mutex::new(documents.into())))
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let server = serve(fake, store, Documents::default(), registrar);
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    server.store.edit(CLAUDE, |r| r.fetched_at -= 600);

    let refresh = || async {
        get(&server.front, &authorize_url(CLAUDE, new, true)).await;
        release.notify_one();
    };
    finish(async { tokio::join!(refresh(), refresh()) }).await;
    let signed_in = finish(sign_in(&server, &claude(new))).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
}

#[tokio::test]
async fn a_document_due_for_a_refresh_signs_in_while_app_client_writes_are_spent() {
    let server = open_server();
    let added = "https://claude.ai/api/mcp/auth_callback/2";
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK, added]));
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    // A refresh that added `added` stored it, and Cognito never got it.
    let app_client = server.store.registrations().remove(0).app_client;
    server
        .cognito
        .set_callback_urls(&app_client, &[CLAUDE_CALLBACK.to_owned()])
        .await
        .unwrap();
    server.store.edit(CLAUDE, |r| r.fetched_at -= 600);
    spend(&server.front).await;
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    let fetches = server.documents.fetches();
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    assert_eq!(
        server.documents.fetches(),
        fetches,
        "fetched at most once a minute while the writes are spent"
    );

    // Another server, with writes to spare, refreshes the document, and
    // Cognito throttles its first write.
    let cognito = FaultyCognito {
        cognito: server.cognito.clone(),
        fails: Arc::new(AtomicBool::new(true)),
        ..FaultyCognito::default()
    };
    let registrar = Registrar::builder(cognito, server.store.clone())
        .fetcher(server.documents.clone())
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let other = serve(
        server.cognito.clone(),
        server.store.clone(),
        server.documents.clone(),
        registrar,
    );
    let _ = sign_in(&other, &claude(added)).await;
    let on_spent = sign_in(&server, &claude(added)).await;
    assert!(signed_in_or_retry(&on_spent), "{on_spent:?}");
    let signed_in = sign_in(&other, &claude(added)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
}

#[tokio::test]
async fn a_retry_signs_in_after_cognito_refused_a_refresh() {
    let new = "https://claude.ai/api/mcp/auth_callback/2";
    let fake = FakeCognito::new();
    let store = MemoryStore::new();
    let documents = Documents::default();
    let fails = Arc::new(AtomicBool::new(false));
    let cognito = FaultyCognito {
        cognito: fake.clone(),
        fails: fails.clone(),
        ..FaultyCognito::default()
    };
    let registrar = Registrar::builder(cognito, store.clone())
        .fetcher(documents.clone())
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let server = serve(fake, store, documents, registrar);
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    // Claude moves its callback, and Cognito throttles the refresh's write.
    server.documents.serve(CLAUDE, &claude_document(&[new]));
    server.store.edit(CLAUDE, |r| r.fetched_at -= 120);
    fails.store(true, Ordering::SeqCst);
    let _ = sign_in(&server, &claude(new)).await;
    let retried = sign_in(&server, &claude(new)).await;
    assert!(retried.is_ok(), "{retried:?}");
}

#[tokio::test]
async fn a_sign_in_repairs_a_refresh_that_ran_out_of_writes_partway() {
    let old = "https://claude.ai/api/mcp/auth_callback/2";
    let new = "https://claude.ai/api/mcp/auth_callback/3";
    // Two servers share the pool and the store, and their fetches of
    // Claude's document cross: A gets the old one, B the new. A stores the
    // old one, B stores the new one and finishes, A's other app-client writes
    // of the minute are spent, and then A's Cognito write lands.
    let fake = FakeCognito::new();
    let store = MemoryStore::new();
    let faulty = Faulty {
        store: store.clone(),
        order: Some(Arc::new(Order {
            first: old.to_owned(),
            then: new.to_owned(),
            written: SetOnce::new(),
        })),
        ..Faulty::default()
    };
    let release = Arc::new(Notify::new());
    let slow = FaultyCognito {
        cognito: fake.clone(),
        store: store.clone(),
        slow: Some(old.to_owned()),
        release: release.clone(),
        ..FaultyCognito::default()
    };
    let documents = Documents::default();
    documents.serve(CLAUDE, &claude_document(&[old]));
    let registrar = Registrar::builder(slow, faulty.clone())
        .fetcher(documents.clone())
        .dynamic_registration()
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let a = serve(fake.clone(), store.clone(), documents, registrar);
    let documents = Documents::default();
    documents.serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    let registrar = Registrar::builder(fake.clone(), faulty)
        .fetcher(documents.clone())
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let b = serve(fake, store, documents, registrar);
    sign_in(&b, &claude(CLAUDE_CALLBACK)).await.unwrap();
    b.documents.serve(CLAUDE, &claude_document(&[new]));
    b.store.edit(CLAUDE, |r| r.fetched_at -= 600);

    let url = authorize_url(CLAUDE, new, true);
    let refresh_b = async {
        get(&b.front, &url).await;
        spend(&a.front).await;
        release.notify_one();
    };
    finish(async { tokio::join!(get(&a.front, &url), refresh_b) }).await;
    // Claude's document settles on the new callback.
    a.documents.serve(CLAUDE, &claude_document(&[new]));
    let on_a = finish(sign_in(&a, &claude(new))).await;
    assert!(signed_in_or_retry(&on_a), "{on_a:?}");
    let signed_in = finish(sign_in(&b, &claude(new))).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
}

/// Fetches from `documents`, with faults: the next fetch times out while
/// `fails` is set, and one fetch made while `holds` is set notifies `held`
/// and waits until `release` is notified.
#[derive(Clone, Default)]
struct FaultyFetch {
    documents: Documents,
    fails: Arc<AtomicBool>,
    holds: Arc<AtomicBool>,
    held: Arc<Notify>,
    release: Arc<Notify>,
}

impl FetchDocument for FaultyFetch {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        if self.fails.swap(false, Ordering::SeqCst) {
            return Box::pin(async { Err(FetchError::Timeout) });
        }
        let holds = self.holds.swap(false, Ordering::SeqCst);
        let fetched = self.documents.fetch(url);
        Box::pin(async move {
            if holds {
                self.held.notify_one();
                self.release.notified().await;
            }
            fetched.await
        })
    }
}

#[tokio::test]
async fn a_sign_in_while_writes_are_spent_uses_the_app_client_registered_meanwhile() {
    // A sign-in on A reads Claude's registration and fetches its unchanged
    // document. Meanwhile cleanup removes the registration and its app
    // client, and a sign-in on B registers the document again.
    let fake = FakeCognito::new();
    let store = MemoryStore::new();
    let fetcher = FaultyFetch::default();
    fetcher
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    let registrar = Registrar::builder(fake.clone(), store.clone())
        .fetcher(fetcher.clone())
        .dynamic_registration()
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let a = serve(fake.clone(), store.clone(), fetcher.documents.clone(), registrar);
    let registrar = Registrar::builder(fake.clone(), store.clone())
        .fetcher(fetcher.documents.clone())
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let b = serve(fake, store, fetcher.documents.clone(), registrar);
    sign_in(&a, &claude(CLAUDE_CALLBACK)).await.unwrap();
    a.store.edit(CLAUDE, |r| {
        r.fetched_at -= 600;
        r.last_used = Some(r.created_at - 40 * 24 * 3600);
    });
    spend(&a.front).await;

    fetcher.holds.store(true, Ordering::SeqCst);
    let register_again = async {
        fetcher.held.notified().await;
        assert_eq!(a.registrar.cleanup().await.unwrap().idle, 1);
        sign_in(&b, &claude(CLAUDE_CALLBACK)).await.unwrap();
        fetcher.release.notify_one();
    };
    let auth = claude(CLAUDE_CALLBACK);
    let (on_a, ()) = finish(async { tokio::join!(sign_in(&a, &auth), register_again) }).await;
    assert!(signed_in_or_retry(&on_a), "{on_a:?}");
}

#[tokio::test]
async fn a_sign_in_repairs_a_failed_refresh_while_the_document_host_is_down() {
    let new = "https://claude.ai/api/mcp/auth_callback/2";
    let fake = FakeCognito::new();
    let store = MemoryStore::new();
    let fetcher = FaultyFetch::default();
    let cognito = FaultyCognito {
        cognito: fake.clone(),
        ..FaultyCognito::default()
    };
    let write_fails = cognito.fails.clone();
    let registrar = Registrar::builder(cognito, store.clone())
        .fetcher(fetcher.clone())
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let server = serve(fake, store, fetcher.documents.clone(), registrar);
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    // Claude moves its callback, Cognito throttles the refresh's write, and
    // then Claude's host stops answering.
    server.documents.serve(CLAUDE, &claude_document(&[new]));
    server.store.edit(CLAUDE, |r| r.fetched_at -= 120);
    write_fails.store(true, Ordering::SeqCst);
    let _ = sign_in(&server, &claude(new)).await;
    fetcher.fails.store(true, Ordering::SeqCst);
    let retried = sign_in(&server, &claude(new)).await;
    assert!(retried.is_ok(), "{retried:?}");
}
