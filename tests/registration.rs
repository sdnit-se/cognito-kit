//! What an attacker, or an operator watching the pool, would notice about
//! client registration: where codes may go, which documents count, which
//! tokens pass, and how app clients are kept in check. And what a person
//! signing in meets while a client's document changes.

mod front;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cognito_kit::registration::{
    AdminError, AppClients, BoxFuture, FetchDocument, FetchError, Lease, Leased, Registrar, Registration,
    RegistrationStore,
};
use cognito_kit::test_kit::{FakeCognito, MemoryStore};
use cognito_kit::{BoxError, ClientId};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;

use front::{
    Authorization, DRAFTS, Documents, MCP, ORIGIN, Server, call_mcp, get, json, location, open_server,
    post_form, post_json, serve, server, sign_in,
};
use http::StatusCode;
use serde_json::json;
use url::Url;

const CLAUDE: &str = "https://claude.ai/oauth/mcp-oauth-client-metadata";
const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
const MOVED: &str = "https://claude.ai/api/mcp/auth_callback/2";
const MOVED_AGAIN: &str = "https://claude.ai/api/mcp/auth_callback/3";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

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

fn claude(redirect_uri: &str) -> Authorization<'_> {
    Authorization {
        client_id: CLAUDE,
        redirect_uri,
        scope: DRAFTS,
        resource: Some(MCP),
        extra: &[],
    }
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
    let lease = Lease::new("refresh", u64::MAX);
    let leased = server.store.lease(CLAUDE, &lease, 0).await.unwrap();
    assert_eq!(leased, Some(Leased::Taken(first.clone())));
    // Another refresh finds it held, and the registration as stored.
    let another = Lease::new("another refresh", u64::MAX);
    let held = server.store.lease(CLAUDE, &another, 0).await.unwrap();
    assert_eq!(held, Some(Leased::Held(first.clone())));
    server.store.remove(&first).await.unwrap();
    // The next sign-in registers the document again, with a new app client.
    assert_eq!(get(&server.front, &url).await.status(), StatusCode::FOUND);
    // A refresh that leased the first registration stores its fetch late,
    // and a cleanup that listed it removes it late.
    let mut refreshed = first.clone();
    refreshed.redirect_uris = vec!["https://claude.ai/api/mcp/old_callback".into()];
    assert!(!server.store.update(&refreshed, &lease).await.unwrap());
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
    fn lease<'a>(
        &'a self,
        client_id: &'a str,
        lease: &'a Lease,
        now: u64,
    ) -> BoxFuture<'a, Result<Option<Leased>, BoxError>> {
        self.store.lease(client_id, lease, now)
    }
    fn update<'a>(
        &'a self,
        registration: &'a Registration,
        lease: &'a Lease,
    ) -> BoxFuture<'a, Result<bool, BoxError>> {
        self.store.update(registration, lease)
    }
    fn release<'a>(&'a self, client_id: &'a str, lease: &'a Lease) -> BoxFuture<'a, Result<(), BoxError>> {
        self.store.release(client_id, lease)
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
            if let Some(client) = &self.used_after_list {
                self.store.touch(client, now()).await?;
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

/// While holding, every app-client and store call that a [`Held`] server
/// makes waits until the test lets it go, so a test can step through a
/// refresh, or run two in any order. A call named by [`fail`](Self::fail)
/// fails, as a throttled AWS call does.
#[derive(Clone, Default)]
struct Steps(Arc<Calls>);

#[derive(Default)]
struct Calls {
    holding: AtomicBool,
    held: Mutex<Vec<(&'static str, oneshot::Sender<()>)>>,
    failing: Mutex<Option<&'static str>>,
}

#[derive(Debug, thiserror::Error)]
#[error("throttled")]
struct Throttled;

impl From<Throttled> for AdminError {
    fn from(throttled: Throttled) -> Self {
        AdminError::Other(Arc::new(throttled.into()))
    }
}

impl Steps {
    fn hold(&self) {
        self.0.holding.store(true, Ordering::SeqCst);
    }

    fn fail(&self, call: &'static str) {
        *self.0.failing.lock().unwrap() = Some(call);
    }

    async fn wait(&self, call: &'static str) -> Result<(), Throttled> {
        if self.0.holding.load(Ordering::SeqCst) {
            let (go, gone) = oneshot::channel();
            self.0.held.lock().unwrap().push((call, go));
            let _ = gone.await;
        }
        match *self.0.failing.lock().unwrap() {
            Some(failing) if failing == call => Err(Throttled),
            _ => Ok(()),
        }
    }

    /// The names of the calls held now.
    fn held(&self) -> Vec<&'static str> {
        self.0
            .held
            .lock()
            .unwrap()
            .iter()
            .map(|(call, _)| *call)
            .collect()
    }

    /// Waits until each task has a call held or has finished, and returns
    /// whether a call is held.
    async fn settle<T>(&self, tasks: &[JoinHandle<T>]) -> bool {
        loop {
            let held = self.0.held.lock().unwrap().len();
            if held + tasks.iter().filter(|t| t.is_finished()).count() == tasks.len() {
                return held > 0;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Lets the held call that `order` picks go.
    fn release(&self, order: &Order) {
        let mut held = self.0.held.lock().unwrap();
        let pick = if held.len() > 1 { order.pick(held.len()) } else { 0 };
        let _ = held.remove(pick).1.send(());
    }

    /// Lets held calls go until the one held is `call`.
    async fn run_to<T>(&self, tasks: &[JoinHandle<T>], call: &str) {
        while self.settle(tasks).await && self.held() != [call] {
            self.release(&Order::default());
        }
        assert_eq!(self.held(), [call]);
    }

    /// Lets held calls go until the tasks finish.
    async fn run_out<T>(&self, tasks: &[JoinHandle<T>]) {
        while self.settle(tasks).await {
            self.release(&Order::default());
        }
    }
}

/// The choices one run makes among held calls: those in `prefix`, then the
/// first. `taken` records each choice and how many there were.
#[derive(Clone, Default)]
struct Order(Arc<Mutex<Choices>>);

#[derive(Default)]
struct Choices {
    prefix: Vec<usize>,
    taken: Vec<(usize, usize)>,
}

impl Order {
    fn pick(&self, of: usize) -> usize {
        let mut choices = self.0.lock().unwrap();
        let chosen = choices.prefix.get(choices.taken.len()).copied().unwrap_or(0);
        choices.taken.push((chosen, of));
        chosen
    }

    fn taken(&self) -> Vec<(usize, usize)> {
        self.0.lock().unwrap().taken.clone()
    }
}

/// Runs `scenario` once for each order in which its held calls can go, and
/// returns how many orders there were.
async fn every_order<F: Future<Output = ()>>(scenario: impl Fn(Order) -> F) -> usize {
    let mut prefix = Vec::new();
    let mut runs = 0;
    loop {
        let order = Order(Arc::new(Mutex::new(Choices {
            prefix,
            taken: Vec::new(),
        })));
        scenario(order.clone()).await;
        runs += 1;
        let taken = order.taken();
        let Some(last) = taken.iter().rposition(|&(chosen, of)| chosen + 1 < of) else {
            return runs;
        };
        prefix = taken[..last]
            .iter()
            .map(|&(chosen, _)| chosen)
            .chain([taken[last].0 + 1])
            .collect();
    }
}

/// One server's view of a pool and store that others share, with its calls
/// held at `steps`, and its clock `ahead` of the others' by that many
/// seconds.
#[derive(Clone)]
struct Held {
    cognito: FakeCognito,
    store: MemoryStore,
    steps: Steps,
    ahead: u64,
}

impl AppClients for Held {
    fn create<'a>(
        &'a self,
        name: &'a str,
        callback_urls: &'a [String],
    ) -> BoxFuture<'a, Result<ClientId, AdminError>> {
        Box::pin(async move {
            self.steps.wait("create").await?;
            self.cognito.create(name, callback_urls).await
        })
    }
    fn callback_urls<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<Vec<String>, AdminError>> {
        Box::pin(async move {
            self.steps.wait("callback_urls").await?;
            self.cognito.callback_urls(client).await
        })
    }
    fn set_callback_urls<'a>(
        &'a self,
        client: &'a ClientId,
        urls: &'a [String],
    ) -> BoxFuture<'a, Result<(), AdminError>> {
        Box::pin(async move {
            self.steps.wait("set_callback_urls").await?;
            self.cognito.set_callback_urls(client, urls).await
        })
    }
    fn delete<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<(), AdminError>> {
        Box::pin(async move {
            self.steps.wait("delete").await?;
            self.cognito.delete(client).await
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<ClientId>, AdminError>> {
        Box::pin(async move {
            self.steps.wait("list").await?;
            self.cognito.list(prefix).await
        })
    }
    fn created<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<SystemTime, AdminError>> {
        Box::pin(async move {
            self.steps.wait("created").await?;
            self.cognito.created(client).await
        })
    }
}

impl RegistrationStore for Held {
    fn get<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        Box::pin(async move {
            self.steps.wait("get").await?;
            self.store.get(client_id).await
        })
    }
    fn get_by_app_client<'a>(
        &'a self,
        app_client: &'a ClientId,
    ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
        Box::pin(async move {
            self.steps.wait("get_by_app_client").await?;
            self.store.get_by_app_client(app_client).await
        })
    }
    fn insert(&self, registration: Registration) -> BoxFuture<'_, Result<Registration, BoxError>> {
        Box::pin(async move {
            self.steps.wait("insert").await?;
            self.store.insert(registration).await
        })
    }
    fn lease<'a>(
        &'a self,
        client_id: &'a str,
        lease: &'a Lease,
        now: u64,
    ) -> BoxFuture<'a, Result<Option<Leased>, BoxError>> {
        Box::pin(async move {
            self.steps.wait("lease").await?;
            let lease = Lease::new(lease.owner.clone(), lease.until + self.ahead);
            self.store.lease(client_id, &lease, now + self.ahead).await
        })
    }
    fn update<'a>(
        &'a self,
        registration: &'a Registration,
        lease: &'a Lease,
    ) -> BoxFuture<'a, Result<bool, BoxError>> {
        Box::pin(async move {
            self.steps.wait("update").await?;
            self.store.update(registration, lease).await
        })
    }
    fn release<'a>(&'a self, client_id: &'a str, lease: &'a Lease) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.steps.wait("release").await?;
            self.store.release(client_id, lease).await
        })
    }
    fn touch<'a>(&'a self, client_id: &'a str, at: u64) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.steps.wait("touch").await?;
            self.store.touch(client_id, at).await
        })
    }
    fn remove<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.steps.wait("remove").await?;
            self.store.remove(registration).await
        })
    }
    fn list(&self) -> BoxFuture<'_, Result<Vec<Registration>, BoxError>> {
        Box::pin(async move {
            self.steps.wait("list").await?;
            self.store.list().await
        })
    }
}

/// A pool and store that several servers share, with Claude registered by
/// a document listing `CLAUDE_CALLBACK`.
async fn shared_pool() -> (FakeCognito, MemoryStore) {
    let cognito = FakeCognito::new();
    let store = MemoryStore::new();
    let first = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK]);
    sign_in(&first, &claude(CLAUDE_CALLBACK)).await.unwrap();
    (cognito, store)
}

/// Makes Claude's stored document due for a refresh.
fn due(store: &MemoryStore) {
    store.edit(CLAUDE, |r| r.fetched_at -= 600);
}

/// A server on `cognito` and `store` whose calls `steps` holds, fetching
/// Claude's document with `redirect_uris`.
fn sharing(cognito: &FakeCognito, store: &MemoryStore, steps: &Steps, redirect_uris: &[&str]) -> Server {
    let held = Held {
        cognito: cognito.clone(),
        store: store.clone(),
        steps: steps.clone(),
        ahead: 0,
    };
    on(held, redirect_uris)
}

/// A server on `cognito` and `store` whose clock reads `seconds` later than
/// the others'. An hour later, every lease they took has run out for it.
fn later_by(seconds: u64, cognito: &FakeCognito, store: &MemoryStore, redirect_uris: &[&str]) -> Server {
    let held = Held {
        cognito: cognito.clone(),
        store: store.clone(),
        steps: Steps::default(),
        ahead: seconds,
    };
    on(held, redirect_uris)
}

/// A server over `held`, fetching Claude's document with `redirect_uris`.
fn on(held: Held, redirect_uris: &[&str]) -> Server {
    let documents = Documents::default();
    documents.serve(CLAUDE, &claude_document(redirect_uris));
    fetching(held, documents.clone(), documents)
}

/// A server over `held` that fetches with `fetcher`.
fn fetching(held: Held, documents: Documents, fetcher: impl FetchDocument) -> Server {
    let (cognito, store) = (held.cognito.clone(), held.store.clone());
    let registrar = Registrar::builder(held.clone(), held)
        .fetcher(fetcher)
        .dynamic_registration()
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    serve(cognito, store, documents, registrar)
}

/// A document host whose answer takes two seconds to arrive, with the
/// document as it was when the fetch began. `began` is told when it does.
#[derive(Clone)]
struct Slow {
    documents: Documents,
    began: Arc<Notify>,
}

impl FetchDocument for Slow {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        let answer = self.documents.fetch(url);
        self.began.notify_one();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            answer.await
        })
    }
}

/// A server like [`sharing`]'s, whose fetches take two seconds.
fn slow(cognito: &FakeCognito, store: &MemoryStore, steps: &Steps, redirect_uris: &[&str]) -> (Server, Slow) {
    let held = Held {
        cognito: cognito.clone(),
        store: store.clone(),
        steps: steps.clone(),
        ahead: 0,
    };
    let documents = Documents::default();
    documents.serve(CLAUDE, &claude_document(redirect_uris));
    let fetcher = Slow {
        documents: documents.clone(),
        began: Arc::default(),
    };
    (fetching(held, documents, fetcher.clone()), fetcher)
}

/// Claude's authorization at `server` with `redirect_uri`, on its own task.
fn authorize(server: Server, redirect_uri: &'static str) -> JoinHandle<http::Response<String>> {
    tokio::spawn(async move { get(&server.front, &authorize_url(CLAUDE, redirect_uri, true)).await })
}

fn stored(store: &MemoryStore) -> Option<Registration> {
    store.registrations().into_iter().find(|r| r.client_id == CLAUDE)
}

/// The callback URLs of Claude's app client.
fn callbacks(cognito: &FakeCognito, store: &MemoryStore) -> Vec<String> {
    let app_client = stored(store).expect("Claude is registered").app_client;
    let found = cognito.app_clients().into_iter().find(|c| c.id == app_client);
    found.map(|c| c.callback_urls).unwrap_or_default()
}

/// The app client an authorization sends the browser to managed login with.
fn app_client_of(at_login: &Url) -> String {
    let found = at_login.query_pairs().find(|(name, _)| name == "client_id");
    found.expect("a client_id").1.into_owned()
}

/// Whether Cognito allows every redirect URI the store lists for Claude:
/// the check a sign-in meets at managed login after the front sends it on.
fn allowed(cognito: &FakeCognito, store: &MemoryStore) -> bool {
    let callbacks = callbacks(cognito, store);
    stored(store)
        .unwrap()
        .redirect_uris
        .iter()
        .all(|uri| callbacks.contains(uri))
}

/// Registers a client on `server`, an app-client write that counts against
/// the ten a minute it may make, and returns the answer's status.
async fn register_one(server: &Server) -> StatusCode {
    let answer = post_json(
        &server.front,
        REGISTER,
        &registration(&["http://127.0.0.1:9000/cb"]),
    )
    .await;
    answer.status()
}

#[tokio::test]
async fn a_sign_in_meets_its_redirect_uri_at_cognito_whatever_step_a_refresh_is_at() {
    for writes_left in [10, 1, 0] {
        let (cognito, store) = shared_pool().await;
        let steps = Steps::default();
        let refreshing = sharing(&cognito, &store, &steps, &[MOVED]);
        let other = sharing(&cognito, &store, &Steps::default(), &[MOVED]);
        for _ in writes_left..10 {
            assert_eq!(register_one(&refreshing).await, StatusCode::CREATED);
        }
        // Someone who began signing in before Claude moved its callback is
        // at managed login while the refresh runs. Only the contraction to
        // the new list, after the store holds it, refuses them.
        let answer = get(&other.front, &authorize_url(CLAUDE, CLAUDE_CALLBACK, true)).await;
        let at_login = location(&answer).unwrap();
        due(&store);

        steps.hold();
        let refresh = [authorize(refreshing, MOVED)];
        while steps.settle(&refresh).await {
            if callbacks(&cognito, &store) != [MOVED] {
                let arrived = cognito.sign_in(&at_login, "6f1c2e7a-user");
                assert!(arrived.is_ok(), "{writes_left} writes left: {arrived:?}");
            }
            // The refresh stored the new callback: a sign-in reads it.
            if stored(&store).unwrap().redirect_uris == [MOVED] {
                let signed_in = sign_in(&other, &claude(MOVED)).await;
                assert!(signed_in.is_ok(), "{writes_left} writes left: {signed_in:?}");
            }
            steps.release(&Order::default());
        }
        // The sign-in that refreshed goes on to Cognito when a write is left
        // for the expansion, even with none left for the contraction.
        let [refresh] = refresh;
        let expected = if writes_left > 0 {
            StatusCode::FOUND
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        assert_eq!(
            refresh.await.unwrap().status(),
            expected,
            "{writes_left} writes left"
        );

        // Cognito ends with exactly the new list once a refresh with a write
        // to spare has run.
        due(&store);
        let signed_in = sign_in(&other, &claude(MOVED)).await;
        assert!(signed_in.is_ok(), "{writes_left} writes left: {signed_in:?}");
        assert_eq!(callbacks(&cognito, &store), [MOVED], "{writes_left} writes left");
    }
}

/// Signs in with the redirect URI the store lists for Claude, through a
/// server that fetches the document as stored, and checks that the
/// sign-in completes.
async fn sign_in_as_stored(cognito: &FakeCognito, store: &MemoryStore, context: &str) {
    let listed = stored(store).unwrap().redirect_uris;
    let uris: Vec<&str> = listed.iter().map(String::as_str).collect();
    let server = sharing(cognito, store, &Steps::default(), &uris);
    let signed_in = sign_in(&server, &claude(uris[0])).await;
    assert!(signed_in.is_ok(), "{context}: {signed_in:?}");
}

#[tokio::test]
async fn two_servers_refreshing_a_changing_document_keep_every_stored_redirect_uri_allowed() {
    // Their fetches get the same new version, two new ones, or a new one
    // and a stale copy of the old, as a CDN may serve.
    for (a, b) in [(MOVED, MOVED), (MOVED, MOVED_AGAIN), (MOVED, CLAUDE_CALLBACK)] {
        let orders = every_order(|order| async move {
            let (cognito, store) = shared_pool().await;
            due(&store);
            let steps = Steps::default();
            steps.hold();
            let refreshes = [
                authorize(sharing(&cognito, &store, &steps, &[a]), a),
                authorize(sharing(&cognito, &store, &steps, &[b]), b),
            ];
            while steps.settle(&refreshes).await {
                assert!(allowed(&cognito, &store), "choices {:?}", order.taken());
                steps.release(&order);
            }
            let choices = order.taken();
            let listed = stored(&store).unwrap().redirect_uris;
            assert_eq!(callbacks(&cognito, &store), listed, "choices {choices:?}");
            // A sign-in after both reads the store, not due, and goes on to
            // managed login.
            sign_in_as_stored(&cognito, &store, &format!("choices {choices:?}")).await;
        })
        .await;
        assert!(orders > 1, "{orders}");
    }
}

#[tokio::test]
async fn a_refresh_whose_lease_runs_out_leaves_the_document_to_the_one_that_takes_over() {
    for at in 0.. {
        let (cognito, store) = shared_pool().await;
        due(&store);
        let steps = Steps::default();
        let slow = sharing(&cognito, &store, &steps, &[MOVED]);
        let later = later_by(3600, &cognito, &store, &[MOVED_AGAIN]);
        steps.hold();
        let refresh = [authorize(slow, MOVED)];
        let (mut step, mut taken_over) = (0, false);
        while steps.settle(&refresh).await {
            let call = steps.held()[0];
            // Cognito has no conditional write: one that lands after its
            // lease ran out is the window that the lease's length covers.
            if step == at && call != "set_callback_urls" {
                // By the later server's clock, the stored document is due.
                due(&store);
                let signed_in = sign_in(&later, &claude(MOVED_AGAIN)).await;
                assert!(signed_in.is_ok(), "held at {call}: {signed_in:?}");
                taken_over = true;
            }
            step += 1;
            steps.release(&Order::default());
        }
        if step <= at {
            break;
        }
        assert!(allowed(&cognito, &store), "held at call {at}");
        if taken_over {
            let listed = stored(&store).unwrap().redirect_uris;
            assert_eq!(listed, [MOVED_AGAIN], "held at call {at}");
        }
        sign_in_as_stored(&cognito, &store, &format!("held at call {at}")).await;
        // The next refresh leaves Cognito exactly the stored list.
        due(&store);
        sign_in_as_stored(&cognito, &store, &format!("held at call {at}")).await;
        let listed = stored(&store).unwrap().redirect_uris;
        assert_eq!(callbacks(&cognito, &store), listed, "held at call {at}");
    }
}

#[tokio::test]
async fn a_refresh_leaves_alone_a_registration_made_again_while_it_ran() {
    for at in 0.. {
        let (cognito, store) = shared_pool().await;
        due(&store);
        store.edit(CLAUDE, |r| r.last_used = Some(1));
        let steps = Steps::default();
        let refreshing = sharing(&cognito, &store, &steps, &[MOVED]);
        let other = sharing(&cognito, &store, &Steps::default(), &[MOVED_AGAIN]);
        steps.hold();
        let refresh = [authorize(refreshing, MOVED)];
        let (mut step, mut at_login) = (0, None);
        while steps.settle(&refresh).await {
            if step == at {
                // Cleanup removes the idle registration and deletes its app
                // client. The next sign-in registers Claude again, from the
                // document as it is now, and goes on to managed login.
                assert_eq!(other.registrar.cleanup().await.unwrap().idle, 1);
                let answer = get(&other.front, &authorize_url(CLAUDE, MOVED_AGAIN, true)).await;
                at_login = location(&answer);
            }
            step += 1;
            steps.release(&Order::default());
        }
        if step <= at {
            break;
        }
        // Whichever call the refresh was at, the new registration keeps its
        // list. The user it sent on signs in, and so do the next ones.
        let context = format!("held at call {at}");
        assert_eq!(stored(&store).unwrap().redirect_uris, [MOVED_AGAIN], "{context}");
        assert_eq!(callbacks(&cognito, &store), [MOVED_AGAIN], "{context}");
        let at_login = at_login.expect("sent on to managed login");
        let arrived = cognito.sign_in(&at_login, "6f1c2e7a-user");
        assert!(arrived.is_ok(), "{context}: {arrived:?}");
        let signed_in = sign_in(&other, &claude(MOVED_AGAIN)).await;
        assert!(signed_in.is_ok(), "{context}: {signed_in:?}");
    }
}

#[tokio::test]
async fn a_slow_fetch_leaves_the_document_that_a_refresh_begun_after_it_stored() {
    let (cognito, store) = shared_pool().await;
    due(&store);
    // A server's fetch reads the document while it lists MOVED, and the
    // answer takes two seconds to arrive.
    let (server, fetcher) = slow(&cognito, &store, &Steps::default(), &[MOVED]);
    let late = authorize(server, MOVED);
    fetcher.began.notified().await;

    // Meanwhile the document moves on, another server refreshes it, and a
    // user goes on to managed login.
    let other = sharing(&cognito, &store, &Steps::default(), &[MOVED_AGAIN]);
    let answer = get(&other.front, &authorize_url(CLAUDE, MOVED_AGAIN, true)).await;
    let at_login = location(&answer).expect("sent on to managed login");
    assert_eq!(late.await.unwrap().status(), StatusCode::BAD_REQUEST);

    assert_eq!(stored(&store).unwrap().redirect_uris, [MOVED_AGAIN]);
    assert_eq!(callbacks(&cognito, &store), [MOVED_AGAIN]);
    let arrived = cognito.sign_in(&at_login, "6f1c2e7a-user");
    assert!(arrived.is_ok(), "{arrived:?}");
    let signed_in = sign_in(&other, &claude(MOVED_AGAIN)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
}

#[tokio::test]
async fn a_lease_lasts_thirty_seconds_from_when_it_is_taken_however_long_the_fetch_took() {
    let (cognito, store) = shared_pool().await;
    due(&store);
    let steps = Steps::default();
    steps.hold();
    let (server, _) = slow(&cognito, &store, &steps, &[CLAUDE_CALLBACK]);
    let refresh = [authorize(server, CLAUDE_CALLBACK)];
    steps.run_to(&refresh, "callback_urls").await;

    // By another server's clock, the lease was taken 28 seconds ago, and
    // then 31. Each needs the document refreshed for its sign-in.
    due(&store);
    let answer = get(
        &later_by(28, &cognito, &store, &[MOVED]).front,
        &authorize_url(CLAUDE, MOVED, true),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE, "still leased");
    let signed_in = sign_in(&later_by(31, &cognito, &store, &[MOVED]), &claude(MOVED)).await;
    assert!(signed_in.is_ok(), "run out: {signed_in:?}");
    steps.run_out(&refresh).await;
}

#[tokio::test]
async fn a_sign_in_whose_fetch_outlasted_cleanup_goes_through_the_current_app_client() {
    // After cleanup, nobody registers Claude again, another server does, or
    // another server does and is refreshing it.
    for (again, refreshing) in [(false, false), (true, false), (true, true)] {
        let context = format!("registered again {again}, refreshing {refreshing}");
        let (cognito, store) = shared_pool().await;
        due(&store);
        store.edit(CLAUDE, |r| r.last_used = Some(1));
        let steps = Steps::default();
        steps.hold();
        let slow = [authorize(
            sharing(&cognito, &store, &steps, &[CLAUDE_CALLBACK]),
            CLAUDE_CALLBACK,
        )];
        steps.run_to(&slow, "lease").await;

        let other = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK]);
        assert_eq!(other.registrar.cleanup().await.unwrap().idle, 1);
        if again {
            sign_in(&other, &claude(CLAUDE_CALLBACK)).await.unwrap();
        }
        if refreshing {
            let lease = Lease::new("another server", now() + 30);
            let leased = store.lease(CLAUDE, &lease, now()).await.unwrap();
            assert!(matches!(leased, Some(Leased::Taken(_))), "{context}");
        }
        steps.run_out(&slow).await;
        let [slow] = slow;
        let at_login = location(&slow.await.unwrap()).expect("sent on to managed login");
        let current = stored(&store).unwrap().app_client;
        assert_eq!(app_client_of(&at_login), current.as_str(), "{context}");
        let arrived = cognito.sign_in(&at_login, "6f1c2e7a-user");
        assert!(arrived.is_ok(), "{context}: {arrived:?}");
    }
}

#[tokio::test]
async fn a_sign_in_that_finds_the_lease_held_goes_on_with_a_redirect_uri_the_holder_stored() {
    let (cognito, store) = shared_pool().await;
    due(&store);
    let waiting_steps = Steps::default();
    waiting_steps.hold();
    let waiting = [authorize(
        sharing(&cognito, &store, &waiting_steps, &[MOVED]),
        MOVED,
    )];
    waiting_steps.run_to(&waiting, "lease").await;

    // Another server's refresh has stored MOVED and still holds the lease.
    let holder_steps = Steps::default();
    holder_steps.hold();
    let holder = [authorize(
        sharing(&cognito, &store, &holder_steps, &[MOVED]),
        MOVED,
    )];
    holder_steps.run_to(&holder, "release").await;
    waiting_steps.run_out(&waiting).await;
    let [waiting] = waiting;
    let at_login = location(&waiting.await.unwrap()).expect("sent on to managed login");
    let arrived = cognito.sign_in(&at_login, "6f1c2e7a-user");
    assert!(arrived.is_ok(), "{arrived:?}");
    holder_steps.run_out(&holder).await;
}

#[tokio::test]
async fn a_refresh_that_stopped_holds_its_document_back_only_until_its_lease_runs_out() {
    let (cognito, store) = shared_pool().await;
    due(&store);
    // A server took the lease to refresh Claude's document, and stopped.
    let stopped = Lease::new("stopped", now() + 30);
    let leased = store.lease(CLAUDE, &stopped, now()).await.unwrap();
    assert!(matches!(leased, Some(Leased::Taken(_))));
    let server = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK, MOVED]);

    // The stored redirect URI goes on to managed login. The one only the
    // new document lists is told to try again, and nothing is sent to it.
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    let answer = get(&server.front, &authorize_url(CLAUDE, MOVED, true)).await;
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(location(&answer), None);
    assert_eq!(stored(&store).unwrap().redirect_uris, [CLAUDE_CALLBACK]);

    // Once the lease has run out, the next sign-in refreshes the document.
    let later = later_by(3600, &cognito, &store, &[CLAUDE_CALLBACK, MOVED]);
    let signed_in = sign_in(&later, &claude(MOVED)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    let mut allowed = callbacks(&cognito, &store);
    allowed.sort();
    assert_eq!(allowed, [CLAUDE_CALLBACK, MOVED]);
}

/// A document host that is down.
struct Down;

impl FetchDocument for Down {
    fn fetch<'a>(&'a self, _: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        Box::pin(async { Err(FetchError::Status(503)) })
    }
}

#[tokio::test]
async fn while_the_document_host_is_down_a_refresh_gives_cognito_the_stored_redirect_uris() {
    let (cognito, store) = shared_pool().await;
    // Cognito lacks the stored callback and has another, as crossing
    // refreshes of earlier releases could leave it.
    let app_client = stored(&store).unwrap().app_client;
    cognito
        .set_callback_urls(&app_client, &[MOVED.to_owned()])
        .await
        .unwrap();
    due(&store);
    let registrar = Registrar::builder(cognito.clone(), store.clone())
        .fetcher(Down)
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let server = serve(cognito.clone(), store.clone(), Documents::default(), registrar);
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    assert_eq!(callbacks(&cognito, &store), [CLAUDE_CALLBACK]);
}

#[tokio::test]
async fn while_the_document_host_is_down_a_sign_in_is_not_sent_through_an_app_client_cleanup_deleted() {
    // The refresh holds the lease when cleanup removes the registration,
    // before it reads the app client or before it stores.
    for call in ["callback_urls", "update"] {
        let (cognito, store) = shared_pool().await;
        due(&store);
        store.edit(CLAUDE, |r| r.last_used = Some(1));
        let steps = Steps::default();
        let held = Held {
            cognito: cognito.clone(),
            store: store.clone(),
            steps: steps.clone(),
            ahead: 0,
        };
        let down = fetching(held, Documents::default(), Down);
        steps.hold();
        let refresh = [authorize(down, CLAUDE_CALLBACK)];
        steps.run_to(&refresh, call).await;

        let other = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK]);
        assert_eq!(other.registrar.cleanup().await.unwrap().idle, 1, "{call}");
        steps.run_out(&refresh).await;
        let [refresh] = refresh;
        let answer = refresh.await.unwrap();
        assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE, "{call}");
        assert_eq!(location(&answer), None, "{call}");
    }
}

#[tokio::test]
async fn a_document_at_cognitos_limit_of_100_callback_urls_can_swap_one() {
    let server = open_server();
    let old: Vec<String> = (0..100)
        .map(|i| format!("https://claude.ai/callback/{i}"))
        .collect();
    let mut new = old.clone();
    new[99] = "https://claude.ai/callback/new".into();
    let document = |uris: &[String]| claude_document(&uris.iter().map(String::as_str).collect::<Vec<_>>());
    server.documents.serve(CLAUDE, &document(&old));
    sign_in(&server, &claude(&old[0])).await.unwrap();

    server.documents.serve(CLAUDE, &document(&new));
    due(&server.store);
    for uri in [&old[0], &new[99]] {
        let signed_in = sign_in(&server, &claude(uri)).await;
        assert!(signed_in.is_ok(), "{uri}: {signed_in:?}");
    }
    let mut allowed = callbacks(&server.cognito, &server.store);
    allowed.sort();
    new.sort();
    assert_eq!(allowed, new);
}

fn uris(uris: &[String]) -> Vec<&str> {
    uris.iter().map(String::as_str).collect()
}

#[tokio::test]
async fn at_cognitos_limit_a_swap_the_store_misses_sends_on_only_what_cognito_and_the_store_list() {
    // 99 web callbacks and a loopback one, which Cognito knows as the relay.
    let mut old: Vec<String> = (0..99)
        .map(|i| format!("https://claude.ai/callback/{i}"))
        .collect();
    old.push("http://127.0.0.1:1111/callback".into());
    let mut new = old.clone();
    new[98] = "https://claude.ai/callback/new".into();
    new[99] = "http://127.0.0.1:2222/callback".into();
    let (cognito, store) = (FakeCognito::new(), MemoryStore::new());
    let first = sharing(&cognito, &store, &Steps::default(), &uris(&old));
    sign_in(&first, &claude(&old[0])).await.unwrap();
    due(&store);
    let steps = Steps::default();
    steps.fail("update");
    let server = sharing(&cognito, &store, &steps, &uris(&new));
    // Cognito gets the new list alone before the store, which fails.
    // Cognito no longer allows the dropped URI, and token redemption reads
    // the store, which doesn't list the added one yet.
    for uri in [&old[98], &new[98]] {
        let answer = get(&server.front, &authorize_url(CLAUDE, uri, true)).await;
        assert_eq!(location(&answer), None, "{uri} is never sent on");
    }
    let signed_in = sign_in(&server, &claude(&old[0])).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    // A loopback redirect URI matches on any port, in both lists.
    let answer = get(
        &server.front,
        &authorize_url(CLAUDE, "http://127.0.0.1:3333/callback", true),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::FOUND, "{}", answer.body());
}

#[tokio::test]
async fn a_refresh_never_leaves_a_host_no_longer_trusted_in_cognito_alone() {
    const CHATGPT_CALLBACK: &str = "https://chatgpt.com/connector/oauth/callback";
    let (cognito, store, documents) = (FakeCognito::new(), MemoryStore::new(), Documents::default());
    documents.serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK, CHATGPT_CALLBACK]));
    let trusting = |hosts: &[&'static str]| {
        let registrar = Registrar::builder(cognito.clone(), store.clone())
            .fetcher(documents.clone())
            .dynamic_registration()
            .client_hosts(hosts.to_vec())
            .build()
            .unwrap();
        serve(cognito.clone(), store.clone(), documents.clone(), registrar)
    };
    sign_in(&trusting(&["claude.ai", "chatgpt.com"]), &claude(CLAUDE_CALLBACK))
        .await
        .unwrap();

    // The operator stops trusting chatgpt.com, and the minute's app-client
    // writes run out before the next refresh.
    let server = trusting(&["claude.ai"]);
    while register_one(&server).await == StatusCode::CREATED {}
    due(&store);
    let _ = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    // Cleanup removes a registration whose stored document names the host.
    trusting(&["claude.ai"]).registrar.cleanup().await.unwrap();
    let kept: Vec<String> = cognito
        .app_clients()
        .into_iter()
        .flat_map(|c| c.callback_urls)
        .collect();
    assert!(!kept.iter().any(|c| c == CHATGPT_CALLBACK), "{kept:?}");
}

#[tokio::test]
async fn while_the_document_host_is_down_a_refresh_gives_cognito_no_host_no_longer_trusted() {
    const CHATGPT_CALLBACK: &str = "https://chatgpt.com/connector/oauth/callback";
    let (cognito, store, documents) = (FakeCognito::new(), MemoryStore::new(), Documents::default());
    documents.serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK, CHATGPT_CALLBACK]));
    let registrar = Registrar::builder(cognito.clone(), store.clone())
        .fetcher(documents.clone())
        .client_hosts(["claude.ai", "chatgpt.com"])
        .build()
        .unwrap();
    let both = serve(cognito.clone(), store.clone(), documents.clone(), registrar);
    sign_in(&both, &claude(CLAUDE_CALLBACK)).await.unwrap();
    // Cognito has a callback the store doesn't, so the refresh contracts.
    let app_client = stored(&store).unwrap().app_client;
    let drifted = [CLAUDE_CALLBACK, CHATGPT_CALLBACK, MOVED].map(str::to_owned);
    cognito.set_callback_urls(&app_client, &drifted).await.unwrap();

    // The operator stops trusting chatgpt.com, and the host is down.
    due(&store);
    let registrar = Registrar::builder(cognito.clone(), store.clone())
        .fetcher(Down)
        .client_hosts(["claude.ai"])
        .build()
        .unwrap();
    let server = serve(cognito.clone(), store.clone(), Documents::default(), registrar);
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    assert_eq!(callbacks(&cognito, &store), [CLAUDE_CALLBACK]);
    // The store still names the host, so cleanup finds it.
    assert!(
        stored(&store)
            .unwrap()
            .redirect_uris
            .iter()
            .any(|u| u == CHATGPT_CALLBACK)
    );
}

#[tokio::test]
async fn a_sign_in_is_not_sent_through_an_app_client_cleanup_deleted_before_the_refresh_contracted() {
    let (cognito, store) = (FakeCognito::new(), MemoryStore::new());
    let first = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK, MOVED]);
    sign_in(&first, &claude(CLAUDE_CALLBACK)).await.unwrap();
    due(&store);
    store.edit(CLAUDE, |r| r.last_used = Some(1));
    let steps = Steps::default();
    let server = sharing(&cognito, &store, &steps, &[CLAUDE_CALLBACK]);
    steps.hold();
    // Dropping MOVED needs no expansion, so the one Cognito write is the
    // contraction, after the store write.
    let refresh = [authorize(server, CLAUDE_CALLBACK)];
    steps.run_to(&refresh, "set_callback_urls").await;

    let other = sharing(&cognito, &store, &Steps::default(), &[CLAUDE_CALLBACK]);
    assert_eq!(other.registrar.cleanup().await.unwrap().idle, 1);
    steps.run_out(&refresh).await;
    let [refresh] = refresh;
    let answer = refresh.await.unwrap();
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(location(&answer), None);
}

#[tokio::test]
async fn a_document_due_for_a_refresh_signs_in_with_no_app_client_writes_left() {
    let server = open_server();
    server
        .documents
        .serve(CLAUDE, &claude_document(&[CLAUDE_CALLBACK]));
    sign_in(&server, &claude(CLAUDE_CALLBACK)).await.unwrap();
    while register_one(&server).await == StatusCode::CREATED {}
    due(&server.store);
    let fetches = server.documents.fetches();
    let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");
    assert_eq!(server.documents.fetches(), fetches + 1, "refreshed");
}

/// When `call` fails a due refresh, as a throttled AWS call does, and
/// whether the document is unchanged, adds or swaps a redirect URI or can't
/// be fetched, a sign-in with the stored redirect URI completes. One with a
/// redirect URI only the new document lists is told to try again.
async fn signs_in_while_failing(call: &'static str) {
    for document in [
        Some(&[CLAUDE_CALLBACK][..]),
        Some(&[CLAUDE_CALLBACK, MOVED]),
        Some(&[MOVED]),
        None,
    ] {
        let context = format!("{call} fails, document {document:?}");
        let (cognito, store) = shared_pool().await;
        due(&store);
        let steps = Steps::default();
        steps.fail(call);
        let server = match document {
            Some(uris) => sharing(&cognito, &store, &steps, uris),
            None => {
                let held = Held {
                    cognito: cognito.clone(),
                    store: store.clone(),
                    steps,
                    ahead: 0,
                };
                fetching(held, Documents::default(), Down)
            }
        };
        let signed_in = sign_in(&server, &claude(CLAUDE_CALLBACK)).await;
        assert!(signed_in.is_ok(), "{context}: {signed_in:?}");
        if document.is_some_and(|uris| uris.contains(&MOVED)) {
            let answer = get(&server.front, &authorize_url(CLAUDE, MOVED, true)).await;
            assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE, "{context}");
            assert_eq!(location(&answer), None, "{context}");
        }
    }
}

#[tokio::test]
async fn a_due_sign_in_with_a_stored_redirect_uri_completes_while_cognito_fails() {
    for call in ["callback_urls", "set_callback_urls"] {
        signs_in_while_failing(call).await;
    }
}

#[tokio::test]
async fn a_due_sign_in_with_a_stored_redirect_uri_completes_while_the_store_fails() {
    for call in ["lease", "update"] {
        signs_in_while_failing(call).await;
    }
}
