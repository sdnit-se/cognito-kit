//! An MCP server's OAuth front over the test kit's fake Cognito, and a
//! client's half of the authorization code flow.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cognito_kit::OAuthFront;
use cognito_kit::registration::{BoxFuture, FetchDocument, FetchError, Registrar, RegistrarBuilder};
use cognito_kit::test_kit::{FakeCognito, MemoryStore};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use ring::digest::{SHA256, digest};
use serde_json::Value;
use url::Url;

pub const MCP: &str = "https://portal.example.com/mcp";
pub const DRAFTS: &str = "https://portal.example.com/mcp/drafts";
pub const ORIGIN: &str = "https://portal.example.com";

/// Client ID Metadata Documents served from memory, counting fetches.
#[derive(Clone, Default)]
pub struct Documents(Arc<(Mutex<BTreeMap<String, String>>, AtomicUsize)>);

impl Documents {
    pub fn serve(&self, url: &str, document: &str) {
        self.0
            .0
            .lock()
            .unwrap()
            .insert(url.to_owned(), document.to_owned());
    }

    pub fn fetches(&self) -> usize {
        self.0.1.load(Ordering::SeqCst)
    }
}

impl FetchDocument for Documents {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        self.0.1.fetch_add(1, Ordering::SeqCst);
        let found = self.0.0.lock().unwrap().get(url.as_str()).cloned();
        Box::pin(async move {
            // A fetch takes time, so concurrent sign-ins interleave here.
            tokio::task::yield_now().await;
            found.map(String::into_bytes).ok_or(FetchError::Status(404))
        })
    }
}

pub struct Server {
    pub cognito: FakeCognito,
    pub store: MemoryStore,
    pub documents: Documents,
    pub registrar: Registrar,
    pub front: OAuthFront,
}

/// A server whose registrar `configure` sets up, given the documents it may
/// fetch.
pub fn server(configure: impl FnOnce(RegistrarBuilder, Documents) -> RegistrarBuilder) -> Server {
    let cognito = FakeCognito::new();
    let store = MemoryStore::new();
    let documents = Documents::default();
    let builder = Registrar::builder(cognito.clone(), store.clone());
    let registrar = configure(builder, documents.clone()).build().unwrap();
    serve(cognito, store, documents, registrar)
}

/// A server with `registrar` over a pool and store that may already hold
/// registrations, as after a restart with other settings.
pub fn serve(cognito: FakeCognito, store: MemoryStore, documents: Documents, registrar: Registrar) -> Server {
    let verifier = cognito
        .pool()
        .access_tokens()
        .registrar(registrar.clone())
        .resource(MCP.parse().unwrap())
        .scope(DRAFTS.parse().unwrap())
        .build()
        .unwrap();
    let front = OAuthFront::new(verifier, cognito.login_domain()).unwrap();
    Server {
        cognito,
        store,
        documents,
        registrar,
        front,
    }
}

/// The documents and dynamic registration on, trusting the hosts that the
/// web assistants send codes to.
pub fn open_server() -> Server {
    server(|b, documents| {
        b.fetcher(documents)
            .dynamic_registration()
            .client_hosts(["claude.ai", "chatgpt.com", "executor.sh"])
    })
}

pub async fn send(front: &OAuthFront, request: http::Request<Vec<u8>>) -> http::Response<String> {
    front.handle(&request).await.expect("the front answers")
}

pub async fn get(front: &OAuthFront, url: &str) -> http::Response<String> {
    send(front, http::Request::get(url).body(Vec::new()).unwrap()).await
}

pub async fn post_form(front: &OAuthFront, url: &str, form: &[(&str, &str)]) -> http::Response<String> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let request = http::Request::post(url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.into_bytes())
        .unwrap();
    send(front, request).await
}

pub async fn post_json(front: &OAuthFront, url: &str, body: &Value) -> http::Response<String> {
    let request = http::Request::post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into_bytes())
        .unwrap();
    send(front, request).await
}

pub fn json(response: &http::Response<String>) -> Value {
    serde_json::from_str(response.body()).unwrap_or(Value::Null)
}

pub fn location(response: &http::Response<String>) -> Option<Url> {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .and_then(|l| l.parse().ok())
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn pkce(seed: &str) -> Pkce {
    let verifier = format!("{seed}-verifier-0123456789-0123456789-0123456789");
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()));
    Pkce { verifier, challenge }
}

/// One authorization as a client asks for it.
pub struct Authorization<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub resource: Option<&'a str>,
    pub extra: &'a [(&'a str, &'a str)],
}

/// Authorize at the front, sign in at managed login, come back with a code,
/// and redeem it at the front. Returns the token endpoint's answer.
pub async fn sign_in(server: &Server, auth: &Authorization<'_>) -> Result<Value, String> {
    let pkce = pkce(auth.client_id);
    let mut url = Url::parse(&format!("{ORIGIN}/oauth2/authorize")).unwrap();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", auth.client_id)
            .append_pair("redirect_uri", auth.redirect_uri)
            .append_pair("scope", auth.scope)
            .append_pair("state", "client-state")
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(resource) = auth.resource {
            query.append_pair("resource", resource);
        }
        for (name, value) in auth.extra {
            query.append_pair(name, value);
        }
    }
    let answer = get(&server.front, url.as_str()).await;
    let to_cognito = location(&answer).ok_or_else(|| format!("{}: {}", answer.status(), answer.body()))?;
    let mut back = server.cognito.sign_in(&to_cognito, "6f1c2e7a-user")?;
    // The browser follows managed login's redirect, through the front's
    // relay for a loopback redirect URI.
    if back.as_str().starts_with(&format!("{ORIGIN}/oauth2/callback")) {
        let relayed = get(&server.front, back.as_str()).await;
        back = location(&relayed).ok_or_else(|| format!("relay: {} {}", relayed.status(), relayed.body()))?;
    }
    if !back.as_str().starts_with(auth.redirect_uri) {
        return Err(format!("came back to {back}"));
    }
    let query: BTreeMap<String, String> = back.query_pairs().into_owned().collect();
    if query.get("state").map(String::as_str) != Some("client-state") {
        return Err("the state didn't come back".into());
    }
    let code = query.get("code").ok_or("no code")?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", auth.redirect_uri),
        ("client_id", auth.client_id),
        ("code_verifier", pkce.verifier.as_str()),
    ];
    if let Some(resource) = auth.resource {
        form.push(("resource", resource));
    }
    let token = post_form(&server.front, &format!("{ORIGIN}/oauth2/token"), &form).await;
    if token.status() != StatusCode::OK {
        return Err(format!("token: {} {}", token.status(), token.body()));
    }
    Ok(json(&token))
}

pub fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// The MCP endpoint's check of a token.
pub async fn call_mcp(server: &Server, token: &str) -> StatusCode {
    match server.front.verifier().authenticate::<()>(&bearer(token)).await {
        Ok(_) => StatusCode::OK,
        Err(challenge) => challenge.response().status(),
    }
}
