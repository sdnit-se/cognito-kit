//! A portal on axum: people sign in on the web through managed login, and AI
//! assistants call an MCP endpoint with access tokens from the same pool.
//!
//! ```sh
//! COGNITO_POOL_ID=eu-north-1_AbC123 \
//! COGNITO_LOGIN_DOMAIN=https://login.example.com \
//! WEB_CLIENT_ID=... WEB_CLIENT_SECRET=... \
//! MCP_CLIENT_IDS=claude-client-id,cli-client-id \
//! PUBLIC_URL=http://localhost:3000 \
//! cargo run --example portal --features axum
//! ```
//!
//! The MCP endpoint answers every JSON-RPC request with who is calling; a
//! real server would hand the claims to its MCP library instead.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{FromRef, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use cognito_kit::{
    AccessClaims, AccessTokenVerifier, AuthorizeOptions, ClientSecret, LoginDomain, ManagedLogin, OAuthFront,
    PendingLogin, SignedIn, UserPool,
};
use serde_json::{Value, json};
use url::Url;

#[derive(Clone)]
struct App {
    login: ManagedLogin,
    mcp: AccessTokenVerifier,
    public_url: Url,
    // In memory for the example. A real portal keeps both in its session store.
    pending: Arc<Mutex<BTreeMap<String, PendingLogin>>>,
    sessions: Arc<Mutex<BTreeMap<String, SignedIn>>>,
}

impl FromRef<App> for AccessTokenVerifier {
    fn from_ref(app: &App) -> Self {
        app.mcp.clone()
    }
}

fn random_id() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

fn set_cookie(name: &str, value: &str) -> (header::HeaderName, String) {
    (
        header::SET_COOKIE,
        format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/"),
    )
}

async fn home(State(app): State<App>, headers: HeaderMap) -> Html<String> {
    let sessions = app.sessions.lock().unwrap();
    match cookie(&headers, "session").and_then(|id| sessions.get(id)) {
        Some(session) => Html(format!(
            "<p>Signed in as {}.</p><p><a href=\"/logout\">Sign out</a></p>",
            session
                .claims
                .email
                .as_deref()
                .unwrap_or(session.claims.username.as_str())
        )),
        None => Html("<p><a href=\"/login\">Sign in</a></p>".to_owned()),
    }
}

async fn start_login(State(app): State<App>) -> impl IntoResponse {
    let (url, pending) = app.login.authorize(&AuthorizeOptions::default());
    let id = random_id();
    app.pending.lock().unwrap().insert(id.clone(), pending);
    ([set_cookie("login", &id)], Redirect::to(url.as_str()))
}

async fn callback(State(app): State<App>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    let pending = cookie(&headers, "login").and_then(|id| app.pending.lock().unwrap().remove(id));
    let Some(pending) = pending else {
        return (StatusCode::BAD_REQUEST, "no sign-in in progress").into_response();
    };
    match app
        .login
        .callback(pending, query.as_deref().unwrap_or_default())
        .await
    {
        Ok(signed_in) => {
            let id = random_id();
            app.sessions.lock().unwrap().insert(id.clone(), signed_in);
            ([set_cookie("session", &id)], Redirect::to("/")).into_response()
        }
        Err(error) => (StatusCode::FORBIDDEN, error.to_string()).into_response(),
    }
}

async fn me(State(app): State<App>, headers: HeaderMap) -> Response {
    let sessions = app.sessions.lock().unwrap();
    match cookie(&headers, "session").and_then(|id| sessions.get(id)) {
        Some(session) => Json(json!({
            "sub": session.claims.sub,
            "email": session.claims.email,
            "groups": session.claims.groups,
            "has_refresh_token": session.tokens.refresh_token.is_some(),
        }))
        .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Swaps the session's tokens for fresh ones. With rotation on, the old
/// refresh token stops working.
async fn refresh(State(app): State<App>, headers: HeaderMap) -> Response {
    let Some(id) = cookie(&headers, "session") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let token = app
        .sessions
        .lock()
        .unwrap()
        .get(id)
        .and_then(|s| s.tokens.refresh_token.clone());
    let Some(token) = token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match app.login.refresh(&token).await {
        Ok(mut refreshed) => {
            let rotated = refreshed.tokens.refresh_token.is_some();
            refreshed.tokens.refresh_token.get_or_insert(token);
            app.sessions.lock().unwrap().insert(id.to_owned(), refreshed);
            Json(json!({ "rotated": rotated })).into_response()
        }
        Err(error) => (StatusCode::UNAUTHORIZED, error.to_string()).into_response(),
    }
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let session = cookie(&headers, "session").and_then(|id| app.sessions.lock().unwrap().remove(id));
    if let Some(refresh) = session.and_then(|s| s.tokens.refresh_token) {
        if let Err(error) = app.login.revoke(&refresh).await {
            eprintln!("revoking the refresh token failed: {error}");
        }
    }
    Redirect::to(app.login.logout_url(&app.public_url).as_str())
}

async fn mcp(claims: AccessClaims, Json(request): Json<Value>) -> Json<Value> {
    let scopes: Vec<_> = claims.scopes.iter().map(|s| s.as_str()).collect();
    Json(json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": { "sub": claims.sub, "client_id": claims.client_id, "scopes": scopes },
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = |key: &str| std::env::var(key).map_err(|_| format!("set {key}"));
    let pool = UserPool::new(env("COGNITO_POOL_ID")?.parse()?);
    let domain: LoginDomain = env("COGNITO_LOGIN_DOMAIN")?.parse()?;
    let public_url: Url = env("PUBLIC_URL")?.parse()?;

    let mut login = pool.managed_login(
        domain.clone(),
        env("WEB_CLIENT_ID")?.parse()?,
        public_url.join("/callback")?,
    );
    if let Ok(secret) = std::env::var("WEB_CLIENT_SECRET") {
        login = login.client_secret(ClientSecret::new(secret));
    }
    let resource = public_url.join("/mcp")?;
    let clients = env("MCP_CLIENT_IDS")?
        .split(',')
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let mcp_verifier = pool
        .access_tokens()
        .clients(clients)
        .resource(resource.clone())
        .scope(format!("{resource}/drafts").parse()?)
        .build()?;
    let front = OAuthFront::new(mcp_verifier.clone(), domain)?;

    let app = App {
        login: login.build()?,
        mcp: mcp_verifier,
        public_url: public_url.clone(),
        pending: Arc::default(),
        sessions: Arc::default(),
    };
    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(start_login))
        .route("/callback", get(callback))
        .route("/me", get(me))
        .route("/refresh", post(refresh))
        .route("/logout", get(logout))
        .route("/mcp", post(mcp))
        .merge(front.router())
        .with_state(app);

    let address = format!("127.0.0.1:{}", public_url.port_or_known_default().unwrap_or(3000));
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on {public_url}");
    axum::serve(listener, router).await?;
    Ok(())
}
