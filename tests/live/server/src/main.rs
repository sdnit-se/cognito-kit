//! An MCP endpoint behind the OAuth front, with clients registering by
//! metadata document or RFC 7591, against a real pool and table.
//!
//! ```sh
//! AWS_PROFILE=... COGNITO_POOL_ID=eu-north-1_AbC123 COGNITO_LOGIN_DOMAIN=https://x.auth.eu-north-1.amazoncognito.com \
//! TEMPLATE_CLIENT_ID=... REGISTRATION_TABLE=... PUBLIC_URL=http://localhost:3000 cargo run
//! ```

use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_smithy_http_client::tls::{Provider, rustls_provider::CryptoMode};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{any, post};
use axum::{Json, Router};
use cognito_kit::registration::{CognitoApi, DynamoStore, Registrar};
use cognito_kit::{AccessClaims, AccessTokenVerifier, OAuthFront, PoolId, UserPool};
use serde_json::{Value, json};
use url::Url;

#[derive(Clone)]
struct App {
    verifier: AccessTokenVerifier,
    registrar: Registrar,
}

impl axum::extract::FromRef<App> for AccessTokenVerifier {
    fn from_ref(app: &App) -> Self {
        app.verifier.clone()
    }
}

async fn mcp(claims: AccessClaims) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": 1, "result": { "sub": claims.sub, "client_id": claims.client_id } }))
}

async fn cleanup(State(app): State<App>) -> (StatusCode, Json<Value>) {
    match app.registrar.cleanup().await {
        Ok(report) => (
            StatusCode::OK,
            Json(json!({ "unused": report.unused, "idle": report.idle, "orphans": report.orphans })),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": error.to_string() })),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = |key: &str| std::env::var(key).map_err(|_| format!("set {key}"));
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .build_https();
    let aws = aws_config::defaults(BehaviorVersion::latest()).http_client(http).load().await;
    let pool_id: PoolId = env("COGNITO_POOL_ID")?.parse()?;
    let cognito = CognitoApi::new(
        aws_sdk_cognitoidentityprovider::Client::new(&aws),
        pool_id.clone(),
        env("TEMPLATE_CLIENT_ID")?.parse()?,
    );
    let store = DynamoStore::new(aws_sdk_dynamodb::Client::new(&aws), env("REGISTRATION_TABLE")?);
    let mut registrar = Registrar::builder(cognito, store)
        .metadata_documents()
        .dynamic_registration();
    if let Ok(hosts) = std::env::var("CLIENT_HOSTS") {
        registrar = registrar.client_hosts(hosts.split(','));
    }
    if let Ok(seconds) = std::env::var("IDLE_AFTER_SECONDS") {
        registrar = registrar.idle_after(Duration::from_secs(seconds.parse()?));
    }
    let registrar = registrar.build()?;

    let public: Url = env("PUBLIC_URL")?.parse()?;
    let resource = public.join("/mcp")?;
    let verifier = UserPool::new(pool_id)
        .access_tokens()
        .registrar(registrar.clone())
        .resource(resource.clone())
        .scope(format!("{resource}/drafts").parse()?)
        .build()?;
    let front = OAuthFront::new(verifier.clone(), env("COGNITO_LOGIN_DOMAIN")?.parse()?)?;
    let app = Router::new()
        .route("/mcp", any(mcp))
        .route("/cleanup", post(cleanup))
        .merge(front.router())
        .with_state(App { verifier, registrar });
    let address = format!("127.0.0.1:{}", public.port_or_known_default().unwrap_or(3000));
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on {public}");
    axum::serve(listener, app).await?;
    Ok(())
}
