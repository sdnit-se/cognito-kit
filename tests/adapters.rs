//! The axum extractor and the tower layer, seen from an HTTP client.
#![cfg(any(feature = "axum", feature = "tower"))]

mod support;

use cognito_kit::{AccessClaims, AccessTokenVerifier};
use http::{Request, StatusCode, header};
use support::{CLIENT, FakeCognito, access_claims, sign};
use tower::ServiceExt;

const API: &str = "https://api.example.com";
const READ: &str = "https://api.example.com/read";

fn verifier(cognito: &FakeCognito) -> AccessTokenVerifier {
    cognito
        .pool()
        .access_tokens()
        .client(CLIENT.parse().unwrap())
        .audience(API.parse().unwrap())
        .scope(READ.parse().unwrap())
        .build()
        .unwrap()
}

fn request(token: Option<&str>) -> Request<axum::body::Body> {
    let mut request = Request::get("/me");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(axum::body::Body::empty()).unwrap()
}

async fn body(response: http::Response<axum::body::Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_handlers_receive_verified_claims() {
    use axum::routing::get;

    let cognito = FakeCognito::publishing(&["k1"]);
    let app = axum::Router::new()
        .route(
            "/me",
            get(|claims: AccessClaims| async move { claims.sub.to_string() }),
        )
        .with_state(verifier(&cognito));

    let refused = app.clone().oneshot(request(None)).await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(refused.headers().contains_key(header::WWW_AUTHENTICATE));

    let token = sign("k1", &access_claims(API, READ));
    let admitted = app.oneshot(request(Some(&token))).await.unwrap();
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(body(admitted).await, "6f1c2e7a-0000-4000-8000-000000000001");
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_serves_the_front_s_documents() {
    let cognito = FakeCognito::default();
    let verifier = cognito
        .pool()
        .access_tokens()
        .client(CLIENT.parse().unwrap())
        .resource("https://portal.example.com/mcp".parse().unwrap())
        .build()
        .unwrap();
    let front = cognito_kit::OAuthFront::new(verifier, support::LOGIN.parse().unwrap()).unwrap();
    let app: axum::Router = front.router();
    for path in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
    ] {
        let request = Request::get(path).body(axum::body::Body::empty()).unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK,
            "{path}"
        );
    }
}

#[cfg(feature = "tower")]
#[tokio::test]
async fn the_tower_layer_admits_only_valid_tokens() {
    use tower::{Layer, service_fn};

    let cognito = FakeCognito::publishing(&["k1"]);
    let service = cognito_kit::RequireBearerLayer::<()>::new(verifier(&cognito)).layer(service_fn(
        |request: Request<axum::body::Body>| async move {
            let claims = request
                .extensions()
                .get::<AccessClaims>()
                .expect("claims from the layer");
            Ok::<_, std::convert::Infallible>(http::Response::new(axum::body::Body::from(
                claims.sub.to_string(),
            )))
        },
    ));

    let expired = {
        let mut claims = access_claims(API, READ);
        claims["exp"] = serde_json::json!(support::now() - 3600);
        sign("k1", &claims)
    };
    let refused = service.clone().oneshot(request(Some(&expired))).await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    let token = sign("k1", &access_claims(API, READ));
    let admitted = service.oneshot(request(Some(&token))).await.unwrap();
    assert_eq!(body(admitted).await, "6f1c2e7a-0000-4000-8000-000000000001");
}
