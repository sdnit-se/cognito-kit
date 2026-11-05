Test your token checks, sign-in and MCP front without AWS.

The `test-kit` feature adds [`FakeCognito`]: a user pool in memory, with a
key set, signed tokens, and managed login's authorize and token endpoints.
Turn it on for your tests only:

```toml
[dev-dependencies]
cognito-kit = { version = "0.3", features = ["test-kit"] }
```

The example below also uses the crate's `axum` feature for the extractor,
and calls the router directly:

```toml
[dev-dependencies]
cognito-kit = { version = "0.3", features = ["test-kit", "axum"] }
axum = "0.8"
http = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tower = { version = "0.5", features = ["util"] }
```

The fake's signing key is fixed and public, since it is in this crate's
source. Only a [`UserPool`](crate::UserPool) from
[`FakeCognito::pool`](crate::test_kit::FakeCognito::pool) trusts it, so the
feature can't open a door in production.

# Test a handler with signed tokens

Build your verifier from the fake's pool, as you would from a real one.
[`access_token`](crate::test_kit::FakeCognito::access_token) signs an
access token as Cognito issues it to an app client. This test runs an axum
handler with the token, and without one:

```rust
use axum::Router;
use axum::body::Body;
use axum::routing::get;
use cognito_kit::AccessClaims;
use cognito_kit::test_kit::FakeCognito;
use http::{Request, StatusCode, header};
use tower::ServiceExt;

async fn me(claims: AccessClaims) -> String {
    claims.sub.to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cognito = FakeCognito::new();
    let client = cognito.add_client("api", &["https://app.example.com/callback"]);
    let verifier = cognito.pool().access_tokens().client(client.clone()).build()?;
    let app = Router::new().route("/me", get(me)).with_state(verifier);

    let anonymous = Request::get("/me").body(Body::empty())?;
    let refused = app.clone().oneshot(anonymous).await?;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    let token = cognito.access_token(&client, None, "openid");
    let signed = Request::get("/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;
    let admitted = app.oneshot(signed).await?;
    assert_eq!(admitted.status(), StatusCode::OK);
    Ok(())
}
```

`oneshot` comes from tower's `util` feature.

For tokens Cognito wouldn't issue, such as an expired one or one with a
custom attribute, write the claims yourself and sign them with
[`sign`](crate::test_kit::FakeCognito::sign):

```rust
use cognito_kit::test_kit::FakeCognito;
use cognito_kit::{AccessClaims, Rejection};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cognito = FakeCognito::new();
    let client = cognito.add_client("api", &["https://app.example.com/callback"]);
    let verifier = cognito.pool().access_tokens().client(client.clone()).build()?;

    let expired = cognito.sign(&json!({
        "sub": "user-1", "iss": cognito.issuer(), "token_use": "access",
        "client_id": client.as_str(), "scope": "openid",
        "iat": 1_700_000_000, "exp": 1_700_003_600,
    }));
    let rejection = verifier.verify::<()>(&expired).await.unwrap_err();
    assert!(matches!(rejection, Rejection::Expired));
    Ok(())
}
```

# Test web sign-in

[`sign_in`](crate::test_kit::FakeCognito::sign_in) plays a person at
managed login. Give it the URL that your app redirected to, and it returns
the URL managed login sends the browser back to, with a code and the
state. It refuses as Cognito does: an unknown app client, or a redirect
URI that isn't one of the app client's callback URLs exactly.

```rust
use cognito_kit::AuthorizeOptions;
use cognito_kit::test_kit::FakeCognito;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cognito = FakeCognito::new();
    let callback = "https://app.example.com/callback";
    let client = cognito.add_client("web", &[callback]);
    let login = cognito
        .pool()
        .managed_login(cognito.login_domain(), client, callback.parse()?)
        .build()?;

    let (to_cognito, _pending) = login.authorize(&AuthorizeOptions::default());
    let back = cognito.sign_in(&to_cognito, "user-1")?;
    assert!(back.as_str().starts_with(callback));
    assert!(back.query_pairs().any(|(name, _)| name == "code"));
    Ok(())
}
```

The fake's ID tokens don't carry the nonce from the authorization request,
so [`ManagedLogin::callback`](crate::ManagedLogin::callback) refuses them
with [`LoginError::Nonce`](crate::LoginError::Nonce). To test a whole
sign-in, answer the token endpoint with an [`HttpClient`](crate::HttpClient)
of your own that signs an ID token with the nonce, as
[`tests/web_sign_in.rs`](https://github.com/sdnit-se/cognito-kit/blob/main/tests/web_sign_in.rs)
does.

# Test self-registration

With the `registration` feature, `FakeCognito` also implements
[`AppClients`](crate::registration::AppClients), so a
[`Registrar`](crate::registration::Registrar) can create app clients in
it, and [`MemoryStore`](crate::test_kit::MemoryStore) keeps the
registrations. This test registers a client through the front, as an
assistant does with Dynamic Client Registration:

```rust
use cognito_kit::OAuthFront;
use cognito_kit::registration::Registrar;
use cognito_kit::test_kit::{FakeCognito, MemoryStore};
use http::{Request, StatusCode, header};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cognito = FakeCognito::new();
    let store = MemoryStore::new();
    let registrar = Registrar::builder(cognito.clone(), store.clone())
        .dynamic_registration()
        .build()?;
    let verifier = cognito
        .pool()
        .access_tokens()
        .registrar(registrar)
        .resource("https://portal.example.com/mcp".parse()?)
        .build()?;
    let front = OAuthFront::new(verifier, cognito.login_domain())?;

    let request = Request::post("https://portal.example.com/oauth2/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(br#"{"client_name":"Example CLI","redirect_uris":["http://localhost/callback"]}"#.to_vec())?;
    let response = front.handle(&request).await.expect("the front answers");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(store.registrations().len(), 1);
    assert_eq!(cognito.app_clients().len(), 1);
    Ok(())
}
```

Other helpers set up the states that are hard to reach:

- [`limit_app_clients`](crate::test_kit::FakeCognito::limit_app_clients)
  makes the pool refuse new app clients, as at Cognito's quota.
- [`age_app_client`](crate::test_kit::FakeCognito::age_app_client) and
  [`MemoryStore::edit`](crate::test_kit::MemoryStore::edit) make app
  clients and registrations old, to test cleanup.
- [`FetchDocument`](crate::registration::FetchDocument) is a trait, so a
  test can serve metadata documents from memory.

The crate's own
[`tests/assistants.rs`](https://github.com/sdnit-se/cognito-kit/blob/main/tests/assistants.rs)
replays Claude's, ChatGPT's, Claude Code's, Codex's and Executor's sign-in
flows against the front this way, with their real metadata documents.

[`FakeCognito`]: crate::test_kit::FakeCognito
