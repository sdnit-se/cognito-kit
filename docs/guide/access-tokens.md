Check the access tokens that callers send to your API.

A Cognito user pool signs every token it issues. Your API receives an
access token in the `Authorization: Bearer` header and must decide whether
to trust it. An [`AccessTokenVerifier`] makes that decision without calling
Cognito for each request. It checks the signature against the pool's
published keys, which it fetches once and caches.

# Build a verifier

A verifier belongs to one pool and accepts tokens issued to the app clients
you name. Build it once at startup and share it. Clones are cheap and
share one key cache.

```rust,no_run
use cognito_kit::{AccessClaims, UserPool};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = UserPool::new("eu-north-1_AbC123".parse()?);
    let verifier = pool
        .access_tokens()
        .client("1example23456789".parse()?)
        .scope("https://api.example.com/read".parse()?)
        .build()?;

    let token = std::env::args().nth(1).ok_or("pass an access token")?;
    let claims: AccessClaims = verifier.verify(&token).await?;
    println!("{} called through app client {}", claims.sub, claims.client_id);
    Ok(())
}
```

[`verify`](crate::AccessTokenVerifier::verify) accepts a token only when
all of these hold:

- It is a JWT signed with RS256 by a key the pool publishes.
- Its `iss` is the pool's issuer, `https://cognito-idp.<region>.amazonaws.com/<pool id>`.
- It has not expired. A token stays valid for 60 seconds past its `exp`, for
  clock skew. Change that with [`leeway`](crate::AccessTokenVerifierBuilder::leeway).
- Its `token_use` is `access`, so an ID token is refused.
- Its `client_id` is one of the app clients you named, or one the
  [`registrar`](crate::AccessTokenVerifierBuilder::registrar) registered.
- Its `aud` is your API's URL, if you set
  [`audience`](crate::AccessTokenVerifierBuilder::audience) or
  [`resource`](crate::AccessTokenVerifierBuilder::resource).
- It grants every scope you required with
  [`scope`](crate::AccessTokenVerifierBuilder::scope).

A verifier needs at least one app client, or a registrar. Every app client
in a pool gets tokens from the same keys, so without that check a token
issued to any app in the pool would pass.

Cognito sets `aud` on an access token only when the client sent your URL as
the RFC 8707 `resource` parameter while signing in. Require an audience
only when your clients do that. MCP clients do, and
[the MCP chapter](crate::guide::mcp_server) relies on it.

# Refuse a request the way clients expect

[`authenticate`](crate::AccessTokenVerifier::authenticate) reads the
`Authorization` header and verifies its token. When it refuses, it returns
a [`Challenge`], which is a complete response with the status, an RFC 6750
`WWW-Authenticate` header and a small JSON body.

```rust
use cognito_kit::{AccessTokenVerifier, Rejection, Scope};
use http::{HeaderMap, Response};

async fn delete_draft(
    verifier: &AccessTokenVerifier,
    headers: &HeaderMap,
) -> Result<Response<String>, Response<String>> {
    let claims = verifier
        .authenticate::<()>(headers)
        .await
        .map_err(|challenge| challenge.response())?;

    // A scope that only this route needs.
    let write: Scope = "https://api.example.com/write".parse().expect("a valid scope");
    if !claims.scopes.contains(&write) {
        return Err(verifier.challenge(Rejection::Scope(write)).response());
    }
    Ok(Response::new(format!("deleted by {}", claims.sub)))
}
```

The status follows [`Rejection::status`](crate::Rejection::status). A
missing, forged, expired or misdirected token gets 401. A valid token
without a required scope gets 403 with `error="insufficient_scope"`. If the
pool's keys can't be fetched, the answer is 503 without a
`WWW-Authenticate` header, because the client did nothing wrong.
[`Challenge::rejection`](crate::Challenge::rejection) says why, for your logs.

# Read custom attributes

Claims that [`AccessClaims`] and [`IdClaims`] don't name go to their type
parameter, through serde's `flatten`. Declare the ones you use:

```rust
use cognito_kit::{IdClaims, IdTokenVerifier, Rejection};

#[derive(serde::Deserialize)]
struct Attributes {
    #[serde(rename = "custom:tenant")]
    tenant: Option<String>,
}

async fn tenant(verifier: &IdTokenVerifier, token: &str) -> Result<Option<String>, Rejection> {
    let claims: IdClaims<Attributes> = verifier.verify(token).await?;
    Ok(claims.custom.tenant)
}
```

ID tokens carry custom attributes when the app client may read them.
Access tokens carry them only when a pre-token-generation Lambda trigger
adds them. A claim whose type doesn't match your struct makes the token
[`Rejection::Malformed`](crate::Rejection::Malformed), so make a field an
`Option` when some users lack it.

Get an [`IdTokenVerifier`] from [`UserPool::id_tokens`](crate::UserPool::id_tokens).
It checks that the ID token's `aud` is the app client you pass.

# Use the axum extractor

With the `axum` feature, a handler takes [`AccessClaims`] as an argument.
The extractor uses the [`AccessTokenVerifier`] in your router's state, and
a refused request gets the verifier's [`Challenge`] before your handler
runs.

```rust,no_run
use axum::Router;
use axum::routing::get;
use cognito_kit::{AccessClaims, UserPool};

async fn me(claims: AccessClaims) -> String {
    format!("you are {}", claims.sub)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = UserPool::new("eu-north-1_AbC123".parse()?)
        .access_tokens()
        .client("1example23456789".parse()?)
        .build()?;
    let app = Router::new().route("/me", get(me)).with_state(verifier);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

When your state is a struct of your own, implement
[`FromRef`](axum::extract::FromRef) for it so the extractor can find the
verifier:

```rust
use axum::extract::FromRef;
use cognito_kit::AccessTokenVerifier;

#[derive(Clone)]
struct App {
    verifier: AccessTokenVerifier,
}

impl FromRef<App> for AccessTokenVerifier {
    fn from_ref(app: &App) -> Self {
        app.verifier.clone()
    }
}
```

# Use the tower layer

With the `tower` feature, [`RequireBearerLayer`](crate::RequireBearerLayer)
admits only requests with a valid access token. It puts the claims into
the request's extensions, and answers every other request with the
verifier's challenge, so your service never sees it.

```rust,no_run
use axum::routing::get;
use axum::{Extension, Router};
use cognito_kit::{AccessClaims, RequireBearerLayer, UserPool};

async fn me(Extension(claims): Extension<AccessClaims>) -> String {
    format!("you are {}", claims.sub)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = UserPool::new("eu-north-1_AbC123".parse()?)
        .access_tokens()
        .client("1example23456789".parse()?)
        .build()?;
    let app = Router::new()
        .route("/me", get(me))
        .layer(RequireBearerLayer::<()>::new(verifier));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

The layer works with any tower stack whose requests are
[`http::Request`] and whose response body can be built from a `String`.
Its type parameter is the custom claims type, as for [`AccessClaims`].

# Use your own HTTP client

[`UserPool::new`](crate::UserPool::new) needs the default `reqwest`
feature. Without it, implement [`HttpClient`] for the client you already
have, and build the pool with
[`UserPool::with_http_client`](crate::UserPool::with_http_client). The
crate sends at most three kinds of request through it: the pool's key set,
and managed login's token and revocation endpoints.

[`AccessTokenVerifier`]: crate::AccessTokenVerifier
[`AccessClaims`]: crate::AccessClaims
[`IdClaims`]: crate::IdClaims
[`IdTokenVerifier`]: crate::IdTokenVerifier
[`Challenge`]: crate::Challenge
[`HttpClient`]: crate::HttpClient
