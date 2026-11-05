Put an MCP server behind Cognito, so that AI assistants sign in with your
pool's users.

An MCP client such as Claude or Codex finds out how to sign in from the
server itself. It calls the MCP URL without a token and gets a 401. The
`WWW-Authenticate` header points at the server's protected resource
metadata (RFC 9728), which names an authorization server, whose metadata
(RFC 8414) lists the authorize and token endpoints. The client then runs
the authorization code flow with PKCE.

Cognito can issue the tokens, but it doesn't publish these documents in
the form MCP clients need. Its own discovery document doesn't list
`code_challenge_methods_supported`, and some clients refuse a server
without `S256` there. [`OAuthFront`] fills the gap. It serves both
documents, and its verifier's challenges point at them. Managed login still
signs people in, and Cognito still issues and refreshes every token.

# What you need in Cognito

- A resource server whose identifier is your MCP URL, with a scope for
  your tools, such as `https://portal.example.com/mcp/drafts`.
- A public app client for each assistant, with the assistant's callback URL
  and refresh-token rotation on. MCP requires rotation for public clients.

[The OpenTofu module](crate::guide::opentofu) creates both. Each person then
types the assistant's app client id into the assistant once. To skip that
step, let assistants [register themselves](crate::guide::self_registration).

# Serve the front

Build the verifier with [`resource`](crate::AccessTokenVerifierBuilder::resource)
set to your MCP URL. MCP clients send that URL as the RFC 8707 `resource`
parameter, Cognito puts it in the access token's `aud`, and the verifier
refuses a token without it. A token issued for another service in the same
pool can't be replayed against yours.

With the `axum` feature, merge [`OAuthFront::router`](crate::OAuthFront::router)
into your app:

```rust,no_run
use axum::Router;
use axum::routing::post;
use cognito_kit::{AccessClaims, OAuthFront, UserPool};

async fn mcp(claims: AccessClaims, body: String) -> String {
    // Hand the request and the caller to your MCP library here.
    format!("{} sent {} bytes", claims.sub, body.len())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = UserPool::new("eu-north-1_AbC123".parse()?)
        .access_tokens()
        .clients(["1example23456789".parse()?, "2example23456789".parse()?])
        .resource("https://portal.example.com/mcp".parse()?)
        .scope("https://portal.example.com/mcp/drafts".parse()?)
        .build()?;
    let front = OAuthFront::new(verifier.clone(), "https://login.example.com".parse()?)?;

    let app = Router::new()
        .route("/mcp", post(mcp))
        .merge(front.router())
        .with_state(verifier);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Without axum, give each request to [`OAuthFront::handle`](crate::OAuthFront::handle)
first. It answers the front's own paths and returns `None` for everything
else:

```rust
use cognito_kit::OAuthFront;
use http::{Request, Response};

async fn serve(front: &OAuthFront, request: Request<Vec<u8>>) -> Response<String> {
    if let Some(response) = front.handle(&request).await {
        return response;
    }
    match front.verifier().authenticate::<()>(request.headers()).await {
        Ok(claims) => Response::new(format!("MCP request from {}", claims.sub)),
        Err(challenge) => challenge.response(),
    }
}
```

# What the front serves

For an MCP URL of `https://portal.example.com/mcp`, the front answers
these `GET` requests:

| Path | Document |
|------|----------|
| `/.well-known/oauth-protected-resource/mcp` | Protected resource metadata, at its RFC 9728 path |
| `/.well-known/oauth-protected-resource` | The same document, at the root |
| `/.well-known/oauth-authorization-server` | Authorization server metadata, with managed login's endpoints and `S256` |

The authorization server's issuer is the MCP URL's origin, so the
documents and the MCP endpoint must share a host. The root copy of the
resource document is for clients that never see `WWW-Authenticate`, as
behind a Lambda function URL, which renames it. Those clients look only at
the root.

Every document allows any origin (`Access-Control-Allow-Origin: *`),
because browser-based MCP clients read them from another origin.

# What clients see when they are refused

The verifier's challenges follow RFC 6750 and carry `resource_metadata`, so
a client that gets one can start signing in:

- No token, or a bad one: 401, with `resource_metadata` and the required
  scopes in `WWW-Authenticate`.
- A valid token without a required scope: 403 with
  `error="insufficient_scope"`.
- The pool's keys can't be fetched: 503, without `WWW-Authenticate`.

# A complete server

[`examples/portal.rs`](https://github.com/sdnit-se/cognito-kit/blob/main/examples/portal.rs)
puts web sign-in and an MCP endpoint behind one pool, and
[`opentofu/examples/mcp-portal`](https://github.com/sdnit-se/cognito-kit/tree/main/opentofu/examples/mcp-portal)
creates the pool it expects, with app clients for Claude, ChatGPT,
Executor and command-line assistants.

[`OAuthFront`]: crate::OAuthFront
