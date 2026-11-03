# cognito-kit

Unofficial. Not affiliated with or endorsed by AWS.

A Rust toolkit for Amazon Cognito. It checks the tokens a user pool issues,
signs people in on the web through managed login, and puts an MCP server
behind Cognito so that AI assistants can sign in to it.

- **Token checks** for any service that Cognito protects. Keys are fetched
  and cached, and refetched for an unknown key at a limited rate. Issuer,
  token kind, expiry, app client, audience and scopes are all checked, and
  you get typed claims, with your custom attributes through a generic.
- **Web sign-in** through managed login: the redirect with PKCE, state and
  nonce, the callback, refresh, revocation and the sign-out URL.
- **An OAuth front for MCP.** Cognito issues every token. This crate serves
  what MCP clients need and Cognito lacks: the protected resource metadata
  (RFC 9728), authorization server metadata (RFC 8414) that lists `S256`,
  and `WWW-Authenticate` challenges.
- **An OpenTofu module** for the pool, Google sign-in, a resource server,
  app clients with refresh-token rotation, and branded managed login.

The core uses only the [`http`](https://docs.rs/http) crate's types and works
with any web framework or none. The `axum` and `tower` features add
adapters. It doesn't depend on any MCP SDK.

## Install

```sh
cargo add cognito-kit
```

| Feature   | Default | What it adds |
|-----------|---------|--------------|
| `reqwest` | yes     | `UserPool::new`, with a reqwest client (rustls) for fetching keys and calling the token endpoint |
| `axum`    | no      | `AccessClaims` as an extractor, and `OAuthFront::router` |
| `tower`   | no      | `RequireBearerLayer`, which admits only requests with a valid token |

Without `reqwest`, implement `HttpClient` for the client you already use and
build the pool with `UserPool::with_http_client`.

The minimum supported Rust version is 1.88.

## Check access tokens

```rust,no_run
use cognito_kit::{AccessClaims, UserPool};

let pool = UserPool::new("eu-north-1_AbC123".parse()?);
let verifier = pool
    .access_tokens()
    .client("1example23456789".parse()?)
    .scope("https://api.example.com/read".parse()?)
    .build()?;

let claims: AccessClaims = verifier.verify(token).await?;
```

A verifier needs at least one app client: Cognito access tokens carry
`client_id`, and a token from another app client in the same pool is
refused. `verify` returns a `Rejection` that says why a token failed, and
`Rejection::status` maps it to 401, 403 for a missing scope, or 503 when the
keys can't be fetched.

`authenticate` reads the `Authorization` header and returns a `Challenge`
instead, a ready response with the right `WWW-Authenticate` header.

With `axum`, handlers take the claims as an argument:

```rust,ignore
async fn me(claims: AccessClaims) -> String {
    claims.sub.to_string()
}

let app = Router::new().route("/me", get(me)).with_state(verifier);
```

### Custom attributes

```rust,ignore
#[derive(serde::Deserialize)]
struct Attributes {
    #[serde(rename = "custom:tenant")]
    tenant: Option<String>,
}

let claims: IdClaims<Attributes> = pool.id_tokens(client).verify(token).await?;
```

## Sign people in on the web

```rust,no_run
use cognito_kit::{AuthorizeOptions, ClientSecret};

let login = pool
    .managed_login(
        "https://login.example.com".parse()?,
        "1example23456789".parse()?,
        "https://app.example.com/callback".parse()?,
    )
    .client_secret(ClientSecret::new(secret))
    .build()?;

// GET /login: redirect, and keep `pending` until the callback.
let (url, pending) = login.authorize(&AuthorizeOptions::default());

// GET /callback: checks state, redeems the code with the PKCE verifier,
// and verifies the ID token and its nonce.
let signed_in = login.callback::<()>(pending, query).await?;
```

Keep the `PendingLogin` server-side or in an encrypted cookie; it holds the
PKCE verifier. `refresh` returns new tokens, `revoke` revokes a refresh
token, and `logout_url` ends the managed login session.

## Put an MCP server behind Cognito

MCP clients find their way to sign-in through two metadata documents.
Cognito publishes neither in the form they need: its discovery document
doesn't list `code_challenge_methods_supported`, and some clients refuse a
server without `S256` there. `OAuthFront` serves both, pointing at managed
login's own endpoints.

```rust,no_run
use cognito_kit::{OAuthFront, UserPool};

let pool = UserPool::new("eu-north-1_AbC123".parse()?);
let verifier = pool
    .access_tokens()
    .clients([claude_client, cli_client])
    .resource("https://portal.example.com/mcp".parse()?)
    .scope("https://portal.example.com/mcp/drafts".parse()?)
    .build()?;
let front = OAuthFront::new(verifier, "https://login.example.com".parse()?)?;

// For each request: the documents first, then the token.
if let Some(response) = front.respond(request.method(), request.uri().path()) {
    return response;
}
let claims = match front.verifier().authenticate::<()>(request.headers()).await {
    Ok(claims) => claims,
    Err(challenge) => return challenge.response(),
};
```

How it fits together:

- Each assistant gets its own pre-registered public app client, with its
  callback URL. Clients send the MCP URL as the RFC 8707 `resource`
  parameter, and Cognito puts it in the access token's `aud`. A token
  without it is refused, so a token for another service can't be replayed
  here.
- Refresh-token rotation is on for every client, as MCP requires for public
  clients. A reused refresh token gets `invalid_grant`.
- The protected resource document is served at its RFC 9728 path and at the
  root. Lambda function URLs rename `WWW-Authenticate`, and some clients
  then look only at the root.
- The challenge for a missing token is a 401 with `resource_metadata`; for a
  missing scope, a 403 with `error="insufficient_scope"`.

[`examples/portal.rs`](examples/portal.rs) is a small portal on axum with
web sign-in and an MCP endpoint.

## The OpenTofu module

```hcl
module "cognito" {
  source = "github.com/sdnit-se/cognito-kit//opentofu?ref=v0.1.0"

  name   = "portal"
  domain = { name = "login.example.com", certificate_arn = var.certificate_arn }
  google = { client_id = var.google_client_id }

  resource_server = {
    identifier = "https://portal.example.com/mcp"
    scopes     = { drafts = "Create and edit drafts" }
  }

  clients = {
    claude = {
      callback_urls      = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]
      identity_providers = ["Google"]
      scopes             = ["openid", "email", "https://portal.example.com/mcp/drafts"]
    }
  }
}
```

Every app client uses the authorization code grant and rotates refresh
tokens; the module refuses `ALLOW_REFRESH_TOKEN_AUTH`, which turns rotation
off. Google's client secret is written once, as a placeholder unless you pass
it, and never changed afterwards, so you can set it out of band and keep it
out of your files. See [`opentofu/examples/mcp-portal`](opentofu/examples/mcp-portal/main.tf)
for a pool with clients for Claude, ChatGPT, Executor and command-line
assistants.

## Development

Every tool and task runs through [mise](https://mise.jdx.dev): `mise run ci`
runs what CI runs. `tests/live/flow.ts` drives the example against a real
pool with Playwright; the tests in `tests/` use a fake Cognito and need no
AWS account.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT
