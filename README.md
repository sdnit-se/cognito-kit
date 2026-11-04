# cognito-kit

Unofficial. Not affiliated with or endorsed by AWS.

A Rust toolkit for Amazon Cognito. It checks the tokens a user pool issues,
signs people in on the web through managed login, and puts an MCP server
behind Cognito so that AI assistants can sign in to it from its URL alone.

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
- **Clients that register themselves.** An assistant sends the URL of its
  Client ID Metadata Document as its client id, or registers through
  Dynamic Client Registration (RFC 7591), and gets an app client of its own
  in the pool. Nobody types a client id.
- **A test kit**: a fake Cognito with a key set, signed tokens and managed
  login's endpoints, for your own tests.
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
| `reqwest` | yes     | `UserPool::new`, with a reqwest client for fetching keys and calling the token endpoint: rustls with ring, trusting the system's root certificates |
| `axum`    | no      | `AccessClaims` as an extractor, and `OAuthFront::router` |
| `tower`   | no      | `RequireBearerLayer`, which admits only requests with a valid token |
| `registration` | no | `Registrar`, for clients that register themselves, with `CognitoApi` over the AWS SDK. Turns on `reqwest` |
| `dynamodb` | no     | `DynamoStore`, which keeps registrations in DynamoDB. Turns on `registration` |
| `test-kit` | no     | `FakeCognito`, and with `registration`, `MemoryStore` |

Without `reqwest`, implement `HttpClient` for the client you already use and
build the pool with `UserPool::with_http_client`.

The minimum supported Rust version is 1.88. `registration` and `dynamodb`
need what the AWS SDK needs, Rust 1.94.1 for the versions this release was
tested with.

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

## Let assistants register themselves

With a `Registrar` on the verifier, the front serves its own
`/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke` and
`/oauth2/callback`, and with Dynamic Client Registration `/oauth2/register`. Its metadata points at them and
says `client_id_metadata_document_supported`. Claude, ChatGPT, Claude Code,
Codex and Executor then connect from the MCP URL alone.

```rust,ignore
use cognito_kit::registration::{CognitoApi, DynamoStore, Registrar};

let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
let registrar = Registrar::builder(
    CognitoApi::new(aws_sdk_cognitoidentityprovider::Client::new(&aws), pool_id.clone(), template_client),
    DynamoStore::new(aws_sdk_dynamodb::Client::new(&aws), "portal-registrations"),
)
.metadata_documents()
.dynamic_registration()
.client_hosts(["claude.ai", "chatgpt.com", "executor.sh"])
.build()?;

let verifier = UserPool::new(pool_id)
    .access_tokens()
    .registrar(registrar.clone())
    .resource("https://portal.example.com/mcp".parse()?)
    .scope("https://portal.example.com/mcp/drafts".parse()?)
    .build()?;
let front = OAuthFront::new(verifier, "https://login.example.com".parse()?)?;

// For each request: the front's documents and endpoints, then your MCP server.
if let Some(response) = front.handle(&request).await {
    return response;
}
```

How it works:

- **One app client per client.** A client's first authorization creates a
  public app client like the template client you name: its scopes, identity
  providers, token lifetimes and managed login style, with refresh-token
  rotation. The front swaps the client's `client_id` for the app client's on
  the way to managed login and the token endpoint; Cognito still issues
  every token. The verifier accepts tokens from these app clients, and a
  token from any other app client is refused.
- **Client ID Metadata Documents.** A `client_id` that is an https URL is
  fetched with `GuardedFetcher`: https only, at most 5 KiB within five
  seconds, no redirects and no proxy. Every address the host resolves to
  must be public, and the connection goes to exactly the addresses checked,
  so DNS rebinding can't reach a private one. The document must name its
  own URL and list the redirect URI. It is fetched again after five
  minutes, and kept while its host is briefly down.
- **Any port on loopback.** Claude Code, Codex and Executor list
  `http://localhost/callback`-style URIs and listen on a port the system
  picks (RFC 8252). Cognito matches callback URLs exactly, and managed login
  took 140 seconds to accept a callback URL added to an existing app client
  when we measured. So Cognito sends these clients' codes to the front's
  `/oauth2/callback`, its only callback URL for them, and the front passes
  each code on to the loopback URI its authorization started with. It never
  passes one anywhere else.
- **Dynamic Client Registration** is for clients without a document. The
  client id it hands out is the app client's id.
- **App clients you create yourself** keep working through the front's
  endpoints, unchanged.
- **Where codes may go.** Cognito has no consent step, and its authorize
  endpoint is public: anyone who learns an app client's id can send a
  signed-in user through it. So an app client is only ever created with
  redirect URIs that keep the code on the user's device (http on a loopback
  host), or that point at an https host you list with `client_hosts`. Other
  schemes are refused: one can hand its URL to a browser and send the code
  off the device. With a list, documents are fetched only from those
  hosts too. Every registered client is public and must use PKCE with S256.

**What happens near the limit.** Cognito allows 1,000 app clients per pool
by default; AWS Support can raise it. The registrar stops at
`max_registrations`, 500 by default, so the app clients you manage still
fit. Past it, and when Cognito refuses at its own limit, new clients get a
503 with `temporarily_unavailable`, while registered ones keep working.
An OpenTofu apply that adds an app client also fails at Cognito's limit.

**Cleanup.** Run `Registrar::cleanup` on a schedule, such as daily. It
deletes registrations and their app clients that never completed a token
request within a day, and those without one for longer than `idle_after`
(31 days, longer than Cognito's default refresh-token lifetime). It also
deletes app clients with the registrar's name prefix that it has no
registration for, which a server can leave behind if it stops between
creating one and storing it.

**Rates.** Cognito allows five app-client changes per second per pool,
shared with every other caller. Requests can cause at most ten a minute per
process. Put a rate rule in front of `/oauth2/authorize` and
`/oauth2/register` too, such as an AWS WAF rule.

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

With `registration = { template_client = "claude" }` the module also
creates a DynamoDB table for `DynamoStore`, and outputs
`registration_policy_json`: an IAM policy for the server that allows the
registrar's calls on this pool and table, and nothing else.

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
pool with Playwright, and `tests/live/registration.sh` creates a throwaway
pool and table, connects Claude Code's flows and the real Codex CLI to them
by document and by registration, and deletes both. The tests in `tests/`
use a fake Cognito and need no AWS account; `tests/assistants.rs` replays
each assistant's OAuth flow against the front.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT
