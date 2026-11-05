# cognito-kit

Unofficial. Not affiliated with or endorsed by AWS.

A Rust toolkit for Amazon Cognito. It checks the tokens a user pool issues,
signs people in on the web through managed login, and lets AI assistants
sign in to an MCP server from its URL alone.

Cognito issues JSON Web Tokens and hosts a sign-in page for each user pool.
The AWS SDK for Rust manages pools, but it doesn't check their tokens or
run the sign-in, and Cognito's OAuth server lacks parts that MCP clients
need. This crate fills those gaps. Its core uses only the
[`http`](https://docs.rs/http) crate's types, so it works with any web
framework, or none.

## Install

```sh
cargo add cognito-kit
```

| Feature | Default | Adds |
|---------|---------|------|
| `reqwest` | yes | `UserPool::new`, with a reqwest client over rustls and the system's root certificates |
| `axum` | no | `AccessClaims` as an axum extractor, and `OAuthFront::router` |
| `tower` | no | `RequireBearerLayer`, which admits only requests with a valid token |
| `registration` | no | `Registrar`, for assistants that register themselves, with `CognitoApi` over the AWS SDK. Turns on `reqwest` |
| `dynamodb` | no | `DynamoStore`, which keeps registrations in DynamoDB. Turns on `registration` |
| `test-kit` | no | `FakeCognito` for your tests, and with `registration`, `MemoryStore` |

Without `reqwest`, implement `HttpClient` for the client you already use
and build the pool with `UserPool::with_http_client`.

## Quick start

Check an access token from the command line. Put in your pool's id and an
app client's id, then run it with a token that the app client got.

```sh
cargo add tokio --features macros,rt-multi-thread
```

```rust,no_run
use cognito_kit::{AccessClaims, UserPool};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = UserPool::new("eu-north-1_AbC123".parse()?);
    let verifier = pool
        .access_tokens()
        .client("1example23456789".parse()?)
        .build()?;

    let token = std::env::args().nth(1).ok_or("pass an access token")?;
    let claims: AccessClaims = verifier.verify(&token).await?;
    println!("{} called through app client {}", claims.sub, claims.client_id);
    Ok(())
}
```

To get a token to try it with, use the client credentials grant. It needs
an app client with a secret, that grant turned on, and a scope from a
resource server. Ask your managed login domain's token endpoint:

```sh
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=https://api.example.com/read \
  https://login.example.com/oauth2/token | jq -r .access_token)
cargo run -- "$TOKEN"
```

It prints the token's subject and app client. For this grant, both are the
app client's id.

`verify` checks the signature against the pool's published keys, which it
fetches once and caches, and then the issuer, expiry, token kind and app
client. In a web service, build the verifier once and call `authenticate`
with the request's headers. A refused request gets a ready response: 401
or 403 with a `WWW-Authenticate` challenge, or 503 when the pool's keys
can't be fetched.

## Documentation

The [API documentation](https://docs.rs/cognito-kit) has a guide with a
chapter for each job:

1. [Checking access tokens](https://docs.rs/cognito-kit/latest/cognito_kit/guide/access_tokens/index.html),
   with custom attributes, the axum extractor and the tower layer.
2. [Web sign-in with managed login](https://docs.rs/cognito-kit/latest/cognito_kit/guide/web_sign_in/index.html).
3. [An MCP server behind Cognito](https://docs.rs/cognito-kit/latest/cognito_kit/guide/mcp_server/index.html).
4. [Letting assistants register themselves](https://docs.rs/cognito-kit/latest/cognito_kit/guide/self_registration/index.html),
   by Client ID Metadata Document or Dynamic Client Registration.
5. [Testing with the test kit](https://docs.rs/cognito-kit/latest/cognito_kit/guide/testing/index.html).
6. [The OpenTofu module](https://docs.rs/cognito-kit/latest/cognito_kit/guide/opentofu/index.html)
   in [`opentofu/`](opentofu), for the pool, managed login and app clients.
7. [Production notes](https://docs.rs/cognito-kit/latest/cognito_kit/guide/production/index.html):
   key caching, status codes, Lambda, and the security model.

[`examples/portal.rs`](examples/portal.rs) is a small axum app with web
sign-in and an MCP endpoint. [`CHANGELOG.md`](CHANGELOG.md) lists what
changed in each release.

## Rust version

The crate builds on Rust 1.88 and later. `registration` and `dynamodb` need
the AWS SDK's minimum Rust, 1.94.1 for the SDK versions this release was
tested with.

## Development

Every tool and task runs through [mise](https://mise.jdx.dev), and
`mise run ci` runs what CI runs. The tests in `tests/` use a fake Cognito
and need no AWS account. `tests/live/` drives the example and real
assistants against a throwaway pool.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT
