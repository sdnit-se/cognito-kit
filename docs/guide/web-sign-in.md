Sign people in to a web app through Cognito's managed login.

Managed login is the sign-in page Cognito hosts for your pool, on a prefix
domain such as `https://example.auth.eu-north-1.amazoncognito.com` or on a
custom domain. Your app sends the browser there, and Cognito sends it back
with a code that your server redeems for tokens. [`ManagedLogin`] runs your
server's half: the redirect with PKCE, state and nonce, the callback,
refresh, revocation and sign-out.

# Set up the app client

The app client must allow the authorization code grant and list your
callback URL exactly. A server-side web app should be a confidential client
with a secret. In [the OpenTofu module](crate::guide::opentofu), that is a client
with `confidential = true`, and the secret is in the `client_secrets`
output.

# Build a `ManagedLogin`

```rust,no_run
use cognito_kit::{ClientSecret, ManagedLogin, UserPool};

fn login() -> Result<ManagedLogin, Box<dyn std::error::Error>> {
    let pool = UserPool::new("eu-north-1_AbC123".parse()?);
    let login = pool
        .managed_login(
            "https://login.example.com".parse()?,
            "1example23456789".parse()?,
            "https://app.example.com/callback".parse()?,
        )
        .client_secret(ClientSecret::new(std::env::var("WEB_CLIENT_SECRET")?))
        .build()?;
    Ok(login)
}
```

It asks for the `openid` and `email` scopes. To ask for others instead,
pass them to [`scopes`](crate::ManagedLoginBuilder::scopes). It always adds
`openid`.

# Sign a person in

A sign-in takes two requests. On the first, redirect the browser to the URL
that [`authorize`](crate::ManagedLogin::authorize) returns, and keep the
[`PendingLogin`] until the browser comes back. On the second, pass the
callback's query string to [`callback`](crate::ManagedLogin::callback).

```rust
use cognito_kit::{AuthorizeOptions, LoginError, ManagedLogin, PendingLogin, SignedIn};

/// GET /login: where to send the browser, and what to keep for the callback.
fn start(login: &ManagedLogin) -> (String, PendingLogin) {
    let (url, pending) = login.authorize(&AuthorizeOptions::default());
    (url.to_string(), pending)
}

/// GET /callback?code=...&state=...: the person, verified.
async fn finish(
    login: &ManagedLogin,
    pending: PendingLogin,
    query: &str,
) -> Result<SignedIn, LoginError> {
    let signed_in = login.callback(pending, query).await?;
    println!("signed in: {}", signed_in.claims.sub);
    Ok(signed_in)
}
```

`callback` checks that the callback's `state` is this sign-in's, redeems
the code with the PKCE verifier, verifies the ID token, and checks its
nonce. The result holds the ID token's claims and the tokens.

Keep the `PendingLogin` in your server-side session store, or in an
encrypted cookie. It holds the PKCE verifier, so it must not reach the
browser in clear text. It implements `Serialize` and `Deserialize` for
that purpose.

To skip managed login's own page and go straight to an identity provider
such as Google, use
[`AuthorizeOptions::identity_provider`](crate::AuthorizeOptions::identity_provider).

# Refresh and sign out

The ID and access tokens last an hour unless the app client says
otherwise. [`refresh`](crate::ManagedLogin::refresh) trades the refresh
token for new ones. With refresh-token rotation on, as the OpenTofu module
sets it, the response holds a new refresh token and the old one stops
working. Keep the newest one.

```rust
use cognito_kit::{LoginError, ManagedLogin, SignedIn};

/// Replaces the session's tokens. `false` means the person must sign in again.
async fn refresh(login: &ManagedLogin, session: &mut SignedIn) -> Result<bool, LoginError> {
    let Some(token) = session.tokens.refresh_token.clone() else {
        return Ok(false);
    };
    match login.refresh(&token).await {
        Ok(mut fresh) => {
            // Without rotation, Cognito sends no new refresh token.
            fresh.tokens.refresh_token.get_or_insert(token);
            *session = fresh;
            Ok(true)
        }
        Err(LoginError::Refused(error)) if error.is_invalid_grant() => Ok(false),
        Err(error) => Err(error),
    }
}
```

To sign out, revoke the refresh token with
[`revoke`](crate::ManagedLogin::revoke), delete your session, and redirect
the browser to [`logout_url`](crate::ManagedLogin::logout_url), which
ends the managed login session too. The URL you pass to `logout_url` must be one of the app client's
sign-out URLs.

# When a sign-in fails

[`LoginError`] says why. These cases are worth handling apart:

- [`LoginError::Denied`](crate::LoginError::Denied): the person cancelled,
  or managed login refused them. Show a message and offer to try again.
- [`LoginError::State`](crate::LoginError::State) or
  [`LoginError::Nonce`](crate::LoginError::Nonce): the callback doesn't
  belong to this sign-in. It may be forged or replayed. Start over.
- [`LoginError::Refused`](crate::LoginError::Refused) with
  [`is_invalid_grant`](crate::OAuthError::is_invalid_grant): the code or
  refresh token was already used, revoked or expired. Sign in again.
- [`LoginError::Http`](crate::LoginError::Http): Cognito could not be
  reached. Try again later.

# A complete app

[`examples/portal.rs`](https://github.com/sdnit-se/cognito-kit/blob/main/examples/portal.rs)
is an axum app with sign-in, refresh, sign-out and an MCP endpoint, in one
file. Run it against your own pool with
`cargo run --example portal --features axum`.

[`ManagedLogin`]: crate::ManagedLogin
[`PendingLogin`]: crate::PendingLogin
[`LoginError`]: crate::LoginError
