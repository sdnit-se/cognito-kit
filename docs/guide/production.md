What to know before you run this crate in production: how it caches keys,
which status codes it answers with, how it fits AWS Lambda, and what it
leaves to you.

# Key caching

A [`UserPool`](crate::UserPool) fetches the pool's signing keys on the
first token check and caches them. Every verifier built from one
`UserPool` shares that cache, and so do its clones. Build the pool once at
startup.

The cache refetches the key set in two cases:

- A token names a key the cache doesn't have, as after Cognito rotates its
  keys. A stream of tokens with made-up key ids causes at most one fetch
  per cooldown, 30 seconds by default, so it can't turn your service into
  a key fetcher.
- The cached set is older than the maximum key age, ten minutes by
  default. A key that Cognito withdraws then stops working within ten
  minutes.

Stale keys are never used. If a refetch fails once the set is older than
the maximum age, every check fails with 503 until a fetch succeeds. One
task fetches at a time, and the others wait for its result.

Change these with
[`refetch_cooldown`](crate::UserPool::refetch_cooldown) and
[`max_key_age`](crate::UserPool::max_key_age), before you build verifiers:
each starts a new, empty cache. The cooldown is never longer than the
maximum age.

The default HTTP client gives up after ten seconds. It uses rustls with
ring and the system's root certificates, and installs no process-wide
rustls provider. [`UserPool::new`](crate::UserPool::new) panics if the
system has no root certificates.

# 401, 403 or 503

[`Rejection::status`](crate::Rejection::status) decides the status, and
[`Challenge::response`](crate::Challenge::response) sends it:

| Status | When | `WWW-Authenticate` |
|--------|------|--------------------|
| 401 | No token, or one that is malformed, forged, expired, from another pool, the wrong kind, for another audience, or from an app client you don't accept | `Bearer`, with `error="invalid_token"` when there was a token |
| 403 | A valid token without a required scope | `Bearer error="insufficient_scope"`, with the scopes needed |
| 503 | The keys can't be fetched, or the registrar's store can't be read | None, because the client did nothing wrong |

A 401 tells a client to get a new token. A 503 tells it to try again
later, so a Cognito outage doesn't sign everyone out. Log
[`Challenge::rejection`](crate::Challenge::rejection) to see which check
failed.

A verifier checks a token's signature and claims, and doesn't ask
Cognito about it. An access token stays valid until it expires, even after
[`ManagedLogin::revoke`](crate::ManagedLogin::revoke) or a sign-out. Keep
access tokens short-lived. An hour is Cognito's default.

# AWS Lambda

- Build the [`UserPool`](crate::UserPool), verifiers and
  [`OAuthFront`](crate::OAuthFront) once, before the runtime starts
  handling events. The key cache then survives between invocations of a
  warm instance. A warm instance fetches keys only when the cache needs it:
  for a key id it hasn't seen, at most once per cooldown, and once the keys
  are ten minutes old.
- A Lambda function URL renames the `WWW-Authenticate` header, so MCP
  clients don't see the challenge. They then look for the protected
  resource document at the root, and the front serves it there too.
- [`OAuthFront::router`](crate::OAuthFront::router) reads at most 64 KiB of
  each request body. OAuth requests are a few hundred bytes.
- The registrar limits app-client changes per process, and each Lambda
  instance is one. Put a rate rule in front of `/oauth2/authorize` and
  `/oauth2/register`, such as an AWS WAF rule on a CloudFront
  distribution in front of the function.
- Run [`Registrar::cleanup`](crate::registration::Registrar::cleanup) from
  a scheduled invocation, such as an EventBridge schedule, rather than on a
  request path.

# The security model

The crate refuses a token unless every check passes, and your code sees
claims only from a token that passed. [`AccessClaims`](crate::AccessClaims)
and [`IdClaims`](crate::IdClaims) are separate types, and each verifier
refuses the other kind of token.

Web sign-in uses PKCE with `S256`, a random state, compared in constant
time, and a nonce checked against the ID token.

With self-registration, codes go only to a loopback address on the
person's device or to an https host you trust. [The self-registration
chapter](crate::guide::self_registration) explains why, and how the relay keeps
loopback codes on the device. Metadata documents are fetched only from
public addresses.

# What the crate leaves to you

- **Sessions.** Where you keep a [`PendingLogin`](crate::PendingLogin) and
  the tokens of a [`SignedIn`](crate::SignedIn) is up to you. Keep both
  server-side or encrypted.
- **Authorization.** The verifier checks scopes. What a user may do with
  their `sub`, groups and attributes is your code's decision.
- **Rate limits.** The crate limits its own writes to Cognito, not the
  requests it receives.
- **Consent.** Cognito has no consent step, and the front adds none. The
  limits on where codes may go take its place.
- **Logs.** The front's `/oauth2/callback` receives authorization codes in
  its query string, so they reach your access logs. They are single-use,
  short-lived, and useless without the client's PKCE verifier.
- **Users and pools.** The crate doesn't create users or change pool
  settings. The registrar changes only the app clients it created.

# Supported Rust versions

The crate builds on Rust 1.88 and later. The `registration` and `dynamodb`
features need what the AWS SDK needs, Rust 1.94.1 for the SDK versions
this release was tested with.

# Reporting a vulnerability

See [SECURITY.md](https://github.com/sdnit-se/cognito-kit/blob/main/SECURITY.md).
Report privately through GitHub's security tab, not in a public issue.
