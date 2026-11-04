# Changelog

## 0.3.0 (2026-11-04)

Assistants connect to an MCP server from its URL alone. They register
themselves, and each gets an app client of its own; nobody types a client id.

- **Client ID Metadata Documents and Dynamic Client Registration**, with the
  `registration` feature. Build a `Registrar` from `CognitoApi` (the AWS SDK)
  and a `RegistrationStore`, and give it to the verifier with
  `AccessTokenVerifierBuilder::registrar`. The `OAuthFront` then serves
  `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/callback`
  and `/oauth2/register` through the new `OAuthFront::handle`, and its
  metadata points at them. Each client's first authorization creates a public app
  client like a template client, with its managed login style and
  refresh-token rotation.
- **`GuardedFetcher`** fetches metadata documents: https only, at most 5 KiB
  within five seconds, no redirects or proxy, and only from public
  addresses, checked after DNS and pinned for the connection.
- **Codes go only to the user's device or a host you trust.** Cognito has no
  consent step, so https redirect URIs must be on a host listed with
  `client_hosts`, checked on every authorization, so a host taken off the
  list gets no more codes through the front, even for clients registered
  while it was on. Their app clients still list it as a callback, so run
  `Registrar::cleanup` after taking a host off: it removes them. Loopback
  ones match on any port: Cognito sends their codes
  to the front's `/oauth2/callback`, which passes each on to the loopback
  URI its authorization started with.
- **Limits and cleanup.** At `max_registrations` (500 by default), or at
  Cognito's quota of 1,000 app clients per pool, new clients get a 503 and
  registered ones keep working. `Registrar::cleanup` removes registrations
  that were never used or have been idle, and orphaned app clients. It reads
  each registration again before removing it, and keeps one used since the
  list.
- **App clients you manage by hand pass through unchanged.** The front checks
  the code grant and PKCE only for clients it registered; Cognito checks the
  rest, as it did before.
- **`DynamoStore`**, with the `dynamodb` feature, keeps registrations in a
  table that the OpenTofu module's new `registration` variable creates,
  together with a least-privilege IAM policy.
- **A test kit**, with the `test-kit` feature: `FakeCognito` serves a key
  set, signs tokens, and plays managed login and its token endpoint; with
  `registration` it also keeps app clients, and `MemoryStore` keeps
  registrations. `tests/assistants.rs` replays Claude's, ChatGPT's, Claude
  Code's, Codex's and Executor's OAuth flows against the front with it.
- `Rejection::RegistryUnavailable` (503), `ConfigError::Registration`, and
  `registration_endpoint` and `client_id_metadata_document_supported` in
  `AuthorizationServerMetadata` are new; the enum and struct are
  `#[non_exhaustive]`, so code written for 0.2 still compiles.
- `AccessTokenVerifier::verify` checks the app client before reading the
  claims into your type. A token from an app client the verifier doesn't
  accept is now `Rejection::Client` even when its claims don't fit; the
  status stays 401.
- `OAuthFront::router` sends every method on its paths to `handle`.
- `registration` and `dynamodb` need the AWS SDK's minimum Rust, 1.94.1 for
  the versions tested; the rest of the crate still builds on 1.88.

## 0.2.0 (2026-11-04)

A lighter dependency tree, with the same API.

- Token signatures are checked with `ring` instead of `jsonwebtoken`, so
  `rsa` and its advisories (RUSTSEC-2023-0071, RUSTSEC-2026-0387) no longer
  reach your build or your audit.
- The `reqwest` feature uses rustls with ring and the system's root
  certificates, without aws-lc's C build (#3). It installs no process-wide
  rustls provider.
- PKCE's SHA-256 and the random state, nonce and verifier come from ring
  too, so `sha2` and `getrandom` are gone.
- A token signed with `none` is now `Rejection::Algorithm`, as documented,
  rather than `Rejection::Malformed`. A token with another algorithm, or
  one that isn't three base64url segments, no longer triggers a key fetch.
- Crates added to a dependent's tree: 54 instead of 102 with no default
  features, 91 instead of 141 with the defaults, and 95 instead of 145 with
  every feature.

## 0.1.0 (2026-11-03)

The first release.

- Token checks: `UserPool`, `AccessTokenVerifier`, `IdTokenVerifier`, typed
  `AccessClaims` and `IdClaims` with custom attributes, and `Rejection`.
- Web sign-in through managed login: `ManagedLogin` with PKCE, state and
  nonce, refresh, revocation and the sign-out URL.
- The OAuth front for MCP servers: `OAuthFront`, with RFC 9728 and RFC 8414
  metadata and `WWW-Authenticate` challenges.
- `axum` and `tower` adapters.
- An OpenTofu module in `opentofu/`.
