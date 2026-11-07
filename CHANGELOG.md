# Changelog

## 0.4.0 (2026-11-07)

- **A client that changes its redirect URIs keeps signing in.** A refresh
  of a metadata document now takes a lease on its registration in the
  store, so refreshes take turns, also across servers. Under the lease it
  adds the new callback URLs to the app client before it stores the
  document, and removes the dropped ones after. A sign-in that read
  either list from the store finds its callback URL on the app client.
  Before, a refresh replaced the callback URLs first, and two refreshes at
  once could leave the store listing a URI that the app client lacked
  until the document changed again (#6).
- While another server holds the lease, a sign-in with a redirect URI the
  store lists goes on, and one with a URI that only the new document lists
  gets 503. A lease runs out after 30 seconds, so a server that stops
  mid-refresh holds the document back no longer than that. A refresh whose
  lease ran out and was taken over doesn't store its fetch.
- A refresh goes by the registration as taking the lease finds it, not as
  read before the fetch. A fetched document replaces the stored one only
  if its fetch began after the stored one's, so a slow fetch can't undo a
  newer refresh, or a registration that a sign-in made again after
  cleanup. A sign-in that finds another server's lease goes on with the
  registration as stored then, and one that finds it removed registers
  the document again. A refresh that finds the app client gone answers
  503, also while the host is down. The lease's 30 seconds count from when
  it is taken, after the fetch.
- Every refresh reads the app client's callback URLs, one
  `DescribeUserPoolClient`, and sets them to the stored list if they
  differ, also while the document's host is down. So an app client that
  lacks a stored callback URL, as earlier releases could leave it, is
  repaired by the next refresh. If Cognito or the store fails, or no
  app-client write is left, a sign-in with a redirect URI the store lists
  goes on with the stored document, and one with a URI only the new
  document lists gets 503, as while another server holds the lease. A
  refresh that changes nothing makes no app-client write. One that changes
  the list makes up to two: one to add callback URLs and one to remove
  them. If the removal finds the minute's writes spent, the app client
  keeps the old callback URLs as well until a later refresh removes them.
  A callback URL on a host the server no longer trusts goes in the first
  write.
- A refresh never sends Cognito more than its limit of 100 callback URLs.
  If the stored and the fetched lists together have more, the app client
  gets the fetched list before the store does, as before this release.
- `FakeCognito` refuses more than 100 callback URLs on an app client, as
  Cognito does.
- **Breaking:** `RegistrationStore` has two new methods, `lease`, which
  returns the registration as stored and whether the caller got the lease
  (`Leased`), and `release`. `update` takes the `Lease` and returns whether
  it stored the registration. `DynamoStore` keeps the lease in two
  attributes of the registration's item, with the `UpdateItem` permission
  it already needed, and reads a refused lease's item from the refusal.
  `MemoryStore` implements them too. If you implement `RegistrationStore`
  yourself, make `lease` one conditional write that returns the
  registration either way, as its docs say.
- **Breaking:** `AppClients` has a new method, `callback_urls`. `CognitoApi`
  and `FakeCognito` implement it. If you implement `AppClients` yourself,
  add it.
- During a rolling deploy, servers on 0.3 take no lease, so their
  refreshes can still cross others' until every server runs this release.

## 0.3.1 (2026-11-05)

- `FakeCognito`'s ID tokens carry the sign-in's nonce, as Cognito's do, so
  `ManagedLogin::callback` completes a sign-in against the fake. Before, it
  always failed with `LoginError::Nonce`.
- Docs: a guide on docs.rs with a chapter for each job, a shorter README,
  and `# Errors` and examples on the main types.

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
