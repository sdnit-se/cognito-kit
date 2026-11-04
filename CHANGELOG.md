# Changelog

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
