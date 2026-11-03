# Changelog

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
