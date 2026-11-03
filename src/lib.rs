//! A Rust toolkit for Amazon Cognito.
//!
//! Unofficial. Not affiliated with or endorsed by AWS.
//!
//! `cognito-kit` covers three jobs:
//!
//! - **Token checks** for any service that Cognito protects. It verifies
//!   access tokens and ID tokens against the user pool's published keys and
//!   hands you typed claims.
//! - **Web sign-in through managed login**: the login redirect with PKCE,
//!   state and nonce, the callback exchange, refresh, revocation and the
//!   logout URL.
//! - **An OAuth front for MCP servers.** Cognito issues every token, and this
//!   crate publishes the metadata that MCP clients need and Cognito lacks:
//!   RFC 9728 protected resource metadata, RFC 8414 authorization server
//!   metadata that advertises PKCE with `S256`, and `WWW-Authenticate`
//!   challenges.
//!
//! The core uses only [`http`] types and works with any web framework or
//! none. The `axum` and `tower` features add adapters. The crate is
//! independent of any MCP SDK.
//!
//! # The API at a glance
//!
//! ```text
//! // Identity
//! PoolId: FromStr            "eu-north-1_AbC123"; the region comes from the id
//! ClientId: FromStr          an app client id
//! Scope: FromStr             an OAuth scope, such as "https://api.example.com/read"
//! LoginDomain: FromStr       the managed login origin, "https://login.example.com"
//!
//! // The pool and its keys
//! UserPool::new(PoolId) -> UserPool                                  (feature `reqwest`)
//! UserPool::with_http_client(PoolId, impl HttpClient) -> UserPool
//! UserPool::refetch_cooldown(self, Duration) -> UserPool
//! UserPool::max_key_age(self, Duration) -> UserPool
//! UserPool::issuer(&self) -> &str
//!
//! // Access tokens
//! UserPool::access_tokens(&self) -> AccessTokenVerifierBuilder
//!     .client(ClientId) / .clients(impl IntoIterator<Item = ClientId>)  at least one
//!     .scope(Scope)                                                     required on every token
//!     .audience(Url)                                                    `aud` must equal it
//!     .resource(Url)                                                    as `audience`, and challenges point at its metadata
//!     .leeway(Duration)
//!     .build() -> Result<AccessTokenVerifier, ConfigError>
//! AccessTokenVerifier::verify::<C>(&self, &str) -> Result<AccessClaims<C>, Rejection>
//! AccessTokenVerifier::authenticate::<C>(&self, &HeaderMap) -> Result<AccessClaims<C>, Challenge>
//! AccessTokenVerifier::challenge(&self, Rejection) -> Challenge
//!
//! // ID tokens
//! UserPool::id_tokens(&self, ClientId) -> IdTokenVerifier
//! IdTokenVerifier::verify::<C>(&self, &str) -> Result<IdClaims<C>, Rejection>
//!
//! // Claims; C carries custom attributes through serde's flatten
//! AccessClaims<C = ()> { sub, client_id, username, groups, scopes, exp, iat, auth_time, jti, custom: C }
//! IdClaims<C = ()>     { sub, username, email, email_verified, name, groups, identities, exp, iat, auth_time, custom: C }
//! Rejection            Missing | Malformed | Algorithm | UnknownKey | Signature | Expired | Issuer
//!                      | TokenUse | Audience | Client | Scope(Scope) | KeysUnavailable(..)
//! Rejection::status(&self) -> StatusCode    401, 403 for a missing scope, 503 when keys can't be fetched
//! Challenge::response(self) -> http::Response<String>
//!
//! // Web sign-in through managed login
//! UserPool::managed_login(&self, LoginDomain, ClientId, Url) -> ManagedLoginBuilder
//!     .client_secret(ClientSecret) .scopes(..) .build() -> Result<ManagedLogin, ConfigError>
//! ManagedLogin::authorize(&self, &AuthorizeOptions) -> (Url, PendingLogin)
//! ManagedLogin::callback::<C>(&self, PendingLogin, query: &str) -> Result<SignedIn<C>, LoginError>
//! ManagedLogin::refresh::<C>(&self, &RefreshToken) -> Result<SignedIn<C>, LoginError>
//! ManagedLogin::revoke(&self, &RefreshToken) -> Result<(), LoginError>
//! ManagedLogin::logout_url(&self, &Url) -> Url
//! SignedIn<C> { claims: IdClaims<C>, tokens: Tokens }
//! Tokens { id_token: IdToken, access_token: AccessToken, refresh_token: Option<RefreshToken>, expires_in: Duration }
//!
//! // The OAuth front for MCP servers
//! OAuthFront::new(AccessTokenVerifier, LoginDomain) -> Result<OAuthFront, ConfigError>
//! OAuthFront::respond(&self, &Method, path: &str) -> Option<http::Response<String>>
//! OAuthFront::paths(&self) -> impl Iterator<Item = &str>
//! OAuthFront::protected_resource_metadata(&self) -> &ProtectedResourceMetadata
//! OAuthFront::authorization_server_metadata(&self) -> &AuthorizationServerMetadata
//! OAuthFront::verifier(&self) -> &AccessTokenVerifier
//!
//! // Adapters
//! AccessClaims<C>: axum::extract::FromRequestParts<S> where AccessTokenVerifier: FromRef<S>   (feature `axum`)
//! OAuthFront::router<S>(&self) -> axum::Router<S>                                             (feature `axum`)
//! RequireBearerLayer::<C>::new(AccessTokenVerifier)                                          (feature `tower`)
//! ```
//!
//! Every token check runs before your code sees a claim, so a value of
//! [`AccessClaims`] or [`IdClaims`] always comes from a verified token. The
//! two are distinct types, and each verifier refuses the other kind of token.
//!
//! # Checking access tokens
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use cognito_kit::{AccessClaims, UserPool};
//!
//! let pool = UserPool::new("eu-north-1_AbC123".parse()?);
//! let verifier = pool
//!     .access_tokens()
//!     .client("1example23456789".parse()?)
//!     .scope("https://api.example.com/read".parse()?)
//!     .build()?;
//!
//! # let token = "";
//! let claims: AccessClaims = verifier.verify(token).await?;
//! println!("{} via {}", claims.sub, claims.client_id);
//! # Ok(()) }
//! ```
//!
//! [`AccessTokenVerifier::verify`] fetches the pool's keys on first use and
//! caches them. A token signed with a key it hasn't seen triggers one refetch,
//! at most once per cooldown (30 seconds by default), so a stream of forged
//! key ids can't turn the service into a JWKS fetcher. Keys older than ten
//! minutes are refetched on the next check, so a key that Cognito withdraws
//! stops working.
//!
//! # Custom attributes
//!
//! ```
//! #[derive(serde::Deserialize)]
//! struct Attributes {
//!     #[serde(rename = "custom:tenant")]
//!     tenant: Option<String>,
//! }
//! type Claims = cognito_kit::IdClaims<Attributes>;
//! ```
//!
//! # An MCP server
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use cognito_kit::{OAuthFront, UserPool};
//!
//! let pool = UserPool::new("eu-north-1_AbC123".parse()?);
//! let verifier = pool
//!     .access_tokens()
//!     .clients(["1claude".parse()?, "2chatgpt".parse()?])
//!     .resource("https://portal.example.com/mcp".parse()?)
//!     .scope("https://portal.example.com/mcp/drafts".parse()?)
//!     .build()?;
//! let front = OAuthFront::new(verifier, "https://login.example.com".parse()?)?;
//!
//! # let request = http::Request::new(());
//! // In the request handler: serve the metadata documents, then check the token.
//! if let Some(response) = front.respond(request.method(), request.uri().path()) {
//!     // return response
//! }
//! match front.verifier().authenticate::<()>(request.headers()).await {
//!     Ok(claims) => { /* handle the MCP request */ }
//!     Err(challenge) => { /* return challenge.response() */ }
//! }
//! # Ok(()) }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod claims;
mod config;
mod http_client;
mod keys;
mod login;
mod mcp;
mod pool;
mod verify;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "tower")]
mod tower;

pub use claims::{AccessClaims, IdClaims, Identity, Scopes, Sub};
pub use config::{ClientId, ConfigError, LoginDomain, PoolId, Scope};
pub use http_client::{BoxError, HttpClient};
pub use login::{
    AccessToken, AuthorizeOptions, ClientSecret, IdToken, LoginError, ManagedLogin, ManagedLoginBuilder,
    OAuthError, PendingLogin, RefreshToken, SignedIn, Tokens,
};
pub use mcp::{AuthorizationServerMetadata, OAuthFront, ProtectedResourceMetadata};
pub use pool::UserPool;
pub use verify::{AccessTokenVerifier, AccessTokenVerifierBuilder, Challenge, IdTokenVerifier, Rejection};

#[cfg(feature = "tower")]
pub use tower::{RequireBearer, RequireBearerLayer};
