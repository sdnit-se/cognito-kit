//! A Rust toolkit for Amazon Cognito: check its tokens, sign people in on the
//! web, and let AI assistants sign in to your MCP server.
//!
//! Unofficial. Not affiliated with or endorsed by AWS.
//!
//! Cognito is AWS's user directory and sign-in service. It issues JSON Web
//! Tokens and hosts a sign-in page, managed login, for each user pool. The
//! AWS SDK for Rust manages pools, but it doesn't check the tokens they
//! issue or drive the sign-in, and Cognito's OAuth server lacks parts that
//! MCP clients need. This crate fills those gaps:
//!
//! - **Token checks** for an API that Cognito protects: signature, issuer,
//!   expiry, app client, audience and scopes, with typed claims.
//! - **Web sign-in** through managed login, with PKCE, state and nonce.
//! - **An OAuth front for MCP servers**, serving the metadata documents
//!   that MCP clients look for and Cognito doesn't publish.
//! - **Self-registration** for assistants such as Claude and Codex, so they
//!   connect from your MCP server's URL alone.
//! - **A fake Cognito** for your tests, and an OpenTofu module for the pool.
//!
//! The core uses only the [`http`] crate's types and works with any web
//! framework, or none. It doesn't depend on an MCP SDK.
//!
//! # Quick start
//!
//! Check an access token from the command line. Put in your pool's id and
//! an app client's id, then run it with a token that the app client got:
//!
//! ```sh
//! cargo add cognito-kit
//! cargo add tokio --features macros,rt-multi-thread
//! ```
//!
//! ```no_run
//! use cognito_kit::{AccessClaims, UserPool};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let pool = UserPool::new("eu-north-1_AbC123".parse()?);
//!     let verifier = pool
//!         .access_tokens()
//!         .client("1example23456789".parse()?)
//!         .build()?;
//!
//!     let token = std::env::args().nth(1).ok_or("pass an access token")?;
//!     let claims: AccessClaims = verifier.verify(&token).await?;
//!     println!("{} called through app client {}", claims.sub, claims.client_id);
//!     Ok(())
//! }
//! ```
//!
//! [`verify`](AccessTokenVerifier::verify) fetches the pool's keys on first
//! use and caches them. In a web service, build the verifier once and use
//! [`authenticate`](AccessTokenVerifier::authenticate), which reads the
//! `Authorization` header. A refused request gets a ready response: 401 or
//! 403 with a `WWW-Authenticate` challenge, or 503 when the pool's keys
//! can't be fetched.
//!
//! # Which type you want
//!
//! | To | Start with |
//! |----|------------|
//! | Check access tokens in an API | [`UserPool::access_tokens`], which builds an [`AccessTokenVerifier`] |
//! | Check ID tokens | [`UserPool::id_tokens`], which returns an [`IdTokenVerifier`] |
//! | Read custom attributes | The type parameter of [`AccessClaims`] and [`IdClaims`] |
//! | Sign people in on a website | [`UserPool::managed_login`], which builds a [`ManagedLogin`] |
//! | Put an MCP server behind Cognito | [`OAuthFront`] |
//! | Let assistants register themselves | [`Registrar`] |
//! | Test without AWS | [`FakeCognito`] |
//! | Use your own HTTP client | [`HttpClient`] and [`UserPool::with_http_client`] |
//!
//! # Features
//!
//! | Feature | Default | Adds |
//! |---------|---------|------|
//! | `reqwest` | yes | [`UserPool::new`], with a reqwest client over rustls and the system's root certificates |
//! | `axum` | no | [`AccessClaims`] as an axum extractor, and [`OAuthFront::router`] |
//! | `tower` | no | [`RequireBearerLayer`], which admits only requests with a valid token |
//! | `registration` | no | The [`registration`] module, with [`CognitoApi`] over the AWS SDK. Turns on `reqwest` |
//! | `dynamodb` | no | [`DynamoStore`], which keeps registrations in DynamoDB. Turns on `registration` |
//! | `test-kit` | no | The [`test_kit`] module: [`FakeCognito`], and with `registration`, [`MemoryStore`] |
//!
//! The crate builds on Rust 1.88. `registration` and `dynamodb` need the AWS
//! SDK's minimum, Rust 1.94.1 for the versions this release was tested with.
//!
//! # Guide
//!
//! The [`guide`] walks through each job:
//!
//! 1. [Checking access tokens](guide::access_tokens), with custom
//!    attributes, the axum extractor and the tower layer.
//! 2. [Web sign-in with managed login](guide::web_sign_in).
//! 3. [An MCP server behind Cognito](guide::mcp_server).
//! 4. [Letting assistants register themselves](guide::self_registration).
//! 5. [Testing with the test kit](guide::testing).
//! 6. [The OpenTofu module](guide::opentofu).
//! 7. [Production notes](guide::production): key caching, status codes,
//!    Lambda, and the security model.
//!
// Items behind a feature: in a build without it, their links go to docs.rs.
#![cfg_attr(feature = "tower", doc = "[`RequireBearerLayer`]: RequireBearerLayer")]
#![cfg_attr(
    not(feature = "tower"),
    doc = "[`RequireBearerLayer`]: https://docs.rs/cognito-kit/latest/cognito_kit/struct.RequireBearerLayer.html"
)]
#![cfg_attr(feature = "axum", doc = "[`OAuthFront::router`]: OAuthFront::router")]
#![cfg_attr(
    not(feature = "axum"),
    doc = "[`OAuthFront::router`]: https://docs.rs/cognito-kit/latest/cognito_kit/struct.OAuthFront.html#method.router"
)]
#![cfg_attr(feature = "registration", doc = "[`registration`]: registration")]
#![cfg_attr(
    not(feature = "registration"),
    doc = "[`registration`]: https://docs.rs/cognito-kit/latest/cognito_kit/registration/index.html"
)]
#![cfg_attr(feature = "registration", doc = "[`Registrar`]: registration::Registrar")]
#![cfg_attr(
    not(feature = "registration"),
    doc = "[`Registrar`]: https://docs.rs/cognito-kit/latest/cognito_kit/registration/struct.Registrar.html"
)]
#![cfg_attr(feature = "registration", doc = "[`CognitoApi`]: registration::CognitoApi")]
#![cfg_attr(
    not(feature = "registration"),
    doc = "[`CognitoApi`]: https://docs.rs/cognito-kit/latest/cognito_kit/registration/struct.CognitoApi.html"
)]
#![cfg_attr(feature = "dynamodb", doc = "[`DynamoStore`]: registration::DynamoStore")]
#![cfg_attr(
    not(feature = "dynamodb"),
    doc = "[`DynamoStore`]: https://docs.rs/cognito-kit/latest/cognito_kit/registration/struct.DynamoStore.html"
)]
#![cfg_attr(feature = "test-kit", doc = "[`test_kit`]: test_kit")]
#![cfg_attr(
    not(feature = "test-kit"),
    doc = "[`test_kit`]: https://docs.rs/cognito-kit/latest/cognito_kit/test_kit/index.html"
)]
#![cfg_attr(feature = "test-kit", doc = "[`FakeCognito`]: test_kit::FakeCognito")]
#![cfg_attr(
    not(feature = "test-kit"),
    doc = "[`FakeCognito`]: https://docs.rs/cognito-kit/latest/cognito_kit/test_kit/struct.FakeCognito.html"
)]
#![cfg_attr(
    all(feature = "test-kit", feature = "registration"),
    doc = "[`MemoryStore`]: test_kit::MemoryStore"
)]
#![cfg_attr(
    not(all(feature = "test-kit", feature = "registration")),
    doc = "[`MemoryStore`]: https://docs.rs/cognito-kit/latest/cognito_kit/test_kit/struct.MemoryStore.html"
)]
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
#[cfg(any(doc, doctest))]
pub mod guide;
#[cfg(feature = "registration")]
#[cfg_attr(docsrs, doc(cfg(feature = "registration")))]
pub mod registration;
#[cfg(feature = "test-kit")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-kit")))]
pub mod test_kit;
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
