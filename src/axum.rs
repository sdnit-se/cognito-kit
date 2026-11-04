use axum::extract::{FromRef, FromRequestParts};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::request::Parts;
use serde::de::DeserializeOwned;

use crate::{AccessClaims, AccessTokenVerifier, Challenge, OAuthFront};

impl IntoResponse for Challenge {
    fn into_response(self) -> Response {
        self.response().into_response()
    }
}

/// Handlers take `AccessClaims<C>` as an argument; the token is verified by
/// the state's [`AccessTokenVerifier`], and a refused request gets the
/// verifier's [`Challenge`].
impl<S, C> FromRequestParts<S> for AccessClaims<C>
where
    AccessTokenVerifier: FromRef<S>,
    S: Send + Sync,
    C: DeserializeOwned,
{
    type Rejection = Challenge;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        AccessTokenVerifier::from_ref(state)
            .authenticate(&parts.headers)
            .await
    }
}

impl OAuthFront {
    /// Routes for the front's paths, to merge into your router: the
    /// metadata documents, and with a registrar its own endpoints.
    #[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
    pub fn router<S: Clone + Send + Sync + 'static>(&self) -> axum::Router<S> {
        self.paths().fold(axum::Router::new(), |router, path| {
            let front = self.clone();
            let handle = move |request: axum::extract::Request| {
                let front = front.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    // OAuth requests are a few hundred bytes.
                    let Ok(body) = axum::body::to_bytes(body, 64 * 1024).await else {
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    };
                    let request = http::Request::from_parts(parts, body);
                    front.handle(&request).await.map_or_else(
                        || StatusCode::METHOD_NOT_ALLOWED.into_response(),
                        IntoResponse::into_response,
                    )
                }
            };
            router.route(path, axum::routing::any(handle))
        })
    }
}
