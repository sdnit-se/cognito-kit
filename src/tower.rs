use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde::de::DeserializeOwned;
use tower_layer::Layer;
use tower_service::Service;

use crate::{AccessClaims, AccessTokenVerifier};

/// Admits only requests with a valid access token, and puts its
/// [`AccessClaims<C>`] into the request's extensions. Other requests get the
/// verifier's challenge and never reach the inner service.
pub struct RequireBearerLayer<C = ()> {
    verifier: AccessTokenVerifier,
    claims: PhantomData<fn() -> C>,
}

impl<C> RequireBearerLayer<C> {
    pub fn new(verifier: AccessTokenVerifier) -> Self {
        Self {
            verifier,
            claims: PhantomData,
        }
    }
}

impl<C> Clone for RequireBearerLayer<C> {
    fn clone(&self) -> Self {
        Self::new(self.verifier.clone())
    }
}

impl<S, C> Layer<S> for RequireBearerLayer<C> {
    type Service = RequireBearer<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireBearer {
            inner,
            verifier: self.verifier.clone(),
            claims: PhantomData,
        }
    }
}

/// The service [`RequireBearerLayer`] wraps around yours.
pub struct RequireBearer<S, C = ()> {
    inner: S,
    verifier: AccessTokenVerifier,
    claims: PhantomData<fn() -> C>,
}

impl<S: Clone, C> Clone for RequireBearer<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            verifier: self.verifier.clone(),
            claims: PhantomData,
        }
    }
}

impl<S, C, B, R> Service<http::Request<B>> for RequireBearer<S, C>
where
    S: Service<http::Request<B>, Response = http::Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
    R: From<String>,
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Response = http::Response<R>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        let verifier = self.verifier.clone();
        // The clone that was polled ready serves this request.
        let fresh = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, fresh);
        Box::pin(async move {
            match verifier.authenticate::<C>(request.headers()).await {
                Ok(claims) => {
                    request.extensions_mut().insert::<AccessClaims<C>>(claims);
                    inner.call(request).await
                }
                Err(challenge) => Ok(challenge.response().map(R::from)),
            }
        })
    }
}
