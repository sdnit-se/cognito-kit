use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;

/// The error an [`HttpClient`] returns.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Sends the few HTTP requests this crate makes: the pool's key set, and
/// managed login's token and revocation endpoints.
///
/// With the `reqwest` feature, [`reqwest::Client`] implements it. Implement it
/// yourself to use another client, or to answer from memory in tests.
pub trait HttpClient: Send + Sync + 'static {
    /// Sends one request and returns the whole response, whatever its
    /// status. An error means no response arrived.
    fn send(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> impl Future<Output = Result<http::Response<Vec<u8>>, BoxError>> + Send;
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait DynHttpClient: Send + Sync {
    fn send_boxed(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, BoxError>>;
}

impl<T: HttpClient> DynHttpClient for T {
    fn send_boxed(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, BoxError>> {
        Box::pin(self.send(request))
    }
}

#[derive(Clone)]
pub(crate) struct Http(Arc<dyn DynHttpClient>);

impl Http {
    pub(crate) fn new(client: impl HttpClient) -> Self {
        Self(Arc::new(client))
    }

    pub(crate) async fn send(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, BoxError> {
        self.0.send_boxed(request).await
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, BoxError> {
        let request = http::Request::get(url)
            .header(http::header::ACCEPT, "application/json")
            .body(Vec::new())?;
        let response = self.send(request).await?;
        if !response.status().is_success() {
            return Err(format!("GET {url}: {}", response.status()).into());
        }
        Ok(serde_json::from_slice(response.body())?)
    }
}

#[cfg(feature = "reqwest")]
impl HttpClient for reqwest::Client {
    async fn send(&self, request: http::Request<Vec<u8>>) -> Result<http::Response<Vec<u8>>, BoxError> {
        let response = self.execute(request.try_into()?).await?;
        let mut builder = http::Response::builder().status(response.status());
        if let Some(headers) = builder.headers_mut() {
            *headers = response.headers().clone();
        }
        Ok(builder.body(response.bytes().await?.to_vec())?)
    }
}

/// rustls with ring, trusting the system's root certificates.
#[cfg(feature = "reqwest")]
pub(crate) fn tls_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::BuilderVerifierExt;

    // Given to this crate's clients only: installing ring as the
    // process-wide provider would make that choice for the whole program.
    let ring = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(ring)
        .with_safe_default_protocol_versions()
        .and_then(BuilderVerifierExt::with_platform_verifier)
        .expect("the system's root certificates load")
        .with_no_client_auth()
}

#[cfg(feature = "reqwest")]
pub(crate) fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .tls_backend_preconfigured(tls_config())
        .build()
        .expect("reqwest takes the rustls configuration")
}
