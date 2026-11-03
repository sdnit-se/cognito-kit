use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::config::{ClientId, LoginDomain, PoolId};
use crate::http_client::{Http, HttpClient};
use crate::keys::KeyCache;
use crate::login::ManagedLoginBuilder;
use crate::verify::{AccessTokenVerifierBuilder, IdTokenVerifier};

/// A Cognito user pool: its issuer and its signing keys.
///
/// Cheap to clone. Clones share one key cache, so build every verifier from
/// the same `UserPool`.
#[derive(Clone)]
pub struct UserPool {
    inner: Arc<Inner>,
}

struct Inner {
    id: PoolId,
    issuer: String,
    http: Http,
    keys: KeyCache,
}

impl UserPool {
    /// A pool whose keys are fetched with a [`reqwest::Client`] that gives up
    /// after ten seconds.
    ///
    /// # Panics
    ///
    /// If reqwest's TLS backend can't be initialised, as `reqwest::Client::new` does.
    #[cfg(feature = "reqwest")]
    pub fn new(id: PoolId) -> Self {
        Self::with_http_client(id, crate::http_client::default_client())
    }

    /// A pool whose keys are fetched, and whose token endpoint is called, with
    /// your own HTTP client.
    pub fn with_http_client(id: PoolId, http: impl HttpClient) -> Self {
        // With exactly one of jsonwebtoken's crypto features on, it picks a
        // provider by itself. Feature unification can turn on both, and then
        // every check would panic, so choose one unless the program did.
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
        let issuer = format!("https://cognito-idp.{}.amazonaws.com/{id}", id.region());
        let http = Http::new(http);
        let keys = KeyCache::new(
            format!("{issuer}/.well-known/jwks.json"),
            http.clone(),
            Duration::from_secs(30),
            Duration::from_secs(600),
        );
        Self {
            inner: Arc::new(Inner {
                id,
                issuer,
                http,
                keys,
            }),
        }
    }

    /// The shortest time between two key fetches. Defaults to 30 seconds.
    ///
    /// Call it before building verifiers: it starts a new, empty key cache.
    #[must_use]
    pub fn refetch_cooldown(self, cooldown: Duration) -> Self {
        let keys = self.inner.keys.with_policy(cooldown, self.inner.keys.max_age);
        self.with_keys(keys)
    }

    /// How long fetched keys are trusted before the next check refetches
    /// them. Defaults to ten minutes.
    ///
    /// Call it before building verifiers: it starts a new, empty key cache.
    #[must_use]
    pub fn max_key_age(self, max_age: Duration) -> Self {
        let keys = self.inner.keys.with_policy(self.inner.keys.cooldown, max_age);
        self.with_keys(keys)
    }

    fn with_keys(&self, keys: KeyCache) -> Self {
        let Inner { id, issuer, http, .. } = &*self.inner;
        Self {
            inner: Arc::new(Inner {
                id: id.clone(),
                issuer: issuer.clone(),
                http: http.clone(),
                keys,
            }),
        }
    }

    /// The pool's id.
    pub fn id(&self) -> &PoolId {
        &self.inner.id
    }

    /// `https://cognito-idp.<region>.amazonaws.com/<pool id>`, the `iss` of
    /// every token the pool issues.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// A verifier for access tokens, for a service that the pool protects.
    pub fn access_tokens(&self) -> AccessTokenVerifierBuilder {
        AccessTokenVerifierBuilder::new(self.clone())
    }

    /// A verifier for ID tokens issued to `client`.
    pub fn id_tokens(&self, client: ClientId) -> IdTokenVerifier {
        IdTokenVerifier::new(self.clone(), client)
    }

    /// Web sign-in for one app client, which must allow the authorization
    /// code grant and list `redirect_uri` among its callback URLs.
    pub fn managed_login(
        &self,
        domain: LoginDomain,
        client: ClientId,
        redirect_uri: Url,
    ) -> ManagedLoginBuilder {
        ManagedLoginBuilder::new(self.clone(), domain, client, redirect_uri)
    }

    pub(crate) fn keys(&self) -> &KeyCache {
        &self.inner.keys
    }

    pub(crate) fn http(&self) -> &Http {
        &self.inner.http
    }
}
