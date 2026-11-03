use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};

use crate::http_client::{BoxError, Http};
use crate::verify::Rejection;

struct KeySet {
    keys: BTreeMap<String, DecodingKey>,
    fetched: Instant,
}

#[derive(Default)]
struct Attempt {
    at: Option<Instant>,
    error: Option<Arc<BoxError>>,
}

/// The pool's signing keys, fetched on first use and refetched when a token
/// names an unknown key or the set is older than `max_age`, at most once per
/// `cooldown`.
pub(crate) struct KeyCache {
    url: String,
    http: Http,
    pub(crate) cooldown: Duration,
    pub(crate) max_age: Duration,
    current: RwLock<Option<Arc<KeySet>>>,
    attempt: tokio::sync::Mutex<Attempt>,
}

impl KeyCache {
    pub(crate) fn new(url: String, http: Http, cooldown: Duration, max_age: Duration) -> Self {
        Self {
            url,
            http,
            cooldown,
            max_age,
            current: RwLock::default(),
            attempt: tokio::sync::Mutex::default(),
        }
    }

    pub(crate) fn with_policy(&self, cooldown: Duration, max_age: Duration) -> Self {
        Self::new(self.url.clone(), self.http.clone(), cooldown, max_age)
    }

    fn current(&self) -> Option<Arc<KeySet>> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn fresh(&self, kid: &str) -> Option<DecodingKey> {
        self.current()
            .filter(|set| set.fetched.elapsed() < self.max_age)
            .and_then(|set| set.keys.get(kid).cloned())
    }

    pub(crate) async fn key(&self, kid: &str) -> Result<DecodingKey, Rejection> {
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        // One task fetches; the others wait here and then find its result.
        let mut attempt = self.attempt.lock().await;
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        if attempt.at.is_none_or(|at| at.elapsed() >= self.cooldown) {
            attempt.at = Some(Instant::now());
            match self.fetch().await {
                Ok(set) => {
                    attempt.error = None;
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(set));
                }
                Err(error) => attempt.error = Some(Arc::new(error)),
            }
        }
        // A failed refetch keeps the keys already known, stale or not.
        match self.current() {
            Some(set) => set.keys.get(kid).cloned().ok_or(Rejection::UnknownKey),
            None => Err(attempt
                .error
                .clone()
                .map_or(Rejection::UnknownKey, Rejection::KeysUnavailable)),
        }
    }

    async fn fetch(&self) -> Result<KeySet, BoxError> {
        let set: JwkSet = self.http.get_json(&self.url).await?;
        let keys = set
            .keys
            .iter()
            .filter(|jwk| matches!(jwk.algorithm, AlgorithmParameters::RSA(_)))
            .filter(|jwk| {
                jwk.common
                    .public_key_use
                    .as_ref()
                    .is_none_or(|u| *u == PublicKeyUse::Signature)
            })
            .filter(|jwk| jwk.common.key_algorithm.is_none_or(|a| a == KeyAlgorithm::RS256))
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, DecodingKey::from_jwk(jwk).ok()?)))
            .collect();
        Ok(KeySet {
            keys,
            fetched: Instant::now(),
        })
    }
}
