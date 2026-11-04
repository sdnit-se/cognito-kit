use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::RsaPublicKeyComponents;
use serde::Deserialize;

use crate::http_client::{BoxError, Http};
use crate::verify::Rejection;

pub(crate) type PublicKey = RsaPublicKeyComponents<Vec<u8>>;

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// The members of a JWK that an RS256 key needs (RFC 7517, RFC 7518 section 6.3).
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

struct KeySet {
    keys: BTreeMap<String, PublicKey>,
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

    fn fresh(&self, kid: &str) -> Option<PublicKey> {
        self.current()
            .filter(|set| set.fetched.elapsed() < self.max_age)
            .and_then(|set| set.keys.get(kid).cloned())
    }

    pub(crate) async fn key(&self, kid: &str) -> Result<PublicKey, Rejection> {
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        // One task fetches; the others wait here and then find its result.
        let mut attempt = self.attempt.lock().await;
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        // A set goes stale after max_age, so the cooldown can't be longer, or
        // a stale set would wait out the cooldown with no usable keys.
        if attempt
            .at
            .is_none_or(|at| at.elapsed() >= self.cooldown.min(self.max_age))
        {
            attempt.at = Some(Instant::now());
            match self.fetch().await {
                Ok(set) => {
                    attempt.error = None;
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(set));
                }
                Err(error) => attempt.error = Some(Arc::new(error)),
            }
        }
        // Stale keys are never used, even while a refetch fails: a key that
        // Cognito withdrew must stop working.
        match self.current().filter(|set| set.fetched.elapsed() < self.max_age) {
            Some(set) => set.keys.get(kid).cloned().ok_or(Rejection::UnknownKey),
            None => Err(Rejection::KeysUnavailable(attempt.error.clone().unwrap_or_else(
                || Arc::new("no key set is younger than max_key_age".into()),
            ))),
        }
    }

    async fn fetch(&self) -> Result<KeySet, BoxError> {
        let set: JwkSet = self.http.get_json(&self.url).await?;
        let keys = set
            .keys
            .into_iter()
            .filter(|jwk| jwk.kty == "RSA")
            .filter(|jwk| jwk.usage.as_deref().is_none_or(|u| u == "sig"))
            .filter(|jwk| jwk.alg.as_deref().is_none_or(|a| a == "RS256"))
            .filter_map(|jwk| {
                let n = URL_SAFE_NO_PAD.decode(jwk.n?).ok()?;
                let e = URL_SAFE_NO_PAD.decode(jwk.e?).ok()?;
                Some((jwk.kid?, PublicKey { n, e }))
            })
            .collect();
        Ok(KeySet {
            keys,
            fetched: Instant::now(),
        })
    }
}
