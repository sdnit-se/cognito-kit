//! A fake Cognito: RSA keys generated per test run, a JWKS endpoint that
//! counts its fetches, signed tokens, and a scriptable token endpoint.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cognito_kit::{BoxError, HttpClient, UserPool};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use serde_json::{Value, json};

pub const POOL: &str = "eu-north-1_TestPool1";
pub const ISSUER: &str = "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_TestPool1";
pub const CLIENT: &str = "assistant1client";
pub const LOGIN: &str = "https://login.example.com";

pub struct Key {
    pub kid: &'static str,
    pub encoding: EncodingKey,
    pub jwk: Jwk,
    pub public_pem: String,
}

fn generate(kid: &'static str) -> Key {
    let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("an RSA key");
    let encoding = EncodingKey::from_rsa_der(private.to_pkcs1_der().expect("DER").as_bytes());
    let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::RS256).expect("a JWK");
    jwk.common.key_id = Some(kid.to_owned());
    let public_pem = private
        .to_public_key()
        .to_pkcs1_pem(Default::default())
        .expect("PEM");
    Key {
        kid,
        encoding,
        jwk,
        public_pem,
    }
}

pub static KEYS: LazyLock<[Key; 2]> = LazyLock::new(|| [generate("k1"), generate("k2")]);

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn sign(kid: &str, claims: &Value) -> String {
    let key = KEYS.iter().find(|k| k.kid == kid).expect("a known test key");
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(Algorithm::RS256)
    };
    jsonwebtoken::encode(&header, claims, &key.encoding).expect("a signed token")
}

/// The claims of an access token Cognito issues to the assistant client for
/// an MCP resource, with `aud` from the RFC 8707 `resource` parameter.
pub fn access_claims(resource: &str, scope: &str) -> Value {
    json!({
        "sub": "6f1c2e7a-0000-4000-8000-000000000001",
        "cognito:groups": ["editors"],
        "iss": ISSUER,
        "version": 2,
        "client_id": CLIENT,
        "token_use": "access",
        "scope": scope,
        "aud": resource,
        "auth_time": now(),
        "iat": now(),
        "exp": now() + 3600,
        "jti": "b1e3",
        "username": "google_1234567890",
    })
}

pub fn id_claims(client: &str, nonce: Option<&str>) -> Value {
    let mut claims = json!({
        "sub": "6f1c2e7a-0000-4000-8000-000000000001",
        "cognito:groups": ["editors"],
        "email_verified": "true",
        "iss": ISSUER,
        "cognito:username": "google_1234567890",
        "aud": client,
        "token_use": "id",
        "auth_time": now(),
        "iat": now(),
        "exp": now() + 3600,
        "email": "ada@example.com",
        "name": "Ada",
        "custom:tenant": "acme",
        "identities": [{
            "userId": "1234567890", "providerName": "Google", "providerType": "Google",
            "issuer": null, "primary": "true", "dateCreated": "1700000000000"
        }],
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    claims
}

pub type Form = BTreeMap<String, String>;
type TokenHandler = Box<dyn Fn(&Form) -> (u16, Value) + Send + Sync>;

#[derive(Default)]
struct State {
    published: Mutex<Vec<&'static str>>,
    jwks_status: Mutex<Option<u16>>,
    jwks_fetches: AtomicUsize,
    token_handler: Mutex<Option<TokenHandler>>,
    requests: Mutex<Vec<(String, Form, Option<String>)>>,
}

/// Serves `ISSUER`'s key set and `LOGIN`'s endpoints from memory.
#[derive(Clone, Default)]
pub struct FakeCognito(Arc<State>);

impl FakeCognito {
    pub fn publishing(kids: &[&'static str]) -> Self {
        let fake = Self::default();
        fake.publish(kids);
        fake
    }

    pub fn publish(&self, kids: &[&'static str]) {
        *self.0.published.lock().unwrap() = kids.to_vec();
    }

    pub fn fail_jwks_with(&self, status: u16) {
        *self.0.jwks_status.lock().unwrap() = Some(status);
    }

    pub fn jwks_fetches(&self) -> usize {
        self.0.jwks_fetches.load(Ordering::SeqCst)
    }

    pub fn on_token(&self, handler: impl Fn(&Form) -> (u16, Value) + Send + Sync + 'static) {
        *self.0.token_handler.lock().unwrap() = Some(Box::new(handler));
    }

    /// Each request to the login domain: its path, form and `Authorization`.
    pub fn requests(&self) -> Vec<(String, Form, Option<String>)> {
        self.0.requests.lock().unwrap().clone()
    }

    pub fn pool(&self) -> UserPool {
        UserPool::with_http_client(POOL.parse().unwrap(), self.clone())
    }
}

fn json_response(status: u16, body: &Value) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .body(serde_json::to_vec(body).unwrap())
        .unwrap()
}

impl HttpClient for FakeCognito {
    async fn send(&self, request: http::Request<Vec<u8>>) -> Result<http::Response<Vec<u8>>, BoxError> {
        let url = request.uri().to_string();
        if url == format!("{ISSUER}/.well-known/jwks.json") {
            self.0.jwks_fetches.fetch_add(1, Ordering::SeqCst);
            if let Some(status) = *self.0.jwks_status.lock().unwrap() {
                return Ok(json_response(status, &json!({})));
            }
            let published = self.0.published.lock().unwrap().clone();
            let keys = KEYS
                .iter()
                .filter(|k| published.contains(&k.kid))
                .map(|k| k.jwk.clone())
                .collect();
            return Ok(json_response(200, &serde_json::to_value(JwkSet { keys })?));
        }
        let path = url
            .strip_prefix(LOGIN)
            .ok_or_else(|| format!("unexpected request to {url}"))?
            .to_owned();
        let form: Form = url::form_urlencoded::parse(request.body()).into_owned().collect();
        let authorization = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_owned());
        self.0
            .requests
            .lock()
            .unwrap()
            .push((path.clone(), form.clone(), authorization));
        match path.as_str() {
            "/oauth2/token" => {
                let handler = self.0.token_handler.lock().unwrap();
                let (status, body) = handler.as_ref().expect("a token handler")(&form);
                Ok(json_response(status, &body))
            }
            "/oauth2/revoke" => Ok(json_response(200, &json!({}))),
            other => Err(format!("unexpected path {other}").into()),
        }
    }
}
