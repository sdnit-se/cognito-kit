//! A fake Cognito for your own tests: a user pool with a key set, tokens
//! signed with its key, and managed login's authorize and token endpoints.
//! With the `registration` feature it also keeps app clients for a
//! [`Registrar`](crate::registration::Registrar), and [`MemoryStore`] keeps
//! registrations.
//!
//! ```
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use cognito_kit::test_kit::FakeCognito;
//!
//! let cognito = FakeCognito::new();
//! let client = cognito.add_client("assistant", &["https://app.example.com/callback"]);
//! let verifier = cognito.pool().access_tokens().client(client.clone()).build()?;
//!
//! let token = cognito.access_token(&client, None, "openid");
//! let claims: cognito_kit::AccessClaims = verifier.verify(&token).await?;
//! assert_eq!(claims.client_id, client);
//! # Ok(()) }
//! # tokio::runtime::Runtime::new().unwrap().block_on(run()).unwrap();
//! ```
//!
//! The signing key is fixed and public: it is in this crate's source. Only a
//! [`UserPool`] that fetches keys through [`FakeCognito`] trusts it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::rsa::PublicKeyComponents;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Value, json};
use url::Url;
use url::form_urlencoded;

use crate::config::{ClientId, LoginDomain, PoolId};
use crate::http_client::{BoxError, HttpClient};
use crate::pool::UserPool;

const KID: &str = "test-kit-1";
/// Cognito's limit of callback URLs per app client.
const MAX_CALLBACKS: usize = 100;

/// An app client in the fake pool.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FakeAppClient {
    /// Its id.
    pub id: ClientId,
    /// Its name.
    pub name: String,
    /// Its callback URLs, matched exactly, as Cognito does.
    pub callback_urls: Vec<String>,
    /// When it was created.
    pub created: SystemTime,
}

#[derive(Clone)]
struct Grant {
    client: ClientId,
    redirect_uri: String,
    challenge: Option<String>,
    nonce: Option<String>,
    resource: Option<String>,
    scope: String,
    sub: String,
}

struct State {
    pool: PoolId,
    issuer: String,
    login: LoginDomain,
    key: RsaKeyPair,
    jwk: Value,
    clients: Mutex<BTreeMap<ClientId, FakeAppClient>>,
    codes: Mutex<BTreeMap<String, Grant>>,
    refresh_tokens: Mutex<BTreeMap<String, Grant>>,
    limit: Mutex<Option<usize>>,
    serial: AtomicU64,
}

/// A user pool, its managed login and its app clients, in memory.
///
/// Cheap to clone; clones share the pool. Give [`pool`](Self::pool) to the
/// code under test, sign tokens with [`access_token`](Self::access_token)
/// or [`sign`](Self::sign), and play a person signing in with
/// [`sign_in`](Self::sign_in).
///
/// [The testing chapter](crate::guide::testing) has more examples.
///
/// # Examples
///
/// ```
/// use cognito_kit::test_kit::FakeCognito;
/// use cognito_kit::{AccessClaims, Rejection};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let cognito = FakeCognito::new();
/// let api = cognito.add_client("api", &["https://app.example.com/callback"]);
/// let other = cognito.add_client("other", &["https://other.example.com/callback"]);
/// let verifier = cognito.pool().access_tokens().client(api.clone()).build()?;
///
/// let claims: AccessClaims = verifier.verify(&cognito.access_token(&api, None, "openid")).await?;
/// assert_eq!(claims.client_id, api);
///
/// let refused = verifier.verify::<()>(&cognito.access_token(&other, None, "openid")).await;
/// assert!(matches!(refused, Err(Rejection::Client)));
/// # Ok(()) }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run()).unwrap();
/// ```
#[derive(Clone)]
pub struct FakeCognito(Arc<State>);

impl Default for FakeCognito {
    fn default() -> Self {
        Self::new()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_response(status: u16, body: &Value) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into_bytes())
        .expect("a valid response")
}

fn oauth_error(error: &str) -> http::Response<Vec<u8>> {
    json_response(400, &json!({ "error": error }))
}

impl FakeCognito {
    /// A pool named `eu-north-1_TestKit`, with managed login at
    /// `https://login.test-kit.example`.
    pub fn new() -> Self {
        let key = RsaKeyPair::from_pkcs8(include_bytes!("key.der")).expect("the test key parses");
        let public = PublicKeyComponents::<Vec<u8>>::from(key.public());
        let jwk = json!({
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(&public.n), "e": URL_SAFE_NO_PAD.encode(&public.e),
        });
        let pool: PoolId = "eu-north-1_TestKit".parse().expect("a pool id");
        Self(Arc::new(State {
            issuer: format!("https://cognito-idp.eu-north-1.amazonaws.com/{pool}"),
            pool,
            login: "https://login.test-kit.example".parse().expect("a login domain"),
            key,
            jwk,
            clients: Mutex::default(),
            codes: Mutex::default(),
            refresh_tokens: Mutex::default(),
            limit: Mutex::default(),
            serial: AtomicU64::new(1),
        }))
    }

    /// The pool, fetching its keys and calling its token endpoint through
    /// this fake.
    pub fn pool(&self) -> UserPool {
        UserPool::with_http_client(self.0.pool.clone(), self.clone())
    }

    /// Managed login's origin.
    pub fn login_domain(&self) -> LoginDomain {
        self.0.login.clone()
    }

    /// The `iss` of every token.
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }

    /// Signs `claims` as a JWT with the pool's key, whatever they say.
    pub fn sign(&self, claims: &Value) -> String {
        let header = json!({ "alg": "RS256", "kid": KID, "typ": "JWT" });
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.0.key.public().modulus_len()];
        self.0
            .key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .expect("signing works");
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// An access token as Cognito issues it to `client`: valid for an hour,
    /// with `aud` when the client sent an RFC 8707 `resource`, and the
    /// space-separated `scope`.
    pub fn access_token(&self, client: &ClientId, audience: Option<&str>, scope: &str) -> String {
        self.sign(&self.access_claims(client, audience, scope, "6f1c2e7a-0000-4000-8000-000000000001"))
    }

    fn access_claims(&self, client: &ClientId, audience: Option<&str>, scope: &str, sub: &str) -> Value {
        let mut claims = json!({
            "sub": sub, "iss": self.0.issuer, "version": 2, "client_id": client.as_str(),
            "token_use": "access", "scope": scope, "auth_time": now(), "iat": now(),
            "exp": now() + 3600, "jti": self.random(), "username": sub,
        });
        if let Some(audience) = audience {
            claims["aud"] = json!(audience);
        }
        claims
    }

    /// Adds an app client, as you would with OpenTofu.
    ///
    /// # Panics
    ///
    /// If `callback_urls` is empty or has more than Cognito's 100, or the
    /// pool is at the limit set with
    /// [`limit_app_clients`](Self::limit_app_clients).
    pub fn add_client(&self, name: &str, callback_urls: &[&str]) -> ClientId {
        let urls: Vec<String> = callback_urls.iter().map(|u| (*u).to_owned()).collect();
        self.create_client(name, &urls)
            .unwrap_or_else(|error| panic!("the fake Cognito refused the app client: {error}"))
    }

    /// The pool's app clients.
    pub fn app_clients(&self) -> Vec<FakeAppClient> {
        self.0.clients.lock().unwrap().values().cloned().collect()
    }

    /// Refuses to create app clients beyond `limit`, as Cognito does at its
    /// quota of 1,000 per pool.
    pub fn limit_app_clients(&self, limit: usize) {
        *self.0.limit.lock().unwrap() = Some(limit);
    }

    fn random(&self) -> String {
        let serial = self.0.serial.fetch_add(1, Ordering::SeqCst);
        let digest = digest(&SHA256, &serial.to_be_bytes());
        digest.as_ref()[..13].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn create_client(&self, name: &str, callback_urls: &[String]) -> Result<ClientId, &'static str> {
        let mut clients = self.0.clients.lock().unwrap();
        if self
            .0
            .limit
            .lock()
            .unwrap()
            .is_some_and(|limit| clients.len() >= limit)
        {
            return Err("LimitExceededException");
        }
        if callback_urls.is_empty() {
            return Err("InvalidOAuthFlowException");
        }
        if callback_urls.len() > MAX_CALLBACKS {
            return Err("InvalidParameterException");
        }
        let id: ClientId = self.random().parse().expect("an app client id");
        clients.insert(
            id.clone(),
            FakeAppClient {
                id: id.clone(),
                name: name.to_owned(),
                callback_urls: callback_urls.to_vec(),
                created: SystemTime::now(),
            },
        );
        Ok(id)
    }

    /// Plays a person who signs in as `sub` at the managed login URL a
    /// client was sent to, and returns where managed login sends the browser
    /// next: the client's redirect URI with a code and the state. Refuses as
    /// Cognito does: an unknown client, or a redirect URI that isn't one of
    /// the app client's callback URLs exactly.
    ///
    /// The ID token that the code redeems for carries the authorization
    /// request's nonce, as Cognito's does, so
    /// [`ManagedLogin::callback`](crate::ManagedLogin::callback) completes the
    /// sign-in.
    ///
    /// # Errors
    ///
    /// Cognito's error code, or a description, when `authorize` isn't this
    /// pool's authorize endpoint, names an unknown app client, or has a
    /// `redirect_uri`, `response_type` or `code_challenge_method` that
    /// Cognito would refuse.
    pub fn sign_in(&self, authorize: &Url, sub: &str) -> Result<Url, String> {
        if authorize.origin() != self.0.login.url().origin() || authorize.path() != "/oauth2/authorize" {
            return Err(format!("{authorize} is not this pool's authorize endpoint"));
        }
        let query: BTreeMap<String, String> = authorize.query_pairs().into_owned().collect();
        let param = |name: &str| query.get(name).cloned();
        let client: ClientId = param("client_id")
            .and_then(|c| c.parse().ok())
            .ok_or("no client_id")?;
        let redirect_uri = param("redirect_uri").ok_or("no redirect_uri")?;
        let known = self.0.clients.lock().unwrap().get(&client).cloned();
        let known = known.ok_or_else(|| format!("client {client} not found"))?;
        if !known.callback_urls.contains(&redirect_uri) {
            return Err("redirect_mismatch".into());
        }
        if param("response_type").as_deref() != Some("code") {
            return Err("unsupported_response_type".into());
        }
        let challenge = param("code_challenge");
        if challenge.is_some() && param("code_challenge_method").as_deref() != Some("S256") {
            return Err("invalid_request: only S256".into());
        }
        let code = self.random();
        let grant = Grant {
            client,
            redirect_uri: redirect_uri.clone(),
            challenge,
            nonce: param("nonce"),
            resource: param("resource"),
            scope: param("scope").unwrap_or_default(),
            sub: sub.to_owned(),
        };
        self.0.codes.lock().unwrap().insert(code.clone(), grant);
        let mut back = Url::parse(&redirect_uri).map_err(|e| e.to_string())?;
        back.query_pairs_mut().append_pair("code", &code);
        if let Some(state) = param("state") {
            back.query_pairs_mut().append_pair("state", &state);
        }
        Ok(back)
    }

    fn token(&self, form: &BTreeMap<String, String>) -> http::Response<Vec<u8>> {
        let param = |name: &str| form.get(name).map(String::as_str);
        let Some(client) = param("client_id").and_then(|c| c.parse::<ClientId>().ok()) else {
            return oauth_error("invalid_request");
        };
        if !self.0.clients.lock().unwrap().contains_key(&client) {
            return oauth_error("invalid_client");
        }
        // Only the ID token a code redeems for carries the nonce.
        let (grant, nonce) = match param("grant_type") {
            Some("authorization_code") => {
                let grant = param("code").and_then(|c| self.0.codes.lock().unwrap().remove(c));
                let Some(grant) = grant.filter(|g| g.client == client) else {
                    return oauth_error("invalid_grant");
                };
                if param("redirect_uri") != Some(grant.redirect_uri.as_str()) {
                    return oauth_error("invalid_grant");
                }
                if let Some(challenge) = &grant.challenge {
                    let verifier = param("code_verifier").unwrap_or_default();
                    if URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes())) != *challenge {
                        return oauth_error("invalid_grant");
                    }
                }
                let nonce = grant.nonce.clone();
                (grant, nonce)
            }
            // Rotation: each refresh token works once.
            Some("refresh_token") => {
                let grant =
                    param("refresh_token").and_then(|t| self.0.refresh_tokens.lock().unwrap().remove(t));
                match grant.filter(|g| g.client == client) {
                    Some(grant) => (grant, None),
                    None => return oauth_error("invalid_grant"),
                }
            }
            _ => return oauth_error("unsupported_grant_type"),
        };
        let refresh_token = self.random();
        self.0
            .refresh_tokens
            .lock()
            .unwrap()
            .insert(refresh_token.clone(), grant.clone());
        let access = self.access_claims(&grant.client, grant.resource.as_deref(), &grant.scope, &grant.sub);
        let mut body = json!({
            "access_token": self.sign(&access), "refresh_token": refresh_token,
            "token_type": "Bearer", "expires_in": 3600,
        });
        if grant.scope.split(' ').any(|s| s == "openid") {
            let mut id = json!({
                "sub": grant.sub, "iss": self.0.issuer, "aud": grant.client.as_str(), "token_use": "id",
                "cognito:username": grant.sub, "auth_time": now(), "iat": now(), "exp": now() + 3600,
            });
            if let Some(nonce) = nonce {
                id["nonce"] = json!(nonce);
            }
            body["id_token"] = json!(self.sign(&id));
        }
        json_response(200, &body)
    }
}

impl HttpClient for FakeCognito {
    async fn send(&self, request: http::Request<Vec<u8>>) -> Result<http::Response<Vec<u8>>, BoxError> {
        let url = request.uri().to_string();
        if url == format!("{}/.well-known/jwks.json", self.0.issuer) {
            return Ok(json_response(200, &json!({ "keys": [self.0.jwk] })));
        }
        let path = url
            .strip_prefix(self.0.login.url().as_str().trim_end_matches('/'))
            .ok_or_else(|| format!("the fake Cognito has nothing at {url}"))?;
        let form: BTreeMap<String, String> = form_urlencoded::parse(request.body()).into_owned().collect();
        match (request.method(), path) {
            (&http::Method::POST, "/oauth2/token") => Ok(self.token(&form)),
            (&http::Method::POST, "/oauth2/revoke") => {
                if let Some(token) = form.get("token") {
                    self.0.refresh_tokens.lock().unwrap().remove(token);
                }
                Ok(json_response(200, &json!({})))
            }
            _ => Err(format!("the fake Cognito has nothing at {url}").into()),
        }
    }
}

#[cfg(feature = "registration")]
mod registration {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    use super::FakeCognito;
    use crate::config::ClientId;
    use crate::http_client::BoxError;
    use crate::registration::{AdminError, AppClients, BoxFuture, Lease, Registration, RegistrationStore};

    impl AppClients for FakeCognito {
        fn create<'a>(
            &'a self,
            name: &'a str,
            callback_urls: &'a [String],
        ) -> BoxFuture<'a, Result<ClientId, AdminError>> {
            let created = self.create_client(name, callback_urls).map_err(|e| match e {
                "LimitExceededException" => AdminError::Limit,
                other => AdminError::Other(Arc::new(other.into())),
            });
            Box::pin(async move { created })
        }

        fn callback_urls<'a>(
            &'a self,
            client: &'a ClientId,
        ) -> BoxFuture<'a, Result<Vec<String>, AdminError>> {
            let found = self
                .0
                .clients
                .lock()
                .unwrap()
                .get(client)
                .map(|c| c.callback_urls.clone());
            Box::pin(async move { found.ok_or(AdminError::NotFound) })
        }

        fn set_callback_urls<'a>(
            &'a self,
            client: &'a ClientId,
            urls: &'a [String],
        ) -> BoxFuture<'a, Result<(), AdminError>> {
            let mut clients = self.0.clients.lock().unwrap();
            let result = match clients.get_mut(client) {
                Some(_) if urls.is_empty() => {
                    Err(AdminError::Other(Arc::new("InvalidOAuthFlowException".into())))
                }
                Some(_) if urls.len() > super::MAX_CALLBACKS => {
                    Err(AdminError::Other(Arc::new("InvalidParameterException".into())))
                }
                Some(found) => {
                    found.callback_urls = urls.to_vec();
                    Ok(())
                }
                None => Err(AdminError::NotFound),
            };
            Box::pin(async move { result })
        }

        fn delete<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<(), AdminError>> {
            self.0.clients.lock().unwrap().remove(client);
            Box::pin(async { Ok(()) })
        }

        fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<ClientId>, AdminError>> {
            let clients = self.0.clients.lock().unwrap();
            let found = clients
                .values()
                .filter(|c| c.name.starts_with(prefix))
                .map(|c| c.id.clone())
                .collect();
            Box::pin(async move { Ok(found) })
        }

        fn created<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<SystemTime, AdminError>> {
            let created = self.0.clients.lock().unwrap().get(client).map(|c| c.created);
            Box::pin(async move { created.ok_or(AdminError::NotFound) })
        }
    }

    impl FakeCognito {
        /// Moves an app client's creation time `by` into the past, to test
        /// cleanup.
        pub fn age_app_client(&self, client: &ClientId, by: std::time::Duration) {
            if let Some(found) = self.0.clients.lock().unwrap().get_mut(client) {
                found.created -= by;
            }
        }
    }

    /// A [`RegistrationStore`] in memory, for tests and single-process
    /// experiments. Its registrations are gone when the process ends, and
    /// their app clients stay behind.
    ///
    /// # Examples
    ///
    /// ```
    /// use cognito_kit::registration::Registrar;
    /// use cognito_kit::test_kit::{FakeCognito, MemoryStore};
    ///
    /// let cognito = FakeCognito::new();
    /// let store = MemoryStore::new();
    /// let registrar = Registrar::builder(cognito.clone(), store.clone())
    ///     .dynamic_registration()
    ///     .build()?;
    /// assert!(store.registrations().is_empty());
    /// # Ok::<(), cognito_kit::ConfigError>(())
    /// ```
    #[derive(Clone, Default)]
    pub struct MemoryStore(Arc<Mutex<Memory>>);

    #[derive(Default)]
    struct Memory {
        registrations: BTreeMap<String, Registration>,
        leases: BTreeMap<String, Lease>,
    }

    impl MemoryStore {
        /// An empty store.
        pub fn new() -> Self {
            Self::default()
        }

        /// Every registration, for assertions.
        pub fn registrations(&self) -> Vec<Registration> {
            self.0.lock().unwrap().registrations.values().cloned().collect()
        }

        /// Changes a stored registration, for tests that need one in a given
        /// state, such as long unused. `change` runs with the store locked,
        /// so it must not use the store.
        pub fn edit(&self, client_id: &str, change: impl FnOnce(&mut Registration)) {
            if let Some(registration) = self.0.lock().unwrap().registrations.get_mut(client_id) {
                change(registration);
            }
        }
    }

    fn ready<T: Send + 'static>(value: T) -> BoxFuture<'static, T> {
        Box::pin(async move { value })
    }

    impl RegistrationStore for MemoryStore {
        fn get<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
            ready(Ok(self.0.lock().unwrap().registrations.get(client_id).cloned()))
        }

        fn get_by_app_client<'a>(
            &'a self,
            app_client: &'a ClientId,
        ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
            let found = self
                .0
                .lock()
                .unwrap()
                .registrations
                .values()
                .find(|r| r.app_client == *app_client)
                .cloned();
            ready(Ok(found))
        }

        fn insert(&self, registration: Registration) -> BoxFuture<'_, Result<Registration, BoxError>> {
            let mut memory = self.0.lock().unwrap();
            let stored = memory
                .registrations
                .entry(registration.client_id.clone())
                .or_insert(registration)
                .clone();
            ready(Ok(stored))
        }

        fn lease<'a>(
            &'a self,
            client_id: &'a str,
            lease: &'a Lease,
            now: u64,
        ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>> {
            let mut memory = self.0.lock().unwrap();
            let free = memory.leases.get(client_id).is_none_or(|held| held.until <= now);
            let leased = memory.registrations.get(client_id).filter(|_| free).cloned();
            if leased.is_some() {
                memory.leases.insert(client_id.to_owned(), lease.clone());
            }
            ready(Ok(leased))
        }

        fn update<'a>(
            &'a self,
            registration: &'a Registration,
            lease: &'a Lease,
        ) -> BoxFuture<'a, Result<bool, BoxError>> {
            let mut memory = self.0.lock().unwrap();
            let holds = memory
                .leases
                .get(&registration.client_id)
                .is_some_and(|held| held.owner == lease.owner);
            let stored = memory
                .registrations
                .get_mut(&registration.client_id)
                .filter(|_| holds);
            let updated = stored.is_some();
            if let Some(stored) = stored {
                stored.redirect_uris = registration.redirect_uris.clone();
                stored.client_name = registration.client_name.clone();
                stored.fetched_at = registration.fetched_at;
            }
            ready(Ok(updated))
        }

        fn release<'a>(
            &'a self,
            client_id: &'a str,
            lease: &'a Lease,
        ) -> BoxFuture<'a, Result<(), BoxError>> {
            let mut memory = self.0.lock().unwrap();
            if memory
                .leases
                .get(client_id)
                .is_some_and(|held| held.owner == lease.owner)
            {
                memory.leases.remove(client_id);
            }
            ready(Ok(()))
        }

        fn touch<'a>(&'a self, client_id: &'a str, at: u64) -> BoxFuture<'a, Result<(), BoxError>> {
            if let Some(stored) = self.0.lock().unwrap().registrations.get_mut(client_id) {
                stored.last_used = Some(at);
            }
            ready(Ok(()))
        }

        fn remove<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>> {
            let mut memory = self.0.lock().unwrap();
            if memory
                .registrations
                .get(&registration.client_id)
                .is_some_and(|r| r.app_client == registration.app_client)
            {
                memory.registrations.remove(&registration.client_id);
                memory.leases.remove(&registration.client_id);
            }
            ready(Ok(()))
        }

        fn list(&self) -> BoxFuture<'_, Result<Vec<Registration>, BoxError>> {
            ready(Ok(self.registrations()))
        }
    }
}

#[cfg(feature = "registration")]
pub use registration::MemoryStore;
