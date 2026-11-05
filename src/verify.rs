use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use url::Url;

use crate::claims::{AccessClaims, IdClaims};
use crate::config::{ClientId, ConfigError, Scope, check_url};
use crate::http_client::BoxError;
use crate::pool::UserPool;
#[cfg(feature = "registration")]
use crate::registration::Registrar;

const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// Why a token was not accepted.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// The request has no `Authorization: Bearer` header.
    #[error("no bearer token")]
    Missing,
    /// Not a JWT, no key id, or claims of the wrong shape (including a
    /// custom attribute type that doesn't match).
    #[error("the token is not a well-formed Cognito JWT")]
    Malformed,
    /// Signed with something other than RS256, such as `none` or HS256.
    #[error("the token is not signed with RS256")]
    Algorithm,
    /// The pool doesn't publish the token's key, even after a refetch.
    #[error("the token is signed with a key the pool doesn't publish")]
    UnknownKey,
    /// The signature doesn't match the token.
    #[error("the token's signature is invalid")]
    Signature,
    /// Expired, beyond the leeway.
    #[error("the token has expired")]
    Expired,
    /// Issued by another pool, or by something that isn't Cognito.
    #[error("the token is from another issuer")]
    Issuer,
    /// An ID token where an access token belongs, or the reverse.
    #[error("the token is the wrong kind: an ID token where an access token belongs, or the reverse")]
    TokenUse,
    /// `aud` is missing or names another resource or client.
    #[error("the token is for another audience")]
    Audience,
    /// Issued to an app client the verifier doesn't accept.
    #[error("the token was issued to an app client this service doesn't accept")]
    Client,
    /// The token lacks a required scope. Answered with 403.
    #[error("the token lacks the scope {0}")]
    Scope(Scope),
    /// The pool's keys could not be fetched. Answered with 503.
    #[error("the pool's signing keys could not be fetched")]
    KeysUnavailable(#[source] Arc<BoxError>),
    /// The registrar's store could not be read to check the token's app
    /// client. Answered with 503.
    #[error("the registered clients could not be read")]
    RegistryUnavailable(#[source] Arc<BoxError>),
}

impl Rejection {
    /// 401 for a missing or invalid token, 403 for a missing scope, and 503
    /// when the keys can't be fetched, which is not the client's fault.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Scope(_) => StatusCode::FORBIDDEN,
            Self::KeysUnavailable(_) | Self::RegistryUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    /// The RFC 6750 error code, if the response gets one.
    fn code(&self) -> Option<&'static str> {
        match self {
            Self::Missing | Self::KeysUnavailable(_) | Self::RegistryUnavailable(_) => None,
            Self::Scope(_) => Some("insufficient_scope"),
            _ => Some("invalid_token"),
        }
    }
}

/// A refused request, ready to send: the status, a `WWW-Authenticate`
/// challenge and a small JSON body.
#[derive(Debug)]
pub struct Challenge {
    rejection: Rejection,
    www_authenticate: Option<HeaderValue>,
}

impl Challenge {
    /// Why the request was refused, for logs.
    pub fn rejection(&self) -> &Rejection {
        &self.rejection
    }

    /// The response to send.
    pub fn response(self) -> http::Response<String> {
        let fallback = match self.rejection {
            Rejection::KeysUnavailable(_) | Rejection::RegistryUnavailable(_) => "temporarily_unavailable",
            _ => "unauthorized",
        };
        let body = serde_json::json!({
            "error": self.rejection.code().unwrap_or(fallback),
            "error_description": self.rejection.to_string(),
        });
        let mut response = http::Response::new(body.to_string());
        *response.status_mut() = self.rejection.status();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(value) = self.www_authenticate {
            headers.insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

/// The token from an `Authorization: Bearer` header. The scheme is
/// case-insensitive (RFC 9110 section 11.1).
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

fn base64url(segment: &str) -> Result<Vec<u8>, Rejection> {
    URL_SAFE_NO_PAD.decode(segment).map_err(|_| Rejection::Malformed)
}

/// `aud` is a string or an array of strings (RFC 7519 section 4.1.3).
fn has_audience(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(aud)) => aud == expected,
        Some(Value::Array(auds)) => {
            auds.iter().all(Value::is_string) && auds.iter().any(|aud| aud.as_str() == Some(expected))
        }
        _ => false,
    }
}

/// Verifies a token's signature, issuer, expiry and kind, and its audience
/// when `audience` is set, and returns its claims.
async fn decode(
    pool: &UserPool,
    token: &str,
    token_use: &str,
    audience: Option<&str>,
    leeway: Duration,
) -> Result<Map<String, Value>, Rejection> {
    // A fourth segment leaves a '.' in the payload, which base64url refuses.
    let (signed, signature) = token.rsplit_once('.').ok_or(Rejection::Malformed)?;
    let (header, payload) = signed.split_once('.').ok_or(Rejection::Malformed)?;
    let header: Map<String, Value> =
        serde_json::from_slice(&base64url(header)?).map_err(|_| Rejection::Malformed)?;
    let payload = base64url(payload)?;
    let signature = base64url(signature)?;
    match header.get("alg").and_then(Value::as_str) {
        Some("RS256") => {}
        Some(_) => return Err(Rejection::Algorithm),
        None => return Err(Rejection::Malformed),
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(Rejection::Malformed)?;
    let key = pool.keys().key(kid).await?;
    key.verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &signature)
        .map_err(|_| Rejection::Signature)?;
    let claims: Map<String, Value> = serde_json::from_slice(&payload).map_err(|_| Rejection::Malformed)?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(Rejection::Malformed)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    if exp.saturating_add(leeway.as_secs()) < now.as_secs() {
        return Err(Rejection::Expired);
    }
    if claims.get("iss").and_then(Value::as_str) != Some(pool.issuer()) {
        return Err(Rejection::Issuer);
    }
    if let Some(audience) = audience
        && !has_audience(claims.get("aud"), audience)
    {
        return Err(Rejection::Audience);
    }
    // Checked before the claims' shape, so an ID token sent as an access
    // token is refused as the wrong kind rather than as malformed.
    if claims.get("token_use").and_then(Value::as_str) != Some(token_use) {
        return Err(Rejection::TokenUse);
    }
    Ok(claims)
}

fn typed<T: DeserializeOwned>(claims: Map<String, Value>) -> Result<T, Rejection> {
    serde_json::from_value(Value::Object(claims)).map_err(|_| Rejection::Malformed)
}

/// Verifies access tokens for one service.
///
/// Cheap to clone: clones share the pool's key cache.
#[derive(Clone)]
pub struct AccessTokenVerifier {
    pool: UserPool,
    clients: Arc<BTreeSet<ClientId>>,
    scopes: Arc<[Scope]>,
    audience: Audience,
    leeway: Duration,
    #[cfg(feature = "registration")]
    registrar: Option<Registrar>,
}

#[derive(Clone)]
enum Audience {
    Unchecked,
    Exact(Url),
    Resource(Url),
}

impl Audience {
    fn url(&self) -> Option<&Url> {
        match self {
            Self::Unchecked => None,
            Self::Exact(url) | Self::Resource(url) => Some(url),
        }
    }
}

/// Settings for an [`AccessTokenVerifier`]; from [`UserPool::access_tokens`].
///
/// # Examples
///
/// ```
/// use cognito_kit::{AccessTokenVerifier, ConfigError, UserPool};
///
/// fn verifier(pool: &UserPool) -> Result<AccessTokenVerifier, ConfigError> {
///     pool.access_tokens()
///         .clients(["1example23456789".parse()?, "2example23456789".parse()?])
///         .scope("https://api.example.com/read".parse()?)
///         .build()
/// }
/// ```
#[must_use]
pub struct AccessTokenVerifierBuilder {
    pool: UserPool,
    clients: BTreeSet<ClientId>,
    scopes: Vec<Scope>,
    audience: Audience,
    leeway: Duration,
    #[cfg(feature = "registration")]
    registrar: Option<Registrar>,
}

impl AccessTokenVerifierBuilder {
    pub(crate) fn new(pool: UserPool) -> Self {
        Self {
            pool,
            clients: BTreeSet::new(),
            scopes: Vec::new(),
            audience: Audience::Unchecked,
            leeway: DEFAULT_LEEWAY,
            #[cfg(feature = "registration")]
            registrar: None,
        }
    }

    /// Accepts tokens issued to the app clients of the registrar's
    /// registrations too, and lets an [`OAuthFront`](crate::OAuthFront)
    /// built from this verifier register clients. With a registrar, no
    /// other app client is required.
    #[cfg(feature = "registration")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registration")))]
    pub fn registrar(mut self, registrar: Registrar) -> Self {
        self.registrar = Some(registrar);
        self
    }

    /// Accepts tokens issued to this app client. At least one is required,
    /// unless the verifier has a registrar.
    pub fn client(mut self, client: ClientId) -> Self {
        self.clients.insert(client);
        self
    }

    /// Accepts tokens issued to each of these app clients.
    pub fn clients(mut self, clients: impl IntoIterator<Item = ClientId>) -> Self {
        self.clients.extend(clients);
        self
    }

    /// Requires this scope on every token. A token without it gets a 403.
    pub fn scope(mut self, scope: Scope) -> Self {
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
        }
        self
    }

    /// Requires `aud` to equal this URL. Cognito sets `aud` on an access
    /// token when the client sent this URL as the RFC 8707 `resource`
    /// parameter; tokens without `aud` are then refused.
    pub fn audience(mut self, audience: Url) -> Self {
        self.audience = Audience::Exact(audience);
        self
    }

    /// Protects an RFC 9728 resource, such as an MCP server's URL: like
    /// [`audience`](Self::audience), and challenges carry `resource_metadata`
    /// pointing at the resource's metadata document, which
    /// [`OAuthFront`](crate::OAuthFront) serves.
    pub fn resource(mut self, resource: Url) -> Self {
        self.audience = Audience::Resource(resource);
        self
    }

    /// How long after `exp` a token is still accepted, for clock skew.
    /// Defaults to 60 seconds.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The verifier, once the settings are checked.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::NoClients`] without an app client or a registrar.
    /// - [`ConfigError::Url`] if the audience or resource is neither https
    ///   nor http on localhost, or has a fragment.
    pub fn build(self) -> Result<AccessTokenVerifier, ConfigError> {
        #[cfg(feature = "registration")]
        let registered = self.registrar.is_some();
        #[cfg(not(feature = "registration"))]
        let registered = false;
        if self.clients.is_empty() && !registered {
            return Err(ConfigError::NoClients);
        }
        if let Some(audience) = self.audience.url() {
            check_url(audience)?;
        }
        Ok(AccessTokenVerifier {
            pool: self.pool,
            clients: Arc::new(self.clients),
            scopes: self.scopes.into(),
            audience: self.audience,
            leeway: self.leeway,
            #[cfg(feature = "registration")]
            registrar: self.registrar,
        })
    }
}

impl AccessTokenVerifier {
    /// Verifies an access token: its signature against the pool's keys, its
    /// issuer, expiry, kind, app client, audience and scopes.
    ///
    /// The first check fetches the pool's keys. A token signed with a key
    /// the cache doesn't know triggers a refetch, at most once per
    /// [cooldown](UserPool::refetch_cooldown).
    ///
    /// # Errors
    ///
    /// The [`Rejection`] for the first check that fails.
    /// [`Rejection::status`] turns it into 401, 403 or 503.
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<AccessClaims<C>, Rejection> {
        let audience = self.audience.url().map(canonical);
        let claims = decode(&self.pool, token, "access", audience.as_deref(), self.leeway).await?;
        let client = claims
            .get("client_id")
            .and_then(Value::as_str)
            .and_then(|c| c.parse::<ClientId>().ok())
            .ok_or(Rejection::Malformed)?;
        // Checked before the typed claims exist, so that `C` needn't be `Send`.
        if !self.accepts(&client).await? {
            return Err(Rejection::Client);
        }
        let claims: AccessClaims<C> = typed(claims)?;
        if let Some(missing) = self.scopes.iter().find(|s| !claims.scopes.contains(s)) {
            return Err(Rejection::Scope(missing.clone()));
        }
        Ok(claims)
    }

    /// Verifies the request's bearer token, or says how to refuse it.
    ///
    /// # Errors
    ///
    /// A [`Challenge`] to send back when the request has no bearer token,
    /// or [`verify`](Self::verify) refuses it.
    pub async fn authenticate<C: DeserializeOwned>(
        &self,
        headers: &HeaderMap,
    ) -> Result<AccessClaims<C>, Challenge> {
        let token = bearer(headers)
            .ok_or(Rejection::Missing)
            .map_err(|r| self.challenge(r))?;
        self.verify(token).await.map_err(|r| self.challenge(r))
    }

    /// The response for a refusal. Use it for checks of your own too, such as
    /// a route that needs a further scope: `verifier.challenge(Rejection::Scope(scope))`.
    pub fn challenge(&self, rejection: Rejection) -> Challenge {
        let mut params = Vec::new();
        if let Some(code) = rejection.code() {
            params.push(format!("error=\"{code}\""));
        }
        match &rejection {
            Rejection::Scope(scope) => {
                params.push(format!("scope=\"{}\"", scope_list(&self.scopes, Some(scope))))
            }
            _ if !self.scopes.is_empty() => {
                params.push(format!("scope=\"{}\"", scope_list(&self.scopes, None)))
            }
            _ => {}
        }
        if let Some(resource) = self.resource() {
            params.push(format!("resource_metadata=\"{}\"", metadata_url(resource)));
        }
        let value = if params.is_empty() {
            "Bearer".to_owned()
        } else {
            format!("Bearer {}", params.join(", "))
        };
        let www_authenticate = HeaderValue::try_from(value).ok().filter(|_| {
            !matches!(
                rejection,
                Rejection::KeysUnavailable(_) | Rejection::RegistryUnavailable(_)
            )
        });
        Challenge {
            rejection,
            www_authenticate,
        }
    }

    async fn accepts(&self, client: &ClientId) -> Result<bool, Rejection> {
        if self.clients.contains(client) {
            return Ok(true);
        }
        #[cfg(feature = "registration")]
        if let Some(registrar) = &self.registrar {
            return registrar
                .knows(client)
                .await
                .map_err(|e| Rejection::RegistryUnavailable(Arc::new(e)));
        }
        Ok(false)
    }

    #[cfg(feature = "registration")]
    pub(crate) fn registrar(&self) -> Option<&Registrar> {
        self.registrar.as_ref()
    }

    #[cfg(feature = "registration")]
    pub(crate) fn pool(&self) -> &UserPool {
        &self.pool
    }

    pub(crate) fn resource(&self) -> Option<&Url> {
        match &self.audience {
            Audience::Resource(url) => Some(url),
            _ => None,
        }
    }

    pub(crate) fn scopes(&self) -> &[Scope] {
        &self.scopes
    }
}

/// The form `aud` takes: the URL as written, without the trailing slash
/// that URL parsing adds to a bare origin (MCP's canonical server URI).
pub(crate) fn canonical(url: &Url) -> String {
    let s = url.as_str();
    if url.path() == "/" && url.query().is_none() {
        s.trim_end_matches('/').to_owned()
    } else {
        s.to_owned()
    }
}

/// RFC 9728 section 3.1: the well-known path goes between the host and the
/// resource's path.
pub(crate) fn metadata_url(resource: &Url) -> Url {
    let mut url = resource.clone();
    url.set_query(None);
    url.set_path(&format!(
        "/.well-known/oauth-protected-resource{}",
        resource.path().trim_end_matches('/')
    ));
    url
}

/// The scopes a challenge asks for: the required ones, and a further one a
/// route asked for.
fn scope_list(required: &[Scope], extra: Option<&Scope>) -> String {
    let mut scopes: Vec<&str> = required.iter().map(Scope::as_str).collect();
    if let Some(extra) = extra.filter(|s| !required.contains(s)) {
        scopes.push(extra.as_str());
    }
    scopes.join(" ")
}

/// Verifies ID tokens issued to one app client.
#[derive(Clone)]
pub struct IdTokenVerifier {
    pool: UserPool,
    client: ClientId,
    leeway: Duration,
}

impl IdTokenVerifier {
    pub(crate) fn new(pool: UserPool, client: ClientId) -> Self {
        Self {
            pool,
            client,
            leeway: DEFAULT_LEEWAY,
        }
    }

    /// How long after `exp` a token is still accepted. Defaults to 60 seconds.
    #[must_use]
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Verifies an ID token: its signature, issuer, expiry, kind, and that
    /// its `aud` is this verifier's app client.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] for the first check that fails.
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<IdClaims<C>, Rejection> {
        typed(decode(&self.pool, token, "id", Some(self.client.as_str()), self.leeway).await?)
    }
}
