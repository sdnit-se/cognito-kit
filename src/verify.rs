use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderValue, StatusCode, header};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use url::Url;

use crate::claims::{AccessClaims, IdClaims};
use crate::config::{ClientId, ConfigError, Scope, check_url};
use crate::http_client::BoxError;
use crate::pool::UserPool;

const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// Why a token was not accepted.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    #[error("no bearer token")]
    Missing,
    #[error("the token is not a well-formed Cognito JWT")]
    Malformed,
    #[error("the token is not signed with RS256")]
    Algorithm,
    #[error("the token is signed with a key the pool doesn't publish")]
    UnknownKey,
    #[error("the token's signature is invalid")]
    Signature,
    #[error("the token has expired")]
    Expired,
    #[error("the token is from another issuer")]
    Issuer,
    #[error("the token is the wrong kind: an ID token where an access token belongs, or the reverse")]
    TokenUse,
    #[error("the token is for another audience")]
    Audience,
    #[error("the token was issued to an app client this service doesn't accept")]
    Client,
    #[error("the token lacks the scope {0}")]
    Scope(Scope),
    #[error("the pool's signing keys could not be fetched")]
    KeysUnavailable(#[source] Arc<BoxError>),
}

impl Rejection {
    /// 401 for a missing or invalid token, 403 for a missing scope, and 503
    /// when the keys can't be fetched, which is not the client's fault.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Scope(_) => StatusCode::FORBIDDEN,
            Self::KeysUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    /// The RFC 6750 error code, if the response gets one.
    fn code(&self) -> Option<&'static str> {
        match self {
            Self::Missing | Self::KeysUnavailable(_) => None,
            Self::Scope(_) => Some("insufficient_scope"),
            _ => Some("invalid_token"),
        }
    }
}

fn rejection(error: &jsonwebtoken::errors::Error) -> Rejection {
    match error.kind() {
        ErrorKind::InvalidSignature => Rejection::Signature,
        ErrorKind::ExpiredSignature => Rejection::Expired,
        ErrorKind::InvalidIssuer => Rejection::Issuer,
        ErrorKind::InvalidAudience => Rejection::Audience,
        ErrorKind::InvalidAlgorithm => Rejection::Algorithm,
        ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => Rejection::Issuer,
        ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => Rejection::Audience,
        _ => Rejection::Malformed,
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
    pub fn rejection(&self) -> &Rejection {
        &self.rejection
    }

    pub fn response(self) -> http::Response<String> {
        let body = serde_json::json!({
            "error": self.rejection.code().unwrap_or("unauthorized"),
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

/// Verifies a token's signature, issuer, expiry and kind, and its audience
/// when `audience` is set, then reads its claims.
async fn decode<T: DeserializeOwned>(
    pool: &UserPool,
    token: &str,
    token_use: &str,
    audience: Option<&str>,
    leeway: Duration,
) -> Result<T, Rejection> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| Rejection::Malformed)?;
    if header.alg != Algorithm::RS256 {
        return Err(Rejection::Algorithm);
    }
    let kid = header.kid.ok_or(Rejection::Malformed)?;
    let key = pool.keys().key(&kid).await?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = leeway.as_secs();
    validation.set_issuer(&[pool.issuer()]);
    match audience {
        Some(aud) => {
            validation.set_audience(&[aud]);
            validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        }
        None => {
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["exp", "iss"]);
        }
    }
    let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| rejection(&e))?
        .claims;
    // Checked before the claims' shape, so an ID token sent as an access
    // token is refused as the wrong kind rather than as malformed.
    if claims.get("token_use").and_then(Value::as_str) != Some(token_use) {
        return Err(Rejection::TokenUse);
    }
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
#[must_use]
pub struct AccessTokenVerifierBuilder {
    pool: UserPool,
    clients: BTreeSet<ClientId>,
    scopes: Vec<Scope>,
    audience: Audience,
    leeway: Duration,
}

impl AccessTokenVerifierBuilder {
    pub(crate) fn new(pool: UserPool) -> Self {
        Self {
            pool,
            clients: BTreeSet::new(),
            scopes: Vec::new(),
            audience: Audience::Unchecked,
            leeway: DEFAULT_LEEWAY,
        }
    }

    /// Accepts tokens issued to this app client. At least one is required.
    pub fn client(mut self, client: ClientId) -> Self {
        self.clients.insert(client);
        self
    }

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

    pub fn build(self) -> Result<AccessTokenVerifier, ConfigError> {
        if self.clients.is_empty() {
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
        })
    }
}

impl AccessTokenVerifier {
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<AccessClaims<C>, Rejection> {
        let audience = self.audience.url().map(canonical);
        let claims: AccessClaims<C> =
            decode(&self.pool, token, "access", audience.as_deref(), self.leeway).await?;
        if !self.clients.contains(&claims.client_id) {
            return Err(Rejection::Client);
        }
        if let Some(missing) = self.scopes.iter().find(|s| !claims.scopes.contains(s)) {
            return Err(Rejection::Scope(missing.clone()));
        }
        Ok(claims)
    }

    /// Verifies the request's bearer token, or says how to refuse it.
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
        let www_authenticate = HeaderValue::try_from(value)
            .ok()
            .filter(|_| !matches!(rejection, Rejection::KeysUnavailable(_)));
        Challenge {
            rejection,
            www_authenticate,
        }
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

    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<IdClaims<C>, Rejection> {
        decode(&self.pool, token, "id", Some(self.client.as_str()), self.leeway).await
    }
}
