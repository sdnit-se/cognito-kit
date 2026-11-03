use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::{HeaderValue, header};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use url::form_urlencoded;

use crate::claims::IdClaims;
use crate::config::{ClientId, ConfigError, LoginDomain, Scope, check_url};
use crate::http_client::{BoxError, Http};
use crate::pool::UserPool;
use crate::verify::{IdTokenVerifier, Rejection};

macro_rules! secret {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(secret: impl Into<String>) -> Self {
                Self(secret.into())
            }

            pub fn secret(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret!(
    /// A confidential app client's secret.
    ClientSecret
);
secret!(
    /// An access token, for calling APIs. `Debug` doesn't print it.
    AccessToken
);
secret!(
    /// An ID token. `Debug` doesn't print it.
    IdToken
);
secret!(
    /// A refresh token. With rotation on, each refresh returns a new one and
    /// the old one stops working. `Debug` doesn't print it.
    RefreshToken
);

/// What a sign-in must remember between the redirect and the callback. Keep
/// it server-side, or in an encrypted cookie: it holds the PKCE verifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingLogin {
    state: String,
    nonce: String,
    verifier: String,
}

impl fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingLogin(..)")
    }
}

/// Options for one sign-in redirect.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AuthorizeOptions {
    /// Skips managed login's own page and goes straight to this identity
    /// provider, such as `Google`.
    pub identity_provider: Option<String>,
}

impl AuthorizeOptions {
    #[must_use]
    pub fn identity_provider(mut self, name: impl Into<String>) -> Self {
        self.identity_provider = Some(name.into());
        self
    }
}

/// The tokens from a sign-in or a refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Tokens {
    pub id_token: IdToken,
    pub access_token: AccessToken,
    /// From a sign-in, if the app client allows refresh; from a refresh, if
    /// rotation is on. Keep the newest one.
    pub refresh_token: Option<RefreshToken>,
    /// How long the access and ID tokens last.
    pub expires_in: Duration,
}

/// A completed sign-in or refresh: the verified ID token's claims and the tokens.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedIn<C = ()> {
    pub claims: IdClaims<C>,
    pub tokens: Tokens,
}

/// An OAuth error response, from the callback or the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthError {
    /// The RFC 6749 code, such as `access_denied` or `invalid_grant`.
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl OAuthError {
    /// The refresh token was reused, revoked or expired, or the code was
    /// already redeemed: the user must sign in again.
    pub fn is_invalid_grant(&self) -> bool {
        self.error == "invalid_grant"
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error)?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

/// Why a sign-in, refresh or revocation failed.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// The callback's `state` isn't this sign-in's: a forged or replayed callback.
    #[error("the callback doesn't belong to this sign-in")]
    State,
    /// Managed login sent the user back with an error, such as `access_denied`.
    #[error("sign-in was refused: {0}")]
    Denied(OAuthError),
    #[error("the callback has neither a code nor an error")]
    NoCode,
    /// The token or revocation endpoint refused the request.
    #[error("the token endpoint refused: {0}")]
    Refused(OAuthError),
    #[error("Cognito could not be reached or answered unexpectedly")]
    Http(#[source] Arc<BoxError>),
    #[error("the ID token was refused: {0}")]
    IdToken(#[source] Rejection),
    /// The ID token's nonce isn't this sign-in's: a replayed token.
    #[error("the ID token's nonce doesn't match this sign-in")]
    Nonce,
}

impl LoginError {
    fn http(error: impl Into<BoxError>) -> Self {
        Self::Http(Arc::new(error.into()))
    }
}

/// Settings for [`ManagedLogin`]; from [`UserPool::managed_login`].
#[must_use]
pub struct ManagedLoginBuilder {
    pool: UserPool,
    domain: LoginDomain,
    client: ClientId,
    redirect_uri: Url,
    secret: Option<ClientSecret>,
    scopes: Vec<Scope>,
}

impl ManagedLoginBuilder {
    pub(crate) fn new(pool: UserPool, domain: LoginDomain, client: ClientId, redirect_uri: Url) -> Self {
        let scopes = vec![Scope::from_token("email")];
        Self {
            pool,
            domain,
            client,
            redirect_uri,
            secret: None,
            scopes,
        }
    }

    /// For a confidential app client: sent with HTTP Basic authentication.
    pub fn client_secret(mut self, secret: ClientSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    /// The scopes to ask for besides `openid`, which is always asked for.
    /// Defaults to `email`.
    pub fn scopes(mut self, scopes: impl IntoIterator<Item = Scope>) -> Self {
        self.scopes = scopes.into_iter().collect();
        self
    }

    pub fn build(self) -> Result<ManagedLogin, ConfigError> {
        check_url(&self.redirect_uri)?;
        let mut scopes = vec!["openid"];
        scopes.extend(self.scopes.iter().map(Scope::as_str).filter(|s| *s != "openid"));
        Ok(ManagedLogin {
            http: self.pool.http().clone(),
            id_tokens: self.pool.id_tokens(self.client.clone()),
            domain: self.domain,
            client: self.client,
            redirect_uri: self.redirect_uri,
            secret: self.secret,
            scope: scopes.join(" "),
        })
    }
}

/// Web sign-in for one app client through Cognito's managed login, with
/// PKCE, state and nonce.
#[derive(Clone)]
pub struct ManagedLogin {
    http: Http,
    id_tokens: IdTokenVerifier,
    domain: LoginDomain,
    client: ClientId,
    redirect_uri: Url,
    secret: Option<ClientSecret>,
    scope: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

fn random() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system's random source works");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn same(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

impl ManagedLogin {
    /// The URL to redirect the browser to, and what to remember until the
    /// callback.
    pub fn authorize(&self, options: &AuthorizeOptions) -> (Url, PendingLogin) {
        let pending = PendingLogin {
            state: random(),
            nonce: random(),
            verifier: random(),
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.verifier.as_bytes()));
        let mut url = self.domain.endpoint("/oauth2/authorize");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", self.client.as_str())
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("scope", &self.scope)
                .append_pair("state", &pending.state)
                .append_pair("nonce", &pending.nonce)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(provider) = &options.identity_provider {
                query.append_pair("identity_provider", provider);
            }
        }
        (url, pending)
    }

    /// Completes a sign-in from the callback's query string: checks `state`,
    /// redeems the code with the PKCE verifier, and verifies the ID token and
    /// its nonce.
    pub async fn callback<C: DeserializeOwned>(
        &self,
        pending: PendingLogin,
        query: &str,
    ) -> Result<SignedIn<C>, LoginError> {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut error_description = None;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match &*key {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                "error_description" => error_description = Some(value.into_owned()),
                _ => {}
            }
        }
        if !state.is_some_and(|state| same(&state, &pending.state)) {
            return Err(LoginError::State);
        }
        if let Some(error) = error {
            return Err(LoginError::Denied(OAuthError {
                error,
                error_description,
            }));
        }
        let code = code.ok_or(LoginError::NoCode)?;
        let signed_in = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("code_verifier", &pending.verifier),
            ])
            .await?;
        let nonce = signed_in.claims.nonce.as_deref().unwrap_or_default();
        if !same(nonce, &pending.nonce) {
            return Err(LoginError::Nonce);
        }
        Ok(signed_in)
    }

    /// New access and ID tokens. With rotation on, also a new refresh token,
    /// and `token` stops working.
    pub async fn refresh<C: DeserializeOwned>(
        &self,
        token: &RefreshToken,
    ) -> Result<SignedIn<C>, LoginError> {
        self.token(&[("grant_type", "refresh_token"), ("refresh_token", token.secret())])
            .await
    }

    /// Revokes a refresh token and the access tokens issued with it.
    pub async fn revoke(&self, token: &RefreshToken) -> Result<(), LoginError> {
        self.post("/oauth2/revoke", &[("token", token.secret())])
            .await
            .map(drop)
    }

    /// Managed login's sign-out URL. It ends the managed login session and
    /// redirects to `logout_uri`, which must be one of the app client's
    /// sign-out URLs.
    pub fn logout_url(&self, logout_uri: &Url) -> Url {
        let mut url = self.domain.endpoint("/logout");
        url.query_pairs_mut()
            .append_pair("client_id", self.client.as_str())
            .append_pair("logout_uri", logout_uri.as_str());
        url
    }

    async fn token<C: DeserializeOwned>(&self, form: &[(&str, &str)]) -> Result<SignedIn<C>, LoginError> {
        let body = self.post("/oauth2/token", form).await?;
        let response: TokenResponse = serde_json::from_slice(&body).map_err(LoginError::http)?;
        let id_token = response
            .id_token
            .ok_or_else(|| LoginError::http("no id_token; is `openid` allowed?"))?;
        let claims = self
            .id_tokens
            .verify(&id_token)
            .await
            .map_err(LoginError::IdToken)?;
        Ok(SignedIn {
            claims,
            tokens: Tokens {
                id_token: IdToken(id_token),
                access_token: AccessToken(response.access_token),
                refresh_token: response.refresh_token.map(RefreshToken),
                expires_in: Duration::from_secs(response.expires_in),
            },
        })
    }

    async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, LoginError> {
        let mut body = form_urlencoded::Serializer::new(String::new());
        body.extend_pairs(form)
            .append_pair("client_id", self.client.as_str());
        let mut request = http::Request::post(self.domain.endpoint(path).as_str())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json");
        if let Some(secret) = &self.secret {
            let credentials = STANDARD.encode(format!("{}:{}", self.client, secret.secret()));
            let mut value =
                HeaderValue::try_from(format!("Basic {credentials}")).map_err(LoginError::http)?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = request
            .body(body.finish().into_bytes())
            .map_err(LoginError::http)?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|e| LoginError::Http(Arc::new(e)))?;
        if response.status().is_success() {
            return Ok(response.into_body());
        }
        match serde_json::from_slice::<OAuthError>(response.body()) {
            Ok(error) => Err(LoginError::Refused(error)),
            Err(_) => Err(LoginError::http(format!("POST {path}: {}", response.status()))),
        }
    }
}
