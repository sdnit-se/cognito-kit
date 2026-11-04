use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::redirect;

/// Cognito allows 100 callback URLs per app client.
pub(crate) const MAX_REDIRECT_URIS: usize = 100;

/// A `client_id` that names a Client ID Metadata Document: an https URL
/// with a path, without credentials, query or fragment, written as URL
/// parsing writes it. The draft compares client ids as plain strings, so a
/// URL in any other form is refused rather than normalized.
#[derive(Debug, Clone)]
pub(crate) struct DocumentUrl(Url);

impl DocumentUrl {
    pub(crate) fn parse(client_id: &str) -> Option<Self> {
        let url = Url::parse(client_id).ok()?;
        let valid = url.scheme() == "https"
            && url.as_str() == client_id
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() != "/"
            && url.query().is_none()
            && url.fragment().is_none();
        valid.then_some(Self(url))
    }

    pub(crate) fn url(&self) -> &Url {
        &self.0
    }

    pub(crate) fn host(&self) -> &str {
        self.0.host_str().unwrap_or_default()
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// What the front keeps of a document it has checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientMetadata {
    pub(crate) client_name: Option<String>,
    pub(crate) redirect_uris: Vec<String>,
}

/// The members of RFC 7591 client metadata that decide whether this front
/// can serve the client. A Client ID Metadata Document and a registration
/// request share them.
#[derive(Deserialize)]
pub(crate) struct Metadata {
    #[serde(default)]
    pub(crate) client_id: Option<String>,
    #[serde(default)]
    pub(crate) client_name: Option<String>,
    #[serde(default)]
    pub(crate) redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) response_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub(crate) token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) client_secret: Option<Value>,
}

impl Metadata {
    /// Checks what both registration paths need: redirect URIs this front
    /// can register in Cognito, the authorization code grant, and a client
    /// that can do without a secret, since every app client it creates is
    /// public and proves itself with PKCE.
    pub(crate) fn check(self) -> Result<ClientMetadata, String> {
        let redirect_uris = self.redirect_uris.unwrap_or_default();
        if redirect_uris.is_empty() {
            return Err("redirect_uris is required".into());
        }
        if redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(format!("at most {MAX_REDIRECT_URIS} redirect_uris"));
        }
        for uri in &redirect_uris {
            redirect::check(uri)?;
        }
        if let Some(grants) = &self.grant_types
            && !grants.iter().any(|g| g == "authorization_code")
        {
            return Err("grant_types must include authorization_code".into());
        }
        if let Some(types) = &self.response_types
            && !types.iter().any(|t| t == "code")
        {
            return Err("response_types must include code".into());
        }
        if self.client_secret.is_some() {
            return Err("client_secret must not be set".into());
        }
        // The plural member lists every method the client can use; the
        // singular one is a preference, and binding only when it's alone.
        let public = match (
            &self.token_endpoint_auth_methods_supported,
            &self.token_endpoint_auth_method,
        ) {
            (Some(methods), _) => methods.iter().any(|m| m == "none"),
            (None, Some(method)) => method == "none",
            (None, None) => true,
        };
        if !public {
            return Err("the client must support token_endpoint_auth_method none".into());
        }
        let client_name = self
            .client_name
            .map(|name| {
                name.chars()
                    .filter(|c| !c.is_control())
                    .take(100)
                    .collect::<String>()
            })
            .filter(|name| !name.trim().is_empty());
        Ok(ClientMetadata {
            client_name,
            redirect_uris,
        })
    }
}

/// Parses and checks a fetched Client ID Metadata Document: its
/// `client_id` must be the URL it was fetched from, exactly.
pub(crate) fn parse(url: &DocumentUrl, body: &[u8]) -> Result<ClientMetadata, String> {
    let metadata: Metadata =
        serde_json::from_slice(body).map_err(|_| "the document is not a JSON object of client metadata")?;
    if metadata.client_id.as_deref() != Some(url.as_str()) {
        return Err("the document's client_id is not its URL".into());
    }
    metadata.check()
}
