use http::{HeaderValue, Method, header};
use serde::Serialize;

use crate::config::{ConfigError, LoginDomain, Scope};
use crate::verify::{AccessTokenVerifier, canonical, metadata_url};

const PROTECTED_RESOURCE: &str = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER: &str = "/.well-known/oauth-authorization-server";

/// RFC 9728 protected resource metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProtectedResourceMetadata {
    /// The resource's URL; a client checks that it is the URL it called.
    pub resource: String,
    /// The issuer of the authorization server metadata: the resource's origin.
    pub authorization_servers: Vec<String>,
    /// The scopes a token needs; clients ask for these.
    pub scopes_supported: Vec<String>,
    /// `header`: tokens go in `Authorization: Bearer`.
    pub bearer_methods_supported: Vec<String>,
}

/// RFC 8414 authorization server metadata. Its endpoints are managed
/// login's own, or with a registrar the front's; the document is ours,
/// because Cognito's discovery document doesn't list
/// `code_challenge_methods_supported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AuthorizationServerMetadata {
    /// The resource's origin. It must equal the URL the document is read from,
    /// minus the well-known path (RFC 8414 section 3.3).
    pub issuer: String,
    /// `/oauth2/authorize`: managed login's, or with a registrar the front's.
    pub authorization_endpoint: String,
    /// `/oauth2/token`, managed login's or the front's.
    pub token_endpoint: String,
    /// `/oauth2/revoke`, managed login's or the front's.
    pub revocation_endpoint: String,
    /// The front's `/oauth2/register`, with Dynamic Client Registration on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// `true` when the front accepts Client ID Metadata Documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_metadata_document_supported: Option<bool>,
    /// `code`.
    pub response_types_supported: Vec<String>,
    /// `query`.
    pub response_modes_supported: Vec<String>,
    /// `authorization_code` and `refresh_token`.
    pub grant_types_supported: Vec<String>,
    /// `S256`, which Cognito supports but doesn't advertise.
    pub code_challenge_methods_supported: Vec<String>,
    /// `none`: the assistants' app clients are public and use PKCE.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// `none`, as for the token endpoint.
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// The resource's scopes.
    pub scopes_supported: Vec<String>,
}

/// What an MCP server needs in front of Cognito so that MCP clients can
/// sign in: the two metadata documents, and the verifier whose challenges
/// point at them.
///
/// Clients use app clients you create. With a registrar on the verifier,
/// they [register themselves](crate::guide::self_registration) through the
/// front's own endpoints instead. The authorization server's issuer is the
/// resource's origin, so the documents and the MCP endpoint share a host.
/// Cognito still authorizes, issues and refreshes every token.
///
/// [The MCP chapter](crate::guide::mcp_server) shows the whole setup.
///
/// # Examples
///
/// ```
/// use cognito_kit::{OAuthFront, UserPool};
///
/// fn front(pool: &UserPool) -> Result<OAuthFront, Box<dyn std::error::Error>> {
///     let verifier = pool
///         .access_tokens()
///         .client("1example23456789".parse()?)
///         .resource("https://portal.example.com/mcp".parse()?)
///         .scope("https://portal.example.com/mcp/drafts".parse()?)
///         .build()?;
///     Ok(OAuthFront::new(verifier, "https://login.example.com".parse()?)?)
/// }
/// ```
#[derive(Clone)]
pub struct OAuthFront {
    verifier: AccessTokenVerifier,
    resource_metadata: ProtectedResourceMetadata,
    authorization_server_metadata: AuthorizationServerMetadata,
    resource_paths: Vec<String>,
    #[cfg(feature = "registration")]
    endpoints: Option<crate::registration::Endpoints>,
}

fn strings<'a>(items: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    items.into_iter().map(str::to_owned).collect()
}

impl OAuthFront {
    /// A front for `verifier`'s resource, whose people sign in through
    /// managed login at `login`.
    ///
    /// When the verifier has a registrar, the front also serves
    /// `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`,
    /// `/oauth2/callback` and, with Dynamic Client Registration,
    /// `/oauth2/register`, and the metadata points at them. Serve them with
    /// [`handle`](Self::handle).
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoResource`] if `verifier` wasn't built with
    /// [`resource`](crate::AccessTokenVerifierBuilder::resource).
    pub fn new(verifier: AccessTokenVerifier, login: LoginDomain) -> Result<Self, ConfigError> {
        let resource = verifier.resource().ok_or(ConfigError::NoResource)?;
        let issuer = resource.origin().ascii_serialization();
        let scopes = strings(verifier.scopes().iter().map(Scope::as_str));
        #[cfg(feature = "registration")]
        let endpoints = verifier
            .registrar()
            .map(|registrar| crate::registration::Endpoints {
                registrar: registrar.clone(),
                login: login.clone(),
                http: verifier.pool().http().clone(),
                relay: format!("{issuer}/oauth2/callback"),
            });
        #[cfg(feature = "registration")]
        let (registration_endpoint, documents) = match &endpoints {
            Some(e) => (
                e.registrar.dynamic().then(|| format!("{issuer}/oauth2/register")),
                e.registrar.documents().then_some(true),
            ),
            None => (None, None),
        };
        #[cfg(not(feature = "registration"))]
        let (registration_endpoint, documents) = (None, None);
        let own = registration_endpoint.is_some() || documents.is_some();
        let origin = issuer.clone();
        let endpoint = |path: &str| {
            if own {
                format!("{origin}{path}")
            } else {
                login.endpoint(path).to_string()
            }
        };
        let resource_metadata = ProtectedResourceMetadata {
            resource: canonical(resource),
            authorization_servers: vec![issuer.clone()],
            scopes_supported: scopes.clone(),
            bearer_methods_supported: strings(["header"]),
        };
        let authorization_server_metadata = AuthorizationServerMetadata {
            issuer,
            authorization_endpoint: endpoint("/oauth2/authorize"),
            token_endpoint: endpoint("/oauth2/token"),
            revocation_endpoint: endpoint("/oauth2/revoke"),
            registration_endpoint,
            client_id_metadata_document_supported: documents,
            response_types_supported: strings(["code"]),
            response_modes_supported: strings(["query"]),
            grant_types_supported: strings(["authorization_code", "refresh_token"]),
            code_challenge_methods_supported: strings(["S256"]),
            token_endpoint_auth_methods_supported: strings(["none"]),
            revocation_endpoint_auth_methods_supported: strings(["none"]),
            scopes_supported: scopes,
        };
        // RFC 9728 puts the document under the resource's path. Some clients
        // look only at the root when a proxy drops `WWW-Authenticate`, as
        // Lambda function URLs do, so the root serves it too.
        let mut resource_paths = vec![metadata_url(resource).path().to_owned()];
        if resource_paths[0] != PROTECTED_RESOURCE {
            resource_paths.push(PROTECTED_RESOURCE.to_owned());
        }
        Ok(Self {
            verifier,
            resource_metadata,
            authorization_server_metadata,
            resource_paths,
            #[cfg(feature = "registration")]
            endpoints,
        })
    }

    /// The verifier for the resource's tokens.
    pub fn verifier(&self) -> &AccessTokenVerifier {
        &self.verifier
    }

    /// The document [`respond`](Self::respond) serves at the protected
    /// resource paths.
    pub fn protected_resource_metadata(&self) -> &ProtectedResourceMetadata {
        &self.resource_metadata
    }

    /// The document [`respond`](Self::respond) serves at
    /// `/.well-known/oauth-authorization-server`.
    pub fn authorization_server_metadata(&self) -> &AuthorizationServerMetadata {
        &self.authorization_server_metadata
    }

    /// Answers a request to the front: the metadata documents, and with a
    /// registrar the front's own endpoints. Returns `None` for every other
    /// request, which is yours to answer.
    pub async fn handle<B: AsRef<[u8]>>(&self, request: &http::Request<B>) -> Option<http::Response<String>> {
        let path = request.uri().path();
        if let Some(response) = self.respond(request.method(), path) {
            return Some(response);
        }
        #[cfg(feature = "registration")]
        if let Some(endpoints) = &self.endpoints {
            let body = request.body().as_ref();
            return endpoints
                .handle(
                    request.method(),
                    path,
                    request.uri().query(),
                    request.headers(),
                    body,
                )
                .await;
        }
        None
    }

    /// Answers a request for one of the metadata documents, or returns
    /// `None` for every other request. With a registrar, use
    /// [`handle`](Self::handle), which also serves the front's endpoints.
    pub fn respond(&self, method: &Method, path: &str) -> Option<http::Response<String>> {
        if method != Method::GET {
            return None;
        }
        let body = if path == AUTHORIZATION_SERVER {
            serde_json::to_string(&self.authorization_server_metadata)
        } else if self.resource_paths.iter().any(|p| p == path) {
            serde_json::to_string(&self.resource_metadata)
        } else {
            return None;
        };
        let mut response = http::Response::new(body.expect("metadata serializes"));
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        // Browser-based MCP clients read the documents cross-origin.
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        Some(response)
    }

    /// The paths [`handle`](Self::handle) answers, for routers that
    /// register routes one by one.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        #[cfg(feature = "registration")]
        let endpoints = self.endpoints.as_ref().map(|e| e.paths()).unwrap_or_default();
        #[cfg(not(feature = "registration"))]
        let endpoints: Vec<&str> = Vec::new();
        self.resource_paths
            .iter()
            .map(String::as_str)
            .chain([AUTHORIZATION_SERVER])
            .chain(endpoints)
    }
}
