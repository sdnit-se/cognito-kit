use http::{HeaderValue, Method, StatusCode, header};
use serde::Serialize;

use crate::config::{ConfigError, LoginDomain, Scope};
use crate::verify::{AccessTokenVerifier, canonical, metadata_url};

const PROTECTED_RESOURCE: &str = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER: &str = "/.well-known/oauth-authorization-server";

/// RFC 9728 protected resource metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

/// RFC 8414 authorization server metadata. Its endpoints are managed
/// login's own; only the document is ours, because Cognito's discovery
/// document doesn't list `code_challenge_methods_supported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

/// What an MCP server needs in front of Cognito so that MCP clients can
/// sign in with pre-registered public app clients: the two metadata
/// documents, and the verifier whose challenges point at them.
///
/// The authorization server's issuer is the resource's origin, so the
/// documents and the MCP endpoint share a host. Cognito still authorizes,
/// issues and refreshes every token.
#[derive(Clone)]
pub struct OAuthFront {
    verifier: AccessTokenVerifier,
    resource_metadata: ProtectedResourceMetadata,
    authorization_server_metadata: AuthorizationServerMetadata,
    resource_paths: Vec<String>,
    resource_body: String,
    authorization_server_body: String,
}

fn strings<'a>(items: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    items.into_iter().map(str::to_owned).collect()
}

impl OAuthFront {
    /// `verifier` must be built with
    /// [`resource`](crate::AccessTokenVerifierBuilder::resource).
    pub fn new(verifier: AccessTokenVerifier, login: LoginDomain) -> Result<Self, ConfigError> {
        let resource = verifier.resource().ok_or(ConfigError::NoResource)?;
        let issuer = resource.origin().ascii_serialization();
        let scopes = strings(verifier.scopes().iter().map(Scope::as_str));
        let endpoint = |path: &str| login.endpoint(path).to_string();
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
            resource_body: serde_json::to_string(&resource_metadata).expect("metadata serializes"),
            authorization_server_body: serde_json::to_string(&authorization_server_metadata)
                .expect("metadata serializes"),
            verifier,
            resource_metadata,
            authorization_server_metadata,
            resource_paths,
        })
    }

    pub fn verifier(&self) -> &AccessTokenVerifier {
        &self.verifier
    }

    pub fn protected_resource_metadata(&self) -> &ProtectedResourceMetadata {
        &self.resource_metadata
    }

    pub fn authorization_server_metadata(&self) -> &AuthorizationServerMetadata {
        &self.authorization_server_metadata
    }

    /// Answers a request for one of the metadata documents, or returns
    /// `None` for every other request.
    pub fn respond(&self, method: &Method, path: &str) -> Option<http::Response<String>> {
        if method != Method::GET {
            return None;
        }
        let body = if path == AUTHORIZATION_SERVER {
            &self.authorization_server_body
        } else if self.resource_paths.iter().any(|p| p == path) {
            &self.resource_body
        } else {
            return None;
        };
        let mut response = http::Response::new(body.clone());
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        // Browser-based MCP clients read the documents cross-origin.
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        Some(response)
    }

    /// The paths [`respond`](Self::respond) answers, for routers that
    /// register routes one by one.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.resource_paths
            .iter()
            .map(String::as_str)
            .chain([AUTHORIZATION_SERVER])
    }
}
