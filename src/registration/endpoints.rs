use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Url, form_urlencoded};

use super::{Authorize, Metadata, Registrar, RegistrationError, redirect};
use crate::config::{ClientId, LoginDomain};
use crate::http_client::Http;

pub(crate) const AUTHORIZE: &str = "/oauth2/authorize";
pub(crate) const TOKEN: &str = "/oauth2/token";
pub(crate) const REVOKE: &str = "/oauth2/revoke";
pub(crate) const REGISTER: &str = "/oauth2/register";
pub(crate) const CALLBACK: &str = "/oauth2/callback";

/// Larger requests are refused: OAuth requests are a few hundred bytes.
const MAX_BODY: usize = 64 * 1024;

/// The front's own authorize, token, revocation and registration
/// endpoints, and the relay for loopback redirect URIs. Authorization and
/// token requests reach managed login with the client's app client id in
/// place of its own `client_id`; everything else passes through, and
/// Cognito still issues every token.
#[derive(Clone)]
pub(crate) struct Endpoints {
    pub(crate) registrar: Registrar,
    pub(crate) login: LoginDomain,
    pub(crate) http: Http,
    /// The front's `/oauth2/callback`, as an absolute URL.
    pub(crate) relay: String,
}

/// What a relayed authorization carries through managed login in `state`:
/// the client's loopback redirect URI and its own state. It needn't be
/// secret or signed: the relay only ever sends a code to a loopback URI, on
/// the device of the browser that brings it.
#[derive(Serialize, Deserialize)]
struct Relayed {
    #[serde(rename = "r")]
    redirect_uri: String,
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

fn response(status: StatusCode, content_type: &'static str, body: String) -> http::Response<String> {
    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json_response(status: StatusCode, body: &Value) -> http::Response<String> {
    let mut response = response(status, "application/json", body.to_string());
    // Browser-based clients call these endpoints cross-origin.
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> http::Response<String> {
    json_response(
        status,
        &json!({ "error": error, "error_description": description }),
    )
}

/// A page for the person in the browser, when the client can't be told
/// through its redirect URI. Plain text, so nothing a client chose renders.
fn page(status: StatusCode, message: &str) -> http::Response<String> {
    response(
        status,
        "text/plain; charset=utf-8",
        format!("Sign-in can't continue: {message}\n"),
    )
}

fn redirect(location: &Url) -> http::Response<String> {
    let mut response = response(StatusCode::FOUND, "text/plain; charset=utf-8", String::new());
    if let Ok(value) = HeaderValue::try_from(location.as_str()) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn status(error: &RegistrationError) -> StatusCode {
    if error.is_temporary() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// The parameters, refusing any that appears twice (RFC 6749 section 3.1).
fn params(encoded: &[u8]) -> Option<Vec<(String, String)>> {
    let pairs: Vec<(String, String)> = form_urlencoded::parse(encoded).into_owned().collect();
    let mut names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    (names.len() == before).then_some(pairs)
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

impl Endpoints {
    pub(crate) fn paths(&self) -> Vec<&'static str> {
        let mut paths = vec![AUTHORIZE, TOKEN, REVOKE, CALLBACK];
        if self.registrar.dynamic() {
            paths.push(REGISTER);
        }
        paths
    }

    pub(crate) async fn handle(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<http::Response<String>> {
        if !self.paths().contains(&path) {
            return None;
        }
        if body.len() > MAX_BODY {
            return Some(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "the request is too large",
            ));
        }
        Some(match (method, path) {
            (&Method::GET, AUTHORIZE) => self.authorize(query.unwrap_or_default()).await,
            (&Method::GET, CALLBACK) => relay(query.unwrap_or_default()),
            (&Method::POST, TOKEN) => self.forward(TOKEN, headers, body, true).await,
            (&Method::POST, REVOKE) => self.forward(REVOKE, headers, body, false).await,
            (&Method::POST, REGISTER) => self.register(body).await,
            (&Method::OPTIONS, TOKEN | REVOKE | REGISTER) => preflight(),
            _ => {
                let mut response = response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "text/plain; charset=utf-8",
                    String::new(),
                );
                let allow = if matches!(path, AUTHORIZE | CALLBACK) {
                    "GET"
                } else {
                    "POST, OPTIONS"
                };
                response
                    .headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static(allow));
                response
            }
        })
    }

    /// Checks the client and its redirect URI, then sends the browser on to
    /// managed login with the app client's id.
    async fn authorize(&self, query: &str) -> http::Response<String> {
        let Some(pairs) = params(query.as_bytes()) else {
            return page(StatusCode::BAD_REQUEST, "a parameter appears more than once");
        };
        let (Some(client_id), Some(redirect_uri)) =
            (param(&pairs, "client_id"), param(&pairs, "redirect_uri"))
        else {
            return page(StatusCode::BAD_REQUEST, "client_id and redirect_uri are required");
        };
        let (app_client, registered, relayed) = match self
            .registrar
            .authorize(client_id, redirect_uri, &self.relay)
            .await
        {
            Ok(Authorize::Registered { app_client, relay }) => (app_client, true, relay),
            Ok(Authorize::Unregistered) => match client_id.parse::<ClientId>() {
                Ok(app_client) => (app_client, false, false),
                Err(_) => return page(StatusCode::BAD_REQUEST, "unknown client_id"),
            },
            Err(error) => return page(status(&error), &error.to_string()),
        };
        let refuse = |error: &str, description: &str| {
            // Only a redirect URI this front checked may receive the error;
            // Cognito checks the others.
            match Url::parse(redirect_uri).ok().filter(|_| registered) {
                Some(mut back) => {
                    back.query_pairs_mut()
                        .append_pair("error", error)
                        .append_pair("error_description", description);
                    if let Some(state) = param(&pairs, "state") {
                        back.query_pairs_mut().append_pair("state", state);
                    }
                    redirect(&back)
                }
                None => page(StatusCode::BAD_REQUEST, description),
            }
        };
        if param(&pairs, "response_type") != Some("code") {
            return refuse(
                "unsupported_response_type",
                "only the authorization code grant is supported",
            );
        }
        if param(&pairs, "code_challenge").is_none() || param(&pairs, "code_challenge_method") != Some("S256")
        {
            return refuse(
                "invalid_request",
                "PKCE with code_challenge_method S256 is required",
            );
        }
        let mut url = self.login.endpoint(AUTHORIZE);
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in &pairs {
                let value = match name.as_str() {
                    "client_id" => app_client.to_string(),
                    "redirect_uri" if relayed => self.relay.clone(),
                    "state" if relayed => continue,
                    _ => value.clone(),
                };
                query.append_pair(name, &value);
            }
            if relayed {
                let relayed = Relayed {
                    redirect_uri: redirect_uri.to_owned(),
                    state: param(&pairs, "state").map(str::to_owned),
                };
                let state = serde_json::to_vec(&relayed).expect("state serializes");
                query.append_pair("state", &URL_SAFE_NO_PAD.encode(state));
            }
        }
        redirect(&url)
    }

    /// Sends a token or revocation request on to managed login, with the
    /// app client's id for a registered client.
    async fn forward(
        &self,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        token: bool,
    ) -> http::Response<String> {
        let Some(mut pairs) = params(body) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "a parameter appears more than once",
            );
        };
        let authorization = headers.get(header::AUTHORIZATION);
        let registration = match param(&pairs, "client_id") {
            Some(client_id) => match self.registrar.token_client(client_id).await {
                Ok(registration) => registration,
                Err(error) if error.is_temporary() => {
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        &error.to_string(),
                    );
                }
                Err(error) => {
                    return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", &error.to_string());
                }
            },
            None => None,
        };
        if let Some(registration) = &registration {
            // A registered client is public: it proves itself with PKCE, and
            // client authentication from it is refused, as the CIMD draft says.
            let authenticates = authorization.is_some()
                || ["client_secret", "client_assertion", "client_assertion_type"]
                    .iter()
                    .any(|name| param(&pairs, name).is_some());
            if authenticates {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "this client is public and must not authenticate",
                );
            }
            for (name, value) in &mut pairs {
                if name == "client_id" {
                    *value = registration.app_client.to_string();
                }
                // A loopback redirect URI went to managed login as the relay.
                if name == "redirect_uri" && redirect::loopback(value).is_some() {
                    if redirect::find(&registration.redirect_uris, value).is_none() {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "the redirect_uri is not registered for this client",
                        );
                    }
                    *value = self.relay.clone();
                }
            }
        }
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&pairs)
            .finish();
        let mut request = http::Request::post(self.login.endpoint(path).as_str())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json");
        if let Some(value) = authorization.filter(|_| registration.is_none()) {
            request = request.header(header::AUTHORIZATION, value);
        }
        let Ok(request) = request.body(form.into_bytes()) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the request can't be sent on",
            );
        };
        let answer = match self.http.send(request).await {
            Ok(answer) => answer,
            Err(_) => {
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "temporarily_unavailable",
                    "managed login could not be reached",
                );
            }
        };
        if token
            && answer.status().is_success()
            && let Some(registration) = &registration
        {
            self.registrar.used(registration).await;
        }
        let status = answer.status();
        let content_type = answer.headers().get(header::CONTENT_TYPE).cloned();
        let mut response = json_response(status, &Value::Null);
        *response.body_mut() = String::from_utf8_lossy(answer.body()).into_owned();
        if let Some(content_type) = content_type {
            response.headers_mut().insert(header::CONTENT_TYPE, content_type);
        }
        response
    }

    /// Dynamic Client Registration (RFC 7591).
    async fn register(&self, body: &[u8]) -> http::Response<String> {
        let Ok(metadata) = serde_json::from_slice::<Metadata>(body) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "the body is not client metadata in JSON",
            );
        };
        match self.registrar.register(metadata, &self.relay).await {
            Ok(registration) => {
                let mut body = json!({
                    "client_id": registration.client_id,
                    "client_id_issued_at": registration.created_at,
                    "redirect_uris": registration.redirect_uris,
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                });
                if let Some(name) = registration.client_name {
                    body["client_name"] = json!(name);
                }
                json_response(StatusCode::CREATED, &body)
            }
            Err(error @ RegistrationError::InvalidRedirectUri(_)) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                &error.to_string(),
            ),
            Err(error) if error.is_temporary() => oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &error.to_string(),
            ),
            Err(error) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &error.to_string(),
            ),
        }
    }
}

/// Passes a code, or an error, from managed login on to the loopback
/// redirect URI that the relayed authorization started with.
fn relay(query: &str) -> http::Response<String> {
    let Some(pairs) = params(query.as_bytes()) else {
        return page(StatusCode::BAD_REQUEST, "a parameter appears more than once");
    };
    let relayed = param(&pairs, "state")
        .and_then(|state| URL_SAFE_NO_PAD.decode(state).ok())
        .and_then(|state| serde_json::from_slice::<Relayed>(&state).ok());
    let Some(relayed) = relayed else {
        return page(StatusCode::BAD_REQUEST, "this sign-in didn't start here");
    };
    let Some(mut back) = redirect::loopback(&relayed.redirect_uri) else {
        return page(StatusCode::BAD_REQUEST, "this sign-in didn't start here");
    };
    {
        let mut query = back.query_pairs_mut();
        for name in ["code", "error", "error_description"] {
            if let Some(value) = param(&pairs, name) {
                query.append_pair(name, value);
            }
        }
        if let Some(state) = &relayed.state {
            query.append_pair("state", state);
        }
    }
    redirect(&back)
}

fn preflight() -> http::Response<String> {
    let mut response = json_response(StatusCode::NO_CONTENT, &Value::Null);
    response.body_mut().clear();
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, authorization"),
    );
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
    response
}
