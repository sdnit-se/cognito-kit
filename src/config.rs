use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

/// A setting that can't work, found when it is parsed or a builder runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("{0:?} is not a user pool id such as eu-north-1_AbC123")]
    PoolId(String),
    #[error("{0:?} is not an app client id")]
    ClientId(String),
    #[error("{0:?} is not an OAuth scope")]
    Scope(String),
    #[error("{url}: {reason}")]
    Url { url: String, reason: &'static str },
    #[error("an access-token verifier needs at least one app client")]
    NoClients,
    #[error("the OAuth front needs a verifier built with `resource`")]
    NoResource,
}

fn url_error(url: &str, reason: &'static str) -> ConfigError {
    ConfigError::Url {
        url: url.to_owned(),
        reason,
    }
}

/// A user pool id, such as `eu-north-1_AbC123`. Its prefix is the region.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PoolId(String);

impl PoolId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn region(&self) -> &str {
        self.0.split_once('_').map_or("", |(region, _)| region)
    }
}

impl FromStr for PoolId {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = s.split_once('_').is_some_and(|(region, suffix)| {
            let mut parts = region.split('-');
            let geo = parts.next().unwrap_or_default();
            let tail: Vec<_> = parts.collect();
            geo.len() == 2
                && geo.bytes().all(|b| b.is_ascii_lowercase())
                && tail.len() >= 2
                && tail
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
                && !suffix.is_empty()
                && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        });
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(ConfigError::PoolId(s.to_owned()))
        }
    }
}

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An app client id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientId(String);

impl ClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ClientId {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = (1..=128).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'+');
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(ConfigError::ClientId(s.to_owned()))
        }
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for ClientId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

/// An OAuth scope: a standard one such as `openid`, or a resource server's,
/// such as `https://api.example.com/read`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(String);

impl Scope {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_token(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl FromStr for Scope {
    type Err = ConfigError;

    /// RFC 6749 section 3.3: printable ASCII except space, `"` and `\`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = !s.is_empty() && s.bytes().all(|b| matches!(b, 0x21 | 0x23..=0x5B | 0x5D..=0x7E));
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(ConfigError::Scope(s.to_owned()))
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The origin that serves managed login: a custom domain such as
/// `https://login.example.com`, or a prefix domain such as
/// `https://example.auth.eu-north-1.amazoncognito.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDomain(Url);

impl LoginDomain {
    pub fn url(&self) -> &Url {
        &self.0
    }

    pub(crate) fn endpoint(&self, path: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(path);
        url
    }
}

impl FromStr for LoginDomain {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|_| url_error(s, "not a URL"))?;
        if url.scheme() != "https" {
            return Err(url_error(s, "managed login is served over https"));
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(url_error(
                s,
                "a login domain is an origin, without a path or query",
            ));
        }
        Ok(Self(url))
    }
}

/// Checks a URL that a client is sent to or that names a resource: https, or
/// http on a loopback host for local development, and no fragment.
pub(crate) fn check_url(url: &Url) -> Result<(), ConfigError> {
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(url_error(url.as_str(), "must use https, or http on localhost")),
    }
    if url.fragment().is_some() {
        return Err(url_error(url.as_str(), "must not have a fragment"));
    }
    Ok(())
}
