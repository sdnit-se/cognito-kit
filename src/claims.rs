use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::config::{ClientId, Scope};

/// A user's (or, for machine-to-machine tokens, an app client's) stable
/// identifier in the pool. It never changes and is never reused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sub(String);

impl Sub {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The scopes an access token grants, from its space-separated `scope` claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scopes(BTreeSet<Scope>);

impl Scopes {
    pub fn contains(&self, scope: &Scope) -> bool {
        self.0.contains(scope)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let joined = String::deserialize(deserializer)?;
        Ok(Self(
            joined.split_ascii_whitespace().map(Scope::from_token).collect(),
        ))
    }
}

/// The claims of a verified access token.
///
/// `C` receives the claims this struct doesn't name, through serde's
/// `flatten`. Cognito puts custom attributes into access tokens only when a
/// pre-token-generation trigger adds them.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct AccessClaims<C = ()> {
    pub sub: Sub,
    pub client_id: ClientId,
    /// Absent from machine-to-machine tokens.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, rename = "cognito:groups")]
    pub groups: Vec<String>,
    #[serde(default, rename = "scope")]
    pub scopes: Scopes,
    /// Expiry, in seconds since the Unix epoch.
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(flatten)]
    pub custom: C,
}

/// The claims of a verified ID token.
///
/// Custom attributes (`custom:*`) and any standard attribute not named here
/// go to `C`, through serde's `flatten`.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct IdClaims<C = ()> {
    pub sub: Sub,
    #[serde(rename = "cognito:username")]
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "lenient_bool")]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "cognito:groups")]
    pub groups: Vec<String>,
    /// The external identity providers linked to this user, such as Google.
    /// Empty for users who sign in with the pool's own credentials.
    #[serde(default)]
    pub identities: Vec<Identity>,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(flatten)]
    pub custom: C,
    #[serde(default)]
    pub(crate) nonce: Option<String>,
}

/// An external identity linked to a user, from the ID token's `identities`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Identity {
    /// The provider's name in the pool, such as `Google`.
    pub provider_name: String,
    /// `Google`, `Facebook`, `LoginWithAmazon`, `SignInWithApple`, `OIDC` or `SAML`.
    pub provider_type: String,
    /// The user's id at the provider.
    pub user_id: String,
}

/// Cognito sends `email_verified` as a boolean for its own users and as a
/// string for some federated ones.
fn lenient_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Lenient {
        Bool(bool),
        Text(String),
    }
    Ok(match Lenient::deserialize(deserializer)? {
        Lenient::Bool(b) => b,
        Lenient::Text(s) => s == "true",
    })
}
