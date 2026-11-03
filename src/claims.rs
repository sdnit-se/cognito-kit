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
    /// The identifier, usually a UUID.
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
    /// Whether the token grants `scope`.
    pub fn contains(&self, scope: &Scope) -> bool {
        self.0.contains(scope)
    }

    /// The granted scopes, in order.
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
    /// The user, or for a machine-to-machine token the app client.
    pub sub: Sub,
    /// The app client the token was issued to.
    pub client_id: ClientId,
    /// Absent from machine-to-machine tokens.
    #[serde(default)]
    pub username: Option<String>,
    /// The user's groups in the pool (`cognito:groups`).
    #[serde(default, rename = "cognito:groups")]
    pub groups: Vec<String>,
    /// The granted scopes (`scope`).
    #[serde(default, rename = "scope")]
    pub scopes: Scopes,
    /// Expiry, in seconds since the Unix epoch.
    pub exp: u64,
    /// Issue time, in seconds since the Unix epoch.
    pub iat: u64,
    /// When the user signed in, in seconds since the Unix epoch.
    #[serde(default)]
    pub auth_time: Option<u64>,
    /// The token's unique id.
    #[serde(default)]
    pub jti: Option<String>,
    /// The claims this struct doesn't name.
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
    /// The user.
    pub sub: Sub,
    /// The user's name in the pool (`cognito:username`). For a federated
    /// user it is `<provider>_<id at the provider>`, such as `google_1234`.
    #[serde(rename = "cognito:username")]
    pub username: String,
    /// The user's email address, if the app client may read it.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the email address is verified. For a federated user, it is
    /// what the provider said, through the pool's attribute mapping.
    #[serde(default, deserialize_with = "lenient_bool")]
    pub email_verified: bool,
    /// The user's full name.
    #[serde(default)]
    pub name: Option<String>,
    /// The user's groups in the pool (`cognito:groups`).
    #[serde(default, rename = "cognito:groups")]
    pub groups: Vec<String>,
    /// The external identity providers linked to this user, such as Google.
    /// Empty for users who sign in with the pool's own credentials.
    #[serde(default)]
    pub identities: Vec<Identity>,
    /// Expiry, in seconds since the Unix epoch.
    pub exp: u64,
    /// Issue time, in seconds since the Unix epoch.
    pub iat: u64,
    /// When the user signed in, in seconds since the Unix epoch.
    #[serde(default)]
    pub auth_time: Option<u64>,
    /// The claims this struct doesn't name.
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
