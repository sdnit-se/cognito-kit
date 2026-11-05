//! Clients that register themselves: Client ID Metadata Documents and
//! Dynamic Client Registration (RFC 7591), each mapped to a Cognito app
//! client that the [`Registrar`] creates on first use.
//!
//! Cognito has no consent step, and its authorize endpoint is public: anyone
//! who learns an app client's id can send a signed-in user through it.
//! So an app client is only ever created with redirect URIs that keep the
//! code on the user's device (http on a loopback host), or that point at an
//! https host you list with
//! [`client_hosts`](RegistrarBuilder::client_hosts).
//!
//! Native clients listen on a loopback port the system picks, and Cognito
//! matches callback URLs exactly. Managed login also takes minutes to accept
//! a callback URL added to an existing app client. So Cognito sends their
//! codes to the front's `/oauth2/callback`, which passes each on to the
//! loopback URI the authorization started with, and to nothing else.

mod cognito;
mod document;
#[cfg(feature = "dynamodb")]
mod dynamodb;
mod endpoints;
mod fetch;
mod redirect;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use url::Url;

pub use cognito::CognitoApi;
#[cfg(feature = "dynamodb")]
#[cfg_attr(docsrs, doc(cfg(feature = "dynamodb")))]
pub use dynamodb::DynamoStore;
pub use fetch::{BoxFuture, FetchDocument, FetchError, GuardedFetcher};

pub(crate) use endpoints::Endpoints;

pub(crate) use document::Metadata;
use document::{ClientMetadata, DocumentUrl};

use crate::config::{ClientId, ConfigError};
use crate::http_client::BoxError;

/// How long a fetched document is used before it is fetched again.
const REFRESH: Duration = Duration::from_secs(300);
/// The shortest time between two fetches of one document.
const MIN_REFETCH: Duration = Duration::from_secs(60);
/// App-client writes that requests may cause per minute, per process.
/// Cognito allows five per second per pool for every caller together.
const WRITES_PER_MINUTE: usize = 10;
/// How long a check against Cognito or the store is reused.
const KNOWN_FOR: Duration = Duration::from_secs(60);
const TOUCH_EVERY: Duration = Duration::from_secs(3600);

/// How a client registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RegistrationKind {
    /// A Client ID Metadata Document: the client's `client_id` is the
    /// document's URL.
    Document,
    /// Dynamic Client Registration: the client's `client_id` is its app
    /// client's id.
    Dynamic,
}

/// A client the [`Registrar`] created an app client for. It serializes to
/// JSON, for stores of your own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Registration {
    /// What the client sends as `client_id`.
    pub client_id: String,
    /// The app client Cognito issues the client's tokens to.
    pub app_client: ClientId,
    /// How the client registered.
    pub kind: RegistrationKind,
    /// The name the client gave, if any. Not verified.
    #[serde(default)]
    pub client_name: Option<String>,
    /// The redirect URIs the client may use. One with http on a loopback
    /// host matches on any port.
    pub redirect_uris: Vec<String>,
    /// When it was registered, in seconds since the Unix epoch.
    pub created_at: u64,
    /// The last successful token request, in seconds since the Unix epoch.
    #[serde(default)]
    pub last_used: Option<u64>,
    /// For a document: when it was last fetched, in seconds since the Unix epoch.
    #[serde(default)]
    pub fetched_at: u64,
}

/// Keeps the [`Registrar`]'s registrations: which `client_id` maps to which
/// app client. Every server instance must share one store.
///
/// `DynamoStore` implements it with the `dynamodb` feature; implement it
/// yourself for another database. [`Registration`] serializes to JSON.
pub trait RegistrationStore: Send + Sync + 'static {
    /// The registration for a `client_id` as clients send it.
    fn get<'a>(&'a self, client_id: &'a str) -> BoxFuture<'a, Result<Option<Registration>, BoxError>>;
    /// The registration whose app client this is.
    fn get_by_app_client<'a>(
        &'a self,
        app_client: &'a ClientId,
    ) -> BoxFuture<'a, Result<Option<Registration>, BoxError>>;
    /// Stores `registration` unless its `client_id` is taken, and returns
    /// what is stored under that `client_id` afterwards. Two servers that
    /// register one client at once both get the first one's registration.
    fn insert(&self, registration: Registration) -> BoxFuture<'_, Result<Registration, BoxError>>;
    /// Replaces the stored `redirect_uris`, `client_name` and `fetched_at`,
    /// unless the `client_id` has since been registered again with another
    /// app client.
    fn update<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>>;
    /// Sets `last_used`.
    fn touch<'a>(&'a self, client_id: &'a str, at: u64) -> BoxFuture<'a, Result<(), BoxError>>;
    /// Removes a registration, unless its `client_id` has since been
    /// registered again with another app client. One that is already gone
    /// counts as removed.
    fn remove<'a>(&'a self, registration: &'a Registration) -> BoxFuture<'a, Result<(), BoxError>>;
    /// Every registration.
    fn list(&self) -> BoxFuture<'_, Result<Vec<Registration>, BoxError>>;
}

/// Why Cognito refused a change to an app client.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AdminError {
    /// The pool has as many app clients as its quota allows (1,000 by default).
    #[error("the user pool has no room for another app client")]
    Limit,
    /// No such app client.
    #[error("no such app client")]
    NotFound,
    /// Anything else, such as a refused request or no answer.
    #[error("Cognito refused or could not be reached")]
    Other(#[source] Arc<BoxError>),
}

/// The Cognito API the [`Registrar`] needs: creating, changing and deleting
/// the app clients it owns.
///
/// `CognitoApi` implements it over the AWS SDK. The test kit's
/// `FakeCognito` implements it in memory.
pub trait AppClients: Send + Sync + 'static {
    /// Creates a public app client for the authorization code grant, with
    /// refresh-token rotation, a managed login style, and these callback
    /// URLs.
    fn create<'a>(
        &'a self,
        name: &'a str,
        callback_urls: &'a [String],
    ) -> BoxFuture<'a, Result<ClientId, AdminError>>;
    /// Replaces the app client's callback URLs and keeps its other settings.
    fn set_callback_urls<'a>(
        &'a self,
        client: &'a ClientId,
        urls: &'a [String],
    ) -> BoxFuture<'a, Result<(), AdminError>>;
    /// Deletes an app client. One that is already gone counts as deleted.
    fn delete<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<(), AdminError>>;
    /// The pool's app clients whose names start with `prefix`.
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<ClientId>, AdminError>>;
    /// When the app client was created.
    fn created<'a>(&'a self, client: &'a ClientId) -> BoxFuture<'a, Result<SystemTime, AdminError>>;
}

/// Why a client couldn't be registered or served.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The `client_id` is neither a registered client nor a document URL
    /// this registrar accepts.
    #[error("unknown client_id")]
    UnknownClient,
    /// The client's metadata can't be served: what is wrong with it.
    #[error("{0}")]
    InvalidClient(String),
    /// A redirect URI that can't be registered: why.
    #[error("{0}")]
    InvalidRedirectUri(String),
    /// The request's `redirect_uri` isn't one the client registered.
    #[error("the redirect_uri is not registered for this client")]
    RedirectMismatch,
    /// The client's metadata document could not be fetched.
    #[error("the client's metadata document could not be fetched: {0}")]
    Fetch(#[source] FetchError),
    /// The registrar holds as many registrations as it may, or the pool as
    /// many app clients as its quota allows.
    #[error("no room for another app client; unused ones are removed by cleanup")]
    Full,
    /// Requests changed app clients too often in the last minute.
    #[error("too many app client changes; try again in a minute")]
    Busy,
    /// Cognito's API or the store failed.
    #[error("Cognito or the registration store failed")]
    Unavailable(#[source] Arc<BoxError>),
}

impl RegistrationError {
    /// Whether the client may succeed by trying again later.
    pub fn is_temporary(&self) -> bool {
        match self {
            Self::Fetch(error) => error.is_transient(),
            Self::Full | Self::Busy | Self::Unavailable(_) => true,
            _ => false,
        }
    }
}

impl From<AdminError> for RegistrationError {
    fn from(error: AdminError) -> Self {
        match error {
            AdminError::Limit => Self::Full,
            AdminError::NotFound => Self::Unavailable(Arc::new("the app client is gone".into())),
            AdminError::Other(error) => Self::Unavailable(error),
        }
    }
}

fn unavailable(error: BoxError) -> RegistrationError {
    RegistrationError::Unavailable(Arc::new(error))
}

/// What [`Registrar::cleanup`] removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cleanup {
    /// Registrations that never completed a token request.
    pub unused: usize,
    /// Registrations without a token request for longer than `idle_after`.
    pub idle: usize,
    /// App clients with the registrar's name prefix and no registration,
    /// left by a server that stopped between creating and storing one.
    pub orphans: usize,
    /// Registrations with a redirect URI on a host no longer trusted.
    pub untrusted: usize,
}

/// Why cleanup removes a registration.
enum Removal {
    Untrusted,
    Unused,
    Idle,
}

/// Registers clients that bring their own identity, and maps each to a
/// Cognito app client it creates.
///
/// Cheap to clone. Give it to the access-token verifier with
/// [`registrar`](crate::AccessTokenVerifierBuilder::registrar); the
/// [`OAuthFront`](crate::OAuthFront) then serves its own authorize, token
/// and revocation endpoints, and with Dynamic Client Registration on, a
/// registration endpoint.
#[derive(Clone)]
pub struct Registrar {
    inner: Arc<Inner>,
}

struct Inner {
    app_clients: Box<dyn AppClients>,
    store: Box<dyn RegistrationStore>,
    documents: Option<Box<dyn FetchDocument>>,
    dynamic: bool,
    client_hosts: Option<BTreeSet<String>>,
    max_registrations: usize,
    unused_after: Duration,
    idle_after: Duration,
    name_prefix: String,
    known: Mutex<HashMap<ClientId, Instant>>,
    touched: Mutex<HashMap<String, Instant>>,
    writes: Mutex<VecDeque<Instant>>,
}

/// Settings for a [`Registrar`]; from [`Registrar::builder`].
#[must_use]
pub struct RegistrarBuilder {
    app_clients: Box<dyn AppClients>,
    store: Box<dyn RegistrationStore>,
    documents: Option<Box<dyn FetchDocument>>,
    dynamic: bool,
    client_hosts: Option<BTreeSet<String>>,
    max_registrations: usize,
    unused_after: Duration,
    idle_after: Duration,
    name_prefix: String,
}

impl RegistrarBuilder {
    /// Accepts an https URL as `client_id`: the URL of the client's
    /// metadata document, fetched with [`GuardedFetcher`].
    pub fn metadata_documents(self) -> Self {
        self.fetcher(GuardedFetcher::new())
    }

    /// Accepts metadata documents, fetched with your own fetcher.
    pub fn fetcher(mut self, fetcher: impl FetchDocument) -> Self {
        self.documents = Some(Box::new(fetcher));
        self
    }

    /// Accepts Dynamic Client Registration (RFC 7591) at
    /// `/oauth2/register`, for clients without a metadata document.
    pub fn dynamic_registration(mut self) -> Self {
        self.dynamic = true;
        self
    }

    /// The hosts trusted to receive authorization codes, such as
    /// `claude.ai` and `chatgpt.com`. Metadata documents are then accepted
    /// only from these hosts, and https redirect URIs only on them.
    ///
    /// Without a list, documents are accepted from any host, and every
    /// client must keep its codes on the user's device, with http on a
    /// loopback host. That serves command-line and desktop assistants, but
    /// not web ones such as Claude or ChatGPT.
    pub fn client_hosts(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.client_hosts = Some(hosts.into_iter().map(|h| h.into().to_ascii_lowercase()).collect());
        self
    }

    /// The most registrations to hold. Defaults to 500, half the pool's
    /// default quota of 1,000 app clients, so that clients you manage
    /// yourself still fit. At the limit, new clients are refused with 503
    /// until [`cleanup`](Registrar::cleanup) frees room. Registrations
    /// already on their way when the limit is reached still complete, so
    /// the count can pass it by the few that Cognito's rate of five app
    /// clients a second lets through at once.
    pub fn max_registrations(mut self, max: usize) -> Self {
        self.max_registrations = max;
        self
    }

    /// How long a registration may wait for its first token request before
    /// cleanup removes it. Defaults to a day.
    pub fn unused_after(mut self, after: Duration) -> Self {
        self.unused_after = after;
        self
    }

    /// How long after its last token request a registration is removed by
    /// cleanup. Defaults to 31 days; keep it longer than the refresh tokens
    /// last, so that removing an app client never ends a session that could
    /// still refresh.
    pub fn idle_after(mut self, after: Duration) -> Self {
        self.idle_after = after;
        self
    }

    /// The start of every app client name the registrar gives. Cleanup
    /// deletes app clients with this prefix that it has no registration
    /// for, so each registrar sharing a pool needs its own. At most 64
    /// characters, so that a name fits Cognito's 128 with the prefix whole.
    /// Defaults to `cognito-kit`.
    pub fn name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = prefix.into();
        self
    }

    /// Checks that something is accepted: documents, dynamic registration,
    /// or both.
    pub fn build(self) -> Result<Registrar, ConfigError> {
        if self.documents.is_none() && !self.dynamic {
            return Err(ConfigError::Registration(
                "turn on metadata documents, dynamic registration or both",
            ));
        }
        if self.name_prefix.trim().is_empty() {
            return Err(ConfigError::Registration("the app client name prefix is empty"));
        }
        if !self.name_prefix.chars().all(name_char) {
            return Err(ConfigError::Registration(
                "the app client name prefix has a character Cognito refuses in a name",
            ));
        }
        // Names are cut at 128 characters; cleanup knows its own by the
        // whole prefix and the space after it.
        if self.name_prefix.chars().count() > 64 {
            return Err(ConfigError::Registration(
                "the app client name prefix is longer than 64 characters",
            ));
        }
        Ok(Registrar {
            inner: Arc::new(Inner {
                app_clients: self.app_clients,
                store: self.store,
                documents: self.documents,
                dynamic: self.dynamic,
                client_hosts: self.client_hosts,
                max_registrations: self.max_registrations,
                unused_after: self.unused_after,
                idle_after: self.idle_after,
                name_prefix: self.name_prefix,
                known: Mutex::default(),
                touched: Mutex::default(),
                writes: Mutex::default(),
            }),
        })
    }
}

/// Where an authorization request goes.
pub(crate) enum Authorize {
    /// A registered client, through its app client; with `relay`, the code
    /// reaches its loopback redirect URI through the front.
    Registered { app_client: ClientId, relay: bool },
    /// Not a registration: an app client you created yourself, which
    /// Cognito checks.
    Unregistered,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fresh<K: std::hash::Hash + Eq>(map: &Mutex<HashMap<K, Instant>>, key: &K, ttl: Duration) -> bool {
    let map = map.lock().unwrap_or_else(|e| e.into_inner());
    map.get(key).is_some_and(|at| at.elapsed() < ttl)
}

fn remember<K: std::hash::Hash + Eq>(map: &Mutex<HashMap<K, Instant>>, key: K, ttl: Duration) {
    let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, at| at.elapsed() < ttl);
    map.insert(key, Instant::now());
}

impl Registrar {
    /// A registrar that creates app clients through `app_clients` and keeps
    /// its registrations in `store`. Turn on metadata documents, dynamic
    /// registration or both.
    pub fn builder(app_clients: impl AppClients, store: impl RegistrationStore) -> RegistrarBuilder {
        RegistrarBuilder {
            app_clients: Box::new(app_clients),
            store: Box::new(store),
            documents: None,
            dynamic: false,
            client_hosts: None,
            max_registrations: 500,
            unused_after: Duration::from_secs(24 * 3600),
            idle_after: Duration::from_secs(31 * 24 * 3600),
            name_prefix: "cognito-kit".to_owned(),
        }
    }

    pub(crate) fn documents(&self) -> bool {
        self.inner.documents.is_some()
    }

    pub(crate) fn dynamic(&self) -> bool {
        self.inner.dynamic
    }

    /// Whether tokens issued to `app_client` come from a registration.
    pub(crate) async fn knows(&self, app_client: &ClientId) -> Result<bool, BoxError> {
        if fresh(&self.inner.known, app_client, KNOWN_FOR) {
            return Ok(true);
        }
        let known = self.inner.store.get_by_app_client(app_client).await?.is_some();
        if known {
            remember(&self.inner.known, app_client.clone(), KNOWN_FOR);
        }
        Ok(known)
    }

    /// Checks an authorization request's client and redirect URI, creating
    /// the app client for a document on first use. `relay` is the front's
    /// `/oauth2/callback`.
    pub(crate) async fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        relay: &str,
    ) -> Result<Authorize, RegistrationError> {
        let registration = if let Some(url) = DocumentUrl::parse(client_id) {
            self.document(&url, redirect_uri, relay).await?
        } else if client_id.contains(':') {
            return Err(RegistrationError::InvalidClient(
                "a client_id URL must be https, with a path and no query, in normalized form".into(),
            ));
        } else {
            match self.registration(client_id).await? {
                Some(registration) => registration,
                None => return Ok(Authorize::Unregistered),
            }
        };
        redirect::find(&registration.redirect_uris, redirect_uri)
            .ok_or(RegistrationError::RedirectMismatch)?;
        // Checked on every request, so that a host taken off `client_hosts`
        // gets no more codes through the front, even for stored clients.
        if !self.trusted(redirect_uri) {
            return Err(RegistrationError::InvalidRedirectUri(
                self.untrusted(redirect_uri),
            ));
        }
        Ok(Authorize::Registered {
            app_client: registration.app_client,
            relay: redirect::loopback(redirect_uri).is_some(),
        })
    }

    /// The registration behind a token or revocation request's `client_id`,
    /// or `None` for an app client you created yourself.
    pub(crate) async fn token_client(
        &self,
        client_id: &str,
    ) -> Result<Option<Registration>, RegistrationError> {
        if !client_id.contains(':') {
            return self.registration(client_id).await;
        }
        let found = self.inner.store.get(client_id).await.map_err(unavailable)?;
        match found {
            Some(registration) if registration.kind == RegistrationKind::Document => Ok(Some(registration)),
            _ => Err(RegistrationError::UnknownClient),
        }
    }

    /// A dynamic registration; a document's is stored under its URL.
    async fn registration(&self, client_id: &str) -> Result<Option<Registration>, RegistrationError> {
        let found = self.inner.store.get(client_id).await.map_err(unavailable)?;
        Ok(found.filter(|r| r.kind == RegistrationKind::Dynamic))
    }

    /// Records a successful token request, at most once an hour per client
    /// and process.
    pub(crate) async fn used(&self, registration: &Registration) {
        let client_id = &registration.client_id;
        let recent = registration
            .last_used
            .is_some_and(|at| now().saturating_sub(at) < TOUCH_EVERY.as_secs());
        if recent || fresh(&self.inner.touched, client_id, TOUCH_EVERY) {
            return;
        }
        remember(&self.inner.touched, client_id.clone(), TOUCH_EVERY);
        // Until a first touch lands, cleanup sees the client as never used,
        // so a failed one is tried again on the next token request.
        if self.inner.store.touch(client_id, now()).await.is_err() {
            let mut touched = self.inner.touched.lock().unwrap_or_else(|e| e.into_inner());
            touched.remove(client_id);
        }
    }

    /// Registers a client from an RFC 7591 request.
    pub(crate) async fn register(
        &self,
        metadata: Metadata,
        relay: &str,
    ) -> Result<Registration, RegistrationError> {
        let metadata = metadata.check().map_err(RegistrationError::InvalidClient)?;
        for uri in &metadata.redirect_uris {
            if !self.trusted(uri) {
                return Err(RegistrationError::InvalidRedirectUri(self.untrusted(uri)));
            }
        }
        let name = metadata
            .client_name
            .clone()
            .unwrap_or_else(|| "dynamic".to_owned());
        let app_client = self
            .create(&name, &callbacks(&metadata.redirect_uris, relay))
            .await?;
        let registration = Registration {
            client_id: app_client.to_string(),
            app_client,
            kind: RegistrationKind::Dynamic,
            client_name: metadata.client_name,
            redirect_uris: metadata.redirect_uris,
            created_at: now(),
            last_used: None,
            fetched_at: 0,
        };
        self.inner.store.insert(registration).await.map_err(unavailable)
    }

    /// The registration for a document URL: stored, refreshed, or created
    /// from a fetch.
    async fn document(
        &self,
        url: &DocumentUrl,
        redirect_uri: &str,
        relay: &str,
    ) -> Result<Registration, RegistrationError> {
        let fetcher = self
            .inner
            .documents
            .as_ref()
            .ok_or(RegistrationError::UnknownClient)?;
        if let Some(hosts) = &self.inner.client_hosts
            && !hosts.contains(url.host())
        {
            return Err(RegistrationError::InvalidClient(format!(
                "metadata documents from {} are not accepted here",
                url.host()
            )));
        }
        let stored = self.inner.store.get(url.as_str()).await.map_err(unavailable)?;
        let now = now();
        if let Some(stored) = &stored {
            let age = now.saturating_sub(stored.fetched_at);
            let listed = redirect::find(&stored.redirect_uris, redirect_uri).is_some();
            if age < REFRESH.as_secs() && (listed || age < MIN_REFETCH.as_secs()) {
                return Ok(stored.clone());
            }
        }
        let body = match fetcher.fetch(url.url()).await {
            Ok(body) => body,
            Err(error) => {
                return match stored {
                    // A document that was valid stays usable while its host is down.
                    Some(stored) if error.is_transient() => Ok(stored),
                    _ => Err(RegistrationError::Fetch(error)),
                };
            }
        };
        let metadata = document::parse(url, &body).map_err(RegistrationError::InvalidClient)?;
        let metadata = self.trusted_uris(metadata)?;
        let Some(mut registration) = stored else {
            return self.create_document(url, metadata, relay).await;
        };
        registration.redirect_uris = metadata.redirect_uris;
        registration.client_name = metadata.client_name;
        registration.fetched_at = now;
        self.write()?;
        self.inner
            .store
            .update(&registration)
            .await
            .map_err(unavailable)?;
        // Concurrent refreshes interleave their writes. Each one writes
        // Cognito after the store, then reads the store again until it
        // holds what Cognito got, so the last Cognito write is the store's.
        loop {
            let urls = callbacks(&registration.redirect_uris, relay);
            self.inner
                .app_clients
                .set_callback_urls(&registration.app_client, &urls)
                .await?;
            match self.inner.store.get(url.as_str()).await.map_err(unavailable)? {
                Some(stored)
                    if stored.app_client == registration.app_client
                        && callbacks(&stored.redirect_uris, relay) != urls =>
                {
                    self.write()?;
                    registration = stored;
                }
                _ => return Ok(registration),
            }
        }
    }

    /// Keeps the redirect URIs a code may be sent to, and refuses a
    /// document that keeps none.
    fn trusted_uris(&self, mut metadata: ClientMetadata) -> Result<ClientMetadata, RegistrationError> {
        let refused: Vec<String> = metadata
            .redirect_uris
            .iter()
            .filter(|u| !self.trusted(u))
            .cloned()
            .collect();
        metadata.redirect_uris.retain(|u| self.trusted(u));
        if metadata.redirect_uris.is_empty() {
            let reason = refused.first().map(|u| self.untrusted(u)).unwrap_or_default();
            return Err(RegistrationError::InvalidClient(reason));
        }
        Ok(metadata)
    }

    fn trusted(&self, uri: &str) -> bool {
        if !redirect::leaves_device(uri) {
            return true;
        }
        let host = Url::parse(uri).ok().and_then(|u| u.host_str().map(str::to_owned));
        self.inner
            .client_hosts
            .as_ref()
            .zip(host)
            .is_some_and(|(hosts, host)| hosts.contains(&host))
    }

    fn untrusted(&self, uri: &str) -> String {
        format!(
            "{uri}: https redirect URIs must be on a host this server trusts, and http ones on a loopback host"
        )
    }

    async fn create_document(
        &self,
        url: &DocumentUrl,
        metadata: ClientMetadata,
        relay: &str,
    ) -> Result<Registration, RegistrationError> {
        let name = metadata
            .client_name
            .clone()
            .unwrap_or_else(|| url.host().to_owned());
        let app_client = self
            .create(&name, &callbacks(&metadata.redirect_uris, relay))
            .await?;
        let registration = Registration {
            client_id: url.as_str().to_owned(),
            app_client: app_client.clone(),
            kind: RegistrationKind::Document,
            client_name: metadata.client_name,
            redirect_uris: metadata.redirect_uris,
            created_at: now(),
            last_used: None,
            fetched_at: now(),
        };
        let stored = self.inner.store.insert(registration).await.map_err(unavailable)?;
        if stored.app_client != app_client {
            // Another server registered the document first; use its client.
            let _ = self.inner.app_clients.delete(&app_client).await;
        }
        Ok(stored)
    }

    /// Creates an app client, within the registration limit and the write rate.
    async fn create(&self, name: &str, callbacks: &[String]) -> Result<ClientId, RegistrationError> {
        let count = self.inner.store.list().await.map_err(unavailable)?.len();
        if count >= self.inner.max_registrations {
            return Err(RegistrationError::Full);
        }
        self.write()?;
        let name = app_client_name(&self.inner.name_prefix, name);
        Ok(self.inner.app_clients.create(&name, callbacks).await?)
    }

    /// Counts a request-caused app-client write against the rate.
    fn write(&self) -> Result<(), RegistrationError> {
        let mut writes = self.inner.writes.lock().unwrap_or_else(|e| e.into_inner());
        while writes
            .front()
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(60))
        {
            writes.pop_front();
        }
        if writes.len() >= WRITES_PER_MINUTE {
            return Err(RegistrationError::Busy);
        }
        writes.push_back(Instant::now());
        Ok(())
    }

    /// Why cleanup removes `registration` at `now`, if it does.
    fn removal(&self, registration: &Registration, now: u64) -> Option<Removal> {
        if registration.redirect_uris.iter().any(|uri| !self.trusted(uri)) {
            return Some(Removal::Untrusted);
        }
        match registration.last_used {
            None if now.saturating_sub(registration.created_at) > self.inner.unused_after.as_secs() => {
                Some(Removal::Unused)
            }
            Some(at) if now.saturating_sub(at) > self.inner.idle_after.as_secs() => Some(Removal::Idle),
            _ => None,
        }
    }

    /// Removes registrations nobody uses, and their app clients: those that
    /// never completed a token request within `unused_after`, and those
    /// idle for longer than `idle_after`. Also removes those with an https
    /// redirect URI on a host no longer in `client_hosts`: the front sends
    /// them no codes, but their app client still lists the host as a
    /// callback, and Cognito's own authorize endpoint is public. And it
    /// deletes app clients with this registrar's name prefix that have no
    /// registration and are more than an hour old.
    ///
    /// A removed client's tokens are refused from then on, after at most a
    /// minute in servers that checked one of them recently.
    ///
    /// Run it on a schedule, such as daily, and at once after taking a host
    /// off `client_hosts`. Every registration is listed, and Cognito allows
    /// five app-client changes per second per pool, so a large cleanup
    /// takes a while.
    pub async fn cleanup(&self) -> Result<Cleanup, RegistrationError> {
        let mut report = Cleanup::default();
        let now = now();
        let registrations = self.inner.store.list().await.map_err(unavailable)?;
        let mut owned = BTreeSet::new();
        for registration in registrations {
            if self.removal(&registration, now).is_none() {
                owned.insert(registration.app_client);
                continue;
            }
            // A token request may have used it since the list, which took
            // a while to work through, or it may have been registered again.
            let current = self
                .inner
                .store
                .get(&registration.client_id)
                .await
                .map_err(unavailable)?;
            let removal = match &current {
                Some(current) if current.app_client == registration.app_client => self.removal(current, now),
                Some(_) => None,
                None => self.removal(&registration, now),
            };
            let Some(removal) = removal else {
                owned.extend(current.map(|current| current.app_client));
                continue;
            };
            self.inner.app_clients.delete(&registration.app_client).await?;
            self.inner
                .store
                .remove(&registration)
                .await
                .map_err(unavailable)?;
            match removal {
                Removal::Untrusted => report.untrusted += 1,
                Removal::Unused => report.unused += 1,
                Removal::Idle => report.idle += 1,
            }
        }
        let prefix = format!("{} ", self.inner.name_prefix);
        for app_client in self.inner.app_clients.list(&prefix).await? {
            if owned.contains(&app_client) {
                continue;
            }
            // Young ones may be on their way into the store.
            let created = self.inner.app_clients.created(&app_client).await?;
            let young = created.elapsed().is_ok_and(|age| age < Duration::from_secs(3600));
            let stored = self
                .inner
                .store
                .get_by_app_client(&app_client)
                .await
                .map_err(unavailable)?;
            if !young && stored.is_none() {
                self.inner.app_clients.delete(&app_client).await?;
                report.orphans += 1;
            }
        }
        Ok(report)
    }
}

/// The callback URLs Cognito gets for a client's redirect URIs: each as
/// written, except loopback ones, whose codes go through the front's relay.
fn callbacks(redirect_uris: &[String], relay: &str) -> Vec<String> {
    let mut urls: Vec<String> = redirect_uris
        .iter()
        .filter(|u| redirect::loopback(u).is_none())
        .cloned()
        .collect();
    if urls.len() < redirect_uris.len() {
        urls.push(relay.to_owned());
    }
    urls
}

/// Cognito allows `[\w\s+=,.@-]` and 128 characters in a client name.
fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " _+=,.@-".contains(c)
}

fn app_client_name(prefix: &str, name: &str) -> String {
    let name: String = name.chars().filter(|c| name_char(*c)).collect();
    let name = format!("{prefix} {}", name.trim());
    name.chars().take(128).collect()
}
