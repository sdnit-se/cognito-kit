use std::error::Error as _;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use url::{Host, Url};

use crate::http_client::BoxError;

/// A boxed future, as the registration traits return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The draft's recommended limit for a Client ID Metadata Document.
const MAX_BYTES: usize = 5 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Why a Client ID Metadata Document could not be fetched.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The host is, or resolves to, an address that isn't public: private,
    /// loopback, link-local, or another special-use range (RFC 6890).
    #[error("{0} is not a public address")]
    Address(IpAddr),
    /// The response wasn't 200 OK. Redirects are never followed, so a 3xx
    /// ends here too.
    #[error("the document's URL answered {0}")]
    Status(u16),
    /// The body is larger than the limit.
    #[error("the document is larger than the limit")]
    TooLarge,
    /// No complete response within the time limit.
    #[error("the document took too long to arrive")]
    Timeout,
    /// DNS, the connection or TLS failed.
    #[error("the document could not be fetched")]
    Network(#[source] Arc<BoxError>),
}

impl FetchError {
    /// A failure that may pass: a timeout, a network error or a 5xx. A
    /// registration that was valid before stays usable through one.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Timeout | Self::Network(_) => true,
            Self::Status(status) => *status >= 500,
            Self::Address(_) | Self::TooLarge => false,
        }
    }
}

/// Fetches Client ID Metadata Documents for a
/// [`Registrar`](super::Registrar).
///
/// Implement it to fetch through your own egress, or to serve documents
/// from memory in tests. An implementation must refuse what
/// [`GuardedFetcher`] refuses, or a client id URL can make the server
/// request its own network.
pub trait FetchDocument: Send + Sync + 'static {
    /// The body of a 200 response to a GET for `url`.
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>>;
}

/// The default [`FetchDocument`]: https only, at most 5 KiB within five
/// seconds, no redirects and no proxy. Every address a host resolves to is
/// checked, and the connection goes to exactly the checked addresses, so a
/// DNS answer that changes between check and connect (DNS rebinding) can't
/// reach a private one.
#[derive(Clone)]
pub struct GuardedFetcher {
    client: reqwest::Client,
    policy: Policy,
    max_bytes: usize,
}

/// Which addresses a fetch may connect to. Tests open up their local server.
#[derive(Clone, Copy)]
enum Policy {
    Public,
    #[cfg(test)]
    PublicAnd(IpAddr),
}

impl Policy {
    fn allows(self, address: SocketAddr) -> bool {
        match self {
            Self::Public => is_public(address.ip()),
            #[cfg(test)]
            Self::PublicAnd(allowed) => address.ip() == allowed || is_public(address.ip()),
        }
    }
}

impl Default for GuardedFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardedFetcher {
    /// A fetcher with the default limits, trusting the system's root
    /// certificates.
    ///
    /// # Panics
    ///
    /// If the system has no root certificates to load.
    pub fn new() -> Self {
        let resolver = Guard {
            lookup: Arc::new(SystemLookup),
            policy: Policy::Public,
        };
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(crate::http_client::tls_config())
            .https_only(true)
            .dns_resolver(resolver)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .user_agent(concat!("cognito-kit/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest takes the rustls configuration");
        Self {
            client,
            policy: Policy::Public,
            max_bytes: MAX_BYTES,
        }
    }

    async fn get(&self, url: &Url) -> Result<Vec<u8>, FetchError> {
        // Literal addresses never reach the resolver.
        match url.host() {
            Some(Host::Ipv4(ip)) => self.check(SocketAddr::new(ip.into(), port(url)))?,
            Some(Host::Ipv6(ip)) => self.check(SocketAddr::new(ip.into(), port(url)))?,
            _ => {}
        }
        let mut response = self
            .client
            .get(url.as_str())
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(fetch_error)?;
        if response.status() != http::StatusCode::OK {
            return Err(FetchError::Status(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.max_bytes as u64)
        {
            return Err(FetchError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(fetch_error)? {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(FetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn check(&self, address: SocketAddr) -> Result<(), FetchError> {
        if self.policy.allows(address) {
            Ok(())
        } else {
            Err(FetchError::Address(address.ip()))
        }
    }
}

impl FetchDocument for GuardedFetcher {
    fn fetch<'a>(&'a self, url: &'a Url) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        Box::pin(self.get(url))
    }
}

fn port(url: &Url) -> u16 {
    url.port_or_known_default().unwrap_or(443)
}

/// Finds a refused address or a timeout in reqwest's error chain.
fn fetch_error(error: reqwest::Error) -> FetchError {
    if error.is_timeout() {
        return FetchError::Timeout;
    }
    let mut source = error.source();
    while let Some(inner) = source {
        if let Some(refused) = inner.downcast_ref::<FetchError>() {
            return refused.clone();
        }
        source = inner.source();
    }
    FetchError::Network(Arc::new(error.into()))
}

trait Lookup: Send + Sync + 'static {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>>;
}

struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host, 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// reqwest's resolver: it resolves once per connection and connects only to
/// the addresses it returns, so checking them here pins the connection.
struct Guard {
    lookup: Arc<dyn Lookup>,
    policy: Policy,
}

impl reqwest::dns::Resolve for Guard {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let lookup = self.lookup.lookup(name.as_str().to_owned());
        let policy = self.policy;
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = lookup
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            // One refused address refuses the name: a mixed answer is how
            // rebinding services hand out a private address.
            if let Some(refused) = addresses.iter().find(|a| !policy.allows(**a)) {
                return Err(Box::new(FetchError::Address(refused.ip())) as BoxError);
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Special-use IPv4 blocks (RFC 6890 and its updates), as (network, prefix length).
const V4_SPECIAL: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8, "this network"
    (0x0a00_0000, 8),  // 10.0.0.0/8, private
    (0x6440_0000, 10), // 100.64.0.0/10, shared address space
    (0x7f00_0000, 8),  // 127.0.0.0/8, loopback
    (0xa9fe_0000, 16), // 169.254.0.0/16, link-local (cloud metadata services)
    (0xac10_0000, 12), // 172.16.0.0/12, private
    (0xc000_0000, 24), // 192.0.0.0/24, protocol assignments
    (0xc000_0200, 24), // 192.0.2.0/24, documentation
    (0xc058_6300, 24), // 192.88.99.0/24, 6to4 relay
    (0xc0a8_0000, 16), // 192.168.0.0/16, private
    (0xc612_0000, 15), // 198.18.0.0/15, benchmarking
    (0xc633_6400, 24), // 198.51.100.0/24, documentation
    (0xcb00_7100, 24), // 203.0.113.0/24, documentation
    (0xe000_0000, 4),  // 224.0.0.0/4, multicast
    (0xf000_0000, 4),  // 240.0.0.0/4, reserved and broadcast
];

/// Special-use blocks inside IPv6 global unicast (2000::/3).
const V6_SPECIAL: &[(u128, u8)] = &[
    (0x2001_0000_u128 << 96, 23), // 2001::/23, protocol assignments (Teredo and others)
    (0x2001_0db8_u128 << 96, 32), // 2001:db8::/32, documentation
    (0x2002_0000_u128 << 96, 16), // 2002::/16, 6to4
    (0x3fff_0000_u128 << 96, 20), // 3fff::/20, documentation
];

fn in_v4(ip: u32, (network, prefix): (u32, u8)) -> bool {
    ip & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0) == network
}

fn in_v6(ip: u128, (network, prefix): (u128, u8)) -> bool {
    ip & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0) == network
}

/// Whether a server may fetch from `ip`: a globally routable unicast
/// address. IPv4 inside an IPv6 address (mapped, or NAT64's well-known
/// prefix) is judged as the IPv4 address it reaches.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    !V4_SPECIAL.iter().any(|block| in_v4(ip, *block))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let bits = u128::from(ip);
    if in_v6(bits, (0x0064_ff9b_u128 << 96, 96)) {
        return public_v4(Ipv4Addr::from(bits as u32));
    }
    in_v6(bits, (0x2000_u128 << 112, 3)) && !V6_SPECIAL.iter().any(|block| in_v6(bits, *block))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A resolver that answers from a script, one answer per lookup, and
    /// counts lookups.
    struct Scripted {
        answers: Mutex<Vec<Vec<IpAddr>>>,
        lookups: Arc<AtomicUsize>,
    }

    impl Lookup for Scripted {
        fn lookup(&self, _host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            let answer = if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            };
            Box::pin(async move { Ok(answer) })
        }
    }

    /// A fetcher whose DNS answers come from `answers`, over plain http
    /// when `test_server` is set so a local server can play the client's
    /// host; only that one socket is opened up.
    fn fetcher(
        answers: Vec<Vec<IpAddr>>,
        test_server: Option<SocketAddr>,
        timeout: Duration,
    ) -> (GuardedFetcher, Arc<AtomicUsize>) {
        let lookups = Arc::new(AtomicUsize::new(0));
        let policy = test_server.map_or(Policy::Public, |server| Policy::PublicAnd(server.ip()));
        let resolver = Guard {
            lookup: Arc::new(Scripted {
                answers: Mutex::new(answers),
                lookups: lookups.clone(),
            }),
            policy,
        };
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(crate::http_client::tls_config())
            .https_only(test_server.is_none())
            .dns_resolver(resolver)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .unwrap();
        let fetcher = GuardedFetcher {
            client,
            policy,
            max_bytes: MAX_BYTES,
        };
        (fetcher, lookups)
    }

    /// A loopback server that counts connections and answers each with `response`.
    async fn server(
        response: impl Fn() -> Vec<Vec<u8>> + Send + Sync + 'static,
        pause: Duration,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let parts = response();
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let _ = socket.read(&mut request).await;
                    for part in parts {
                        if socket.write_all(&part).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(pause).await;
                    }
                });
            }
        });
        (address, connections)
    }

    fn ok(body: &str) -> Vec<Vec<u8>> {
        vec![
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        ]
    }

    fn url(host: &str, address: SocketAddr, scheme: &str) -> Url {
        format!("{scheme}://{host}:{}/oauth/client.json", address.port())
            .parse()
            .unwrap()
    }

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn refuses_special_use_addresses_and_their_ipv6_spellings() {
        let refused = [
            "127.0.0.1",
            "10.1.2.3",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "2001::1",
            "::127.0.0.1",
            "100::1",
        ];
        for ip in refused {
            assert!(!is_public(ip.parse().unwrap()), "{ip} must be refused");
        }
        for ip in [
            "93.184.215.14",
            "1.1.1.1",
            "2606:4700::1111",
            "2a00:1450:4010::64",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[tokio::test]
    async fn never_connects_to_a_name_that_resolves_to_a_private_address() {
        let (address, connections) = server(|| ok("{}"), Duration::ZERO).await;
        for answer in [vec![LOOPBACK], vec!["1.1.1.1".parse().unwrap(), LOOPBACK]] {
            let (fetcher, _) = fetcher(vec![answer], None, TIMEOUT);
            let error = fetcher
                .get(&url("client.example", address, "https"))
                .await
                .unwrap_err();
            assert!(
                matches!(error, FetchError::Address(ip) if ip == LOOPBACK),
                "{error:?}"
            );
        }
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn never_connects_to_a_private_address_written_into_the_url() {
        let (address, connections) = server(|| ok("{}"), Duration::ZERO).await;
        let (fetcher, lookups) = fetcher(vec![vec![]], None, TIMEOUT);
        for host in ["127.0.0.1", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "2130706433"] {
            let error = fetcher.get(&url(host, address, "https")).await.unwrap_err();
            assert!(matches!(error, FetchError::Address(_)), "{host}: {error:?}");
        }
        let metadata = "https://169.254.169.254/latest/meta-data/".parse().unwrap();
        assert!(matches!(
            fetcher.get(&metadata).await,
            Err(FetchError::Address(_))
        ));
        assert_eq!(connections.load(Ordering::SeqCst), 0);
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn checks_the_address_it_connects_to_when_dns_rebinds() {
        let (address, connections) = server(|| ok("{}"), Duration::ZERO).await;
        // First a public answer, then loopback for anyone who asks again.
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        let (fetcher, lookups) = fetcher(
            vec![vec![public], vec![LOOPBACK]],
            None,
            Duration::from_millis(500),
        );
        let first = fetcher.get(&url("rebind.example", address, "https")).await;
        assert!(
            first.is_err(),
            "nothing serves the document at the public address"
        );
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            1,
            "the checked answer is the one connected to"
        );
        let second = fetcher
            .get(&url("rebind.example", address, "https"))
            .await
            .unwrap_err();
        assert!(
            matches!(second, FetchError::Address(ip) if ip == LOOPBACK),
            "{second:?}"
        );
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn does_not_follow_a_redirect() {
        let (inside, inside_connections) = server(|| ok("{}"), Duration::ZERO).await;
        let location = format!("http://127.0.0.1:{}/latest/meta-data/", inside.port());
        let (outside, _) = server(
            move || {
                vec![
                    format!("HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n")
                        .into_bytes(),
                ]
            },
            Duration::ZERO,
        )
        .await;
        let (fetcher, _) = fetcher(vec![vec![LOOPBACK]], Some(outside), TIMEOUT);
        let error = fetcher
            .get(&url("client.example", outside, "http"))
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Status(302)), "{error:?}");
        assert_eq!(inside_connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stops_reading_a_document_over_the_limit() {
        let big = format!("{{\"client_name\":\"{}\"}}", "a".repeat(MAX_BYTES));
        let declared = big.clone();
        let (declared_size, _) = server(move || ok(&declared), Duration::ZERO).await;
        // Without a length up front, the body is cut off while it streams.
        let (streamed, _) = server(
            || {
                let chunk = format!("400\r\n{}\r\n", "a".repeat(0x400)).into_bytes();
                let mut parts = vec![b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec()];
                parts.extend(std::iter::repeat_n(chunk, 1024));
                parts
            },
            Duration::ZERO,
        )
        .await;
        for address in [declared_size, streamed] {
            let (fetcher, _) = fetcher(vec![vec![LOOPBACK]], Some(address), TIMEOUT);
            let error = fetcher
                .get(&url("client.example", address, "http"))
                .await
                .unwrap_err();
            assert!(matches!(error, FetchError::TooLarge), "{error:?}");
        }
    }

    #[tokio::test]
    async fn gives_up_on_a_server_that_trickles_its_answer() {
        let (address, _) = server(
            || {
                let mut parts = vec![b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n".to_vec()];
                parts.extend(std::iter::repeat_n(b" ".to_vec(), 100));
                parts
            },
            Duration::from_millis(100),
        )
        .await;
        let (fetcher, _) = fetcher(vec![vec![LOOPBACK]], Some(address), Duration::from_millis(500));
        let started = std::time::Instant::now();
        let error = fetcher
            .get(&url("client.example", address, "http"))
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Timeout), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn fetches_a_document_within_the_limits() {
        let (address, _) = server(|| ok("{\"client_id\":\"x\"}"), Duration::ZERO).await;
        let (fetcher, _) = fetcher(vec![vec![LOOPBACK]], Some(address), TIMEOUT);
        let body = fetcher
            .get(&url("client.example", address, "http"))
            .await
            .unwrap();
        assert_eq!(body, b"{\"client_id\":\"x\"}");
    }
}
