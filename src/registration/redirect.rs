use url::Url;

/// Cognito refuses longer callback URLs.
const MAX_LEN: usize = 1024;

/// Schemes that would run code or read local files instead of returning
/// to an app.
const UNSAFE_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
    "about",
    "filesystem",
];

pub(crate) fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Checks a redirect URI a client registers: https, http on a loopback
/// host, or an app's own scheme; absolute, without credentials or a
/// fragment, and written as URL parsing writes it, so that the string a
/// client sends later can be compared without normalizing.
pub(crate) fn check(uri: &str) -> Result<Url, String> {
    let url = Url::parse(uri).map_err(|_| format!("{uri:?} is not an absolute URL"))?;
    let refuse = |why: &str| Err(format!("{uri}: {why}"));
    if uri.len() > MAX_LEN {
        return refuse("longer than 1024 characters");
    }
    if url.as_str() != uri {
        return refuse("not in normalized form");
    }
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return refuse("has a fragment or credentials");
    }
    match url.scheme() {
        "https" if url.host().is_some() => Ok(url),
        "http" if is_loopback_host(&url) => Ok(url),
        "http" | "https" => refuse("http is allowed only on localhost, 127.0.0.1 and [::1]"),
        scheme if UNSAFE_SCHEMES.contains(&scheme) => refuse("not a scheme an app can receive a code on"),
        _ => Ok(url),
    }
}

/// Whether `requested` is one of the `registered` URIs: the same string, or
/// for http on a loopback host the same URI on any port (RFC 8252 section
/// 7.3), since native clients listen on a port the system picks.
pub(crate) fn find<'a>(registered: &'a [String], requested: &str) -> Option<&'a str> {
    if let Some(exact) = registered.iter().find(|r| *r == requested) {
        return Some(exact);
    }
    let requested = loopback(requested)?;
    registered.iter().map(String::as_str).find(|r| {
        loopback(r).is_some_and(|r| {
            r.host_str() == requested.host_str()
                && r.path() == requested.path()
                && r.query() == requested.query()
        })
    })
}

/// The URI as a loopback http URL, if it is one in normalized form.
pub(crate) fn loopback(uri: &str) -> Option<Url> {
    let url = Url::parse(uri).ok()?;
    (url.scheme() == "http" && is_loopback_host(&url) && url.as_str() == uri && url.fragment().is_none())
        .then_some(url)
}

/// Whether a code sent to `uri` leaves the user's device: an https URL on
/// a host other than a loopback one.
pub(crate) fn leaves_device(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| url.scheme() == "https" && !is_loopback_host(&url))
}
