//! Cookies.
//!
//! [`Cookie`] and [`SetCookie`] are the two sides of the exchange — what a
//! client sends and what a server sets — and [`CookieJar`] is the client-side
//! store that turns one into the other across requests.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::Error;
use crate::helpers::sync::lock;
use crate::models::{Limits, Url};

/// The `SameSite` attribute of a cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Never sent on a cross-site request.
    Strict,
    /// Sent on a cross-site request only when it is a top-level navigation.
    Lax,
    /// Sent on every cross-site request; browsers require `Secure` alongside it.
    None,
}

impl SameSite {
    /// The attribute value as it belongs in a `Set-Cookie` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }

    /// Reads an attribute value, ignoring case. `None` when it names nothing.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "lax" => Some(Self::Lax),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// The contents of a `Cookie` field: the pairs a client sends back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cookie {
    /// The name and value pairs, in the order they were sent.
    pub pairs: Vec<(String, String)>,
}

impl Cookie {

    /// Whether an octet is a separator, and so cannot appear in a token.
    pub fn is_separator(byte: u8) -> bool {
        byte <= 0x20 || byte == 0x7f || b"()<>@,;:\\\"/[]?={}".contains(&byte)
    }
    /// An empty set of pairs.
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// The value stored under this exact name, if there is one.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// Reads a `Cookie` field value.
    ///
    /// Pairs with no `=`, and pairs with an empty name, are skipped; where a
    /// name repeats, the first pair wins. A value wrapped in double quotes is
    /// unwrapped. Parsing never fails — a malformed field yields whatever
    /// pairs could be read from it.
    pub fn parse(value: &str) -> Self {
        let mut cookie = Self::new();

        for part in value.split(';') {
            let Some((name, raw)) = part.split_once('=') else {
                continue;
            };

            let name = name.trim();
            if name.is_empty() || cookie.pairs.iter().any(|(key, _)| key == name) {
                continue;
            }

            cookie.pairs.push((name.to_owned(), raw.trim().trim_matches('"').to_owned()));
        }

        cookie
    }

    /// Writes the pairs back out as a `Cookie` field value.
    pub fn build(&self) -> String {
        self.pairs.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("; ")
    }
}

/// One `Set-Cookie` field: the cookie a server asks a client to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie {
    /// The cookie name, which must be a token.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// The `Expires` attribute, kept verbatim as the peer wrote it.
    pub expires: Option<String>,
    /// The `Max-Age` attribute in seconds; zero or less deletes the cookie.
    pub max_age: Option<i64>,
    /// The `Domain` attribute; absent makes the cookie host-only.
    pub domain: Option<String>,
    /// The `Path` attribute; absent defaults to [`StoredCookie::default_path`] of the request target.
    pub path: Option<String>,
    /// The `Secure` attribute, which confines the cookie to secure transports.
    pub secure: bool,
    /// The `HttpOnly` attribute, which hides the cookie from scripts.
    pub httponly: bool,
    /// The `SameSite` attribute.
    pub samesite: Option<SameSite>,
}

impl SetCookie {
    /// A cookie with no attributes set.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            httponly: false,
            samesite: None,
        }
    }

    /// Reads a `Set-Cookie` field value.
    ///
    /// Attribute names are matched case-insensitively, and ones that are not
    /// recognised are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the field carries no `name=value` pair.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let mut parts = value.split(';');

        let pair = parts.next().unwrap_or_default();
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| Error::Protocol("Set-Cookie has no name=value pair".into()))?;

        let mut cookie = Self::new(name.trim().to_owned(), value.trim().to_owned());

        for attribute in parts {
            let (key, raw) = match attribute.split_once('=') {
                Some((key, raw)) => (key.trim().to_ascii_lowercase(), raw.trim()),
                None => (attribute.trim().to_ascii_lowercase(), ""),
            };

            match key.as_str() {
                "expires" => cookie.expires = Some(raw.to_owned()),
                "max-age" => cookie.max_age = Self::age(raw),
                "domain" => cookie.domain = Some(raw.to_owned()),
                "path" => cookie.path = Some(raw.to_owned()),
                "secure" => cookie.secure = true,
                "httponly" => cookie.httponly = true,
                "samesite" => cookie.samesite = SameSite::parse(raw),
                _ => {}
            }
        }

        Ok(cookie)
    }

    /// Reads a `Max-Age` value: an optional `-` and then digits.
    ///
    /// `None` when the text is not that shape. A value too large for an `i64`
    /// saturates rather than failing.
    pub fn age(text: &str) -> Option<i64> {
        let (sign, digits) = match text.strip_prefix('-') {
            Some(rest) => (-1, rest),
            None => (1, text),
        };

        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }

        Some(sign * digits.parse::<i64>().unwrap_or(i64::MAX))
    }

    /// Writes the cookie out as a `Set-Cookie` field value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] when the name is not a token, or when the
    /// value carries an octet that would let it break out of the field —
    /// whitespace, a quote, a comma, a semicolon, a backslash, or anything
    /// outside printable ASCII.
    pub fn build(&self) -> Result<String, Error> {
        if self.name.is_empty() || self.name.bytes().any(Cookie::is_separator) {
            return Err(Error::Protocol(format!("cookie name {:?} is not a token", self.name)));
        }

        if self.value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte) || b" \",;\\".contains(&byte)) {
            return Err(Error::Protocol(format!("cookie value of {:?} carries a forbidden octet", self.name)));
        }

        let mut out = format!("{}={}", self.name, self.value);

        if let Some(expires) = &self.expires {
            out.push_str(&format!("; Expires={expires}"));
        }

        if let Some(max_age) = self.max_age {
            out.push_str(&format!("; Max-Age={max_age}"));
        }

        if let Some(domain) = &self.domain {
            out.push_str(&format!("; Domain={domain}"));
        }

        if let Some(path) = &self.path {
            out.push_str(&format!("; Path={path}"));
        }

        if self.secure {
            out.push_str("; Secure");
        }

        if self.httponly {
            out.push_str("; HttpOnly");
        }

        if let Some(samesite) = self.samesite {
            out.push_str(&format!("; SameSite={}", samesite.as_str()));
        }

        Ok(out)
    }
}

/// A cookie as a [`CookieJar`] holds it, with its attributes resolved.
///
/// A stored cookie differs from the [`SetCookie`] it came from in that the
/// domain and path have been filled in from the request when the server left
/// them out, and the lifetime has become a deadline on the local clock.
#[derive(Debug, Clone)]
pub struct StoredCookie {
    /// The cookie name.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// The domain this cookie belongs to, lowercased and without a leading dot.
    pub domain: String,
    /// Whether the cookie is confined to exactly `domain` rather than its subdomains.
    pub host_only: bool,
    /// The path prefix this cookie is scoped to.
    pub path: String,
    /// Whether the cookie may only travel over a secure transport.
    pub secure: bool,
    /// When the cookie expires; `None` makes it last as long as the jar does.
    pub expires: Option<Instant>,
}

impl StoredCookie {

    /// Whether a request target falls under a cookie's path.
    ///
    /// The two match when they are equal, or when the target continues past the
    /// cookie path at a `/` boundary.
    pub fn path_matches(target: &str, cookie_path: &str) -> bool {
        let request_path = target.split(['?', '#']).next().unwrap_or("/");
        if request_path == cookie_path {
            return true;
        }
        if let Some(rest) = request_path.strip_prefix(cookie_path) {
            return cookie_path.ends_with('/') || rest.starts_with('/');
        }
        false
    }

    /// The path a cookie takes when the server sets no `Path` attribute: the
    /// request target up to, but not including, its last `/`.
    pub fn default_path(target: &str) -> String {
        let path = target.split(['?', '#']).next().unwrap_or("/");
        match path.rfind('/') {
            Some(0) | None => "/".to_owned(),
            Some(index) => path[..index].to_owned(),
        }
    }
    /// Whether this cookie belongs on a request for `url` at `now`.
    ///
    /// The cookie has to be unexpired, allowed on the transport, and matched
    /// by both domain and path.
    pub fn matches(&self, url: &Url, now: Instant) -> bool {
        if self.expires.is_some_and(|expiry| expiry <= now) {
            return false;
        }

        if self.secure && !url.secure() {
            return false;
        }

        let host = url.host.to_ascii_lowercase();
        let domain_ok = if self.host_only {
            host == self.domain
        } else {
            host == self.domain || host.ends_with(&format!(".{}", self.domain))
        };

        domain_ok && Self::path_matches(&url.target, &self.path)
    }
}

/// The ceilings a [`CookieJar`] keeps itself under.
///
/// A jar's own, so a jar can be built and reasoned about without the rest of
/// the crate: nothing here is a protocol setting, and no protocol setting is
/// here. [`Limits`] converts into one for a caller configuring everything at
/// once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieLimits {
    /// The number of cookies one jar may hold across all origins.
    pub max_cookies: u32,
    /// The number of cookies one jar may hold for a single domain.
    pub max_cookies_per_domain: u16,
}

impl Default for CookieLimits {
    fn default() -> Self {
        Self { max_cookies: 3000, max_cookies_per_domain: 50 }
    }
}

impl From<Limits> for CookieLimits {
    fn from(limits: Limits) -> Self {
        Self { max_cookies: limits.max_cookies, max_cookies_per_domain: limits.max_cookies_per_domain }
    }
}

/// A client-side cookie store.
///
/// The jar is shared and internally locked, so a [`Client`] can hand the same
/// jar to every request it makes. Its size is bounded by
/// [`Limits::max_cookies`] and [`Limits::max_cookies_per_domain`], and the
/// oldest entry is evicted when either ceiling is reached.
///
/// [`Client`]: crate::api::client::Client
#[derive(Default)]
pub struct CookieJar {
    /// The cookies held, in the order they were stored.
    pub entries: Mutex<Vec<StoredCookie>>,
    /// The ceilings the jar keeps itself under.
    pub limits: CookieLimits,
}

impl CookieJar {

    /// Makes room for one more cookie in `domain`.
    ///
    /// Drops the oldest cookie for the domain when it is at
    /// [`Limits::max_cookies_per_domain`], and then the oldest cookies overall
    /// until the jar is under [`Limits::max_cookies`].
    pub fn evict(entries: &mut Vec<StoredCookie>, domain: &str, limits: &CookieLimits) {
        if entries.iter().filter(|stored| stored.domain == domain).count() >= limits.max_cookies_per_domain as usize
            && let Some(oldest) = entries.iter().position(|stored| stored.domain == domain)
        {
            entries.remove(oldest);
        }

        while entries.len() >= limits.max_cookies as usize {
            entries.remove(0);
        }
    }
    /// An empty jar with the default [`Limits`].
    pub fn new() -> Self {
        Self { entries: Mutex::new(Vec::new()), limits: CookieLimits::default() }
    }

    /// The same jar, bounded by `limits`.
    pub fn with_limits(mut self, limits: impl Into<CookieLimits>) -> Self {
        self.limits = limits.into();
        self
    }

    /// Takes in the `Set-Cookie` values a response for `url` carried.
    ///
    /// A cookie replaces any it shares a name, domain and path with. One whose
    /// `Max-Age` has already passed deletes rather than stores. Values that do
    /// not parse are skipped rather than failing the whole batch.
    pub fn learn(&self, url: &Url, values: &[&str], now: Instant) {
        let mut entries = lock(&self.entries);

        for value in values {
            let Ok(cookie) = SetCookie::parse(value) else {
                continue;
            };

            let (domain, host_only) = match &cookie.domain {
                Some(domain) => (domain.trim_start_matches('.').to_ascii_lowercase(), false),
                None => (url.host.to_ascii_lowercase(), true),
            };
            let path = cookie.path.clone().unwrap_or_else(|| StoredCookie::default_path(&url.target));

            let expires = cookie
                .max_age
                .and_then(|seconds| now.checked_add(Duration::from_secs(seconds.max(0) as u64)));

            let expired = cookie.max_age.is_some_and(|seconds| seconds <= 0);
            entries.retain(|stored| !(stored.name == cookie.name && stored.domain == domain && stored.path == path));

            if expired {
                continue;
            }

            entries.retain(|stored| !stored.expires.is_some_and(|expiry| expiry <= now));
            Self::evict(&mut entries, &domain, &self.limits);

            entries.push(StoredCookie {
                name: cookie.name,
                value: cookie.value,
                domain,
                host_only,
                path,
                secure: cookie.secure,
                expires,
            });
        }
    }

    /// The `Cookie` field value for a request to `url`, if any cookie matches.
    pub fn cookie(&self, url: &Url, now: Instant) -> Option<String> {
        let entries = lock(&self.entries);
        let pairs: Vec<String> = entries
            .iter()
            .filter(|cookie| cookie.matches(url, now))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();

        (!pairs.is_empty()).then(|| pairs.join("; "))
    }

    /// Drops every cookie that has expired by `now`.
    pub fn prune(&self, now: Instant) {
        lock(&self.entries).retain(|cookie| !cookie.expires.is_some_and(|expiry| expiry <= now));
    }
}

