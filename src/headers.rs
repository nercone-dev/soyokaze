use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::errors::Error;
use crate::helpers::sync::lock;
use crate::models::{Headers, Limits, Url, Version};

pub fn keep_alive(headers: Option<&Headers>, version: Version) -> bool {
    let mut close = false;
    let mut keep = false;

    if let Some(headers) = headers {
        for value in headers.get_all("connection") {
            for token in value.split(',') {
                let token = token.trim();

                if token.eq_ignore_ascii_case("close") {
                    close = true;
                } else if token.eq_ignore_ascii_case("keep-alive") {
                    keep = true;
                }
            }
        }
    }

    if close {
        return false;
    }

    match version {
        Version::V1_0 => keep,
        _ => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "lax" => Some(Self::Lax),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cookie {
    pub pairs: Vec<(String, String)>,
}

impl Cookie {
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

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

    pub fn build(&self) -> String {
        self.pairs.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("; ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub expires: Option<String>,
    pub max_age: Option<i64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<SameSite>,
}

impl SetCookie {
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

    pub fn build(&self) -> Result<String, Error> {
        if self.name.is_empty() || self.name.bytes().any(is_separator) {
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

pub fn is_separator(byte: u8) -> bool {
    byte <= 0x20 || byte == 0x7f || b"()<>@,;:\\\"/[]?={}".contains(&byte)
}

#[derive(Debug, Clone)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub host_only: bool,
    pub path: String,
    pub secure: bool,
    pub expires: Option<Instant>,
}

impl StoredCookie {
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

        domain_ok && path_matches(&url.target, &self.path)
    }
}

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

pub fn default_path(target: &str) -> String {
    let path = target.split(['?', '#']).next().unwrap_or("/");
    match path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(index) => path[..index].to_owned(),
    }
}

#[derive(Default)]
pub struct CookieJar {
    pub entries: Mutex<Vec<StoredCookie>>,
    pub limits: Limits,
}

impl CookieJar {
    pub fn new() -> Self {
        Self { entries: Mutex::new(Vec::new()), limits: Limits::default() }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

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
            let path = cookie.path.clone().unwrap_or_else(|| default_path(&url.target));

            let expires = cookie
                .max_age
                .and_then(|seconds| now.checked_add(Duration::from_secs(seconds.max(0) as u64)));

            let expired = cookie.max_age.is_some_and(|seconds| seconds <= 0);
            entries.retain(|stored| !(stored.name == cookie.name && stored.domain == domain && stored.path == path));

            if expired {
                continue;
            }

            entries.retain(|stored| !stored.expires.is_some_and(|expiry| expiry <= now));
            evict(&mut entries, &domain, &self.limits);

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

    pub fn cookie(&self, url: &Url, now: Instant) -> Option<String> {
        let entries = lock(&self.entries);
        let pairs: Vec<String> = entries
            .iter()
            .filter(|cookie| cookie.matches(url, now))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();

        (!pairs.is_empty()).then(|| pairs.join("; "))
    }

    pub fn prune(&self, now: Instant) {
        lock(&self.entries).retain(|cookie| !cookie.expires.is_some_and(|expiry| expiry <= now));
    }
}

pub fn evict(entries: &mut Vec<StoredCookie>, domain: &str, limits: &Limits) {
    if entries.iter().filter(|stored| stored.domain == domain).count() >= limits.max_cookies_per_domain as usize
        && let Some(oldest) = entries.iter().position(|stored| stored.domain == domain)
    {
        entries.remove(oldest);
    }

    while entries.len() >= limits.max_cookies as usize {
        entries.remove(0);
    }
}
