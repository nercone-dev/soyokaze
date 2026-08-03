//! HTTP Strict Transport Security.
//!
//! [`HstsPolicy`] is the `Strict-Transport-Security` field itself: a server
//! builds one to send, a client parses one it received. [`HstsStore`] is the
//! client-side memory of which hosts have asked to be reached over TLS only,
//! which a [`Client`] consults before it dials.
//!
//! [`Client`]: crate::api::client::Client

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::helpers::sync::lock;
use crate::helpers::text::Text;
use crate::models::Limits;


/// One `Strict-Transport-Security` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsPolicy {
    /// How many seconds the policy holds for. Zero withdraws it.
    pub max_age: i64,
    /// Whether the policy covers subdomains as well as the host itself.
    pub include_subdomains: bool,
    /// Whether the host asks to be added to browser preload lists.
    pub preload: bool,
}

impl HstsPolicy {
    /// Appends as much of `part` to `out` as fits, advancing `written`.
    ///
    /// Truncates rather than growing or failing, which is what lets
    /// [`HstsPolicy::value`] build its field value on the stack.
    pub fn append(out: &mut [u8], written: &mut usize, part: &[u8]) {
        let end = (*written + part.len()).min(out.len());
        out[*written..end].copy_from_slice(&part[..end - *written]);
        *written = end;
    }

    /// A policy lasting `max_age` seconds, covering this host alone.
    pub fn new(max_age: i64) -> Self {
        Self { max_age, include_subdomains: false, preload: false }
    }

    /// The field value as a `String`.
    pub fn build(&self) -> String {
        self.value().into_string()
    }

    /// The field value.
    ///
    /// A negative `max_age` is written as zero. The value is built without
    /// allocating, since a server writes one on every secure response.
    pub fn value(&self) -> Text {
        let mut out = [0u8; 64];
        let mut written = 0;

        Self::append(&mut out, &mut written, b"max-age=");

        let mut digits = [0u8; 20];
        let mut index = digits.len();
        let mut age = self.max_age.max(0) as u64;

        loop {
            index -= 1;
            digits[index] = b'0' + (age % 10) as u8;
            age /= 10;

            if age == 0 {
                break;
            }
        }

        Self::append(&mut out, &mut written, &digits[index..]);

        if self.include_subdomains {
            Self::append(&mut out, &mut written, b"; includeSubDomains");
        }

        if self.preload {
            Self::append(&mut out, &mut written, b"; preload");
        }

        Text::from_ascii(&out[..written])
    }

    /// Reads a `Strict-Transport-Security` field value.
    ///
    /// Directive names are matched case-insensitively, and unrecognised ones
    /// are ignored. Returns `None` when a directive repeats, when `max-age` is
    /// missing, or when `max-age` is not a run of digits — a field that cannot
    /// be trusted must not be acted on at all.
    pub fn parse(value: &str) -> Option<Self> {
        let mut policy = Self { max_age: -1, include_subdomains: false, preload: false };
        let mut seen = HashSet::new();

        for directive in value.split(';') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            let (name, rest) = match directive.split_once('=') {
                Some((name, rest)) => (name.trim(), Some(rest.trim())),
                None => (directive, None),
            };

            let name = name.to_ascii_lowercase();
            if !seen.insert(name.clone()) {
                return None;
            }

            match name.as_str() {
                "max-age" => {
                    let digits = rest?.trim_matches('"');
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        return None;
                    }
                    policy.max_age = digits.parse().unwrap_or(i64::MAX);
                }
                "includesubdomains" => policy.include_subdomains = true,
                "preload" => policy.preload = true,
                _ => {}
            }
        }

        (policy.max_age >= 0).then_some(policy)
    }
}

/// The ceilings an [`HstsStore`] keeps itself under.
///
/// The store's own, for the same reason [`CookieLimits`] is the jar's.
///
/// [`CookieLimits`]: crate::cookies::CookieLimits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsLimits {
    /// The number of hosts one store may remember.
    pub max_hsts_entries: u32,
}

impl Default for HstsLimits {
    fn default() -> Self {
        Self { max_hsts_entries: 4096 }
    }
}

impl From<Limits> for HstsLimits {
    fn from(limits: Limits) -> Self {
        Self { max_hsts_entries: limits.max_hsts_entries }
    }
}

/// A client-side record of which hosts insist on TLS.
///
/// The store is shared and internally locked, so a [`Client`] can consult the
/// same store from every request. It holds at most
/// [`Limits::max_hsts_entries`] hosts, evicting whichever expires soonest to
/// make room.
///
/// [`Client`]: crate::api::client::Client
pub struct HstsStore {
    /// Host to expiry and whether the policy covers subdomains.
    pub entries: Mutex<HashMap<String, (Instant, bool)>>,
    /// The ceilings the store keeps itself under.
    pub limits: HstsLimits,
}

impl HstsStore {
    /// An empty store with the default [`Limits`].
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()), limits: HstsLimits::default() }
    }

    /// The same store, bounded by `limits`.
    pub fn with_limits(mut self, limits: impl Into<HstsLimits>) -> Self {
        self.limits = limits.into();
        self
    }

    /// The form of a host name the store keys on.
    ///
    /// Strips surrounding brackets and any trailing root dot, and lowercases
    /// the rest. Returns `None` for an empty name and for an IP address, since
    /// HSTS applies to host names only.
    pub fn normalize(host: &str) -> Option<String> {
        let host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');

        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return None;
        }

        Some(host.to_ascii_lowercase())
    }

    /// Takes in the `Strict-Transport-Security` field a response carried.
    ///
    /// Ignored outright unless the response arrived over a secure transport,
    /// since otherwise the field could have been injected. A `max-age` of zero
    /// or less withdraws the host instead of storing it. A field that does not
    /// parse, and a host that is an IP address, are ignored.
    pub fn learn(&self, host: &str, header: &str, secure: bool, now: Instant) {
        if !secure {
            return;
        }

        let Some(name) = Self::normalize(host) else {
            return;
        };

        let Some(policy) = HstsPolicy::parse(header) else {
            return;
        };

        let mut entries = lock(&self.entries);

        if policy.max_age <= 0 {
            entries.remove(&name);
            return;
        }

        let Some(expiry) = now.checked_add(Duration::from_secs(policy.max_age as u64)) else {
            return;
        };

        entries.retain(|_, (expiry, _)| *expiry > now);

        if entries.len() >= self.limits.max_hsts_entries as usize && !entries.contains_key(&name) {
            let soonest = entries.iter().min_by_key(|(_, (expiry, _))| *expiry).map(|(host, _)| host.clone());
            if let Some(soonest) = soonest {
                entries.remove(&soonest);
            }
        }

        entries.insert(name, (expiry, policy.include_subdomains));
    }

    /// Whether `host` must be reached over TLS.
    ///
    /// True when the host itself is stored, or when a parent domain is stored
    /// with `includeSubDomains`. Expired entries are dropped as they are found.
    pub fn secure(&self, host: &str, now: Instant) -> bool {
        let Some(name) = Self::normalize(host) else {
            return false;
        };

        let mut entries = lock(&self.entries);
        entries.retain(|_, (expiry, _)| *expiry > now);

        entries.iter().any(|(stored, (_, include_subdomains))| {
            &name == stored || (*include_subdomains && name.ends_with(&format!(".{stored}")))
        })
    }
}

impl Default for HstsStore {
    fn default() -> Self {
        Self::new()
    }
}
