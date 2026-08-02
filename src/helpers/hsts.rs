use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::helpers::sync::lock;
use crate::helpers::text::Text;
use crate::models::Limits;

pub fn append(out: &mut [u8], written: &mut usize, part: &[u8]) {
    let end = (*written + part.len()).min(out.len());
    out[*written..end].copy_from_slice(&part[..end - *written]);
    *written = end;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsPolicy {
    pub max_age: i64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl HstsPolicy {
    pub fn new(max_age: i64) -> Self {
        Self { max_age, include_subdomains: false, preload: false }
    }

    pub fn build(&self) -> String {
        self.value().into_string()
    }

    pub fn value(&self) -> Text {
        let mut out = [0u8; 64];
        let mut written = 0;

        append(&mut out, &mut written, b"max-age=");

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

        append(&mut out, &mut written, &digits[index..]);

        if self.include_subdomains {
            append(&mut out, &mut written, b"; includeSubDomains");
        }

        if self.preload {
            append(&mut out, &mut written, b"; preload");
        }

        Text::from_ascii(&out[..written])
    }

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

pub struct HstsStore {
    pub entries: Mutex<HashMap<String, (Instant, bool)>>,
    pub limits: Limits,
}

impl HstsStore {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()), limits: Limits::default() }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn normalize(host: &str) -> Option<String> {
        let host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');

        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return None;
        }

        Some(host.to_ascii_lowercase())
    }

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
