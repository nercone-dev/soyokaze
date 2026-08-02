use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::helpers::hsts::HstsPolicy;
use crate::helpers::text::Text;
use crate::models::{Headers, Message};

pub const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub const MONTH_NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

pub const DATE_LENGTH: usize = 29;

pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };

    (year + i64::from(month <= 2), month as u32, day as u32)
}

pub fn two_digits(value: u64, out: &mut [u8]) {
    out[0] = b'0' + (value / 10 % 10) as u8;
    out[1] = b'0' + (value % 10) as u8;
}

pub fn write_http_date(unix_seconds: u64, out: &mut [u8; DATE_LENGTH]) {
    let days = (unix_seconds / 86400) as i64;
    let seconds = unix_seconds % 86400;

    let weekday = (days + 4).rem_euclid(7) as usize;
    let (year, month, day) = civil_from_days(days);
    let year = year.clamp(0, 9999) as u64;

    out[..3].copy_from_slice(DAY_NAMES[weekday].as_bytes());
    out[3] = b',';
    out[4] = b' ';
    two_digits(day as u64, &mut out[5..7]);
    out[7] = b' ';
    out[8..11].copy_from_slice(MONTH_NAMES[(month - 1) as usize].as_bytes());
    out[11] = b' ';
    two_digits(year / 100, &mut out[12..14]);
    two_digits(year, &mut out[14..16]);
    out[16] = b' ';
    two_digits(seconds / 3600, &mut out[17..19]);
    out[19] = b':';
    two_digits(seconds % 3600 / 60, &mut out[20..22]);
    out[22] = b':';
    two_digits(seconds % 60, &mut out[23..25]);
    out[25..].copy_from_slice(b" GMT");
}

pub fn http_date(unix_seconds: u64) -> String {
    let mut out = [0u8; DATE_LENGTH];
    write_http_date(unix_seconds, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

pub struct DateCache;

thread_local! {
    pub static CACHED_DATE: Cell<(u64, [u8; DATE_LENGTH])> = const { Cell::new((0, [0; DATE_LENGTH])) };
}

impl DateCache {
    pub fn new() -> Self {
        Self
    }

    pub fn now(&self) -> Text {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0);

        CACHED_DATE.with(|cell| {
            let (cached, mut octets) = cell.get();

            if cached != seconds || octets[0] == 0 {
                write_http_date(seconds, &mut octets);
                cell.set((seconds, octets));
            }

            Text::from_verified_ascii(&octets)
        })
    }
}

impl Default for DateCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn date_cache() -> &'static DateCache {
    static CACHE: std::sync::OnceLock<DateCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(DateCache::new)
}

pub fn finalize_response(message: &mut Message, date: &DateCache, hsts: Option<&HstsPolicy>) {
    if !message.is_response() {
        return;
    }

    if message.status_code.unwrap_or(0) < 200 {
        return;
    }

    let headers = message.headers.get_or_insert_with(Headers::new);

    if !headers.contains("date") {
        headers.append_lowercase("date", date.now());
    }

    if !headers.contains("server") {
        headers.append_lowercase("server", "Soyokaze");
    }

    if let Some(policy) = hsts
        && message.secure
        && !headers.contains("strict-transport-security")
    {
        headers.append_lowercase("strict-transport-security", policy.value());
    }
}

pub fn finalize_request(message: &mut Message, authority: &str) {
    if !message.is_request() || message.version.major() != 1 {
        return;
    }

    let headers = message.headers.get_or_insert_with(Headers::new);

    if !headers.contains("host") {
        headers.append_lowercase("host", authority);
    }
}
