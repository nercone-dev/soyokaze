//! The fields an endpoint fills in for itself just before a message goes out.
//!
//! [`ResponseFinalizer`] and [`RequestFinalizer`] are the pair: every
//! connection holds one of each and applies both on the way out, and each does
//! nothing for the role and the kind of message that is not its own. A server
//! owes a response its `Date`, `Server` and HSTS fields, through
//! [`Message::finalize_response`]; a client owes a request the authority it
//! was dialled with, through [`Message::finalize_request`].
//!
//! The date machinery here exists because formatting an HTTP date is otherwise
//! done once per response: [`DateCache`] keeps the formatted second in
//! thread-local storage and reformats only when the clock ticks.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hsts::HstsPolicy;
use crate::helpers::text::Text;
use crate::models::{Headers, Message, Role};

/// Weekday names as an HTTP date spells them, indexed from Sunday.
pub const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
/// Month names as an HTTP date spells them, indexed from January.
pub const MONTH_NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// The length of an HTTP date, which is fixed: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const DATE_LENGTH: usize = 29;

/// A handle on the per-thread HTTP date cache.
///
/// The cache itself is thread-local, so this holds nothing and costs nothing
/// to make or copy; it exists to give the cache a name a caller can pass
/// around. A response is stamped at most one date format per thread per
/// second, however many responses go out in that second.
pub struct DateCache;

thread_local! {
    /// The last second formatted on this thread, and its formatted form.
    pub static CACHED_DATE: Cell<(u64, [u8; DATE_LENGTH])> = const { Cell::new((0, [0; DATE_LENGTH])) };
}

impl DateCache {

    /// The proleptic Gregorian year, month and day for a count of days since
    /// the Unix epoch.
    ///
    /// Month and day are one-based.
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

    /// Writes the last two decimal digits of `value` into the first two octets
    /// of `out`.
    ///
    /// # Panics
    ///
    /// Panics when `out` is shorter than two octets.
    pub fn two_digits(value: u64, out: &mut [u8]) {
        out[0] = b'0' + (value / 10 % 10) as u8;
        out[1] = b'0' + (value % 10) as u8;
    }

    /// Writes an HTTP date for `unix_seconds` into `out`.
    ///
    /// The result is always in GMT and always [`DATE_LENGTH`] octets long.
    /// Years are clamped to four digits so the length never changes.
    pub fn write(unix_seconds: u64, out: &mut [u8; DATE_LENGTH]) {
        let days = (unix_seconds / 86400) as i64;
        let seconds = unix_seconds % 86400;

        let weekday = (days + 4).rem_euclid(7) as usize;
        let (year, month, day) = Self::civil_from_days(days);
        let year = year.clamp(0, 9999) as u64;

        out[..3].copy_from_slice(DAY_NAMES[weekday].as_bytes());
        out[3] = b',';
        out[4] = b' ';
        Self::two_digits(day as u64, &mut out[5..7]);
        out[7] = b' ';
        out[8..11].copy_from_slice(MONTH_NAMES[(month - 1) as usize].as_bytes());
        out[11] = b' ';
        Self::two_digits(year / 100, &mut out[12..14]);
        Self::two_digits(year, &mut out[14..16]);
        out[16] = b' ';
        Self::two_digits(seconds / 3600, &mut out[17..19]);
        out[19] = b':';
        Self::two_digits(seconds % 3600 / 60, &mut out[20..22]);
        out[22] = b':';
        Self::two_digits(seconds % 60, &mut out[23..25]);
        out[25..].copy_from_slice(b" GMT");
    }

    /// [`DateCache::write`], returning the date as a string.
    ///
    /// Use [`DateCache::now`] instead when stamping responses; this allocates
    /// each time.
    pub fn format(unix_seconds: u64) -> String {
        let mut out = [0u8; DATE_LENGTH];
        Self::write(unix_seconds, &mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The shared handle the connections stamp responses through.
    pub fn shared() -> &'static Self {
        static CACHE: std::sync::OnceLock<DateCache> = std::sync::OnceLock::new();
        CACHE.get_or_init(DateCache::new)
    }
    /// A handle on this thread's cache.
    pub fn new() -> Self {
        Self
    }

    /// The current time as an HTTP date, reformatting only when the second has turned.
    ///
    /// A clock that fails to read falls back to the Unix epoch rather than failing.
    pub fn now(&self) -> Text {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0);

        CACHED_DATE.with(|cell| {
            let (cached, mut octets) = cell.get();

            if cached != seconds || octets[0] == 0 {
                Self::write(seconds, &mut octets);
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

/// The finalisation a server connection applies to a response on the way out.
///
/// The counterpart of [`RequestFinalizer`]: every version's connection holds
/// one and calls it the same way, so the stamping of transport facts and the
/// fields of [`Message::finalize_response`] happen once, here, rather than
/// once per protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseFinalizer {
    /// The HSTS policy to attach to responses, if any.
    pub hsts: Option<HstsPolicy>,
}

impl ResponseFinalizer {
    /// A finalizer attaching `hsts`, when there is a policy to attach.
    pub fn new(hsts: Option<HstsPolicy>) -> Self {
        Self { hsts }
    }

    /// Finalises a response about to leave a server connection.
    ///
    /// Does nothing on a client, or to a request: only a server owes the
    /// response its `Date`, `Server` and HSTS fields, and only a response
    /// carries them.
    pub fn finalize(&self, role: Role, secure: bool, message: &mut Message) {
        if role.is_server() && message.is_response() {
            message.security.secure = secure;
            message.finalize_response(DateCache::shared(), self.hsts.as_ref());
        }
    }
}

impl Message {
    /// Fills in the fields a server owes on a response.
    ///
    /// Adds `Date` and `Server` when the handler left them out, and
    /// `Strict-Transport-Security` when a policy is configured and the message
    /// went over a secure transport. Nothing the handler set is overwritten.
    ///
    /// Requests and informational (1xx) responses are left alone: a 1xx is
    /// followed by the real response, which carries the fields instead.
    pub fn finalize_response(&mut self, date: &DateCache, hsts: Option<&HstsPolicy>) {
        if !self.is_response() {
            return;
        }

        if self.status_code.unwrap_or(0) < 200 {
            return;
        }

        let headers = self.headers.get_or_insert_with(Headers::new);

        if !headers.contains("date") {
            headers.append_lowercase("date", date.now());
        }

        if !headers.contains("server") {
            headers.append_lowercase("server", "Soyokaze");
        }

        if let Some(policy) = hsts
            && self.security.secure
            && !headers.contains("strict-transport-security")
        {
            headers.append_lowercase("strict-transport-security", policy.value());
        }
    }

    /// Fills in the fields a client owes on a request.
    ///
    /// Adds `Host` when the caller left it out. Nothing here is version
    /// specific: HTTP/1.x puts the authority in `Host` and sends it as it
    /// stands, and HTTP/2 and HTTP/3 frame the same field as `:authority`,
    /// which is what [`Fields::of`] does with it. Responses are left alone.
    ///
    /// [`Fields::of`]: crate::protocol::common::Fields::of
    pub fn finalize_request(&mut self, authority: &str) {
        if !self.is_request() {
            return;
        }

        let headers = self.headers.get_or_insert_with(Headers::new);

        if !headers.contains("host") {
            headers.append_lowercase("host", authority);
        }
    }
}

/// The finalisation a client connection applies to a request on the way out.
///
/// The counterpart of [`ResponseFinalizer`]: every version's connection holds
/// one and calls it the same way, so the fields of
/// [`Message::finalize_request`] are supplied once, here, rather than once per
/// protocol or — worse — once per caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestFinalizer {
    /// The authority the connection was dialled with, if it is known.
    ///
    /// A connection built over a transport the caller already had knows no
    /// authority, and leaves this unset rather than inventing one.
    pub authority: Option<Text>,
}

impl RequestFinalizer {
    /// A finalizer supplying `authority`, when there is one to supply.
    pub fn new(authority: Option<impl Into<Text>>) -> Self {
        Self { authority: authority.map(Into::into) }
    }

    /// Finalises a request about to leave a client connection.
    ///
    /// Does nothing on a server, or to a response: only a client owes the
    /// request its authority, and only a request carries one.
    pub fn finalize(&self, role: Role, message: &mut Message) {
        if let Some(authority) = &self.authority
            && role.is_client()
            && message.is_request()
        {
            message.finalize_request(authority);
        }
    }
}
