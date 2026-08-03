use std::time::{Duration, Instant};

use soyokaze::cookies::{self, StoredCookie};
use soyokaze::models::Url;
use soyokaze::{Cookie, CookieJar, SameSite, SetCookie};

fn url(text: &str) -> Url {
    Url::parse(text).expect("a fixture URL did not parse")
}

#[test]
fn parses_a_cookie_header() {
    let cookie = Cookie::parse("session=abc123; theme=dark");

    assert_eq!(cookie.get("session"), Some("abc123"));
    assert_eq!(cookie.get("theme"), Some("dark"));
    assert_eq!(cookie.get("missing"), None);
    assert_eq!(cookie.build(), "session=abc123; theme=dark");
}

#[test]
fn cookie_parsing_trims_space_and_quotes_and_keeps_the_first_of_a_name() {
    let cookie = Cookie::parse("  a = \"one\" ; a=two; ; no-equals; b=");

    assert_eq!(cookie.get("a"), Some("one"), "the first value of a name wins");
    assert_eq!(cookie.get("b"), Some(""));
    assert_eq!(cookie.pairs.len(), 2, "a pair with no '=' is skipped");
}

#[test]
fn parses_a_set_cookie_header() {
    let cookie = SetCookie::parse(
        "session=abc123; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600; \
         Domain=example.test; Path=/app; Secure; HttpOnly; SameSite=Lax",
    )
    .expect("a well-formed Set-Cookie did not parse");

    assert_eq!(cookie.name, "session");
    assert_eq!(cookie.value, "abc123");
    assert_eq!(cookie.expires.as_deref(), Some("Wed, 21 Oct 2015 07:28:00 GMT"));
    assert_eq!(cookie.max_age, Some(3600));
    assert_eq!(cookie.domain.as_deref(), Some("example.test"));
    assert_eq!(cookie.path.as_deref(), Some("/app"));
    assert!(cookie.secure && cookie.httponly);
    assert_eq!(cookie.samesite, Some(SameSite::Lax));
}

#[test]
fn set_cookie_attributes_are_case_insensitive() {
    let cookie = SetCookie::parse("a=1; SECURE; httponly; samesite=STRICT").expect("a Set-Cookie did not parse");

    assert!(cookie.secure && cookie.httponly);
    assert_eq!(cookie.samesite, Some(SameSite::Strict));
}

#[test]
fn refuses_a_set_cookie_with_no_pair() {
    assert!(SetCookie::parse("").is_err());
    assert!(SetCookie::parse("nonsense; Path=/").is_err());
}

#[test]
fn a_max_age_must_be_a_signed_run_of_digits() {
    assert_eq!(SetCookie::age("0"), Some(0));
    assert_eq!(SetCookie::age("-1"), Some(-1));
    assert_eq!(SetCookie::age(""), None);
    assert_eq!(SetCookie::age("+1"), None);
    assert_eq!(SetCookie::age("1.5"), None);

    assert_eq!(SetCookie::age("99999999999999999999999"), Some(i64::MAX));
}

#[test]
fn builds_a_set_cookie_header() {
    let mut cookie = SetCookie::new("session", "abc123");
    cookie.max_age = Some(3600);
    cookie.domain = Some("example.test".to_owned());
    cookie.path = Some("/".to_owned());
    cookie.secure = true;
    cookie.httponly = true;
    cookie.samesite = Some(SameSite::None);

    assert_eq!(
        cookie.build().ok().as_deref(),
        Some("session=abc123; Max-Age=3600; Domain=example.test; Path=/; Secure; HttpOnly; SameSite=None"),
    );
}

#[test]
fn refuses_to_build_a_cookie_that_would_not_survive_the_wire() {
    assert!(SetCookie::new("", "value").build().is_err(), "a name is required");
    assert!(SetCookie::new("bad name", "value").build().is_err(), "a name must be a token");
    assert!(SetCookie::new("name", "with;semicolon").build().is_err());
    assert!(SetCookie::new("name", "with space").build().is_err());
    assert!(SetCookie::new("name", "with\"quote").build().is_err());
    assert!(SetCookie::new("name", "with\\backslash").build().is_err());

    assert!(SetCookie::new("name", "").build().is_ok(), "an empty value is legitimate");
}

#[test]
fn same_site_values_round_trip() {
    for value in [SameSite::Strict, SameSite::Lax, SameSite::None] {
        assert_eq!(SameSite::parse(value.as_str()), Some(value));
        assert_eq!(SameSite::parse(&value.as_str().to_ascii_uppercase()), Some(value));
    }

    assert_eq!(SameSite::parse("nonsense"), None);
}

#[test]
fn paths_match_by_segment() {
    assert!(cookies::StoredCookie::path_matches("/app", "/app"));
    assert!(cookies::StoredCookie::path_matches("/app/page", "/app"));
    assert!(cookies::StoredCookie::path_matches("/app/page", "/app/"));
    assert!(cookies::StoredCookie::path_matches("/app?q=1", "/app"));
    assert!(cookies::StoredCookie::path_matches("/anything", "/"));
    assert!(!cookies::StoredCookie::path_matches("/application", "/app"));
    assert!(!cookies::StoredCookie::path_matches("/other", "/app"));
}

#[test]
fn a_default_path_is_the_directory_of_the_target() {
    assert_eq!(cookies::StoredCookie::default_path("/app/page.html"), "/app");
    assert_eq!(cookies::StoredCookie::default_path("/app/sub/page"), "/app/sub");
    assert_eq!(cookies::StoredCookie::default_path("/page"), "/");
    assert_eq!(cookies::StoredCookie::default_path("/"), "/");
    assert_eq!(cookies::StoredCookie::default_path("/app/page?q=1"), "/app");
}

#[test]
fn a_stored_cookie_matches_the_host_it_was_set_for() {
    let now = Instant::now();

    let host_only = StoredCookie {
        name: "a".into(),
        value: "1".into(),
        domain: "example.test".into(),
        host_only: true,
        path: "/".into(),
        secure: false,
        expires: None,
    };

    assert!(host_only.matches(&url("http://example.test/"), now));
    assert!(!host_only.matches(&url("http://api.example.test/"), now));

    let with_subdomains = StoredCookie { host_only: false, ..host_only.clone() };
    assert!(with_subdomains.matches(&url("http://api.example.test/"), now));
    assert!(!with_subdomains.matches(&url("http://notexample.test/"), now));

    let secure = StoredCookie { secure: true, ..host_only.clone() };
    assert!(secure.matches(&url("https://example.test/"), now));
    assert!(!secure.matches(&url("http://example.test/"), now), "a secure cookie is not sent in the clear");

    let expired = StoredCookie { expires: Some(now), ..host_only };
    assert!(!expired.matches(&url("http://example.test/"), now));
}

#[test]
fn the_jar_learns_and_returns_a_cookie() {
    let jar = CookieJar::new();
    let now = Instant::now();

    jar.learn(&url("https://example.test/app/page"), &["session=abc123; Max-Age=3600"], now);

    assert_eq!(jar.cookie(&url("https://example.test/app/other"), now).as_deref(), Some("session=abc123"));
    assert_eq!(jar.cookie(&url("https://example.test/elsewhere"), now), None, "the default path is /app");
}

#[test]
fn a_later_set_cookie_replaces_the_earlier_one() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &["a=1"], now);
    jar.learn(&target, &["a=2"], now);

    assert_eq!(jar.cookie(&target, now).as_deref(), Some("a=2"));
}

#[test]
fn a_max_age_of_zero_removes_a_cookie() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &["a=1"], now);
    jar.learn(&target, &["a=1; Max-Age=0"], now);

    assert_eq!(jar.cookie(&target, now), None);
}

#[test]
fn the_jar_forgets_a_cookie_once_it_expires() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &["a=1; Max-Age=60"], now);
    assert!(jar.cookie(&target, now).is_some());
    assert_eq!(jar.cookie(&target, now + Duration::from_secs(61)), None);

    jar.prune(now + Duration::from_secs(61));
    assert_eq!(jar.cookie(&target, now), None, "pruning should have dropped it for good");
}

#[test]
fn the_jar_skips_a_set_cookie_it_cannot_parse() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &["nonsense", "a=1"], now);
    assert_eq!(jar.cookie(&target, now).as_deref(), Some("a=1"));
}

#[test]
fn the_jar_joins_every_matching_cookie() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &["a=1", "b=2"], now);

    let joined = jar.cookie(&target, now).expect("no cookies matched");
    assert!(joined.contains("a=1") && joined.contains("b=2") && joined.contains("; "));
}

#[test]
fn a_domain_cannot_fill_the_jar_with_new_names() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    let ceiling = jar.limits.max_cookies_per_domain as usize;

    for index in 0..(ceiling * 4) {
        jar.learn(&target, &[&format!("name{index}=value")], now);
    }

    let held = jar.entries.lock().expect("the jar was poisoned").len();
    assert!(held <= ceiling, "one host stored {held} cookies");
}

#[test]
fn many_hosts_cannot_fill_the_jar_either() {
    let jar = CookieJar::new();
    let now = Instant::now();

    let ceiling = jar.limits.max_cookies as usize;

    for index in 0..(ceiling + 64) {
        let target = url(&format!("https://host{index}.test/"));
        jar.learn(&target, &["session=value"], now);
    }

    let held = jar.entries.lock().expect("the jar was poisoned").len();
    assert!(held <= ceiling, "the jar stored {held} cookies");
}

#[test]
fn an_expired_cookie_makes_room_for_a_new_one() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    for index in 0..jar.limits.max_cookies_per_domain {
        jar.learn(&target, &[&format!("name{index}=value; Max-Age=1")], now);
    }

    let later = now + Duration::from_secs(2);
    jar.learn(&target, &["fresh=value", "other=value"], later);

    assert_eq!(jar.cookie(&target, later).as_deref(), Some("fresh=value; other=value"));
}

#[test]
fn an_unreachable_expiry_does_not_overflow_the_clock() {
    let jar = CookieJar::new();
    let now = Instant::now();
    let target = url("https://example.test/");

    jar.learn(&target, &[&format!("session=value; Max-Age={}", i64::MAX)], now);

    assert_eq!(jar.cookie(&target, now).as_deref(), Some("session=value"));
}

/// A jar's ceilings are its own, not the whole crate's.
///
/// A cookie jar that cannot be built without QPACK timeouts and HTTP/2 window
/// sizes is not a cookie jar; these are the only two numbers it needs.
#[test]
fn a_jar_is_built_from_its_own_limits() {
    let jar = CookieJar::new().with_limits(soyokaze::CookieLimits { max_cookies: 2, max_cookies_per_domain: 1 });
    let now = Instant::now();

    jar.learn(&url("https://a.test/"), &["one=1"], now);
    jar.learn(&url("https://b.test/"), &["two=2"], now);
    jar.learn(&url("https://c.test/"), &["three=3"], now);

    assert!(jar.entries.lock().expect("poisoned").len() <= 2, "the jar kept more than its ceiling");
}

#[test]
fn the_whole_limits_still_configure_a_jar() {
    let limits = soyokaze::Limits { max_cookies: 7, ..soyokaze::Limits::default() };
    let jar = CookieJar::new().with_limits(limits);

    assert_eq!(jar.limits.max_cookies, 7);
    assert_eq!(jar.limits.max_cookies_per_domain, soyokaze::Limits::default().max_cookies_per_domain);
}
