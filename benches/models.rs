//! The vocabulary a message is held in.
//!
//! [`Headers`], [`Message`], [`URL`] and the message-level concerns built on
//! them — cookies, HSTS, and what a response is finalised with. These sit
//! between the codecs and the connections: every request crosses all of them
//! once, whichever version framed it.
//!
//! ```bash
//! cargo bench --bench models
//! cargo bench --bench models -- cookies
//! ```

mod support;

use std::hint::black_box;
use std::time::Instant;

use soyokaze::cookies::{Cookie, CookieJar, SetCookie};
use soyokaze::hsts::{HSTSPolicy, HSTSStore};
use soyokaze::models::{Headers, Message, Method, URL, Version};
use soyokaze::responses::Status;
use soyokaze::DateCache;

use support::{Group, Section};

const COOKIE: &str = "session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB; theme=dark";
const SET_COOKIE: &str = "session=8f14e45fceea167a5a36dedd4bea2543; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax";

fn headers() {
    let section = Section::request();
    let filled = section.headers();

    let mut group = Group::new("models::Headers");
    group.throughput("append (8 fields)", section.octets(), || {
        let mut headers = Headers::with_capacity(8);
        for (name, value) in black_box(&filled).iter() {
            headers.append(name, value);
        }
        headers
    });

    group.time("get (a well-known name)", || black_box(&filled).get("user-agent"));
    group.time("get (a name that is not there)", || black_box(&filled).get("x-absent"));
    group.time("contains (a well-known name)", || black_box(&filled).contains("cookie"));
    group.time("absent (a name that is not there)", || black_box(&filled).absent("x-absent"));
    group.time("get_all (one match)", || black_box(&filled).get_all("accept").count());
    group.time("iter (8 fields)", || black_box(&filled).iter().count());
    group.time("clone (8 fields)", || black_box(&filled).clone());

    let mut group = Group::new("models::Headers (crowded)");
    let mut crowded = Headers::with_capacity(64);
    for index in 0..64 {
        crowded.append(format!("x-field-{index}"), "value");
    }

    group.time("get, first of 64", || black_box(&crowded).get("x-field-0"));
    group.time("get, last of 64", || black_box(&crowded).get("x-field-63"));
    group.time("get, none of 64", || black_box(&crowded).get("x-absent"));
    group.time("remove, last of 64", || {
        let mut held = black_box(&crowded).clone();
        held.remove("x-field-63");
        held
    });
}

fn messages() {
    let mut group = Group::new("models::Message");
    for version in [Version::V1_1, Version::V2_0, Version::V3_0] {
        group.time(&format!("request ({version})"), || Message::request(Method::GET, "/index.html", black_box(version)));
        group.time(&format!("response ({version})"), || Message::response(200, black_box(version)));
        group.time(&format!("text ({version})"), || Message::text("Hello, World!", black_box(version)));
    }

    group.time("json", || Message::json(black_box("{\"ok\":true}"), Version::V1_1));
    group.time("redirect", || Message::redirect(black_box("https://www.example.com/"), Version::V1_1));

    let fields = Section::request().headers();
    group.time("request with fields hung on it", || {
        let mut request = Message::request(Method::GET, "/index.html", black_box(Version::V2_0));
        request.headers = Some(fields.clone());
        request
    });

    let mut group = Group::new("models::URL::parse");
    for (name, url) in [
        ("origin only", "https://www.example.com/"),
        ("a long path", "https://www.example.com/assets/app.7f3c9a2b.module.js?v=3&locale=en-GB"),
        ("an explicit port", "https://www.example.com:8443/index.html"),
        ("an IPv6 literal", "https://[2001:db8::1]:8443/index.html"),
    ] {
        group.throughput(name, url.len(), || URL::parse(black_box(url)));
    }

    let parsed = URL::parse("https://www.example.com:8443/index.html").expect("the fixture URL did not parse");
    group.time("URL::authority", || black_box(&parsed).authority());
}

fn cookies() {
    let mut group = Group::new("cookies::Cookie");
    group.throughput("parse (4 pairs)", COOKIE.len(), || Cookie::parse(black_box(COOKIE)));

    let jar_cookie = Cookie::parse(COOKIE);
    group.time("get (the first pair)", || black_box(&jar_cookie).get("session"));
    group.time("get (the last pair)", || black_box(&jar_cookie).get("theme"));
    group.throughput("build (4 pairs)", COOKIE.len(), || black_box(&jar_cookie).build());

    let mut group = Group::new("cookies::SetCookie");
    group.throughput("parse (every attribute)", SET_COOKIE.len(), || SetCookie::parse(black_box(SET_COOKIE)));

    let set = SetCookie::parse(SET_COOKIE).expect("the fixture Set-Cookie did not parse");
    group.throughput("build (every attribute)", SET_COOKIE.len(), || black_box(&set).build());

    let mut group = Group::new("cookies::CookieJar");
    let url = URL::parse("https://www.example.com/index.html").expect("the fixture URL did not parse");
    let now = Instant::now();

    group.time("learn (one cookie)", || {
        let jar = CookieJar::new();
        jar.learn(black_box(&url), &[SET_COOKIE], now);
        jar
    });

    let jar = CookieJar::new();
    jar.learn(&url, &[SET_COOKIE], now);
    group.time("cookie (one stored)", || jar.cookie(black_box(&url), now));

    let crowded = CookieJar::new();
    for index in 0..64 {
        crowded.learn(&url, &[&format!("name{index}=value{index}; Path=/")], now);
    }
    group.time("cookie (64 stored)", || crowded.cookie(black_box(&url), now));
}

fn hsts() {
    let mut group = Group::new("hsts::HSTSPolicy");
    group.time("parse", || HSTSPolicy::parse(black_box("max-age=31536000; includeSubDomains; preload")));

    let policy = HSTSPolicy::parse("max-age=31536000; includeSubDomains").expect("the fixture policy did not parse");
    group.time("build", || black_box(&policy).build());

    let mut group = Group::new("hsts::HSTSStore");
    let now = Instant::now();

    let store = HSTSStore::new();
    store.learn("www.example.com", "max-age=31536000; includeSubDomains", true, now);
    group.time("secure (an exact match)", || store.secure(black_box("www.example.com"), now));
    group.time("secure (a subdomain)", || store.secure(black_box("api.www.example.com"), now));
    group.time("secure (a host never seen)", || store.secure(black_box("other.example"), now));

    let crowded = HSTSStore::new();
    for index in 0..1_000 {
        crowded.learn(&format!("host{index}.example"), "max-age=31536000", true, now);
    }
    group.time("secure (1000 stored)", || crowded.secure(black_box("host999.example"), now));
    group.time("learn (1000 stored)", || crowded.learn(black_box("host500.example"), "max-age=31536000", true, now));
}

fn finalizing() {
    let mut group = Group::new("finalizer::DateCache");
    let cache = DateCache::new();

    group.time("now (the same second)", || black_box(&cache).now());
    group.time("format", || DateCache::format(black_box(1_382_386_401)));

    let mut group = Group::new("message finalizing");
    let policy = HSTSPolicy::new(31_536_000);
    let section = Section::response();

    group.time("finalize_response (plaintext)", || {
        let mut response = black_box(&section).message(Version::V1_1);
        response.security.secure = false;
        response.finalize_response(&cache, None);
        response
    });

    group.time("finalize_response (secure, with HSTS)", || {
        let mut response = black_box(&section).message(Version::V1_1);
        response.finalize_response(&cache, Some(&policy));
        response
    });

    group.time("finalize_request", || {
        let mut request = Message::request(Method::GET, "/index.html", black_box(Version::V1_1));
        request.finalize_request(Some("www.example.com"));
        request
    });

    let mut group = Group::new("responses::Status");
    group.time("reason (200)", || Status::reason(black_box(200)));
    group.time("reason (451)", || Status::reason(black_box(451)));
    group.time("reason (a code with no reason)", || Status::reason(black_box(299)));
    group.time("content_type (a known suffix)", || Message::content_type(black_box("/assets/app.module.js")));
    group.time("content_type (an unknown suffix)", || Message::content_type(black_box("/assets/app.unknown")));
}

fn main() {
    headers();
    messages();
    cookies();
    hsts();
    finalizing();
}
