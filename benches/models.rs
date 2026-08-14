//! The vocabulary a message is held in.
//!
//! [`Headers`], [`Message`], [`URL`] and the message-level concerns built on
//! them — cookies, HSTS, content codings, and what a response is finalised
//! with. These sit between the codecs and the connections: every request
//! crosses all of them once, whichever version framed it.
//!
//! The lookups are looked at twice over. Once at the size a request really
//! carries, which is what a served request pays; and once as a curve over how
//! much the structure holds, because a header set, a cookie jar and an HSTS
//! store all grow with what a peer sends and none of them is allowed to grow a
//! lookup with it.
//!
//! ```bash
//! cargo bench --bench models
//! cargo bench --bench models -- cookies
//! ```

mod support;

use std::hint::black_box;
use std::time::Instant;

use bytes::BytesMut;

use soyokaze::cookies::{Cookie, CookieJar, SetCookie};
use soyokaze::helpers::compression::Compression;
use soyokaze::hsts::{HSTSPolicy, HSTSStore};
use soyokaze::models::{ALPN, Body, HeaderCase, Headers, Message, Method, Port, URL, Version};
use soyokaze::responses::Status;
use soyokaze::DateCache;

use support::{Fixtures, Group, Payload, Section};

const COOKIE: &str = "session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB; theme=dark";
const SET_COOKIE: &str = "session=8f14e45fceea167a5a36dedd4bea2543; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax";

/// The origin every client-state fixture is measured against.
fn origin() -> URL {
    URL::parse("https://www.example.com/index.html").expect("the fixture URL did not parse")
}

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
    group.time("insert (a name already there)", || {
        let mut held = black_box(&filled).clone();
        held.insert("accept", "text/html");
        held
    });

    // The presence bitmap is what makes a lookup for a well-known name answer
    // without walking anything, so it is worth seeing on its own.
    group.time("well_known (a name that is)", || Headers::well_known(black_box("content-length")));
    group.time("well_known (a name that is not)", || Headers::well_known(black_box("x-forwarded-for")));
    group.time("presence (8 fields)", || Headers::presence(black_box(filled.fields())));

    let mut group = Group::new("models::Headers growth");
    group.growth("get, the first of many", Fixtures::COUNTS, Section::crowded, |held| black_box(held.get("x-forwarded-field-0")).is_some());
    group.growth("get, the last of many", Fixtures::COUNTS, |count| (Section::crowded(count), Section::field(count - 1)), |(held, name)| {
        black_box(held.get(name)).is_some()
    });
    group.growth("get, a name that is not there", Fixtures::COUNTS, Section::crowded, |held| black_box(held.get("x-absent")).is_some());
    group.growth("contains, a well-known name", Fixtures::COUNTS, Section::crowded, |held| black_box(held.contains("content-length")));
    group.growth("build a set of n fields", Fixtures::COUNTS, |count| count, |count| Section::crowded(*count));
    group.growth("iter", Fixtures::COUNTS, Section::crowded, |held| black_box(held.iter().count()));
    group.growth("clone", Fixtures::COUNTS, Section::crowded, |held| black_box(&*held).clone());
    group.growth("remove, the last of many", Fixtures::COUNTS, |count| (Section::crowded(count), Section::field(count - 1)), |(held, name)| {
        let mut held = held.clone();
        held.remove(name);
        held
    });
}

fn messages() {
    let mut group = Group::new("models::Message");
    for version in Fixtures::VERSIONS {
        group.time(&format!("request ({version})"), || Message::request(Method::GET, "/index.html", black_box(*version)));
        group.time(&format!("response ({version})"), || Message::response(200, black_box(*version)));
        group.time(&format!("text ({version})"), || Message::text("Hello, World!", black_box(*version)));
    }

    group.time("json", || Message::json(black_box("{\"ok\":true}"), Version::V1_1));
    group.time("redirect", || Message::redirect(black_box("https://www.example.com/"), Version::V1_1));
    group.time("file", || Message::file(black_box("/assets/app.module.js"), Version::V1_1));

    let fields = Section::request().headers();
    group.time("request with fields hung on it", || {
        let mut request = Message::request(Method::GET, "/index.html", black_box(Version::V2_0));
        request.headers = Some(fields.clone());
        request
    });

    let request = Section::request().message(Version::V2_0);
    let response = Section::response().message(Version::V1_1);
    group.time("bodyless (a response)", || black_box(&response).bodyless(Some(Method::GET)));
    group.time("compressed (a response)", || black_box(&response).compressed());
    group.time("accepted (a request)", || black_box(&request).accepted());
    group.time("codable (a response)", || black_box(&response).codable());
    group.time("tunneling (a request)", || black_box(&request).tunneling(Some(Method::GET)));

    // What compressing a response really costs, which is the codec plus
    // everything the message does around it — the negotiation, the field
    // rewrite and the body swap.
    let mut group = Group::new("models::Message content codings");
    for (name, octets) in [("4 KiB", 4096usize), ("64 KiB", 65_536)] {
        let plain = Payload::text(octets);

        for coding in Compression::CODINGS {
            group.throughput(&format!("compress {coding} ({name})"), octets, || {
                let mut held = carrying(black_box(&plain), Some(*coding), None);
                let _ = held.compress(None);
                held
            });

            let mut source = carrying(&plain, Some(*coding), None);
            source.compress(None).expect("the fixture did not compress");
            let encoded = source.body.and_then(|body| body.inline()).expect("the fixture lost its body");

            group.throughput(&format!("decompress {coding} ({name})"), octets, || {
                let mut held = carrying(black_box(&encoded), None, Some(*coding));
                let _ = held.decompress(1 << 24);
                held
            });
        }
    }
}

/// A response carrying this body.
///
/// `asked` is what [`Message::compress`] is to apply, and `applied` is what a
/// received body arrived under, which is what [`Message::decompress`] reads
/// off the fields. Built afresh for every iteration because a [`Message`] is
/// not cloneable; the body is shared rather than copied, so what that costs is
/// a header set and a refcount and not the octets.
fn carrying(body: &bytes::Bytes, asked: Option<Compression>, applied: Option<Compression>) -> Message {
    let mut message = Message::response(200, Version::V1_1);
    let mut headers = Headers::with_capacity(2);

    headers.append_lowercase("content-type", "text/html; charset=utf-8");

    if let Some(coding) = applied {
        headers.append_lowercase("content-encoding", coding.as_str());
    }

    message.headers = Some(headers);
    message.body = Some(Body::Data(body.clone()));
    message.compression = asked;
    message
}

fn urls() {
    let mut group = Group::new("models::URL::parse");
    for (name, url) in [
        ("origin only", "https://www.example.com/"),
        ("a long path", "https://www.example.com/assets/app.7f3c9a2b.module.js?v=3&locale=en-GB"),
        ("an explicit port", "https://www.example.com:8443/index.html"),
        ("an IPv6 literal", "https://[2001:db8::1]:8443/index.html"),
        ("a userinfo that is refused", "https://user:pass@www.example.com/"),
        ("a scheme that is not HTTP", "ftp://www.example.com/"),
    ] {
        group.throughput(name, url.len(), || URL::parse(black_box(url)));
    }

    let parsed = URL::parse("https://www.example.com:8443/index.html").expect("the fixture URL did not parse");
    group.time("URL::authority", || black_box(&parsed).authority());
    group.time("URL::secure", || black_box(&parsed).secure());
    group.time("URL::authority_of", || URL::authority_of(black_box("https"), "www.example.com", 8443));
    group.time("URL::default_port (https)", || URL::default_port(black_box("https")));
    group.time("URL::is_target", || URL::is_target(black_box("/assets/app.7f3c9a2b.module.js")));
    group.time("URL::is_authority", || URL::is_authority(black_box("www.example.com:8443")));
    group.time("URL::is_host", || URL::is_host(black_box("www.example.com")));

    group.growth("parse, over the target length", Fixtures::LENGTHS, |octets| format!("https://www.example.com/{}", "a".repeat(octets)), |url| {
        URL::parse(black_box(url))
    });
}

/// The small vocabulary every layer keys on: versions, transports, methods and
/// field-name casing.
///
/// Each of these is reached for at least once per message and most of them
/// several times, so a cost here is multiplied by everything above it.
fn vocabulary() {
    let mut group = Group::new("models::Version");
    for version in Fixtures::VERSIONS {
        group.time(&format!("alpn ({version})"), || black_box(version).alpn());
        group.time(&format!("transport ({version})"), || black_box(version).transport());
        group.time(&format!("as_str ({version})"), || black_box(version).as_str());
    }
    group.time("from_alpn (h2)", || Version::from_alpn(black_box(b"h2")));
    group.time("from_alpn (a token nothing offers)", || Version::from_alpn(black_box(b"spdy/3.1")));

    let mut group = Group::new("models::ALPN");
    let versions = Fixtures::VERSIONS;
    let offered = ALPN::list(versions);
    group.time("list (three versions)", || ALPN::list(black_box(versions)));
    group.time("wire (three versions)", || ALPN::wire(black_box(versions)));
    group.time("select (the first offered)", || ALPN::select(black_box(&offered), b"\x02h2\x08http/1.1"));
    group.time("select (nothing in common)", || ALPN::select(black_box(&offered), b"\x08spdy/3.1"));
    group.time("negotiated (h2)", || ALPN::negotiated(black_box(Some(b"h2")), versions));
    group.time("negotiated (nothing negotiated)", || ALPN::negotiated(black_box(None), versions));

    let mut group = Group::new("models::Port");
    for port in [Port::TCP(443), Port::QUIC(443)] {
        group.time(&format!("transport ({port:?})"), || black_box(&port).transport());
        group.time(&format!("carries http/2 ({port:?})"), || black_box(&port).carries(Version::V2_0));
        group.time(&format!("offers (three versions) ({port:?})"), || black_box(&port).offers(versions));
    }

    let mut group = Group::new("models::Method");
    group.time("as_str", || black_box(&Method::GET).as_str());
    group.time("safe (GET)", || black_box(&Method::GET).safe());
    group.time("idempotent (POST)", || black_box(&Method::POST).idempotent());

    let mut group = Group::new("models::HeaderCase");
    for case in [HeaderCase::Lower, HeaderCase::Title] {
        group.time(&format!("apply ({case:?})"), || black_box(&case).apply("content-type"));
        group.time(&format!("write ({case:?})"), || {
            let mut out = BytesMut::with_capacity(32);
            black_box(&case).write("content-type", &mut out);
            out
        });

        let mut written = b"content-type".to_vec();
        group.time(&format!("apply_in_place ({case:?})"), || black_box(&case).apply_in_place(&mut written));
    }
    group.time("from_version (http/2)", || HeaderCase::from_version(black_box(Version::V2_0)));

    let mut group = Group::new("models::Body");
    let data = Body::Data(Payload::of(4096));
    let text = Body::Text("Hello, World!".to_owned());
    group.time("len (data)", || black_box(&data).len());
    group.time("len (text)", || black_box(&text).len());
    group.time("is_empty (data)", || black_box(&data).is_empty());
    group.time("inline (data)", || black_box(&data).inline());
    group.time("clone (4 KiB of data)", || black_box(&data).clone());
}

fn cookies() {
    let mut group = Group::new("cookies::Cookie");
    group.throughput("parse (4 pairs)", COOKIE.len(), || Cookie::parse(black_box(COOKIE)));

    let jar_cookie = Cookie::parse(COOKIE);
    group.time("get (the first pair)", || black_box(&jar_cookie).get("session"));
    group.time("get (the last pair)", || black_box(&jar_cookie).get("theme"));
    group.time("get (a pair that is not there)", || black_box(&jar_cookie).get("absent"));
    group.throughput("build (4 pairs)", COOKIE.len(), || black_box(&jar_cookie).build());

    group.growth(
        "parse, over the pair count",
        Fixtures::COUNTS,
        |pairs| (0..pairs).map(|index| format!("name{index}=value{index}")).collect::<Vec<_>>().join("; "),
        |header| Cookie::parse(black_box(header)),
    );

    let mut group = Group::new("cookies::SetCookie");
    group.throughput("parse (every attribute)", SET_COOKIE.len(), || SetCookie::parse(black_box(SET_COOKIE)));
    group.time("parse (a name and value only)", || SetCookie::parse(black_box("session=8f14e45fceea167a5a36dedd4bea2543")));
    group.time("parse (an attribute that is refused)", || SetCookie::parse(black_box("session=1; Domain=example")));

    let set = SetCookie::parse(SET_COOKIE).expect("the fixture Set-Cookie did not parse");
    group.throughput("build (every attribute)", SET_COOKIE.len(), || black_box(&set).build());

    let mut group = Group::new("cookies::CookieJar");
    let url = origin();
    let now = Instant::now();

    group.time("learn (one cookie)", || {
        let jar = CookieJar::new();
        jar.learn(black_box(&url), &[SET_COOKIE], now);
        jar
    });

    let jar = CookieJar::new();
    jar.learn(&url, &[SET_COOKIE], now);
    group.time("cookie (one stored)", || jar.cookie(black_box(&url), now));
    group.time("prune (one stored)", || jar.prune(black_box(now)));

    // Two curves, because a jar grows two ways and only one of them is bounded
    // by what a single origin may store. `learn` is measured as the whole cost
    // of filling a jar rather than of one more cookie: a body that adds to the
    // structure it is measured against changes what the next iteration costs,
    // so the honest reading is the total, where a linear slope means each
    // cookie cost the same as the last.
    group.growth("cookie, over the cookies for this origin", Fixtures::PER_ORIGIN, stocked, |jar| {
        jar.cookie(black_box(&origin()), Instant::now())
    });
    group.growth("cookie, over the cookies for other origins", Fixtures::STORED, elsewhere, |jar| {
        jar.cookie(black_box(&origin()), Instant::now())
    });
    group.growth("fill a jar with n cookies", Fixtures::STORED, |count| count, |count| elsewhere(*count));
}

/// A jar already holding this many cookies for one origin.
fn stocked(cookies: usize) -> CookieJar {
    let jar = CookieJar::new();
    let url = origin();
    let now = Instant::now();

    for index in 0..cookies {
        jar.learn(&url, &[&format!("name{index}=value{index}; Path=/")], now);
    }

    jar
}

/// A jar holding one cookie each for this many other origins, and one for the
/// origin every lookup asks about.
///
/// What a jar really fills up with: a browser's jar holds a cookie for every
/// site it has visited, and a lookup for one of them must not pay for all the
/// rest.
fn elsewhere(origins: usize) -> CookieJar {
    let jar = CookieJar::new();
    let now = Instant::now();

    for index in 0..origins {
        let url = URL::parse(&format!("https://host{index}.example/index.html")).expect("the fixture URL did not parse");
        jar.learn(&url, &["name=value; Path=/"], now);
    }

    jar.learn(&origin(), &[SET_COOKIE], now);
    jar
}

fn hsts() {
    let mut group = Group::new("hsts::HSTSPolicy");
    group.time("parse", || HSTSPolicy::parse(black_box("max-age=31536000; includeSubDomains; preload")));
    group.time("parse (a value that is refused)", || HSTSPolicy::parse(black_box("max-age=; includeSubDomains")));

    let policy = HSTSPolicy::parse("max-age=31536000; includeSubDomains").expect("the fixture policy did not parse");
    group.time("build", || black_box(&policy).build());
    group.time("value", || black_box(&policy).value());

    let mut group = Group::new("hsts::HSTSStore");
    let now = Instant::now();

    let store = HSTSStore::new();
    store.learn("www.example.com", "max-age=31536000; includeSubDomains", true, now);
    group.time("secure (an exact match)", || store.secure(black_box("www.example.com"), now));
    group.time("secure (a subdomain)", || store.secure(black_box("api.www.example.com"), now));
    group.time("secure (a host never seen)", || store.secure(black_box("other.example"), now));
    group.time("normalize", || HSTSStore::normalize(black_box("WWW.Example.COM.")));

    group.growth("secure, over what the store holds", Fixtures::STORED, remembered, |store| store.secure(black_box("host0.example"), Instant::now()));
    group.growth("secure, a host never seen", Fixtures::STORED, remembered, |store| store.secure(black_box("absent.example"), Instant::now()));
    group.growth("fill a store with n hosts", Fixtures::STORED, |count| count, |count| remembered(*count));
}

/// A store already remembering this many hosts.
fn remembered(hosts: usize) -> HSTSStore {
    let store = HSTSStore::new();
    let now = Instant::now();

    for index in 0..hosts {
        store.learn(&format!("host{index}.example"), "max-age=31536000", true, now);
    }

    store
}

fn finalizing() {
    let mut group = Group::new("finalizer::DateCache");
    let cache = DateCache::new();

    group.time("now (the same second)", || black_box(&cache).now());
    group.time("format", || DateCache::format(black_box(1_382_386_401)));
    group.time("civil_from_days", || DateCache::civil_from_days(black_box(15_998)));

    let mut group = Group::new("message finalizing");
    let policy = HSTSPolicy::new(31_536_000);
    let section = Section::response();

    for version in Fixtures::VERSIONS {
        group.time(&format!("finalize_response, plaintext ({version})"), || {
            let mut response = black_box(&section).message(*version);
            response.security.secure = false;
            response.finalize_response(&cache, None);
            response
        });
    }

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

    let cookie = SetCookie::parse(SET_COOKIE).expect("the fixture Set-Cookie did not parse");
    group.time("set_cookie", || {
        let mut response = Message::response(200, black_box(Version::V1_1));
        let _ = response.set_cookie(&cookie);
        response
    });
}

fn main() {
    headers();
    messages();
    urls();
    vocabulary();
    cookies();
    hsts();
    finalizing();
}
