use std::str::FromStr;

use bytes::Bytes;

use soyokaze::models::{Body, HeaderCase, Headers, Message, Method, Port, Role, URL, Version};
use soyokaze::helpers::compression::Compression;
use soyokaze::{Error, SetCookie};

#[test]
fn parses_an_ordinary_url() {
    let url = URL::parse("https://example.test/index.html?q=1#top").expect("a plain URL did not parse");

    assert_eq!(url.scheme, "https");
    assert_eq!(url.host, "example.test");
    assert_eq!(url.port, 443);
    assert_eq!(url.target, "/index.html?q=1#top");
    assert!(url.secure());
}

#[test]
fn fills_in_the_default_port_and_target() {
    let http = URL::parse("http://example.test").expect("a bare URL did not parse");
    assert_eq!((http.port, http.target.as_str()), (80, "/"));
    assert!(!http.secure());

    assert_eq!(URL::parse("wss://example.test").ok().map(|url| url.port), Some(443));
    assert_eq!(URL::parse("ws://example.test").ok().map(|url| url.port), Some(80));
    assert_eq!(URL::default_port("https"), 443);
    assert_eq!(URL::default_port("anything-else"), 80);
}

#[test]
fn lowercases_the_scheme_and_drops_userinfo() {
    let url = URL::parse("HTTPS://user:pass@example.test/").expect("a URL with userinfo did not parse");

    assert_eq!(url.scheme, "https");
    assert_eq!(url.host, "example.test");
}

#[test]
fn parses_an_address_literal() {
    let url = URL::parse("https://[2001:db8::1]:8443/path").expect("an IPv6 URL did not parse");

    assert_eq!(url.host, "2001:db8::1");
    assert_eq!(url.port, 8443);
    assert_eq!(url.authority(), "[2001:db8::1]:8443");

    let default = URL::parse("https://[2001:db8::1]/").expect("an IPv6 URL did not parse");
    assert_eq!(default.authority(), "[2001:db8::1]");
}

#[test]
fn omits_the_port_from_an_authority_when_it_is_the_default() {
    let url = URL::parse("https://example.test/").expect("a URL did not parse");
    assert_eq!(url.authority(), "example.test");

    let explicit = URL::parse("https://example.test:8443/").expect("a URL did not parse");
    assert_eq!(explicit.authority(), "example.test:8443");
}

#[test]
fn refuses_a_url_it_cannot_use() {
    for text in [
        "example.test/",
        "https://",
        "https://example.test:http/",
        "https://[2001:db8::1/",
        "https://[2001:db8::1]x/",
    ] {
        assert!(matches!(URL::parse(text), Err(Error::Protocol(_))), "{text:?} should not parse");
    }
}

#[test]
fn versions_map_to_and_from_their_wire_forms() {
    for (version, alpn, text, major) in [
        (Version::V1_0, "http/1.0", "HTTP/1.0", 1),
        (Version::V1_1, "http/1.1", "HTTP/1.1", 1),
        (Version::V2_0, "h2", "HTTP/2", 2),
        (Version::V3_0, "h3", "HTTP/3", 3),
    ] {
        assert_eq!(version.alpn(), alpn);
        assert_eq!(version.as_str(), text);
        assert_eq!(version.to_string(), text);
        assert_eq!(version.major(), major);
        assert_eq!(Version::from_alpn(alpn.as_bytes()), Some(version));
        assert_eq!(Version::from_str(text), Ok(version));
    }

    assert_eq!(Version::from_alpn(b"spdy/3"), None);
    assert_eq!(Version::from_str("HTTP/9"), Err(()));
}

#[test]
fn methods_map_to_and_from_their_names() {
    for method in [
        Method::GET, Method::HEAD, Method::POST, Method::PUT, Method::DELETE,
        Method::CONNECT, Method::OPTIONS, Method::TRACE, Method::PATCH,
    ] {
        assert_eq!(Method::from_str(method.as_str()), Ok(method));
        assert_eq!(method.to_string(), method.as_str());
    }

    assert_eq!(Method::from_str("get"), Err(()), "method names are case sensitive");
    assert_eq!(Method::from_str("BREW"), Err(()));
}

#[test]
fn safe_methods_are_idempotent_and_writes_mostly_are_not() {
    assert!(Method::GET.safe() && Method::GET.idempotent());
    assert!(Method::HEAD.safe() && Method::OPTIONS.safe() && Method::TRACE.safe());

    assert!(!Method::PUT.safe() && Method::PUT.idempotent());
    assert!(!Method::DELETE.safe() && Method::DELETE.idempotent());
    assert!(!Method::POST.safe() && !Method::POST.idempotent());
    assert!(!Method::PATCH.idempotent());
}

#[test]
fn roles_split_into_clients_and_servers() {
    assert!(Role::UserAgent.is_client() && Role::Proxy.is_client());
    assert!(Role::Origin.is_server() && Role::Gateway.is_server());
    assert!(!Role::Tunnel.is_client() && !Role::Tunnel.is_server());
}

#[test]
fn header_case_follows_the_version() {
    assert_eq!(HeaderCase::from_version(Version::V1_1), HeaderCase::Title);
    assert_eq!(HeaderCase::from_version(Version::V2_0), HeaderCase::Lower);
    assert_eq!(HeaderCase::from_version(Version::V3_0), HeaderCase::Lower);
}

#[test]
fn header_case_rewrites_a_name() {
    assert_eq!(HeaderCase::Title.apply("content-type"), "Content-Type");
    assert_eq!(HeaderCase::Title.apply("SEC-WEBSOCKET-KEY"), "Sec-Websocket-Key");
    assert_eq!(HeaderCase::Title.apply("x"), "X");
    assert_eq!(HeaderCase::Title.apply(""), "");
    assert_eq!(HeaderCase::Lower.apply("Content-Type"), "content-type");
}

#[test]
fn header_lookup_ignores_case_and_keeps_every_value() {
    let mut headers = Headers::new();
    headers.append("Accept", "text/html");
    headers.append("accept", "application/json");

    assert!(headers.contains("ACCEPT"));
    assert_eq!(headers.get("Accept"), Some("text/html"), "get returns the first value");
    assert_eq!(headers.get_all("accept").collect::<Vec<_>>(), ["text/html", "application/json"]);
    assert_eq!(headers.len(), 2);
    assert_eq!(headers.iter().map(|(name, _)| name).collect::<Vec<_>>(), ["accept", "accept"]);
}

#[test]
fn inserting_replaces_and_removing_reports_whether_it_did() {
    let mut headers = Headers::new();
    headers.append("accept", "text/html");
    headers.append("accept", "application/json");

    headers.insert("Accept", "*/*");
    assert_eq!(headers.get_all("accept").collect::<Vec<_>>(), ["*/*"]);

    assert!(headers.remove("ACCEPT"));
    assert!(!headers.remove("accept"));
    assert!(headers.is_empty());
}

#[tokio::test]
async fn a_body_reports_its_length_and_octets() {
    let data = Body::Data(Bytes::from_static(b"abc"));
    assert_eq!(data.len(), Some(3));
    assert_eq!(data.inline().as_deref(), Some(&b"abc"[..]));
    assert_eq!(data.bytes().await.ok().as_deref(), Some(&b"abc"[..]));

    let text = Body::Text("hello".to_owned());
    assert_eq!(text.len(), Some(5));
    assert!(!text.is_empty());

    let file = Body::File("/nonexistent".to_owned());
    assert_eq!(file.len(), None);
    assert_eq!(file.inline(), None);
    assert!(file.bytes().await.is_err());
}

#[tokio::test]
async fn a_file_body_reads_from_disk() {
    let path = std::env::temp_dir().join("soyokaze-body-test");
    tokio::fs::write(&path, b"on disk").await.expect("could not stage the fixture");

    let body = Body::File(path.to_string_lossy().into_owned());
    assert_eq!(body.bytes().await.ok().as_deref(), Some(&b"on disk"[..]));

    let _ = tokio::fs::remove_file(&path).await;
}

#[test]
fn a_message_knows_which_half_of_the_exchange_it_is() {
    let request = Message::request(Method::GET, "/", Version::V1_1);
    assert!(request.is_request() && !request.is_response());
    assert_eq!(request.target.as_deref(), Some("/"));

    let response = Message::response(204, Version::V2_0);
    assert!(response.is_response() && !response.is_request());
    assert!(!response.is_informational());

    assert!(Message::response(100, Version::V2_0).is_informational());
    assert!(Message::response(199, Version::V2_0).is_informational());
    assert!(!Message::response(200, Version::V2_0).is_informational());
}

#[test]
fn the_response_constructors_set_a_content_type() {
    let expected = [
        (Message::text("hi", Version::V1_1), "text/plain"),
        (Message::html("<p>", Version::V1_1), "text/html"),
        (Message::json("{}", Version::V1_1), "application/json"),
        (Message::markdown("# hi", Version::V1_1), "text/markdown"),
        (Message::file("/srv/app.js", Version::V1_1), "text/javascript"),
    ];

    for (message, content_type) in expected {
        assert_eq!(message.status_code, Some(200));
        assert_eq!(
            message.headers.as_ref().and_then(|headers| headers.get("content-type")),
            Some(content_type),
        );
        assert!(message.body.is_some());
    }
}

#[test]
fn a_redirect_names_its_target() {
    let redirect = Message::redirect("/elsewhere", Version::V1_1);

    assert_eq!(redirect.status_code, Some(307));
    assert_eq!(
        redirect.headers.as_ref().and_then(|headers| headers.get("location")),
        Some("/elsewhere"),
    );
}

#[test]
fn content_types_come_from_the_extension() {
    assert_eq!(Message::content_type("/index.html"), "text/html");
    assert_eq!(Message::content_type("/style.CSS"), "text/css");
    assert_eq!(Message::content_type("/pkg/app.wasm"), "application/wasm");
    assert_eq!(Message::content_type("/photo.jpeg"), "image/jpeg");
    assert_eq!(Message::content_type("/README"), "application/octet-stream");
    assert_eq!(Message::content_type("/v1.0/README"), "application/octet-stream");
    assert_eq!(Message::content_type(""), "application/octet-stream");
}

#[test]
fn setting_a_cookie_appends_a_field_and_deleting_expires_it() {
    let mut response = Message::response(200, Version::V1_1);

    let mut cookie = SetCookie::new("session", "abc123");
    cookie.path = Some("/".to_owned());
    cookie.httponly = true;

    response.set_cookie(&cookie).expect("a well-formed cookie was refused");
    response.delete_cookie(cookie).expect("a well-formed cookie was refused");

    let headers = response.headers.as_ref().expect("the response lost its fields");
    let values: Vec<&str> = headers.get_all("set-cookie").collect();

    assert_eq!(values.len(), 2);
    assert!(values[0].starts_with("session=abc123"));
    assert!(values[1].starts_with("session=;"), "a deletion clears the value: {:?}", values[1]);
    assert!(values[1].contains("Max-Age=0"));
}

#[test]
fn a_cookie_that_cannot_be_serialised_is_refused() {
    let mut response = Message::response(200, Version::V1_1);

    assert!(response.set_cookie(&SetCookie::new("bad name", "value")).is_err());
    assert!(response.set_cookie(&SetCookie::new("name", "with;semicolon")).is_err());
}

#[test]
fn a_port_carries_exactly_the_versions_of_its_transport() {
    use soyokaze::models::{Port, TransportKind, Version};

    for port in [Port::TCP(443), Port::UDS("/tmp/sock".into())] {
        assert_eq!(port.transport(), TransportKind::Stream);
        assert!(port.carries(Version::V1_0) && port.carries(Version::V1_1) && port.carries(Version::V2_0));
        assert!(!port.carries(Version::V3_0), "{port:?} must not carry a QUIC version");
    }

    let quic = Port::QUIC(443);
    assert_eq!(quic.transport(), TransportKind::QUIC);
    assert!(quic.carries(Version::V3_0));
    assert!(!quic.carries(Version::V1_1) && !quic.carries(Version::V2_0));
}

#[test]
fn a_version_names_the_transport_it_runs_over() {
    use soyokaze::models::{TransportKind, Version};

    assert_eq!(Version::V1_0.transport(), TransportKind::Stream);
    assert_eq!(Version::V1_1.transport(), TransportKind::Stream);
    assert_eq!(Version::V2_0.transport(), TransportKind::Stream);
    assert_eq!(Version::V3_0.transport(), TransportKind::QUIC);
}

#[test]
fn a_port_offers_only_what_its_transport_carries() {
    let versions = [Version::V3_0, Version::V2_0, Version::V1_1, Version::V1_0];

    assert_eq!(
        Port::TCP(443).offers(&versions),
        vec![Version::V2_0, Version::V1_1, Version::V1_0],
        "a TCP port offers every stream version, in the order it was configured",
    );
    assert_eq!(
        Port::UDS("/tmp/soyokaze.sock".to_owned()).offers(&versions),
        vec![Version::V2_0, Version::V1_1, Version::V1_0],
        "a Unix socket carries the same transport as TCP, so it offers the same versions",
    );

    // A QUIC endpoint settles its ALPN when it is stood up, before any
    // connection arrives, so it has to offer the one version it will run
    // rather than offer several and turn away whichever a peer picks.
    assert_eq!(Port::QUIC(443).offers(&versions), vec![Version::V3_0], "a QUIC port offers exactly the version it will run");
    assert!(Port::QUIC(443).offers(&[Version::V1_1, Version::V2_0]).is_empty(), "a QUIC port carries no stream version");
    assert!(Port::TCP(80).offers(&[Version::V3_0]).is_empty(), "a stream port carries no QUIC version");

    for offered in [Port::TCP(443).offers(&versions), Port::QUIC(443).offers(&versions)] {
        for version in &offered {
            assert!(
                versions.contains(version),
                "a port must never offer a version it was not configured with",
            );
        }
    }
}

#[test]
fn an_authority_is_written_the_same_way_from_parts_as_from_a_url() {
    // RFC 9110 §4.2: the port is elided when it is the scheme's own, and an
    // IPv6 literal wears the brackets it had in the URL.
    let cases = [
        ("https", "example.test", 443, "example.test"),
        ("https", "example.test", 8443, "example.test:8443"),
        ("http", "example.test", 80, "example.test"),
        ("http", "example.test", 8080, "example.test:8080"),
        ("wss", "example.test", 443, "example.test"),
        ("https", "::1", 443, "[::1]"),
        ("https", "::1", 8443, "[::1]:8443"),
    ];

    for (scheme, host, port, expected) in cases {
        assert_eq!(URL::authority_of(scheme, host, port), expected, "{scheme}://{host}:{port} produced the wrong authority");

        let url = URL::parse(&format!("{scheme}://{}:{port}/", if host.contains(':') { format!("[{host}]") } else { host.to_owned() }))
            .expect("the URL did not parse");
        assert_eq!(url.authority(), expected, "a parsed URL and its parts must agree on the authority");
    }
}

/// A message the caller has not sent or received carries nothing about a
/// connection: RFC 9110 gives none of these fields a wire form, and the crate
/// stamps them only where they are actually known.
#[test]
fn a_message_the_caller_built_has_crossed_nothing() {
    let message = Message::request(Method::GET, "/", Version::V1_1);

    assert_eq!(message.client, None, "a message the caller built has no access source");
    assert_eq!(message.compression, None, "a message the caller built is coded in nothing");
    assert!(!message.compressed(), "a message with no Content-Encoding is not compressed");
    assert_eq!(message.accepted(), None, "a message with no Accept-Encoding permits nothing");
}

/// RFC 9110 §8.4: `Content-Encoding` is what says a representation is coded.
#[test]
fn compressed_is_judged_from_content_encoding_alone() {
    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::Data(Bytes::from_static(b"not really gzip")));
    message.compression = Some(Compression::Gzip);

    assert!(!message.compressed(), "the field, not the intent, says whether a body is coded");

    message.headers.get_or_insert_with(Headers::new).append("content-encoding", "gzip");
    assert!(message.compressed());
}

#[test]
fn compressing_sets_the_field_and_corrects_the_length() {
    let body = vec![b'a'; 4096];

    for coding in Compression::CODINGS {
        let mut message = Message::response(200, Version::V1_1);
        message.body = Some(Body::Data(Bytes::from(body.clone())));
        message.compression = Some(*coding);
        message.headers.get_or_insert_with(Headers::new).append("content-length", body.len().to_string());

        message.compress(None).expect("an explicit coding did not apply");

        let headers = message.headers.as_ref().expect("the message lost its fields");
        assert_eq!(headers.get("content-encoding"), Some(coding.as_str()), "{coding} must name itself");
        assert_eq!(message.compression, Some(*coding));

        let encoded = message.body.as_ref().and_then(Body::inline).expect("the body went missing");
        assert_eq!(headers.get("content-length"), Some(encoded.len().to_string().as_str()), "Content-Length must count the coded octets");
        assert_eq!(coding.decode(&encoded, 1 << 20).as_deref(), Ok(&body[..]), "{coding} did not encode the body it was given");
    }
}

/// RFC 9110 §8.4.1: a body already carrying a coding is not coded again — the
/// field would have to list both, and this crate never writes such a body.
#[test]
fn an_already_encoded_body_is_never_encoded_twice() {
    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::Data(Bytes::from_static(b"already coded")));
    message.headers.get_or_insert_with(Headers::new).append("content-encoding", "gzip");
    message.compression = Some(Compression::Brotli);

    message.compress(None).expect("compressing did not run");

    assert_eq!(message.body, Some(Body::Data(Bytes::from_static(b"already coded"))));
    assert_eq!(message.headers.as_ref().and_then(|headers| headers.get("content-encoding")), Some("gzip"));
    assert_eq!(message.compression, None, "a body left alone is coded in nothing this end applied");
}

/// A 1xx, a 204 and a 304 carry no content (RFC 9110 §15.2, §15.3.5, §15.4.5),
/// and a partial response carries a range of a representation, which coding it
/// afterwards would leave naming nothing (RFC 9110 §14.4).
#[test]
fn nothing_without_content_of_its_own_is_compressed() {
    let coded = |mut message: Message| {
        message.body = Some(Body::Data(Bytes::from(vec![b'a'; 4096])));
        message.compression = Some(Compression::Gzip);
        message.compress(None).expect("compressing did not run");
        message.compressed()
    };

    for status in [100, 103, 199, 204, 304, 206] {
        assert!(!coded(Message::response(status, Version::V1_1)), "{status} must not carry a coded body");
    }

    let mut ranged = Message::response(200, Version::V1_1);
    ranged.headers.get_or_insert_with(Headers::new).append("content-range", "bytes 0-99/1000");
    assert!(!coded(ranged), "a partial representation must not be coded");

    let mut empty = Message::response(200, Version::V1_1);
    empty.body = Some(Body::Data(Bytes::new()));
    empty.compression = Some(Compression::Gzip);
    empty.compress(None).expect("compressing did not run");
    assert!(!empty.compressed(), "an empty body has nothing to code");

    assert!(!coded(Message::request(Method::CONNECT, "example.test:443", Version::V1_1)), "a tunnel carries no content");
}

/// RFC 9110 §12.5.3 permits coding a body when the peer named no preference,
/// but a peer that asked for nothing is likelier to be one that cannot decode.
#[test]
fn auto_sends_the_body_as_it_stands_when_nothing_is_accepted() {
    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::Data(Bytes::from(vec![b'a'; 4096])));
    message.compression = Some(Compression::Auto);

    message.compress(None).expect("compressing did not run");

    assert!(!message.compressed());
    assert_eq!(message.compression, None);
    assert_eq!(message.body.as_ref().and_then(Body::len), Some(4096));
}

/// RFC 9110 §12.5.5: a response that varies on Accept-Encoding must say so, or
/// a shared cache will hand one peer's coding to another.
#[test]
fn a_response_coded_from_accept_encoding_carries_vary() {
    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::Data(Bytes::from(vec![b'a'; 4096])));
    message.compression = Some(Compression::Auto);

    message.compress(Some(Compression::Zstd)).expect("compressing did not run");

    assert_eq!(message.compression, Some(Compression::Zstd));
    assert_eq!(message.headers.as_ref().and_then(|headers| headers.get("vary")), Some("Accept-Encoding"));

    let mut explicit = Message::response(200, Version::V1_1);
    explicit.body = Some(Body::Data(Bytes::from(vec![b'a'; 4096])));
    explicit.compression = Some(Compression::Gzip);
    explicit.compress(Some(Compression::Zstd)).expect("compressing did not run");

    assert_eq!(explicit.compression, Some(Compression::Gzip), "an explicit coding is what the caller asked for");
    assert!(!explicit.headers.as_ref().is_some_and(|headers| headers.contains("vary")), "a coding that did not vary must not say it did");
}

#[test]
fn decompressing_removes_the_field_and_corrects_the_length() {
    let body = vec![b'a'; 4096];

    for coding in Compression::CODINGS {
        let encoded = coding.encode(&body).expect("the fixture did not encode");

        let mut message = Message::response(200, Version::V1_1);
        message.body = Some(Body::Data(encoded.clone()));

        let headers = message.headers.get_or_insert_with(Headers::new);
        headers.append("content-encoding", coding.as_str());
        headers.append("content-length", encoded.len().to_string());

        message.decompress(1 << 20).expect("a body did not decode");

        assert!(!message.compressed(), "{coding} must leave no Content-Encoding behind");
        assert_eq!(message.compression, Some(*coding), "{coding} must say what came off the body");
        assert_eq!(message.body, Some(Body::Data(Bytes::from(body.clone()))));
        assert_eq!(message.headers.as_ref().and_then(|headers| headers.get("content-length")), Some("4096"));
    }
}

#[test]
fn a_body_in_a_coding_this_crate_does_not_implement_is_left_encoded() {
    for value in ["compress", "gzip, br"] {
        let mut message = Message::response(200, Version::V1_1);
        message.body = Some(Body::Data(Bytes::from_static(b"opaque octets")));
        message.headers.get_or_insert_with(Headers::new).append("content-encoding", value);

        message.decompress(1 << 20).expect("an undecodable body must not fail");

        assert!(message.compressed(), "{value:?} must leave the body reported as coded");
        assert_eq!(message.compression, None, "{value:?} names nothing this crate took off");
        assert_eq!(message.body, Some(Body::Data(Bytes::from_static(b"opaque octets"))));
    }
}

#[test]
fn decompressing_past_the_ceiling_is_a_limit_error() {
    let encoded = Compression::Gzip.encode(&vec![0u8; 1024 * 1024]).expect("the fixture did not encode");

    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::Data(encoded));
    message.headers.get_or_insert_with(Headers::new).append("content-encoding", "gzip");

    assert!(matches!(message.decompress(1024), Err(Error::Limit(_))), "a body past the ceiling must be a limit failure");
}

#[tokio::test]
async fn a_file_body_is_read_before_it_is_coded() {
    let mut message = Message::response(200, Version::V1_1);
    message.body = Some(Body::File("README.md".to_owned()));
    message.compression = Some(Compression::Gzip);

    assert!(matches!(message.compress(None), Err(Error::Protocol(_))), "a body still on disk cannot be coded");

    message.materialize().await.expect("the file did not read");
    message.compress(None).expect("a read body did not code");

    assert!(message.compressed());
}

/// A connection has one role, and the two halves of it never overlap — which
/// is what lets HTTP/1 keep one queue of pending exchanges for both directions,
/// a client filling it as it sends and a server as it receives.
#[test]
fn no_role_is_both_ends_of_an_exchange() {
    for role in [Role::UserAgent, Role::Origin, Role::Proxy, Role::Gateway, Role::Tunnel] {
        assert!(!(role.is_client() && role.is_server()), "{role:?} would drive the pipeline from both ends");
    }

    assert!(Role::UserAgent.is_client() && Role::Proxy.is_client());
    assert!(Role::Origin.is_server() && Role::Gateway.is_server());
    assert!(!Role::Tunnel.is_client() && !Role::Tunnel.is_server(), "a tunnel reads no messages to pipeline");
}

// ---------------------------------------------------------------- conformance

#[test]
fn a_url_refuses_a_target_that_would_write_a_second_request_line() {
    for text in [
        "http://good.test/ HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET /admin",
        "http://good.test/a b",
        "http://good.test/a\rb",
        "http://good.test/a\nb",
    ] {
        assert!(
            matches!(URL::parse(text), Err(Error::Protocol(_))),
            "a URL whose target carries whitespace or a control octet must not parse: {text:?}"
        );
    }
}

#[test]
fn a_url_refuses_a_host_that_would_break_out_of_the_authority() {
    for text in ["http://a b/", "http://a\rb/", "http://a\nb/", "http://a\0b/"] {
        assert!(matches!(URL::parse(text), Err(Error::Protocol(_))), "a malformed host must not parse: {text:?}");
    }
}

#[test]
fn an_ipv6_authority_must_be_bracketed() {
    let url = URL::parse("http://[::1]:8080/").expect("a bracketed IPv6 authority did not parse");
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 8080);

    assert!(
        matches!(URL::parse("http://::1/"), Err(Error::Protocol(_))),
        "an unbracketed IPv6 literal is not an authority, and must not be read as a host and a port"
    );

    assert!(
        matches!(URL::parse("http://[not hex]/"), Err(Error::Protocol(_))),
        "a bracketed authority that is not an IPv6 literal must not parse"
    );
}

#[test]
fn target_and_authority_are_told_apart_by_what_they_admit() {
    assert!(URL::is_target("/a?b#c"));
    assert!(!URL::is_target(""), "a target is never empty");
    assert!(!URL::is_target("/a b"));

    assert!(URL::is_authority("[::1]:8443"), "an authority wears its brackets and its port");
    assert!(!URL::is_authority("a b"));
    assert!(!URL::is_host("[::1]"), "a host is the literal without them");
}

#[test]
fn a_field_section_keeps_its_lookups_honest_whatever_case_a_name_arrived_in() {
    let fields = vec![
        soyokaze::helpers::fields::HeaderField::new("Content-Length", "10"),
        soyokaze::helpers::fields::HeaderField::new("X-Custom", "v"),
    ];

    let headers = Headers::from_fields(fields);

    assert!(headers.contains("content-length"), "a field the section holds must be found");
    assert_eq!(headers.get("content-length"), Some("10"));
    assert_eq!(headers.get_all("content-length").collect::<Vec<_>>(), vec!["10"]);
    assert_eq!(headers.iter().collect::<Vec<_>>(), vec![("content-length", "10"), ("x-custom", "v")]);
}

#[test]
fn a_message_that_ends_at_its_field_section_says_so() {
    for status_code in [100u16, 199, 204, 304] {
        assert!(Message::response(status_code, Version::V1_1).bodyless(None), "a {status_code} carries no content");
    }

    assert!(
        Message::response(200, Version::V1_1).bodyless(Some(Method::HEAD)),
        "RFC 9112 6.3: a response to HEAD carries none either, however it is labelled"
    );

    assert!(!Message::response(200, Version::V1_1).bodyless(Some(Method::GET)));
    assert!(!Message::request(Method::POST, "/", Version::V1_1).bodyless(None), "a request is never bodyless this way");
}

#[test]
fn asking_for_more_room_than_a_section_could_hold_is_not_an_allocation() {
    let headers = Headers::with_capacity(usize::MAX);

    assert!(headers.is_empty(), "room is an optimisation, so an outsized ask is taken as the ceiling");
}
