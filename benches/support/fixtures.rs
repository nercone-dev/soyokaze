//! The messages the benchmarks are measured over.
//!
//! One set of fixtures for every layer: [`Section`] is a header set as a codec
//! sees it, [`Wire`] is the same thing as octets on an HTTP/1 connection,
//! [`Payload`] is a body, and [`Fixtures`] holds the sizes and shapes worth
//! walking. Keeping them here is what makes a number from one layer comparable
//! with a number from another.

use bytes::Bytes;

use soyokaze::helpers::fields::HeaderField;
use soyokaze::models::{Body, Headers, HeaderCase, Message, Method, Version};

/// The shapes and sizes every benchmark walks.
pub struct Fixtures;

impl Fixtures {
    /// The body sizes worth measuring over: a line, a page, an HTTP/2 window,
    /// and a megabyte.
    pub const SIZES: &'static [(&'static str, usize)] = &[("13 B", 13), ("4 KiB", 4096), ("64 KiB", 65_536), ("1 MiB", 1 << 20)];

    /// The strings a field codec is measured over, and how long each is.
    pub const STRINGS: &'static [(&'static str, &'static [u8])] = &[
        ("authority (15 B)", b"www.example.com"),
        ("path (30 B)", b"/assets/app.7f3c9a2b.module.js"),
        ("date (29 B)", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        ("user-agent (72 B)", b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1 like Gecko"),
        ("cookie (256 B)", &[b'a'; 256]),
        ("incompressible (64 B)", &[0xc0; 64]),
    ];

    /// How many streams a scan is measured against, which is what says whether
    /// a per-I/O-cycle scan costs what a connection's age costs.
    pub const STREAMS: &'static [usize] = &[1, 100, 1_000, 10_000, 50_000];

    /// How many requests a connection has served before a case measures the
    /// next one.
    pub const SERVED: &'static [u64] = &[0, 1_000, 10_000, 50_000];
}

/// A named header set, as a field codec sees it.
#[derive(Debug, Clone)]
pub struct Section {
    /// What the set is called in a report.
    pub name: &'static str,

    /// The fields, pseudo-headers first, as a codec is handed them.
    pub fields: Vec<HeaderField>,
}

impl Section {
    /// The fields a browser sends.
    pub fn request() -> Self {
        Self {
            name: "request (11 fields)",
            fields: Self::of(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "www.example.com"),
                (":path", "/assets/app.7f3c9a2b.module.js"),
                ("accept", "*/*"),
                ("accept-encoding", "gzip, deflate, br"),
                ("accept-language", "en-GB,en;q=0.9"),
                ("cache-control", "no-cache"),
                ("cookie", "session=8f14e45fceea167a5a36dedd4bea2543; consent=1; locale=en-GB; theme=dark"),
                ("referer", "https://www.example.com/index.html"),
                ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1 like Gecko"),
            ]),
        }
    }

    /// The fields a server answers with.
    pub fn response() -> Self {
        Self {
            name: "response (8 fields)",
            fields: Self::of(&[
                (":status", "200"),
                ("content-type", "text/html; charset=utf-8"),
                ("content-length", "16384"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("server", "Soyokaze"),
                ("cache-control", "max-age=0, private, must-revalidate"),
                ("strict-transport-security", "max-age=31536000; includeSubDomains"),
                ("vary", "accept-encoding"),
            ]),
        }
    }

    /// Both directions, which is what a codec is measured over.
    pub fn both() -> [Self; 2] {
        [Self::request(), Self::response()]
    }

    /// Fields from names and values.
    pub fn of(fields: &[(&str, &str)]) -> Vec<HeaderField> {
        fields.iter().map(|(name, value)| HeaderField::new(*name, *value)).collect()
    }

    /// How many octets the names and values hold together, which is what a
    /// throughput is measured against.
    pub fn octets(&self) -> usize {
        self.fields.iter().map(|field| field.name.len() + field.value.len()).sum()
    }

    /// The same fields as [`Headers`], without the pseudo-headers, which is
    /// how a version that has none carries them.
    pub fn headers(&self) -> Headers {
        let mut headers = Headers::with_capacity(self.fields.len());

        for field in self.fields.iter().filter(|field| !field.name.starts_with(':')) {
            headers.append(field.name.as_str(), field.value.as_str());
        }

        headers
    }

    /// The same fields as a whole message of this version.
    pub fn message(&self, version: Version) -> Message {
        let mut message = match self.fields.iter().find(|field| field.name == ":status") {
            Some(status) => Message::response(status.value.as_str().parse().unwrap_or(200), version),
            None => Message::request(Method::GET, "/assets/app.7f3c9a2b.module.js", version),
        };

        message.headers = Some(self.headers());
        message.security.secure = true;
        message
    }
}

/// A body of a given size.
pub struct Payload;

impl Payload {
    /// A body of this many octets.
    ///
    /// The octets vary rather than repeating, so that nothing downstream gets
    /// a compression ratio no real body would give it.
    pub fn of(octets: usize) -> Bytes {
        Bytes::from((0..octets).map(|at| (at * 31 + 17) as u8).collect::<Vec<u8>>())
    }

    /// A body as a [`Body`], ready to hang on a message.
    pub fn body(octets: usize) -> Body {
        Body::Data(Self::of(octets))
    }
}

/// The HTTP/1 wire form of the fixtures, for the parsers that read octets.
pub struct Wire;

impl Wire {
    /// The request line a request head starts with.
    pub const REQUEST_LINE: &'static str = "GET /assets/app.7f3c9a2b.module.js HTTP/1.1";

    /// The status line a response head starts with.
    pub const STATUS_LINE: &'static str = "HTTP/1.1 200 OK";

    /// A field block, each line terminated, without the empty line that ends
    /// it.
    pub fn block(section: &Section) -> Vec<u8> {
        Self::lines(section).iter().flat_map(|line| format!("{line}\r\n").into_bytes()).collect()
    }

    /// A field block with the empty line that ends a head.
    pub fn framed(section: &Section) -> Vec<u8> {
        let mut block = Self::block(section);
        block.extend_from_slice(b"\r\n");
        block
    }

    /// The field lines of a section, as they appear on the wire.
    pub fn lines(section: &Section) -> Vec<String> {
        section
            .headers()
            .iter()
            .map(|(name, value)| format!("{}: {value}", HeaderCase::Title.apply(name)))
            .collect()
    }

    /// A whole request head: the request line, the fields, and the empty line.
    pub fn request() -> Vec<u8> {
        let mut head = format!("{}\r\n", Self::REQUEST_LINE).into_bytes();
        head.extend_from_slice(&Self::framed(&Section::request()));
        head
    }

    /// A whole response head.
    pub fn response() -> Vec<u8> {
        let mut head = format!("{}\r\n", Self::STATUS_LINE).into_bytes();
        head.extend_from_slice(&Self::framed(&Section::response()));
        head
    }
}
