//! The messages the benchmarks are measured over.
//!
//! One set of fixtures for every layer: [`Section`] is a header set as a codec
//! sees it, [`Wire`] is the same thing as octets on an HTTP/1 connection,
//! [`Payload`] is a body, and [`Fixtures`] holds the sizes, shapes and counts
//! worth walking. Keeping them here is what makes a number from one layer
//! comparable with a number from another, and what makes two ways of looking
//! at one layer comparable with each other.

use bytes::Bytes;

use soyokaze::helpers::fields::HeaderField;
use soyokaze::models::{Body, Headers, HeaderCase, Message, Method, Version};

/// The shapes, sizes and counts every benchmark walks.
pub struct Fixtures;

impl Fixtures {
    /// The body sizes worth measuring over: a line, a page, an HTTP/2 window,
    /// and a megabyte.
    pub const SIZES: &'static [(&'static str, usize)] = &[("13 B", 13), ("4 KiB", 4096), ("64 KiB", 65_536), ("1 MiB", 1 << 20)];

    /// The octet lengths a growth curve over an input's size is taken at.
    ///
    /// Bare numbers rather than named sizes: a curve names its own axis, and
    /// what it needs is the spread rather than the labels.
    pub const LENGTHS: &'static [usize] = &[16, 64, 256, 1024, 4096, 16_384];

    /// The counts a growth curve over how much a structure holds is taken at
    /// — fields in a set, addresses in a history, streams on a connection.
    pub const COUNTS: &'static [usize] = &[1, 8, 64, 512, 4096];

    /// The counts a curve over a structure with a ceiling of its own is taken
    /// at.
    ///
    /// Short of every ceiling in [`Limits`], so that what a curve reads is how
    /// the structure behaves rather than where it starts refusing: a store
    /// asked to hold more than it will hold reports the cost of what it kept
    /// and says nothing about the count on the axis.
    ///
    /// [`Limits`]: soyokaze::models::Limits
    pub const STORED: &'static [usize] = &[1, 8, 64, 256, 2048];

    /// The counts a curve over cookies for one origin is taken at.
    ///
    /// Far shorter, because a jar holds only [`CookieLimits::max_per_domain`]
    /// of them for any one domain however many it is handed, and cookies for
    /// one origin is what a lookup for that origin actually walks.
    ///
    /// [`CookieLimits::max_per_domain`]: soyokaze::cookies::CookieLimits
    pub const PER_ORIGIN: &'static [usize] = &[1, 4, 16, 48];

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
    pub const SERVED: &'static [usize] = &[0, 1_000, 10_000, 50_000];

    /// The versions every part that has one per version is measured over.
    pub const VERSIONS: &'static [Version] = &[Version::V1_1, Version::V2_0, Version::V3_0];
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

    /// A set of this many fields, none of them well known.
    ///
    /// What a growth curve is taken over: the names are distinct and share a
    /// prefix, which is the shape a lookup has the hardest time with and the
    /// one a header set really meets — `x-request-id`, `x-forwarded-for` and
    /// the rest of a proxy chain all begin alike.
    pub fn crowded(fields: usize) -> Headers {
        let mut headers = Headers::with_capacity(fields);

        for index in 0..fields {
            headers.append(Self::field(index), "8f14e45fceea167a5a36dedd4bea2543");
        }

        headers
    }

    /// What the field at this position in a crowded set is called.
    pub fn field(index: usize) -> String {
        format!("x-forwarded-field-{index}")
    }
}

/// A body of a given size, in the shapes a body really comes in.
///
/// Three of them, because a content coding reads them nothing alike: text
/// compresses to a fraction of itself, an already-compressed body does not
/// compress at all, and most bodies are somewhere between. A codec measured
/// over one of the three says nothing about what it does to the other two.
pub struct Payload;

impl Payload {
    /// The words a text body is built from.
    pub const WORDS: &'static [&'static str] = &["<div class=\"row\">", "the", "quick", "brown", "fox", "</div>", "jumps", "over", "the", "lazy", "dog", "\n"];

    /// A body of this many octets.
    ///
    /// The octets vary rather than repeating, so that nothing downstream gets
    /// a compression ratio no real body would give it.
    pub fn of(octets: usize) -> Bytes {
        Bytes::from((0..octets).map(|at| (at * 31 + 17) as u8).collect::<Vec<u8>>())
    }

    /// A body of this many octets that compresses the way markup does.
    pub fn text(octets: usize) -> Bytes {
        let mut out = Vec::with_capacity(octets);

        while out.len() < octets {
            out.extend_from_slice(Self::WORDS[out.len() % Self::WORDS.len()].as_bytes());
            out.push(b' ');
        }

        out.truncate(octets);
        Bytes::from(out)
    }

    /// A body of this many octets that does not compress at all.
    ///
    /// A cheap multiplicative generator rather than anything cryptographic:
    /// what a codec needs to meet is octets with no structure to find, and this
    /// has none that a window of any usable size will reach.
    pub fn random(octets: usize) -> Bytes {
        let mut state = 0x2545_f491_4f6c_dd1du64;

        Bytes::from(
            (0..octets)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 33) as u8
                })
                .collect::<Vec<u8>>(),
        )
    }

    /// The three shapes at one size, named.
    pub fn shapes(octets: usize) -> [(&'static str, Bytes); 3] {
        [("text", Self::text(octets)), ("mixed", Self::of(octets)), ("random", Self::random(octets))]
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

    /// The wire form of a header set, as a block of terminated lines.
    pub fn headers(headers: &Headers) -> Vec<u8> {
        headers
            .iter()
            .flat_map(|(name, value)| format!("{}: {value}\r\n", HeaderCase::Title.apply(name)).into_bytes())
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
