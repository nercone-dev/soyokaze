//! The content codings a message body may be carried in.
//!
//! [`Compression`] is both the vocabulary and the codec: the tokens
//! `Content-Encoding` and `Accept-Encoding` are written in, and the encoder
//! and decoder those tokens stand for. [`Coding`] is one entry of such a
//! field, which is how a list of them is read.
//!
//! Nothing here knows what a message is. [`Message::compress`] and
//! [`Message::decompress`] are what put a coding on one, and they are also
//! where the rules about which messages may be coded at all live.
//!
//! [`Message::compress`]: crate::models::Message::compress
//! [`Message::decompress`]: crate::models::Message::decompress

use std::fmt;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;

use bytes::Bytes;

/// A content coding a body may be carried in.
///
/// [`Compression::Auto`] is a choice rather than a coding: it names nothing on
/// the wire and is settled against what the peer said it accepts, just before
/// the body goes out.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// The best coding the peer accepts, settled before the body goes out.
    Auto,
    /// `zstd`, RFC 8878.
    Zstd,
    /// `br`, RFC 7932.
    Brotli,
    /// `gzip`, RFC 1952.
    Gzip,
    /// `deflate`, which is RFC 1950 zlib around RFC 1951 deflate.
    Deflate,
}

impl Compression {
    /// Every coding that names something, in the order one is preferred over the next.
    pub const CODINGS: &[Self] = &[Self::Zstd, Self::Brotli, Self::Gzip, Self::Deflate];
    /// The number of codings, [`Compression::Auto`] included.
    pub const COUNT: usize = Self::CODINGS.len() + 1;
    /// [`Compression::CODINGS`] written as an `Accept-Encoding` field value.
    pub const ACCEPTED: &str = "zstd, br, gzip, deflate";
    /// The token for a body that was not coded at all.
    pub const IDENTITY: &str = "identity";

    /// The zstd level bodies are encoded at.
    pub const ZSTD_LEVEL: i32 = 3;
    /// The brotli quality bodies are encoded at.
    pub const BROTLI_QUALITY: i32 = 5;
    /// The log of the brotli window size bodies are encoded with.
    pub const BROTLI_WINDOW: i32 = 22;
    /// In bytes, the room a streaming codec is given to work in.
    pub const BUFFER: usize = 8192;

    /// The coding's token, as `Content-Encoding` spells it.
    ///
    /// [`Compression::Auto`] names no coding and so is empty: it stands for a
    /// choice that has yet to be made, and never appears on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "",
            Self::Zstd => "zstd",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    /// The coding a token names, ignoring case.
    ///
    /// Never answers [`Compression::Auto`], which names nothing. `x-gzip` is
    /// read as `gzip`, as RFC 9110 §8.4.1 says it must be. A token this crate
    /// does not implement — `compress` and `identity` among them — names
    /// nothing here, so a body carried in one is left exactly as it arrived.
    pub fn parse(token: &str) -> Option<Self> {
        let token = token.trim();

        Self::CODINGS
            .iter()
            .copied()
            .find(|coding| token.eq_ignore_ascii_case(coding.as_str()))
            .or_else(|| token.eq_ignore_ascii_case("x-gzip").then_some(Self::Gzip))
    }

    /// The best coding an `Accept-Encoding` field permits.
    ///
    /// `values` is every `accept-encoding` field the message carries, each of
    /// which may list several codings. A coding at `q=0` is refused, `*` stands
    /// for every coding the field does not name, and among what is left the
    /// first of [`Compression::CODINGS`] wins — quality settles what is
    /// acceptable to the peer, while which of the acceptable ones to send is
    /// this end's own business.
    ///
    /// `None` when nothing is permitted, which is also what an absent field
    /// means. RFC 9110 §12.5.3 would let a sender code anything when the field
    /// is absent, but a peer that asked for nothing is far likelier to be one
    /// that cannot decode than one that did not bother to ask.
    pub fn accepted<'a>(values: impl Iterator<Item = &'a str>) -> Option<Self> {
        let mut quality = [None; Self::COUNT];
        let mut wildcard = None;

        for coding in values.flat_map(Coding::list) {
            match coding.compression() {
                Some(compression) => quality[compression as usize] = Some(coding.quality),
                None if coding.wildcard() => wildcard = Some(coding.quality),
                None => {}
            }
        }

        let permitted = |coding: &Self| quality[*coding as usize].or(wildcard).unwrap_or(Coding::NONE) > Coding::NONE;
        Self::CODINGS.iter().copied().find(permitted)
    }

    /// The coding a `Content-Encoding` field says the body is already carried in.
    ///
    /// `None` when the field is absent, names only `identity`, names a coding
    /// this crate does not implement, or names more than one — in each of those
    /// cases the body cannot be decoded and must be handed on as it arrived.
    pub fn applied<'a>(values: impl Iterator<Item = &'a str>) -> Option<Self> {
        let mut applied = None;

        for coding in values.flat_map(Coding::list) {
            if coding.token.eq_ignore_ascii_case(Self::IDENTITY) {
                continue;
            }

            if applied.is_some() {
                return None;
            }

            applied = Some(coding.compression()?);
        }

        applied
    }

    /// Whether a `Content-Encoding` field says the body is coded at all.
    ///
    /// Answers yes for a coding this crate does not implement, which is what
    /// makes it the question "is the body still compressed" rather than "can
    /// this crate decode it". `identity` codes nothing and so does not count.
    pub fn encoded<'a>(values: impl Iterator<Item = &'a str>) -> bool {
        values.flat_map(Coding::list).any(|coding| !coding.token.eq_ignore_ascii_case(Self::IDENTITY))
    }

    /// Reads a decoder out, refusing to produce more than `max` octets.
    ///
    /// The ceiling is what stops a small body decoding into an enormous one:
    /// the decoder is read one octet past `max`, so passing it is noticed
    /// without ever holding more than that. `out` is left as it was found when
    /// anything goes wrong.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] once the decoded body passes `max`, and
    /// [`Error::Coding`] when the stream will not decode.
    pub fn drain(reader: impl Read, max: u64, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        let mut bounded = reader.take(max.saturating_add(1));

        match std::io::copy(&mut bounded, out) {
            Ok(produced) if produced <= max => Ok(()),
            Ok(_) => {
                out.truncate(start);
                Err(Error::TooLarge(max))
            }
            Err(err) => {
                out.truncate(start);
                Err(Error::coding(err))
            }
        }
    }

    /// Encodes `input` in this coding.
    ///
    /// # Errors
    ///
    /// As [`Compression::encode_into`].
    pub fn encode(&self, input: &[u8]) -> Result<Bytes, Error> {
        let mut out = Vec::with_capacity(input.len() / 2 + Self::BUFFER.min(input.len() + 64));
        self.encode_into(input, &mut out)?;
        Ok(Bytes::from(out))
    }

    /// [`Compression::encode`], appending to a buffer the caller owns.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Settled`] for [`Compression::Auto`], which names no
    /// coding to encode in, and [`Error::Coding`] when the encoder fails.
    pub fn encode_into(&self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Auto => Err(Error::Settled),

            Self::Zstd => zstd::stream::copy_encode(input, out, Self::ZSTD_LEVEL).map_err(Error::coding),

            Self::Brotli => {
                let params = brotli::enc::BrotliEncoderParams { quality: Self::BROTLI_QUALITY, lgwin: Self::BROTLI_WINDOW, ..Default::default() };
                let mut source = input;

                brotli::BrotliCompress(&mut source, out, &params).map(drop).map_err(Error::coding)
            }

            Self::Gzip => {
                let mut encoder = flate2::write::GzEncoder::new(out, flate2::Compression::default());
                encoder.write_all(input).map_err(Error::coding)?;
                encoder.finish().map(drop).map_err(Error::coding)
            }

            Self::Deflate => {
                let mut encoder = flate2::write::ZlibEncoder::new(out, flate2::Compression::default());
                encoder.write_all(input).map_err(Error::coding)?;
                encoder.finish().map(drop).map_err(Error::coding)
            }
        }
    }

    /// Decodes `input`, refusing to produce more than `max` octets.
    ///
    /// # Errors
    ///
    /// As [`Compression::decode_into`].
    pub fn decode(&self, input: &[u8], max: u64) -> Result<Bytes, Error> {
        let mut out = Vec::new();
        self.decode_into(input, max, &mut out)?;
        Ok(Bytes::from(out))
    }

    /// [`Compression::decode`], appending to a buffer the caller owns.
    ///
    /// A `deflate` body is tried as zlib first and then as raw deflate: RFC
    /// 9110 §8.4.1.2 names zlib, but enough deployed senders write the raw
    /// stream that refusing it would turn a readable body into an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Settled`] for [`Compression::Auto`], and otherwise as
    /// [`Compression::drain`].
    pub fn decode_into(&self, input: &[u8], max: u64, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Auto => Err(Error::Settled),

            Self::Zstd => Self::drain(zstd::stream::read::Decoder::new(input).map_err(Error::coding)?, max, out),

            Self::Brotli => Self::drain(brotli::Decompressor::new(input, Self::BUFFER), max, out),

            Self::Gzip => Self::drain(flate2::read::GzDecoder::new(input), max, out),

            Self::Deflate => match Self::drain(flate2::read::ZlibDecoder::new(input), max, out) {
                Err(Error::Coding(_)) => Self::drain(flate2::read::DeflateDecoder::new(input), max, out),
                settled => settled,
            },
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Compression {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text).ok_or(())
    }
}

/// One entry of a comma-separated content coding list.
///
/// Both `Content-Encoding` and `Accept-Encoding` are written this way, so both
/// are read through this; only the latter carries a quality, and an entry that
/// carries none is fully acceptable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Coding<'a> {
    /// The token as it was written, which may be `*` or name nothing at all.
    pub token: &'a str,
    /// The quality the entry carries.
    pub quality: f32,
}

impl<'a> Coding<'a> {
    /// The token standing for every coding the field does not name.
    pub const WILDCARD: &'static str = "*";
    /// The quality of an entry that carries none, which is full acceptance.
    pub const FULL: f32 = 1.0;
    /// The quality at which an entry is a refusal.
    pub const NONE: f32 = 0.0;

    /// Reads one entry, with whatever parameters follow it.
    ///
    /// A quality outside zero to one is a refusal rather than an error: RFC
    /// 9110 §12.4.2 admits no such value, and reading it as full acceptance
    /// would let a malformed field talk this end into coding a body the peer
    /// cannot read.
    pub fn parse(entry: &'a str) -> Self {
        let mut parts = entry.split(';');
        let token = parts.next().unwrap_or_default().trim();

        let written = parts.filter_map(|parameter| parameter.split_once('=')).find(|(name, _)| name.trim().eq_ignore_ascii_case("q"));
        let quality = match written {
            Some((_, value)) => value.trim().parse::<f32>().ok().filter(|quality| (Self::NONE..=Self::FULL).contains(quality)).unwrap_or(Self::NONE),
            None => Self::FULL,
        };

        Self { token, quality }
    }

    /// Reads every entry of a field value, in the order they were written.
    ///
    /// Entries naming nothing at all are dropped, so an empty field value
    /// yields nothing rather than one nameless entry.
    pub fn list(value: &'a str) -> impl Iterator<Item = Self> {
        value.split(',').map(Self::parse).filter(|coding| !coding.token.is_empty())
    }

    /// The coding this entry names, or `None` for a wildcard or an unknown token.
    pub fn compression(&self) -> Option<Compression> {
        Compression::parse(self.token)
    }

    /// Whether this entry stands for every coding the field does not name.
    pub fn wildcard(&self) -> bool {
        self.token == Self::WILDCARD
    }

    /// Whether this entry permits what it names.
    pub fn accepts(&self) -> bool {
        self.quality > Self::NONE
    }
}

/// Why a body would not encode or decode.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The coding was [`Compression::Auto`], which names nothing to code in.
    Settled,
    /// The decoded body would pass the ceiling it was given.
    TooLarge(u64),
    /// The stream will not decode, or the encoder failed.
    Coding(String),
}

impl Error {
    /// Wraps a failure from one of the codecs underneath.
    pub fn coding(error: impl fmt::Display) -> Self {
        Self::Coding(error.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settled => write!(f, "the content coding was never settled"),
            Self::TooLarge(max) => write!(f, "the decoded body exceeds {max} octets"),
            Self::Coding(reason) => write!(f, "the content coding failed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}
