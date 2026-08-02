//! The error every fallible operation in the crate reports.

use std::fmt;

use crate::helpers::hpack;
use crate::helpers::qpack;
use crate::models::StreamID;

/// What went wrong.
///
/// The variants are graded by how much they cost: [`Error::Stream`] takes down
/// one stream and leaves the connection running, while the rest end the
/// connection. The codec errors in [`helpers::hpack`] and [`helpers::qpack`]
/// convert into [`Error::Protocol`], since a field block that will not decode
/// leaves the peer's compression state unrecoverable.
///
/// [`helpers::hpack`]: crate::helpers::hpack
/// [`helpers::qpack`]: crate::helpers::qpack
#[derive(Debug)]
pub enum Error {
    /// The peer closed the connection, or it was closed under us.
    Closed,
    /// The peer broke the protocol.
    Protocol(String),
    /// The peer went past one of the ceilings in [`Limits`].
    ///
    /// [`Limits`]: crate::models::Limits
    Limit(String),
    /// One stream failed, with the error code to reset it by.
    ///
    /// The connection itself stays usable.
    Stream {
        /// The stream that failed.
        id: StreamID,
        /// The protocol error code to reset the stream with.
        code: u64,
        /// Why it failed.
        reason: String,
    },
    /// An operation ran past its deadline.
    Timeout(String),
    /// The TLS handshake failed, or a TLS object could not be built.
    Tls(String),
    /// No usable HTTP version could be agreed on.
    Version(String),
    /// The transport underneath failed.
    Io(std::io::Error),
}

impl Error {
    /// A [`Error::Stream`] for `id`, to be reset with `code`.
    pub fn stream(id: StreamID, code: u64, reason: impl Into<String>) -> Self {
        Self::Stream { id, code, reason: reason.into() }
    }

    /// Narrows a connection-wide failure to one stream.
    ///
    /// [`Error::Protocol`] and [`Error::Limit`] become [`Error::Stream`], so
    /// the stream is reset instead of the connection; everything else is
    /// returned unchanged, because it is not something one stream can absorb.
    pub fn on_stream(self, id: StreamID, code: u64) -> Self {
        match self {
            Self::Protocol(reason) | Self::Limit(reason) => Self::Stream { id, code, reason },
            error => error,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "connection closed"),
            Self::Protocol(reason) => write!(f, "protocol violation: {reason}"),
            Self::Limit(reason) => write!(f, "limit exceeded: {reason}"),
            Self::Stream { id, code, reason } => write!(f, "stream {} failed with {code:#x}: {reason}", id.0),
            Self::Timeout(reason) => write!(f, "timed out: {reason}"),
            Self::Tls(reason) => write!(f, "tls error: {reason}"),
            Self::Version(reason) => write!(f, "version negotiation failed: {reason}"),
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<hpack::Error> for Error {
    fn from(err: hpack::Error) -> Self {
        Self::Protocol(format!("hpack: {err}"))
    }
}

impl From<qpack::Error> for Error {
    fn from(err: qpack::Error) -> Self {
        Self::Protocol(format!("qpack: {err}"))
    }
}
