use std::fmt;

use crate::helpers::hpack;
use crate::helpers::qpack;
use crate::models::StreamID;

#[derive(Debug)]
pub enum Error {
    Closed,
    Protocol(String),
    Limit(String),
    Stream { id: StreamID, code: u64, reason: String },
    Timeout(String),
    Tls(String),
    Version(String),
    Io(std::io::Error),
}

impl Error {
    pub fn stream(id: StreamID, code: u64, reason: impl Into<String>) -> Self {
        Self::Stream { id, code, reason: reason.into() }
    }

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
