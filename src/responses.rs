//! Constructors for the responses a handler reaches for most.
//!
//! Each one builds a [`Message`] with its `Content-Type` already set, so a
//! handler can answer in a line. They extend [`Message`] itself rather than
//! wrapping it, so the result is an ordinary response that can be adjusted
//! further before it is sent.

use crate::errors::Error;
use crate::cookies::SetCookie;
use crate::helpers::text::Text;
use crate::models::{Body, Headers, Message, Version};

/// HTTP status code semantics every version shares.
///
/// The reason phrase belongs to no one version — only HTTP/1.x ever writes it
/// on the wire, but the meaning of a code is the same everywhere.
pub struct Status;

impl Status {
    /// The reason phrase conventionally paired with a status code.
    ///
    /// Unknown codes get `"Unknown"`. The phrase carries no meaning on the wire
    /// — recipients act on the code — so this only has to be something
    /// sensible.
    pub fn reason(status_code: u16) -> &'static str {
        match status_code {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Content Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Content",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            _ => "Unknown",
        }
    }
}

impl Message {
    /// The media type a path's extension suggests.
    ///
    /// The extension is matched case-insensitively, and anything unrecognised —
    /// including a path with no extension at all — becomes
    /// `application/octet-stream`.
    pub fn content_type(path: &str) -> &'static str {
        let extension = path.rsplit('/').next().unwrap_or(path).rsplit_once('.').map(|(_, extension)| extension);

        match extension.map(str::to_ascii_lowercase).as_deref() {
            Some("html" | "htm") => "text/html",
            Some("css") => "text/css",
            Some("js" | "mjs") => "text/javascript",
            Some("txt") => "text/plain",
            Some("md" | "markdown") => "text/markdown",
            Some("csv") => "text/csv",
            Some("xml") => "application/xml",
            Some("json") => "application/json",
            Some("pdf") => "application/pdf",
            Some("wasm") => "application/wasm",
            Some("zip") => "application/zip",
            Some("gz") => "application/gzip",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            Some("avif") => "image/avif",
            Some("svg") => "image/svg+xml",
            Some("ico") => "image/vnd.microsoft.icon",
            Some("mp3") => "audio/mpeg",
            Some("ogg") => "audio/ogg",
            Some("wav") => "audio/wav",
            Some("mp4") => "video/mp4",
            Some("webm") => "video/webm",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("ttf") => "font/ttf",
            Some("otf") => "font/otf",
            _ => "application/octet-stream",
        }
    }

    /// A `200 OK` carrying `body` under the given media type.
    pub fn content(content_type: impl Into<Text>, body: Body, version: Version) -> Self {
        let mut response = Self::response(200, version);
        response.headers.get_or_insert_with(Headers::new).insert("content-type", content_type);
        response.body = Some(body);
        response
    }

    /// A `200 OK` of `text/plain`.
    pub fn text(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/plain", Body::Text(content.into()), version)
    }

    /// A `200 OK` of `text/html`.
    pub fn html(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/html", Body::Text(content.into()), version)
    }

    /// A `200 OK` of `text/markdown`.
    pub fn markdown(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/markdown", Body::Text(content.into()), version)
    }

    /// A `200 OK` of `application/json`.
    ///
    /// The content is sent as given; nothing checks that it is valid JSON.
    pub fn json(content: impl Into<String>, version: Version) -> Self {
        Self::content("application/json", Body::Text(content.into()), version)
    }

    /// A `200 OK` serving a file, typed by its extension.
    ///
    /// The file is not opened here — the body stays a [`Body::File`] until the
    /// connection sends it, so a missing or unreadable file surfaces then.
    pub fn file(path: impl Into<String>, version: Version) -> Self {
        let path = path.into();
        Self::content(Self::content_type(&path), Body::File(path), version)
    }

    /// A `307 Temporary Redirect` to `target`, which preserves the method.
    pub fn redirect(target: impl Into<Text>, version: Version) -> Self {
        let mut response = Self::response(307, version);
        response.headers.get_or_insert_with(Headers::new).insert("location", target);
        response
    }

    /// Adds a `Set-Cookie` field, keeping any already on the response.
    ///
    /// # Errors
    ///
    /// Returns whatever [`SetCookie::build`] rejects the cookie with.
    pub fn set_cookie(&mut self, cookie: &SetCookie) -> Result<(), Error> {
        self.headers.get_or_insert_with(Headers::new).append("set-cookie", cookie.build()?);
        Ok(())
    }

    /// Adds a `Set-Cookie` field that deletes the cookie.
    ///
    /// The value is emptied and `Max-Age=0` replaces any lifetime, so the
    /// client drops the cookie. The name, domain and path have to match those
    /// the cookie was stored under for the deletion to reach it.
    ///
    /// # Errors
    ///
    /// Returns whatever [`SetCookie::build`] rejects the cookie with.
    pub fn delete_cookie(&mut self, cookie: SetCookie) -> Result<(), Error> {
        let mut cookie = cookie;
        cookie.value = String::new();
        cookie.expires = None;
        cookie.max_age = Some(0);
        self.set_cookie(&cookie)
    }

    /// The `426 Upgrade Required` sent when an upgrade does not check out.
    ///
    /// Tells the client which protocol is expected, so it can retry
    /// correctly. The `Upgrade` and `Connection` fields only belong on
    /// HTTP/1.x, where they mean anything. Whatever else the refused protocol
    /// owes the client — a version field, say — is for its module to append.
    pub fn upgrade_required(request: &Message, version: Version, protocol: &str) -> Message {
        let mut headers = Headers::new();
        if version.major() == 1 {
            headers.append("upgrade", protocol);
            headers.append("connection", "Upgrade");
        }

        let mut response = Self::response(426, version);
        response.stream_id = request.stream_id;
        response.headers = Some(headers);
        response
    }
}
