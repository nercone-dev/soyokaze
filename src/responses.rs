use crate::errors::Error;
use crate::headers::SetCookie;
use crate::helpers::text::Text;
use crate::models::{Body, Headers, Message, Version};

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

impl Message {
    pub fn content(content_type: impl Into<Text>, body: Body, version: Version) -> Self {
        let mut response = Self::response(200, version);
        response.headers.get_or_insert_with(Headers::new).insert("content-type", content_type);
        response.body = Some(body);
        response
    }

    pub fn text(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/plain", Body::Text(content.into()), version)
    }

    pub fn html(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/html", Body::Text(content.into()), version)
    }

    pub fn markdown(content: impl Into<String>, version: Version) -> Self {
        Self::content("text/markdown", Body::Text(content.into()), version)
    }

    pub fn json(content: impl Into<String>, version: Version) -> Self {
        Self::content("application/json", Body::Text(content.into()), version)
    }

    pub fn file(path: impl Into<String>, version: Version) -> Self {
        let path = path.into();
        Self::content(content_type(&path), Body::File(path), version)
    }

    pub fn redirect(target: impl Into<Text>, version: Version) -> Self {
        let mut response = Self::response(307, version);
        response.headers.get_or_insert_with(Headers::new).insert("location", target);
        response
    }

    pub fn set_cookie(&mut self, cookie: &SetCookie) -> Result<(), Error> {
        self.headers.get_or_insert_with(Headers::new).append("set-cookie", cookie.build()?);
        Ok(())
    }

    pub fn delete_cookie(&mut self, cookie: SetCookie) -> Result<(), Error> {
        let mut cookie = cookie;
        cookie.value = String::new();
        cookie.expires = None;
        cookie.max_age = Some(0);
        self.set_cookie(&cookie)
    }
}
