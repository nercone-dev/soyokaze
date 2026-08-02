mod support;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::models::{Body, ConnectionID, Limits, Message, Role, Version};
use soyokaze::protocol::common::Connection;
use soyokaze::protocol::h1::H1Connection;
use support::{opaque, Group};

const REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\n\
Host: www.example.com\r\n\
Accept: */*\r\n\
Accept-Encoding: gzip, deflate, br\r\n\
Cookie: session=8f14e45fceea167a5a36dedd4bea2543; consent=1\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) soyokaze/0.1\r\n\
\r\n";

const BODY: &[u8] = b"<!doctype html><title>soyokaze</title><p>hello";

struct Loopback {
    request: &'static [u8],
    at: usize,
}

impl Loopback {
    fn new(request: &'static [u8]) -> Self {
        Self { request, at: 0 }
    }
}

impl tokio::io::AsyncRead for Loopback {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let take = buffer.remaining().min(self.request.len() - self.at);
        let at = self.at;

        buffer.put_slice(&self.request[at..at + take]);
        self.at = (at + take) % self.request.len();

        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for Loopback {
    fn poll_write(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn halves(group: &mut Group) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime");
    let id = ConnectionID(Bytes::from_static(b"bench"));

    let mut reader = H1Connection::new(Loopback::new(REQUEST), Role::Origin, id.clone(), Limits::default());
    group.throughput("receive request (6 fields)", REQUEST.len(), || {
        runtime.block_on(async { server_receive(&mut reader).await })
    });

    let mut writer = H1Connection::new(Loopback::new(REQUEST), Role::Origin, id, Limits::default());
    group.bench("send response (body, 45 B)", || {
        runtime.block_on(async {
            let mut response = Message::response(200, Version::V1_1);
            response.body = Some(Body::Data(Bytes::from_static(BODY)));
            writer.send(opaque(response)).await.expect("the response did not go out");
        })
    });
}

async fn server_receive(connection: &mut H1Connection<Loopback>) -> Message {
    connection.receive().await.expect("the request did not parse")
}

fn untimed() -> Limits {
    Limits { read_timeout: 0.0, write_timeout: 0.0, receive_timeout: 0.0, send_timeout: 0.0, ..Limits::default() }
}

fn exchange(name: &str, group: &mut Group, limits: Limits) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime");

    let (mut peer, transport) = tokio::io::duplex(64 * 1024);
    let id = ConnectionID(Bytes::from_static(b"bench"));
    let mut server = H1Connection::new(transport, Role::Origin, id, limits);

    let mut inbox = [0u8; 4096];
    let octets = REQUEST.len() + BODY.len();

    group.throughput(name, octets, || {
        runtime.block_on(async {
            peer.write_all(opaque(REQUEST)).await.expect("the request did not reach the server");

            let request = server.receive().await.expect("the request did not parse");

            let mut response = Message::response(200, Version::V1_1);
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(Bytes::from_static(BODY)));
            server.send(response).await.expect("the response did not go out");

            let read = peer.read(&mut inbox).await.expect("the response did not arrive");
            assert!(read > 0, "the server closed the connection");
        })
    });
}

fn floor(group: &mut Group) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("no runtime");

    let (mut peer, mut transport) = tokio::io::duplex(64 * 1024);
    let response = {
        let mut out = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 45\r\n\r\n"[..]);
        out.extend_from_slice(BODY);
        out
    };

    let mut server_inbox = [0u8; 4096];
    let mut peer_inbox = [0u8; 4096];
    let octets = REQUEST.len() + BODY.len();

    group.throughput("transport floor (no parsing)", octets, || {
        runtime.block_on(async {
            peer.write_all(opaque(REQUEST)).await.expect("the request did not reach the server");

            let read = transport.read(&mut server_inbox).await.expect("nothing arrived");
            assert!(read > 0, "the peer closed the connection");

            transport.write_all(&response).await.expect("the response did not go out");
            transport.flush().await.expect("the response did not flush");

            let read = peer.read(&mut peer_inbox).await.expect("the response did not arrive");
            assert!(read > 0, "the server closed the connection");
        })
    });
}

fn main() {
    let only = std::env::var("SOYOKAZE_BENCH_ONLY").unwrap_or_default();
    let wanted = |name: &str| only.is_empty() || only == name;

    if wanted("cycle") {
        let mut group = Group::new("http/1 request cycle (keep-alive)");
        exchange("default limits", &mut group, Limits::default());
        exchange("timeouts disabled", &mut group, untimed());
        floor(&mut group);
    }

    if wanted("halves") {
        let mut group = Group::new("http/1 halves");
        halves(&mut group);
    }
}
