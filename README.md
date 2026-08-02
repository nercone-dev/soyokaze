# Soyokaze

HTTP/1/2/3 Library Crate

Soyokaze speaks all three versions of HTTP through one set of types. A `Message` carries a
request or a response regardless of the version that framed it, and every connection
implements `protocol::common::Connection`, so code written against the trait works unchanged
over HTTP/1.1, HTTP/2 and HTTP/3.

Corresponding pieces are kept interchangeable on purpose. Client and server, request and
response, encoder and decoder, HTTP/1 and HTTP/2 and HTTP/3 — each pair shares the shape of
its counterpart, and version-specific connections are drop-in replacements for one another
wherever the protocol itself does not force a difference.

## Highlights

- **One vocabulary for three versions.** `Message`, `Headers`, `Body` and `Connection` do not
  change when the version does; `AnyConnection` carries whichever version was negotiated.
- **Client and server.** `Client` dials an origin and exchanges messages; `Server` binds
  ports, negotiates, and hands connections to a `Handler`.
- **Its own codecs.** Huffman, HPACK (HTTP/2) and QPACK (HTTP/3) field compression, plus the
  Base64 and SHA-1 the WebSocket handshake needs, are implemented in the crate.
- **WebSocket.** Over the HTTP/1.1 `Upgrade`, and over the extended CONNECT of HTTP/2 and
  HTTP/3.
- **TLS and QUIC.** BoringSSL through `boring`/`tokio-boring`, QUIC through
  `quiche`/`tokio-quiche`, including Encrypted Client Hello.
- **Client state that outlives a request.** A cookie jar and an HSTS store, both on by default.
- **Bounded by default.** Every ceiling a connection holds itself to lives in one `Limits`
  struct, and a server admits connections through a `Gate` that caps totals, per-address
  counts and connection rate.
- **Multi-threaded serving.** `Server::serve_workers` gives each worker its own runtime and,
  under `SO_REUSEPORT`, its own listener.

## Requirements

- Rust 1.85 or newer — the crate is on the 2024 edition.
- A C/C++ toolchain and CMake, which building BoringSSL needs.

## Installing

```bash
cargo add soyokaze
```

Or, together with the runtime the examples below use:

```toml
[dependencies]
soyokaze = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
```

## Fetching a resource

`Client::fetch` and its shorthands dial, exchange one message, and close. HSTS is applied to
the URL first, `Host` and `Cookie` are filled in unless you set them, and any `Set-Cookie` or
`Strict-Transport-Security` on the response is taken into the client's state. Redirects are
not followed — the response comes back as it arrived.

```rust
use soyokaze::Client;

#[tokio::main]
async fn main() -> Result<(), soyokaze::Error> {
    let client = Client::builder().build();
    let response = client.get("https://example.com/").await?;

    println!("{:?} {:?}", response.version, response.status_code);

    if let Some(body) = response.body {
        println!("{}", String::from_utf8_lossy(&body.into_bytes().await?));
    }

    Ok(())
}
```

To hold a connection open and send several messages over it, use `Client::open` — or
`Client::connect` for a specific `Port` — and `Client::request`:

```rust
use soyokaze::models::{Message, Method, Url};
use soyokaze::protocol::common::Connection;
use soyokaze::Client;

#[tokio::main]
async fn main() -> Result<(), soyokaze::Error> {
    let client = Client::builder().build();
    let url = Url::parse("https://example.com/")?;
    let mut connection = client.open(&url).await?;

    for target in ["/", "/about", "/contact"] {
        let request = Message::request(Method::GET, target, connection.version());
        let response = client.request(&mut connection, request).await?;

        println!("{target}: {:?}", response.status_code);
    }

    connection.close().await;
    Ok(())
}
```

## Serving

A `Handler` decides what a server does with the connections it accepts. Both of its methods
have defaults, so `impl Handler for Site {}` compiles and answers every request with a
placeholder — enough to get a server running before deciding what it should say.

```rust
use soyokaze::models::Message;
use soyokaze::protocol::common::{AnyConnection, Connection};
use soyokaze::{Handler, Port, Server};

struct Site;

impl Handler for Site {
    async fn on_connection(&self, mut connection: AnyConnection) {
        while let Ok(request) = connection.receive().await {
            let mut response = Message::text("Hello, World!", connection.version());
            response.stream_id = request.stream_id;

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

#[tokio::main]
async fn main() -> Result<(), soyokaze::Error> {
    let server = Server::builder().build();
    let handle = server.serve(Site, &[Port::TCP(8080)]).await?;

    println!("listening on {:?}", handle.address());
    tokio::signal::ctrl_c().await.ok();

    handle.close(Some(5.0)).await;
    Ok(())
}
```

A response must carry the `stream_id` of the request it answers, or HTTP/2 and HTTP/3 cannot
match the two up. `Message::text`, `html`, `json`, `file` and `redirect` build the common ones.

`Server::serve` runs the accept loops on the current runtime. `Server::serve_workers` runs
them on a thread apiece, each with its own runtime, and returns a `Cluster`:

```rust
let cluster = server.serve_workers(Site, &[Port::TCP(8080)], soyokaze::cores())?;
```

## TLS, HTTP/3 and WebSocket

A server offers every version it was built with — by default HTTP/3, HTTP/2 and HTTP/1.1 — and
which one is spoken is settled by ALPN. A certificate is required for TLS and for any QUIC
port; without one, a TCP port is served in plaintext.

```rust
use soyokaze::models::{Port, Version};
use soyokaze::Server;

let server = Server::builder()
    .version(Version::V3_0)
    .version(Version::V2_0)
    .identity(vec![std::fs::read("chain.pem")?], std::fs::read("key.pem")?)
    .max_connections_per_ip(64)
    .build();

let handle = server.serve(Site, &[Port::TCP(443), Port::QUIC(443)]).await?;
```

Certificates and keys are read in whichever encoding they arrive in — nothing has to be
declared. A certificate is DER or PEM, and one PEM blob may hold a whole chain, so a chain can
be a single bundle or one entry per certificate. A key is PKCS#8, PKCS#1 or SEC1, in either
encoding. Each side reads only its own sections, so a combined file holding a certificate and
its key can be passed as both. `Client::builder().roots(..)` takes the same shapes. A PKCS#12
archive — a `.p12` or `.pfx` — is unwrapped first:

```rust
use soyokaze::Identity;

let identity = Identity::from_pkcs12(&std::fs::read("site.p12")?, "passphrase")?;
let server = Server::builder().with_identity(identity).build();
```

Keys encrypted under a passphrase are not read directly; ship them as PKCS#12, or decrypt them
first.

WebSocket works the same way from either end. `Client::websocket` performs whichever
handshake the negotiated version calls for, and a server overrides `Handler::on_websocket`:

```rust
use soyokaze::protocol::common::Transport;
use soyokaze::websocket::{CloseCode, WebSocketConnection};

impl Handler for Site {
    async fn on_websocket(&self, mut socket: WebSocketConnection<Box<dyn Transport>>) {
        while let Ok((opcode, payload)) = socket.receive_message().await {
            if socket.send_message(opcode, payload.to_vec()).await.is_err() {
                break;
            }
        }

        socket.close(CloseCode::Normal, "").await;
    }
}
```

## Layout

The crate is arranged in three layers, each usable on its own. A higher layer drives a lower
one exactly the way an outside caller would: HTTP/1.1 over TCP is built from a TCP server and
an `H1Connection`, with no private back channel between them.

| Module | What is in it |
| --- | --- |
| `api::client` | `Client` and `ClientBuilder`: dialling, one-shot requests, cookie and HSTS state |
| `api::server` | `Server`, `Listener`, `Handler`, `Gate`, `Cluster`: binding, negotiating, accepting |
| `api::tls` | BoringSSL contexts for TLS and QUIC, `Identity`, and Encrypted Client Hello |
| `protocol::common` | `Connection`, `Stream`, `Transport`, `AnyConnection`, and the shared parsing pieces |
| `protocol::h1` / `h2` / `h3` | One connection type per version |
| `helpers::huffman` / `hpack` / `qpack` | Field compression for HTTP/2 and HTTP/3 |
| `helpers::base64` / `sha1` | What the WebSocket handshake needs |
| `helpers::hsts` | `HstsPolicy` and `HstsStore` |
| `models` | `Message`, `Headers`, `Body`, `Url`, `Version`, `Method`, `Role`, `Port`, `Limits` |
| `headers` | Cookies: `Cookie`, `SetCookie`, `CookieJar` |
| `responses` | Response constructors, and media types by file extension |
| `websocket` | Frames, opcodes, close codes, the handshakes, and `WebSocketConnection` |
| `finalizer` | The fields the crate fills in on the way out, and the `Date` cache |

Prefer naming the base type — `Connection`, `AnyConnection` — over a concrete version wherever
there is a choice.

## Limits and admission

`Limits` holds every ceiling one connection applies to itself: message and header sizes, the
read, write, send and receive timeouts, concurrent streams, connection buffer size, WebSocket
fragments, and the caps on the cookie jar and HSTS store. It has a `Default`, and both
builders take one.

Several of those exist to blunt known attacks — `max_premature_resets` for rapid reset,
`max_idle_frames` for PING and SETTINGS floods, `max_pending_handshakes` for slow handshake
floods.

Admission is separate, and lives on the server. `Gate` caps the total number of connections,
the number one address may hold, and how fast one address may connect. Each rate entry is a
period in seconds and a count, and every entry has to be satisfied, so several together shape
both bursts and sustained rate:

```rust
let server = Server::builder()
    .max_connections(10_000)
    .max_connections_per_ip(64)
    .max_connection_rate(vec![(1.0, 20), (60.0, 300)])
    .build();
```

## Development

```bash
cargo test
```

```bash
cargo bench
```

Benchmarks cover Huffman, HPACK, QPACK, the per-version protocol paths, the HTTP/1 pipeline
and HTTP/3.

Fuzzing lives in its own workspace under `fuzz/`, and needs a nightly toolchain with
`cargo-fuzz`. The targets are `huffman`, `hpack`, `qpack`, `frames` and `everything`:

```bash
cargo +nightly fuzz run everything
```

## License

MIT. See [LICENSE](LICENSE).
