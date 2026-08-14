use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::models::{Body, Message, Port};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::{Cluster, Handler, Server, ServerConfig};

#[derive(Clone)]
struct Recorder {
    threads: Arc<Mutex<HashSet<ThreadId>>>,
}

impl Recorder {
    fn new() -> Self {
        Self { threads: Arc::new(Mutex::new(HashSet::new())) }
    }

    fn threads(&self) -> usize {
        self.threads.lock().expect("the recorder was poisoned").len()
    }
}

impl Handler for Recorder {
    async fn on_connection(&self, connection: AnyConnection) {
        self.threads.lock().expect("the recorder was poisoned").insert(std::thread::current().id());

        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(Bytes::from_static(b"ok")));

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

async fn probe(port: u16) -> String {
    let address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let mut stream = tokio::net::TcpStream::connect(address).await.expect("the worker refused a connection");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request did not go out");

    let mut response = Vec::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut response));
    read.await.expect("the worker never answered").expect("the response did not come back");

    String::from_utf8_lossy(&response).into_owned()
}

fn socket_path(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("soyokaze-{name}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("the socket was not created").mode() & 0o7777
}

fn exercise(cluster: &Cluster, requests: usize) {
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");
    runtime.block_on(async move {
        for _ in 0..requests {
            let response = probe(port).await;
            assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response:?}");
            assert!(response.ends_with("ok"), "unexpected body: {response:?}");
        }
    });
}

#[test]
fn reuseport_is_the_default() {
    assert!(ServerConfig::default().reuseport);
}

#[test]
fn workers_share_one_reused_port() {
    let recorder = Recorder::new();
    let server = Server::new(ServerConfig { versions: vec![soyokaze::Version::V1_1], ..ServerConfig::default() });

    let cluster = server.run(recorder.clone(), &[Port::TCP(0)], 4).expect("the cluster did not start");

    assert_eq!(cluster.workers(), 4);
    assert_eq!(cluster.addresses().len(), 1);

    exercise(&cluster, 32);
    cluster.close(Some(5.0));

    assert!(recorder.threads() >= 1);
}

#[test]
fn workers_share_one_descriptor_without_reuseport() {
    let recorder = Recorder::new();
    let server = Server::new(ServerConfig {
        versions: vec![soyokaze::Version::V1_1],
        reuseport: false,
        ..ServerConfig::default()
    });

    let cluster = server.run(recorder.clone(), &[Port::TCP(0)], 2).expect("the cluster did not start");

    assert_eq!(cluster.workers(), 2);

    exercise(&cluster, 16);
    cluster.close(Some(5.0));

    assert!(recorder.threads() >= 1);
}

#[test]
fn a_single_worker_still_serves() {
    let recorder = Recorder::new();
    let server = Server::new(ServerConfig { versions: vec![soyokaze::Version::V1_1], ..ServerConfig::default() });

    let cluster = server.run(recorder.clone(), &[Port::TCP(0)], 1).expect("the cluster did not start");

    exercise(&cluster, 4);
    cluster.close(None);

    assert_eq!(recorder.threads(), 1);
}

#[test]
fn a_quic_port_needs_reuseport_across_workers() {
    let server = Server::new(ServerConfig { reuseport: false, ..ServerConfig::default() });
    assert!(server.run(Recorder::new(), &[Port::QUIC(0)], 2).is_err());
}

/// A port must only ever settle on a version it offered.
///
/// RFC 9113 §3.4 makes the preface the only way to reach HTTP/2 without ALPN,
/// so a plaintext port has exactly two outcomes: the preface arrives and the
/// port speaks HTTP/2, or it does not and the port speaks HTTP/1.x. Neither is
/// available unless the port offered it, and a port left with no outcome must
/// refuse the connection rather than settle on something unnegotiated.
async fn sniff(versions: Vec<soyokaze::Version>, first: &[u8]) -> Result<AnyConnection, soyokaze::Error> {
    let negotiation = soyokaze::protocol::Negotiation {
        versions,
        limits: soyokaze::Limits::default(),
        acceptor: None,
        response_finalizer: soyokaze::finalizer::ResponseFinalizer::default(),
    };

    let (mut peer, port) = tokio::io::duplex(4096);
    peer.write_all(first).await.expect("the peer could not write");

    let id = soyokaze::ConnectionID(Bytes::from_static(b"test"));
    negotiation.assemble_plain(Box::new(port), id, None).await
}

#[tokio::test]
async fn a_plaintext_port_speaks_http_2_only_when_the_preface_arrives() {
    let versions = vec![soyokaze::Version::V2_0, soyokaze::Version::V1_1];

    let connection = sniff(versions.clone(), b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.expect("the preface was refused");
    assert_eq!(connection.version(), soyokaze::Version::V2_0);

    let connection = sniff(versions, b"GET / HTTP/1.1\r\n\r\n").await.expect("a request was refused");
    assert_eq!(connection.version(), soyokaze::Version::V1_1);
}

#[tokio::test]
async fn a_plaintext_port_offering_only_http_2_refuses_a_peer_that_sends_no_preface() {
    let outcome = sniff(vec![soyokaze::Version::V2_0], b"GET / HTTP/1.1\r\n\r\n").await;

    assert!(
        matches!(outcome, Err(soyokaze::Error::Version(_))),
        "a port offering only HTTP/2 must refuse a peer that did not send the preface",
    );
}

#[tokio::test]
async fn a_plaintext_port_offering_only_http_1_never_settles_on_http_2() {
    let connection = sniff(vec![soyokaze::Version::V1_1], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("a port offering HTTP/1.1 refused a connection");

    assert_eq!(connection.version(), soyokaze::Version::V1_1);
}

#[test]
fn a_stream_port_offered_no_stream_version_is_refused_at_bind() {
    let server = Server::new(ServerConfig { versions: vec![soyokaze::Version::V3_0], ..ServerConfig::default() });

    assert!(
        server.run(Recorder::new(), &[Port::TCP(0)], 1).is_err(),
        "a TCP port offered only HTTP/3 must fail to bind, as a QUIC port offered no HTTP/3 does",
    );
}

/// A version the caller pinned is spoken or refused, never exchanged.
///
/// A plaintext port and a Unix socket carry no ALPN, so the version has to be
/// settled in advance. One stream version configured is prior knowledge — h2c
/// included, since RFC 9113 §3.4 lets a client that knows send the preface
/// unprompted. Several configured leaves only HTTP/1.x assumable of a peer that
/// was never asked.
#[test]
fn a_client_pins_the_one_stream_version_it_was_configured_with() {
    for pinned in [soyokaze::Version::V1_0, soyokaze::Version::V1_1, soyokaze::Version::V2_0] {
        let client = soyokaze::Client::new(soyokaze::ClientConfig {
            versions: vec![pinned],
            ..soyokaze::ClientConfig::default()
        });

        assert_eq!(client.prior_version().expect("a stream version was refused"), pinned);
    }
}

#[test]
fn a_client_offered_several_versions_falls_back_to_http_1_x_only() {
    let client = soyokaze::Client::new(soyokaze::ClientConfig {
        versions: vec![soyokaze::Version::V3_0, soyokaze::Version::V2_0, soyokaze::Version::V1_1],
        ..soyokaze::ClientConfig::default()
    });

    assert_eq!(client.prior_version().expect("the default versions were refused"), soyokaze::Version::V1_1);
}

#[test]
fn a_client_pinned_to_http_3_refuses_a_stream_rather_than_speaking_http_1_1() {
    let client = soyokaze::Client::new(soyokaze::ClientConfig {
        versions: vec![soyokaze::Version::V3_0],
        ..soyokaze::ClientConfig::default()
    });

    assert!(
        matches!(client.prior_version(), Err(soyokaze::Error::Version(_))),
        "a client pinned to HTTP/3 must not silently speak HTTP/1.1 over a stream",
    );
}

#[test]
fn http_3_being_configured_does_not_stop_a_stream_version_being_pinned() {
    let client = soyokaze::Client::new(soyokaze::ClientConfig {
        versions: vec![soyokaze::Version::V3_0, soyokaze::Version::V2_0],
        ..soyokaze::ClientConfig::default()
    });

    assert_eq!(
        client.prior_version().expect("the only stream version was refused"),
        soyokaze::Version::V2_0,
        "HTTP/3 cannot run over a stream, so HTTP/2 is the one version left to know in advance",
    );
}

#[test]
fn several_stream_versions_prefer_the_configured_order() {
    let client = soyokaze::Client::new(soyokaze::ClientConfig {
        versions: vec![soyokaze::Version::V2_0, soyokaze::Version::V1_0, soyokaze::Version::V1_1],
        ..soyokaze::ClientConfig::default()
    });

    assert_eq!(
        client.prior_version().expect("the configured versions were refused"),
        soyokaze::Version::V1_0,
        "the most preferred HTTP/1.x wins, not merely the last one listed",
    );
}

#[derive(Clone)]
struct Authorities(Arc<Mutex<Vec<String>>>);

impl Handler for Authorities {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let authority = request.headers.as_ref().and_then(|headers| headers.get("host")).unwrap_or("<none>").to_owned();
            self.0.lock().expect("the recorder was poisoned").push(format!("{} {}", connection.version(), authority));

            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Text("ok".to_owned()));

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_supplies_the_authority_it_dialled_on_every_version() {
    // RFC 9112 §3.2 requires Host on an HTTP/1.1 request, and RFC 9113 §8.3.1
    // requires :authority (or Host) on an HTTP/2 one. A caller that never sets
    // the field is still owed it, whichever way the connection was opened.
    for version in [soyokaze::Version::V1_1, soyokaze::Version::V2_0] {
        let seen = Authorities(Arc::new(Mutex::new(Vec::new())));

        let server = Server::new(ServerConfig { versions: vec![version], ..ServerConfig::default() });
        let handle = server.serve(seen.clone(), &[Port::TCP(0)]).await.expect("the port did not bind");
        let port = handle.address().expect("the port reported no address").port();

        let client = soyokaze::Client::new(soyokaze::ClientConfig {
            versions: vec![version],
            secure: false,
            ..soyokaze::ClientConfig::default()
        });

        let mut connection = client.connect("127.0.0.1", Port::TCP(port)).await.expect("the dial failed");
        let request = Message::request(soyokaze::Method::GET, "/", connection.version());
        let response = client.request(&mut connection, request).await.expect("no response came back");
        assert_eq!(response.status_code, Some(200));
        connection.close().await;

        client
            .fetch(soyokaze::Method::GET, &format!("http://127.0.0.1:{port}/"), None, None)
            .await
            .expect("the one-off request failed");

        handle.close(Some(5.0)).await;

        let seen = seen.0.lock().expect("the recorder was poisoned").clone();
        assert_eq!(seen.len(), 2, "{version}: the server did not see both requests: {seen:?}");

        for line in &seen {
            assert_eq!(
                line,
                &format!("{version} 127.0.0.1:{port}"),
                "{version}: a request left without the authority the connection was dialled with",
            );
        }
    }
}

/// Answers every request with what the connection was told about its peer, and
/// codes the answer as the request asked.
#[derive(Clone)]
struct Reflector;

impl Handler for Reflector {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let seen = request.client.map_or_else(|| "none".to_owned(), |client| client.to_string());

            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(Bytes::from(format!("{seen}|{}", "x".repeat(4096)))));
            response.compression = Some(soyokaze::Compression::Auto);

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

/// A handler must be able to see where a request came from, and it must be the
/// address the peer actually dialled from rather than anything reconstructed.
#[test]
fn a_served_request_carries_the_address_it_came_from() {
    let server = Server::new(ServerConfig::default());
    let cluster = server.run(Reflector, &[Port::TCP(0)], 1).expect("the TCP port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    runtime.block_on(async move {
        let address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let mut stream = tokio::net::TcpStream::connect(address).await.expect("the worker refused a connection");
        let dialled = stream.local_addr().expect("the socket has no local address");

        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request did not go out");

        let mut response = Vec::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut response));
        read.await.expect("the worker never answered").expect("the response did not come back");

        let split = response.windows(4).position(|window| window == b"\r\n\r\n").expect("the response carried no field section");
        let head = String::from_utf8_lossy(&response[..split]).into_owned();
        let body = &response[split + 4..];

        assert!(head.contains("Content-Encoding: gzip"), "a request that accepts gzip must be answered in it: {head}");
        assert!(head.contains("Vary: Accept-Encoding"), "a response coded from Accept-Encoding must vary on it: {head}");
        assert!(body.len() < 4096, "{} octets crossed the wire, which is the identity body", body.len());

        let decoded = soyokaze::Compression::Gzip.decode(body, 1 << 20).expect("the body did not decode");
        let seen = String::from_utf8_lossy(&decoded).into_owned();
        let seen = seen.split('|').next().unwrap_or_default().to_owned();

        assert_eq!(seen, dialled.to_string(), "the handler saw {seen:?} rather than the address the peer dialled from");
    });
}

/// The address of an accepted Unix socket names nothing, so there is nothing to
/// report and nothing for the gate to limit by.
#[test]
fn a_unix_socket_connection_reports_no_client_address() {
    let path = std::env::temp_dir().join(format!("soyokaze-client-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let server = Server::new(ServerConfig::default());
    let cluster = server
        .run(Reflector, &[Port::UDS(path.to_string_lossy().into_owned())], 1)
        .expect("the unix socket did not open");

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    runtime.block_on(async {
        let mut stream = tokio::net::UnixStream::connect(&path).await.expect("the worker refused a connection");

        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request did not go out");

        let mut response = Vec::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut response));
        read.await.expect("the worker never answered").expect("the response did not come back");

        let text = String::from_utf8_lossy(&response).into_owned();
        let (_, body) = text.split_once("\r\n\r\n").expect("the response carried no field section");

        assert!(body.starts_with("none|"), "a unix socket connection must report no address: {body:.32?}");
    });

    drop(cluster);
    let _ = std::fs::remove_file(&path);
}

/// Connecting to a Unix socket asks for write permission on it, and a reverse
/// proxy in front usually runs as another user, so one is bound at 0o666.
#[test]
fn a_unix_socket_is_bound_at_the_default_mode() {
    let path = socket_path("mode-default");
    let server = Server::new(ServerConfig::default());
    let socket = server.open(&Port::UDS(path.to_string_lossy().into_owned())).expect("the unix socket did not open");

    assert_eq!(mode_of(&path), 0o666, "a unix socket must be left reachable by a peer running as another user");

    drop(socket);
    let _ = std::fs::remove_file(&path);
}

/// The mode is the caller's to pick, for a socket that is nobody else's business.
#[test]
fn a_unix_socket_is_bound_at_the_configured_mode() {
    let path = socket_path("mode-configured");
    let server = Server::new(ServerConfig { uds_mode: 0o600, ..ServerConfig::default() });
    let socket = server.open(&Port::UDS(path.to_string_lossy().into_owned())).expect("the unix socket did not open");

    assert_eq!(mode_of(&path), 0o600, "a unix socket must be bound at the mode it was configured with");

    drop(socket);
    let _ = std::fs::remove_file(&path);
}

/// Zero asks for no mode of its own, so the socket keeps the one the process
/// umask gave it, exactly as a bare bind leaves it.
#[test]
fn a_unix_socket_mode_of_zero_leaves_the_umask_its_say() {
    let bare = socket_path("mode-bare");
    let listener = std::os::unix::net::UnixListener::bind(&bare).expect("the reference socket did not bind");

    let path = socket_path("mode-umask");
    let server = Server::new(ServerConfig { uds_mode: 0, ..ServerConfig::default() });
    let socket = server.open(&Port::UDS(path.to_string_lossy().into_owned())).expect("the unix socket did not open");

    assert_eq!(mode_of(&path), mode_of(&bare), "a mode of zero must leave the socket as the umask made it");

    drop(socket);
    drop(listener);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&bare);
}

/// Everything a test needs to watch a port admit: the gate it admits through,
/// the port the kernel gave it, and the connections it hands out.
struct Watched {
    gate: Arc<soyokaze::Gate>,
    port: u16,
    admitted: tokio::sync::mpsc::UnboundedReceiver<soyokaze::api::server::Admitted>,
    held: Vec<soyokaze::api::server::Admitted>,
}

impl Watched {
    /// How many more connections the port has handed out since it was last
    /// asked, keeping every one of them alive — a connection dropped here
    /// would give its slot back and take the count with it.
    fn served(&mut self) -> usize {
        let mut served = 0;

        while let Ok(connection) = self.admitted.try_recv() {
            self.held.push(connection);
            served += 1;
        }

        served
    }

    /// Waits for the port to have handed out `expected` connections, and
    /// reports how many it actually did. Negotiation finishes on another task,
    /// so a tally is only meaningful once it has had the chance to settle.
    async fn handed(&mut self, expected: usize) -> usize {
        let mut served = 0;

        for _ in 0..400 {
            served += self.served();

            if served >= expected {
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        served
    }
}

/// Binds `port` on `server`, drives its accept loop in the background, and
/// watches what it admits. Everything the port hands out is kept alive in the
/// channel, so a connection stays counted until the watcher is dropped.
async fn watch(server: Server, port: Port) -> Watched {
    let listener = server.bind(port).await.expect("the port did not bind");
    let bound = listener.address().expect("the port has no address").port();
    let gate = Arc::clone(listener.gate());

    let (sender, admitted) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        let mut listener = listener;

        while let Ok(connection) = listener.accept().await {
            if sender.send(connection).is_err() {
                break;
            }
        }
    });

    Watched { gate, port: bound, admitted, held: Vec::new() }
}

/// A plaintext HTTP/1.1 server holding to `limits`.
fn plaintext(limits: soyokaze::ServerLimits) -> Server {
    Server::new(ServerConfig { versions: vec![soyokaze::Version::V1_1], limits, ..ServerConfig::default() })
}

/// Limits that leave a silent connection pending for as long as a test runs,
/// so what refuses it is the gate rather than the handshake deadline.
fn patient(limits: soyokaze::ServerLimits) -> soyokaze::ServerLimits {
    soyokaze::ServerLimits {
        message: soyokaze::Limits { handshake_timeout: 30.0, ..limits.message },
        ..limits
    }
}

/// Opens a connection and says nothing on it, as a flood does.
async fn silent(port: u16) -> tokio::net::TcpStream {
    let address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    tokio::net::TcpStream::connect(address).await.expect("the port would not take a connection")
}

/// Whether a connection is turned away: closed by the server, or never taken
/// at all. A connection left open and waiting is neither, and is what a gate
/// that failed to refuse looks like.
async fn refused(port: u16) -> bool {
    let address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let Ok(mut stream) = tokio::net::TcpStream::connect(address).await else {
        return true;
    };

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte));

    matches!(read.await, Ok(Ok(0)) | Ok(Err(_)))
}

/// Waits for the gate to hold `expected` connections, and reports what it
/// actually holds. Admission happens on another task, so a count is only
/// meaningful once it has had the chance to settle.
async fn settles(gate: &soyokaze::Gate, expected: u32) -> u32 {
    for _ in 0..400 {
        if gate.count() == expected {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    gate.count()
}

/// A connection must be admitted before it is negotiated.
///
/// A peer that connects and then says nothing has negotiated nothing, so a
/// gate consulted after negotiation never sees it — and a flood of exactly
/// those connections is what admission control exists to bound. Counting one
/// from the moment it is accepted is what makes every limit below mean
/// anything at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_has_not_negotiated_is_already_counted() {
    let watched = watch(plaintext(patient(soyokaze::ServerLimits::default())), Port::TCP(0)).await;

    let held = silent(watched.port).await;

    assert_eq!(settles(&watched.gate, 1).await, 1, "a connection that has not negotiated must still be counted");

    drop(held);
}

/// The per-address ceiling must bound silent connections too.
///
/// One address holding the ceiling in unnegotiated connections is over it, and
/// the next connection from that address is refused — closed without a
/// handshake being spent on it.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_counts_against_the_per_address_ceiling() {
    let limits = patient(soyokaze::ServerLimits { max_connections_per_ip: 1, ..soyokaze::ServerLimits::default() });
    let watched = watch(plaintext(limits), Port::TCP(0)).await;

    let held = silent(watched.port).await;
    assert_eq!(settles(&watched.gate, 1).await, 1, "the first connection must be admitted");

    assert!(refused(watched.port).await, "an address at its ceiling must be refused even while its connection is silent");
    assert_eq!(watched.gate.count(), 1, "a refused connection must not be counted");

    drop(held);
}

/// The total ceiling must bound silent connections too, exactly as the
/// per-address one does.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_counts_against_the_total_ceiling() {
    let limits = patient(soyokaze::ServerLimits { max_connections: 1, ..soyokaze::ServerLimits::default() });
    let watched = watch(plaintext(limits), Port::TCP(0)).await;

    let held = silent(watched.port).await;
    assert_eq!(settles(&watched.gate, 1).await, 1, "the first connection must be admitted");

    assert!(refused(watched.port).await, "a server at its ceiling must refuse, whether or not what fills it has spoken");
    assert_eq!(watched.gate.count(), 1, "a refused connection must not be counted");

    drop(held);
}

/// A rate limit must be spent by connecting, not by negotiating.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_spends_the_rate_limit() {
    let limits = patient(soyokaze::ServerLimits { max_connection_rate: vec![(60.0, 1)], ..soyokaze::ServerLimits::default() });
    let watched = watch(plaintext(limits), Port::TCP(0)).await;

    let held = silent(watched.port).await;
    assert_eq!(settles(&watched.gate, 1).await, 1, "the first connection must be admitted");

    assert!(refused(watched.port).await, "a rate limit spent by a silent connection must refuse the next one");

    drop(held);
}

/// Refusing must be cheaper than admitting, or a flood is served by the
/// refusal itself.
///
/// A refused connection is turned away before a handshake slot is reserved, so
/// it never takes one of the [`Limits::max_pending_handshakes`]. Were it to
/// take one, a flood would exhaust the slots through refusals alone, the accept
/// loop would stop accepting, and connections after that would be left waiting
/// rather than refused — which is what this checks does not happen.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connection_spends_no_handshake_slot() {
    let limits = soyokaze::ServerLimits {
        max_connections_per_ip: 1,
        message: soyokaze::Limits { max_pending_handshakes: 2, handshake_timeout: 30.0, ..soyokaze::Limits::default() },
        ..soyokaze::ServerLimits::default()
    };

    let watched = watch(plaintext(limits), Port::TCP(0)).await;

    let held = silent(watched.port).await;
    assert_eq!(settles(&watched.gate, 1).await, 1, "the first connection must be admitted");

    for attempt in 0..8 {
        assert!(refused(watched.port).await, "refusal {attempt} was left waiting, so refusing is spending a handshake slot");
    }

    drop(held);
}

/// A handshake that never finishes must give its slot back.
///
/// The permit is taken at the accept and belongs to the connection from then
/// on, so a negotiation that fails or times out has to release it as surely as
/// a connection that ran to completion does. A permit lost on the handshake
/// path would leak the ceiling away one silent connection at a time.
#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_that_times_out_gives_its_slot_back() {
    let limits = soyokaze::ServerLimits {
        message: soyokaze::Limits { handshake_timeout: 0.25, ..soyokaze::Limits::default() },
        ..soyokaze::ServerLimits::default()
    };

    let watched = watch(plaintext(limits), Port::TCP(0)).await;

    let held = silent(watched.port).await;
    assert_eq!(settles(&watched.gate, 1).await, 1, "the connection must be admitted");
    assert_eq!(settles(&watched.gate, 0).await, 0, "a handshake that timed out must release the slot it held");

    drop(held);
}

/// A connection that did negotiate stays counted until the connection itself
/// is done with, not until its peer's socket goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_negotiated_is_counted_until_it_is_dropped() {
    let mut watched = watch(plaintext(soyokaze::ServerLimits::default()), Port::TCP(0)).await;

    let mut stream = silent(watched.port).await;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.expect("the request did not go out");

    assert_eq!(settles(&watched.gate, 1).await, 1, "a negotiated connection must be counted");
    assert_eq!(watched.handed(1).await, 1, "a negotiated connection must be handed out");

    drop(stream);
    assert_eq!(watched.gate.count(), 1, "the permit belongs to the connection, not to the peer's socket");
}

/// Negotiating is given less patience than reading.
///
/// The handshake deadline bounds how long one of the
/// [`Limits::max_pending_handshakes`] slots may be held, so a peer that has not
/// begun speaking must not be given the same patience as one that has: were
/// they the same, a silent connection would hold a slot for as long as a
/// working one holds a read.
#[test]
fn negotiating_is_given_less_patience_than_reading() {
    let limits = soyokaze::Limits::default();

    assert!(limits.handshake_timeout > 0.0, "a handshake left without a deadline holds its slot forever");
    assert!(
        limits.handshake_timeout <= limits.read_timeout,
        "a peer that has not begun speaking must not be given more patience than one that has",
    );
}

/// Admission must reach a QUIC port too.
///
/// What refusing costs there is not what it costs a stream: a QUIC endpoint
/// routes datagrams by the connection IDs it holds for a connection, and gives
/// them up only when whatever drives that connection says so, so a refusal
/// that dropped one undriven would leave those IDs behind for good. That is
/// why [`Negotiation::refuse`] closes a QUIC connection rather than dropping
/// it, and why this checks the ceiling reaches a QUIC port at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_quic_connection_over_the_ceiling_is_refused() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("no certificate was issued");
    let identity = soyokaze::Identity::new(vec![issued.cert.pem().into_bytes()], issued.signing_key.serialize_pem().into_bytes());

    let server = Server::new(ServerConfig {
        versions: vec![soyokaze::Version::V3_0],
        identity: Some(identity),
        limits: soyokaze::ServerLimits { max_connections_per_ip: 1, ..soyokaze::ServerLimits::default() },
        ..ServerConfig::default()
    });

    let mut watched = watch(server, Port::QUIC(0)).await;

    let client = soyokaze::Client::new(soyokaze::ClientConfig {
        versions: vec![soyokaze::Version::V3_0],
        roots: Some(vec![issued.cert.der().to_vec()]),
        ..soyokaze::ClientConfig::default()
    });

    let held = client.connect("localhost", Port::QUIC(watched.port)).await.expect("the first connection was refused");
    assert_eq!(settles(&watched.gate, 1).await, 1, "the first connection must be admitted");
    assert_eq!(watched.handed(1).await, 1, "the first connection must be handed out");

    let over = client.connect("localhost", Port::QUIC(watched.port)).await;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    assert_eq!(watched.gate.count(), 1, "a refused connection must not be counted");
    assert_eq!(watched.served(), 0, "an address at its ceiling must have its QUIC connection refused, not served");

    drop(over);
    drop(held);
}
