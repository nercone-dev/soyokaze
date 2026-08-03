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
    negotiation.assemble_plain(Box::new(port), id).await
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
