use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use soyokaze::models::{Body, Message, Port};
use soyokaze::protocol::common::{AnyConnection, Connection};
use soyokaze::{Cluster, Handler, Server};

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
    assert!(Server::builder().build().reuseport());
    assert!(!Server::builder().reuseport(false).build().reuseport());
}

#[test]
fn workers_share_one_reused_port() {
    let recorder = Recorder::new();
    let server = Server::builder().version(soyokaze::Version::V1_1).build();

    let cluster = server.serve_workers(recorder.clone(), &[Port::TCP(0)], 4).expect("the cluster did not start");

    assert_eq!(cluster.workers(), 4);
    assert_eq!(cluster.addresses().len(), 1);

    exercise(&cluster, 32);
    cluster.close(Some(5.0));

    assert!(recorder.threads() >= 1);
}

#[test]
fn workers_share_one_descriptor_without_reuseport() {
    let recorder = Recorder::new();
    let server = Server::builder().version(soyokaze::Version::V1_1).reuseport(false).build();

    let cluster = server.serve_workers(recorder.clone(), &[Port::TCP(0)], 2).expect("the cluster did not start");

    assert_eq!(cluster.workers(), 2);

    exercise(&cluster, 16);
    cluster.close(Some(5.0));

    assert!(recorder.threads() >= 1);
}

#[test]
fn a_single_worker_still_serves() {
    let recorder = Recorder::new();
    let server = Server::builder().version(soyokaze::Version::V1_1).build();

    let cluster = server.serve_workers(recorder.clone(), &[Port::TCP(0)], 1).expect("the cluster did not start");

    exercise(&cluster, 4);
    cluster.close(None);

    assert_eq!(recorder.threads(), 1);
}

#[test]
fn a_quic_port_needs_reuseport_across_workers() {
    let server = Server::builder().reuseport(false).build();
    assert!(server.serve_workers(Recorder::new(), &[Port::QUIC(0)], 2).is_err());
}
