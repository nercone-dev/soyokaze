use bytes::Bytes;

use soyokaze::models::{Body, ConnectionID, Message, Method, Port, Version};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::protocol::h3;
use soyokaze::websocket::{CloseCode, Opcode};
use soyokaze::{Client, ClientConfig, Handler, Identity, Server, ServerConfig};

#[derive(Clone)]
struct Echo;

impl Handler for Echo {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(Bytes::from_static(b"Hello, World!")));

            if connection.send(response).await.is_err() {
                break;
            }
        }

        connection.close().await;
    }
}

struct Certificate {
    der: Vec<u8>,
    key: Vec<u8>,
}

fn certificate() -> Certificate {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("no certificate");

    Certificate {
        der: issued.cert.der().to_vec(),
        key: issued.signing_key.serialize_der(),
    }
}

#[test]
fn many_requests_share_one_quic_connection() {
    const REQUESTS: usize = 512;

    let certificate = certificate();

    let server = Server::new(ServerConfig {
        versions: vec![Version::V3_0],
        identity: Some(Identity::new(vec![certificate.der.clone()], certificate.key)),
        ..ServerConfig::default()
    });

    let cluster = server.run(Echo, &[Port::QUIC(0)], 1).expect("the QUIC port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let answered = runtime.block_on(async move {
        let client = Client::new(ClientConfig {
            versions: vec![Version::V3_0],
            roots: Some(vec![certificate.der]),
            ..ClientConfig::default()
        });

        let id = ConnectionID(Bytes::from_static(b"test"));
        let mut connection = client
            .connect_quic("localhost", port, id)
            .await
            .expect("the client could not reach the server over QUIC");

        let mut answered = 0;
        for _ in 0..REQUESTS {
            let request = Message::request(Method::GET, "/index.html", Version::V3_0);

            let response = tokio::time::timeout(std::time::Duration::from_secs(10), client.request(&mut connection, request))
                .await
                .expect("the server stopped answering")
                .expect("the exchange failed");

            assert_eq!(response.status_code, Some(200));
            assert_eq!(response.body.as_ref().and_then(Body::inline), Some(Bytes::from_static(b"Hello, World!")));
            answered += 1;
        }

        connection.close().await;
        answered
    });

    cluster.close(Some(1.0));
    assert_eq!(answered, REQUESTS, "the connection stopped serving part way through");
}

#[derive(Clone)]
struct Tunnel;

impl Handler for Tunnel {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        let Ok(request) = connection.receive().await else {
            return;
        };

        let Ok(mut socket) = connection.accept_websocket(&request).await else {
            return;
        };

        while let Ok((opcode, payload)) = socket.receive_message().await {
            if opcode == Opcode::Close || socket.send_message(opcode, payload.to_vec()).await.is_err() {
                break;
            }
        }
    }
}

#[test]
fn a_websocket_over_quic_survives_more_writes_than_it_can_buffer() {
    const MESSAGES: usize = h3::TUNNEL_BACKLOG * 8;

    let certificate = certificate();

    let server = Server::new(ServerConfig {
        versions: vec![Version::V3_0],
        identity: Some(Identity::new(vec![certificate.der.clone()], certificate.key)),
        ..ServerConfig::default()
    });

    let cluster = server.run(Tunnel, &[Port::QUIC(0)], 1).expect("the QUIC port did not open");
    let port = cluster.address().expect("the cluster has no address").port();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("no runtime");

    let echoed = runtime.block_on(async move {
        let client = Client::new(ClientConfig {
            versions: vec![Version::V3_0],
            roots: Some(vec![certificate.der]),
            ..ClientConfig::default()
        });

        let id = ConnectionID(Bytes::from_static(b"test"));
        let connection = client
            .connect_quic("localhost", port, id)
            .await
            .expect("the client could not reach the server over QUIC");

        let mut socket = connection
            .open_websocket("localhost", "/chat")
            .await
            .expect("the tunnel did not open");

        let payload = vec![b'x'; 4096];
        let mut echoed = 0;

        for index in 0..MESSAGES {
            let sending = socket.send_message(Opcode::Binary, payload.clone());
            tokio::time::timeout(std::time::Duration::from_secs(10), sending)
                .await
                .unwrap_or_else(|_| panic!("message {index} never left the writer"))
                .expect("the message did not send");

            let receiving = socket.receive_message();
            let (opcode, echo) = tokio::time::timeout(std::time::Duration::from_secs(10), receiving)
                .await
                .unwrap_or_else(|_| panic!("message {index} was never echoed"))
                .expect("the echo did not arrive");

            assert_eq!(opcode, Opcode::Binary);
            assert_eq!(echo.len(), payload.len());
            echoed += 1;
        }

        socket.close(CloseCode::Normal, "done").await;
        echoed
    });

    cluster.close(Some(1.0));
    assert_eq!(echoed, MESSAGES, "the tunnel stopped carrying messages part way through");
}
