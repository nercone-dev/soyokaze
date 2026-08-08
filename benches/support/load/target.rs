//! The server a load run is driven against.

use bytes::Bytes;

use soyokaze::models::{Body, Message, Port};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::{Client, ClientConfig, Cluster, Handler, Identity, Server, ServerConfig};

use crate::support::fixtures::Payload;
use crate::support::load::workload::Workload;

/// A self-signed certificate for a loopback run.
///
/// A load run over TLS or QUIC needs one, and a run measured against a
/// certificate authority would be measuring the authority. This is issued for
/// `localhost`, handed to the server as its identity and to the client as the
/// one root it trusts, and thrown away when the run ends.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The certificate, DER encoded.
    pub der: Vec<u8>,

    /// The private key, DER encoded.
    pub key: Vec<u8>,
}

impl Certificate {
    /// The name a loopback certificate is issued for.
    pub const NAME: &'static str = "localhost";

    /// A fresh certificate for `localhost`.
    pub fn localhost() -> Self {
        let issued = rcgen::generate_simple_self_signed(vec![Self::NAME.to_owned()]).expect("no certificate was issued");

        Self { der: issued.cert.der().to_vec(), key: issued.signing_key.serialize_der() }
    }

    /// The identity a server serves this certificate as.
    pub fn identity(&self) -> Identity {
        Identity::new(vec![self.der.clone()], self.key.clone())
    }

    /// The roots a client trusts this certificate through.
    pub fn roots(&self) -> Vec<Vec<u8>> {
        vec![self.der.clone()]
    }
}

/// The handler a load target answers with.
///
/// It answers every request with the same body and nothing else, so that what
/// a run measures is the stack under the handler rather than the handler.
#[derive(Clone)]
pub struct Responder {
    /// The body every response carries.
    pub body: Bytes,
}

impl Responder {
    /// A responder answering with a body of this many octets.
    pub fn new(octets: usize) -> Self {
        Self { body: Payload::of(octets) }
    }
}

impl Handler for Responder {
    async fn on_connection(&self, connection: AnyConnection) {
        let mut connection = connection;

        while let Ok(request) = connection.receive().await {
            let mut response = Message::response(200, connection.version());
            response.stream_id = request.stream_id;
            response.body = Some(Body::Data(self.body.clone()));

            if connection.send(response).await.is_err() || !connection.reusable() {
                break;
            }
        }

        connection.close().await;
    }
}

/// A server bound to a loopback port for the length of one run.
pub struct Target {
    /// The worker threads serving it.
    pub cluster: Cluster,

    /// The port it bound, which is never the one that was asked for since a
    /// run always asks for an ephemeral one.
    pub port: u16,

    /// The certificate it serves, when the run needs one.
    pub certificate: Option<Certificate>,
}

impl Target {
    /// Starts a server for this workload on an ephemeral loopback port.
    pub fn start(workload: &Workload) -> Self {
        let certificate = workload.needs_identity().then(Certificate::localhost);

        let config = ServerConfig {
            versions: vec![workload.version],
            identity: certificate.as_ref().map(Certificate::identity),
            ..ServerConfig::default()
        };

        let responder = Responder::new(workload.response_body);
        let cluster = Server::new(config).run(responder, &[workload.port(0)], workload.workers).expect("the load target did not bind");
        let port = cluster.address().expect("the load target bound no address").port();

        Self { cluster, port, certificate }
    }

    /// A client configured to reach this target.
    pub fn client(&self, workload: &Workload) -> Client {
        Client::new(ClientConfig {
            versions: vec![workload.version],
            secure: workload.needs_identity(),
            roots: self.certificate.as_ref().map(Certificate::roots),
            cookies: false,
            hsts: false,
            ..ClientConfig::default()
        })
    }

    /// Where a client dials this target.
    pub fn port(&self, workload: &Workload) -> Port {
        workload.port(self.port)
    }

    /// Stops the server and waits for its workers to wind down.
    pub fn stop(self) {
        self.cluster.close(Some(1.0));
    }
}
