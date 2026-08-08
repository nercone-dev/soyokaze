//! A server and a client in one process, talking over loopback TCP.
//!
//! Needs no network access and no certificate, so it is the fastest way to
//! see a request cross the whole stack:
//!
//! ```bash
//! cargo run --example loopback
//! ```

use soyokaze::models::{Message, Method, Port};
use soyokaze::protocol::base::{AnyConnection, Connection};
use soyokaze::{Client, Handler, Server, URL};

struct Greeter;

impl Handler for Greeter {
    async fn on_connection(&self, mut connection: AnyConnection) {
        while let Ok(request) = connection.receive().await {
            let name = request.target.as_deref().unwrap_or("/").trim_start_matches('/');
            let name = if name.is_empty() { "World" } else { name };

            let mut response = Message::text(format!("Hello, {name}!"), connection.version());
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
    let server = Server::default();
    let handle = server.serve(Greeter, &[Port::TCP(0)]).await?;
    let address = handle.address().expect("the server bound no address");

    let client = Client::default();
    let url = URL::parse(&format!("http://{address}/"))?;
    let mut connection = client.open(&url).await?;

    for target in ["/", "/soyokaze"] {
        let request = Message::request(Method::GET, target, connection.version());
        let response = client.request(&mut connection, request).await?;
        let body = response.body.expect("the handler always answers with a body").into_bytes().await?;

        println!("{target} -> {:?} {}", response.status_code, String::from_utf8_lossy(&body));
    }

    connection.close().await;
    handle.close(Some(5.0)).await;
    Ok(())
}
