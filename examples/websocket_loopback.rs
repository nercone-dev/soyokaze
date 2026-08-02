//! A WebSocket echo server and a client, in one process over loopback TCP.
//!
//! Needs no network access and no certificate:
//!
//! ```bash
//! cargo run --example websocket_loopback
//! ```

use soyokaze::models::Port;
use soyokaze::protocol::base::Transport;
use soyokaze::websocket::{CloseCode, Opcode, WebSocketConnection};
use soyokaze::{Client, Handler, Server};

struct Echo;

impl Handler for Echo {
    async fn on_websocket(&self, mut socket: WebSocketConnection<Box<dyn Transport>>) {
        while let Ok((opcode, payload)) = socket.receive_message().await {
            if socket.send_message(opcode, payload.to_vec()).await.is_err() {
                break;
            }
        }

        socket.close(CloseCode::Normal, "").await;
    }
}

#[tokio::main]
async fn main() -> Result<(), soyokaze::Error> {
    let server = Server::default();
    let handle = server.serve(Echo, &[Port::TCP(0)]).await?;
    let address = handle.address().expect("the server bound no address");

    let client = Client::default();
    let mut socket = client.websocket(&format!("ws://{address}/echo")).await?;

    for message in ["hello", "soyokaze"] {
        socket.send_message(Opcode::Text, message.as_bytes().to_vec()).await?;
        let (opcode, payload) = socket.receive_message().await?;

        println!("{opcode:?} {}", String::from_utf8_lossy(&payload));
    }

    socket.close(CloseCode::Normal, "").await;
    handle.close(Some(5.0)).await;
    Ok(())
}
