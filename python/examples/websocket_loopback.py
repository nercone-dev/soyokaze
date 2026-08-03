"""A WebSocket echo server and a client, in one process over loopback TCP.

The Python half of the crate's ``examples/websocket_loopback.rs``. It needs no
network access and no certificate:

    uv run examples/websocket_loopback.py
"""

from soyokaze import Client, CloseCode, Error, Message, Opcode, Port, Server

def echo(socket):
    """Sends every message back the way it came, until the socket ends.

    The handler runs on its own thread and drives the socket for as long as it
    lives; the bindings close and free it once the handler returns, so this
    one simply stops when the connection does.
    """
    try:
        while True:
            opcode, payload = socket.receive_message()
            socket.send_message(opcode, payload)
    except Error:
        pass

def decline(request):
    """Answers every request that was not a WebSocket upgrade."""
    response = Message.response(426, request.version)
    response.set_body("this port speaks WebSocket")
    return response

def main():
    # A port of zero lets the kernel choose one, so the example names none.
    server = Server()
    handle = server.serve(decline, [Port.TCP(0)], on_websocket=echo)

    client = Client()
    socket = client.websocket(f"ws://127.0.0.1:{handle.port}/echo")

    for message in ["hello", "soyokaze"]:
        socket.send_message(Opcode.TEXT, message)
        opcode, payload = socket.receive_message()
        print(f"{opcode.name} {payload.decode()}")

    socket.close(CloseCode.NORMAL, "")
    handle.close(5)

if __name__ == "__main__":
    main()
