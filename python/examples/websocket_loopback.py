"""A WebSocket echo server and a client, in one process over loopback TCP.

The Python half of the crate's ``examples/websocket_loopback.rs``. It needs no
network access and no certificate:

    uv run examples/websocket_loopback.py
"""

import asyncio

from soyokaze import Client, CloseCode, Error, Message, Opcode, Port, Server

async def echo(socket):
    """Sends every message back the way it came, until the socket ends.

    The handler drives the socket for as long as it lives, awaiting the next
    message rather than holding a thread while nothing arrives; the bindings
    close and free it once the handler returns, so this one simply stops when
    the connection does.
    """
    try:
        while True:
            opcode, payload = await socket.receive_message()
            await socket.send_message(opcode, payload)
    except Error:
        pass

async def decline(request):
    """Answers every request that was not a WebSocket upgrade."""
    response = Message.response(426, request.version)
    response.set_body("this port speaks WebSocket")
    return response

async def main():
    # A port of zero lets the kernel choose one, so the example names none.
    server = Server()
    handle = await server.serve(decline, [Port.TCP(0)], on_websocket=echo)

    client = Client()
    socket = await client.websocket(f"ws://127.0.0.1:{handle.port}/echo")

    for message in ["hello", "soyokaze"]:
        await socket.send_message(Opcode.TEXT, message)
        opcode, payload = await socket.receive_message()
        print(f"{opcode.name} {payload.decode()}")

    await socket.close(CloseCode.NORMAL, "")
    await handle.close(5)

if __name__ == "__main__":
    asyncio.run(main())
