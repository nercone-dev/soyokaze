"""A client and a server, talking to each other through the bindings.

Everything runs over a kernel-chosen plaintext TCP port, so the tests name
none and need no certificates. Every exchange is awaited, so each test is a
coroutine and the event loop is the one thing all of them share.
"""

import asyncio

import pytest

import soyokaze
from soyokaze import Client, ClientConfig, Compression, Limits, Message, Method, Port, Server, ServerConfig, ServerLimits, URL, Version

async def echo(request):
    """Answers with the request's own target, so the round trip proves the
    request reached the handler intact."""
    response = Message.text(request.target or "")
    response.insert_header("x-answered-by", "python")
    if request.header("x-probe") is not None:
        response.insert_header("x-probe-echo", request.header("x-probe"))
    return response

async def serve(handler=echo, on_websocket=None, config=None):
    """A server on a kernel-chosen port, and the origin to reach it by."""
    server = Server(config)
    handle = await server.serve(handler, [Port.TCP(0)], on_websocket=on_websocket)
    assert handle.port != 0, "a port of zero must report the one the kernel chose"
    return server, handle, f"http://127.0.0.1:{handle.port}"

async def test_a_request_crosses_to_the_handler_and_its_answer_crosses_back():
    server, handle, origin = await serve()
    async with handle:
        client = Client()
        response = await client.fetch(Method.GET, f"{origin}/hello", headers=[("x-probe", "sent")])

        assert response.status_code == 200
        assert response.header("x-answered-by") == "python"
        assert response.header("x-probe-echo") == "sent"
        assert await response.body() == b"/hello"

async def test_every_shorthand_reaches_the_server():
    seen = []

    async def record(request):
        seen.append((request.method, await request.body()))
        return Message.text("ok")

    server, handle, origin = await serve(record)
    try:
        client = Client()
        await client.get(f"{origin}/")
        await client.head(f"{origin}/")
        await client.post(f"{origin}/", b"data")
        await client.put(f"{origin}/", "text")
        await client.delete(f"{origin}/")

        assert [method for method, body in seen] == [Method.GET, Method.HEAD, Method.POST, Method.PUT, Method.DELETE]
        assert seen[2][1] == b"data"
        assert seen[3][1] == b"text"
    finally:
        await handle.close(5)

async def test_a_plain_handler_is_served_without_ever_reaching_the_loop():
    """A handler that waits for nothing need not be a coroutine function."""

    def synchronous(request):
        return Message.text("plain")

    server, handle, origin = await serve(synchronous)
    try:
        assert await (await Client().get(f"{origin}/")).body() == b"plain"
    finally:
        await handle.close(5)

async def test_a_handler_that_raises_answers_with_a_bare_500(capsys):
    async def broken(request):
        raise ValueError("deliberate")

    server, handle, origin = await serve(broken)
    try:
        response = await Client().get(f"{origin}/")
        assert response.status_code == 500
        assert "deliberate" in capsys.readouterr().err, "the traceback must not vanish"
    finally:
        await handle.close(5)

async def test_several_messages_go_over_one_connection():
    server, handle, origin = await serve()
    try:
        client = Client(ClientConfig(secure=False))
        async with await client.connect("127.0.0.1", Port.TCP(handle.port)) as connection:
            assert connection.version == Version.V1_1
            assert connection.role == soyokaze.Role.USER_AGENT
            assert connection.role.is_client(), "a connection the client opened sends requests"

            for index in range(3):
                response = await client.request(connection, Message.request(Method.GET, f"/turn/{index}"))
                assert await response.body() == f"/turn/{index}".encode()
                assert connection.reusable()
    finally:
        await handle.close(5)

async def test_requests_awaited_together_do_not_wait_for_one_another():
    """The point of the migration: the loop is free while a request is in flight."""
    started = asyncio.Event()

    async def slow(request):
        if request.target == "/slow":
            started.set()
            await asyncio.sleep(0.2)
        return Message.text(request.target or "")

    server, handle, origin = await serve(slow)
    try:
        client = Client()
        slow_request = asyncio.create_task(client.get(f"{origin}/slow"))
        await asyncio.wait_for(started.wait(), 5)

        quick = await asyncio.wait_for(client.get(f"{origin}/quick"), 5)
        assert await quick.body() == b"/quick", "a second request must not queue behind the first"

        assert await (await slow_request).body() == b"/slow"
    finally:
        await handle.close(5)

async def test_send_and_receive_expose_the_raw_exchange():
    server, handle, origin = await serve()
    try:
        client = Client(ClientConfig(secure=False))
        async with await client.open(URL(origin)) as connection:
            await connection.send(Message.request(Method.GET, "/raw"))
            response = await connection.receive()
            assert response.status_code == 200
            assert await response.body() == b"/raw"
    finally:
        await handle.close(5)

async def test_a_pinned_version_and_ceilinged_limits_still_serve():
    limits = ServerLimits(message=Limits(max_header_count=32), max_connections=16)
    config = ServerConfig(versions=[Version.V1_1], limits=limits)

    server, handle, origin = await serve(config=config)
    try:
        client = Client(ClientConfig(versions=[Version.V1_1]))
        assert (await client.get(f"{origin}/pinned")).status_code == 200
    finally:
        await handle.close(5)

async def test_the_cluster_spreads_the_same_server_across_workers():
    server = Server()
    async with await server.run(echo, [Port.TCP(0)], workers=2) as cluster:
        assert cluster.workers() == 2
        assert cluster.port != 0

        response = await Client().get(f"http://127.0.0.1:{cluster.port}/clustered")
        assert await response.body() == b"/clustered"

async def test_the_websocket_callback_runs_the_socket_both_ways():
    received = []

    async def on_websocket(socket):
        opcode, payload = await socket.receive_message()
        received.append((opcode, payload))
        await socket.send_message(opcode, payload.decode().upper())
        await socket.close(soyokaze.CloseCode.NORMAL, "done")

    server, handle, origin = await serve(on_websocket=on_websocket)
    try:
        client = Client()
        socket = await client.websocket(f"ws://127.0.0.1:{handle.port}/chat")

        await socket.send_message(soyokaze.Opcode.TEXT, "hello")
        opcode, payload = await socket.receive_message()
        assert (opcode, payload) == (soyokaze.Opcode.TEXT, b"HELLO"), "receive_message hands back what send_message takes, in that order"

        opcode, payload = await socket.receive_message()
        assert opcode == soyokaze.Opcode.CLOSE, "the server's close reaches the client"

        assert received == [(soyokaze.Opcode.TEXT, b"hello")]
    finally:
        await handle.close(5)

async def test_the_client_keeps_cookies_across_requests():
    async def set_then_expect(request):
        response = Message.text("ok")
        if request.target == "/set":
            response.set_cookie(soyokaze.SetCookie("sid", "abc"))
        else:
            response.insert_header("x-got-cookie", request.header("cookie") or "none")
        return response

    server, handle, origin = await serve(set_then_expect)
    try:
        client = Client()
        await client.get(f"{origin}/set")
        response = await client.get(f"{origin}/again")
        assert response.header("x-got-cookie") == "sid=abc"

        stateless = Client(ClientConfig(cookies=False))
        await stateless.get(f"{origin}/set")
        response = await stateless.get(f"{origin}/again")
        assert response.header("x-got-cookie") == "none"
    finally:
        await handle.close(5)

async def test_dialling_nothing_raises_rather_than_hanging():
    client = Client()
    with pytest.raises(soyokaze.Error):
        await client.get("http://127.0.0.1:1/")

async def test_a_served_response_is_compressed_when_the_request_accepts_it():
    """The whole path: the client advertises what it decodes, the server codes
    the answer in one of those, and the client hands it back decoded."""

    body = "a" * 8192
    seen = {}

    async def compressing(request):
        seen["accept"] = request.header("accept-encoding")
        seen["client"] = request.client

        response = Message.text(body)
        response.compression = Compression.AUTO
        return response

    server, handle, origin = await serve(compressing)
    async with handle:
        client = Client()
        response = await client.get(f"{origin}/")

        # RFC 9110 §12.5.3: the client says what it decodes without being asked.
        assert seen["accept"] == Compression.accepted_field()

        # The answer comes back decoded, with the field that named the coding
        # gone and the coding it arrived in still reported.
        assert response.compression is Compression.ZSTD
        assert not response.compressed()
        assert response.header("content-encoding") is None
        assert response.header("vary") == "Accept-Encoding"
        assert (await response.body()).decode() == body

async def test_a_request_that_accepts_nothing_is_answered_uncoded():
    async def compressing(request):
        response = Message.text("a" * 8192)
        response.compression = Compression.AUTO
        return response

    server, handle, origin = await serve(compressing)
    async with handle:
        client = Client()
        response = await client.fetch(Method.GET, f"{origin}/", headers=[("accept-encoding", "identity")])

        assert response.compression is None, "a peer that accepts nothing gets the body as it stands"
        assert not response.compressed()
        assert response.header("content-length") == "8192"

async def test_the_handler_sees_the_address_the_request_came_from():
    seen = {}

    async def record(request):
        seen["client"] = request.client
        return Message.text("ok")

    server, handle, origin = await serve(record)
    async with handle:
        client = Client()
        await client.get(f"{origin}/")

    address = seen["client"]
    assert address is not None, "a handler must be told where the request came from"
    assert address.rsplit(":", 1)[-1].isdigit(), f"{address!r} must carry the port the peer dialled from"

async def test_a_response_a_client_receives_names_no_access_source():
    server, handle, origin = await serve()
    async with handle:
        client = Client()
        response = await client.get(f"{origin}/")

        assert response.client is None, "a response names no access source"
