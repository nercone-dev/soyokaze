"""A client and a server, talking to each other through the bindings.

Everything runs over a kernel-chosen plaintext TCP port, so the tests name
none and need no certificates.
"""

import threading

import pytest

import soyokaze
from soyokaze import Client, ClientConfig, Limits, Message, Method, Port, Server, ServerConfig, ServerLimits, URL, Version

def echo(request):
    """Answers with the request's own target, so the round trip proves the
    request reached the handler intact."""
    response = Message.text(request.target or "")
    response.insert_header("x-answered-by", "python")
    if request.header("x-probe") is not None:
        response.insert_header("x-probe-echo", request.header("x-probe"))
    return response

def serve(handler=echo, on_websocket=None, config=None):
    """A server on a kernel-chosen port, and the origin to reach it by."""
    server = Server(config)
    handle = server.serve(handler, [Port.TCP(0)], on_websocket=on_websocket)
    assert handle.port != 0, "a port of zero must report the one the kernel chose"
    return server, handle, f"http://127.0.0.1:{handle.port}"

def test_a_request_crosses_to_the_handler_and_its_answer_crosses_back():
    server, handle, origin = serve()
    try:
        client = Client()
        response = client.fetch(Method.GET, f"{origin}/hello", headers=[("x-probe", "sent")])

        assert response.status_code == 200
        assert response.header("x-answered-by") == "python"
        assert response.header("x-probe-echo") == "sent"
        assert response.body() == b"/hello"
    finally:
        handle.close(5)

def test_every_shorthand_reaches_the_server():
    seen = []

    def record(request):
        seen.append((request.method, request.body()))
        return Message.text("ok")

    server, handle, origin = serve(record)
    try:
        client = Client()
        client.get(f"{origin}/")
        client.head(f"{origin}/")
        client.post(f"{origin}/", b"data")
        client.put(f"{origin}/", "text")
        client.delete(f"{origin}/")

        assert [method for method, body in seen] == [Method.GET, Method.HEAD, Method.POST, Method.PUT, Method.DELETE]
        assert seen[2][1] == b"data"
        assert seen[3][1] == b"text"
    finally:
        handle.close(5)

def test_a_handler_that_raises_answers_with_a_bare_500(capsys):
    def broken(request):
        raise ValueError("deliberate")

    server, handle, origin = serve(broken)
    try:
        response = Client().get(f"{origin}/")
        assert response.status_code == 500
        assert "deliberate" in capsys.readouterr().err, "the traceback must not vanish"
    finally:
        handle.close(5)

def test_several_messages_go_over_one_connection():
    server, handle, origin = serve()
    try:
        client = Client(ClientConfig(secure=False))
        connection = client.connect("127.0.0.1", Port.TCP(handle.port))

        assert connection.version == Version.V1_1
        assert connection.role == soyokaze.Role.USER_AGENT
        assert connection.role.is_client(), "a connection the client opened sends requests"

        for index in range(3):
            response = client.request(connection, Message.request(Method.GET, f"/turn/{index}"))
            assert response.body() == f"/turn/{index}".encode()
            assert connection.reusable()

        connection.close()
    finally:
        handle.close(5)

def test_send_and_receive_expose_the_raw_exchange():
    server, handle, origin = serve()
    try:
        client = Client(ClientConfig(secure=False))
        connection = client.open(URL(origin))

        connection.send(Message.request(Method.GET, "/raw"))
        response = connection.receive()
        assert response.status_code == 200
        assert response.body() == b"/raw"

        connection.close()
    finally:
        handle.close(5)

def test_a_pinned_version_and_ceilinged_limits_still_serve():
    limits = ServerLimits(message=Limits(max_header_count=32), max_connections=16)
    config = ServerConfig(versions=[Version.V1_1], limits=limits)

    server, handle, origin = serve(config=config)
    try:
        client = Client(ClientConfig(versions=[Version.V1_1]))
        assert client.get(f"{origin}/pinned").status_code == 200
    finally:
        handle.close(5)

def test_the_cluster_spreads_the_same_server_across_workers():
    server = Server()
    cluster = server.run(echo, [Port.TCP(0)], workers=2)
    try:
        assert cluster.workers() == 2
        assert cluster.port != 0

        response = Client().get(f"http://127.0.0.1:{cluster.port}/clustered")
        assert response.body() == b"/clustered"
    finally:
        cluster.close(5)

def test_the_websocket_callback_runs_the_socket_both_ways():
    received = []

    def on_websocket(socket):
        opcode, payload = socket.receive_message()
        received.append((opcode, payload))
        socket.send_message(opcode, payload.decode().upper())
        socket.close(soyokaze.CloseCode.NORMAL, "done")

    server, handle, origin = serve(on_websocket=on_websocket)
    try:
        client = Client()
        socket = client.websocket(f"ws://127.0.0.1:{handle.port}/chat")

        socket.send_message(soyokaze.Opcode.TEXT, "hello")
        opcode, payload = socket.receive_message()
        assert (opcode, payload) == (soyokaze.Opcode.TEXT, b"HELLO"), "receive_message hands back what send_message takes, in that order"

        opcode, payload = socket.receive_message()
        assert opcode == soyokaze.Opcode.CLOSE, "the server's close reaches the client"

        assert received == [(soyokaze.Opcode.TEXT, b"hello")]
    finally:
        handle.close(5)

def test_the_client_keeps_cookies_across_requests():
    def set_then_expect(request):
        response = Message.text("ok")
        if request.target == "/set":
            response.set_cookie(soyokaze.SetCookie("sid", "abc"))
        else:
            response.insert_header("x-got-cookie", request.header("cookie") or "none")
        return response

    server, handle, origin = serve(set_then_expect)
    try:
        client = Client()
        client.get(f"{origin}/set")
        response = client.get(f"{origin}/again")
        assert response.header("x-got-cookie") == "sid=abc"

        stateless = Client(ClientConfig(cookies=False))
        stateless.get(f"{origin}/set")
        response = stateless.get(f"{origin}/again")
        assert response.header("x-got-cookie") == "none"
    finally:
        handle.close(5)

def test_dialling_nothing_raises_rather_than_hanging():
    client = Client()
    with pytest.raises(soyokaze.Error):
        client.get("http://127.0.0.1:1/")
