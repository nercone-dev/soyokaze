"""A server and a client in one process, talking over loopback TCP.

The Python half of the crate's ``examples/loopback.rs``. It needs no network
access and no certificate, so it is the fastest way to see a request cross the
whole stack:

    uv run examples/loopback.py
"""

from soyokaze import Client, Message, Method, Port, Server, URL

def greet(request):
    """Answers every request with a greeting taken from its target.

    A handler is an ordinary callable: it takes the request and returns the
    response, and the bindings frame it in whichever version the connection
    negotiated.
    """
    name = (request.target or "/").lstrip("/") or "World"
    return Message.text(f"Hello, {name}!", request.version)

def main():
    # A port of zero lets the kernel choose one, so the example names none.
    server = Server()
    handle = server.serve(greet, [Port.TCP(0)])

    client = Client()
    connection = client.open(URL(f"http://127.0.0.1:{handle.port}/"))

    for target in ["/", "/soyokaze"]:
        response = client.request(connection, Message.request(Method.GET, target, connection.version))
        print(f"{target} -> {response.status_code} {response.body().decode()}")

    connection.close()
    handle.close(5)

if __name__ == "__main__":
    main()
