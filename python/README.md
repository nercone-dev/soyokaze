# soyokaze.py
Python bindings for Soyokaze, an HTTP/1, HTTP/2 and HTTP/3 library written in Rust.

## Requirements

- Linux / macOS (x86_64, AArch64)
- Python 3.9+

## Installation

```bash
uv pip install soyokaze
```

They locate the shared library through, in order: the `SOYOKAZE_LIBRARY` environment variable, the copy bundled with the package, the crate's own `target/{release,debug}` directory when run from within the repository, and the system loader.

## Asynchronous

The crate's surface is async and so is this one. Everything that waits on a peer — a request, a response, a WebSocket frame, a server winding down — is a coroutine, and everything that only reads or builds what is already in hand stays an ordinary call.

```python
import asyncio
import soyokaze

async def main():
    client = soyokaze.Client()
    response = await client.get("https://example.com/")
    print(response.status_code, await response.body())

asyncio.run(main())
```

A handler is a coroutine function, and may await the rest of the bindings:

```python
async def hello(request):
    return soyokaze.Message.text("hello")

async def main():
    server = soyokaze.Server()
    async with await server.serve(hello, [soyokaze.Port.TCP(8080)]) as handle:
        await asyncio.Event().wait()
```

A handler that waits for nothing may stay an ordinary callable; it is then run on the library's own thread and the event loop never hears of it.

Underneath, the C ABI the bindings call through is blocking, so each awaited call is made on a worker thread and the event loop is handed back until it returns — ctypes releases the GIL for the length of a foreign call, so a thread waiting on the library holds nothing Python needs. Requests awaited together therefore run together. Cancelling the task that awaits a call stops the waiting but not the call; close the connection to make a call that is waiting give up. `soyokaze.Threads` is where the pool is configured, and `soyokaze.Runtime` is the library's own runtime on the other side of the seam.

## Examples

[`examples/`](examples/) holds a server and a client in one process over loopback TCP, which needs no network access and no certificate, and its WebSocket counterpart:

```bash
uv run examples/loopback.py
```

```bash
uv run examples/websocket_loopback.py
```

## Links
- [docs.rs](https://docs.rs/soyokaze/) - Documentation (for the Rust crate)
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
