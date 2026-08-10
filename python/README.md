# soyokaze.py
Python bindings for Soyokaze, an HTTP/1, HTTP/2 and HTTP/3 library written in Rust.

## Requirements

- Linux / macOS (x86_64, AArch64)
- Python 3.10+

## Installation

```bash
uv pip install soyokaze
```

They locate the shared library through, in order: the `SOYOKAZE_LIBRARY` environment variable, the copy bundled with the package, the crate's own `target/{release,debug}` directory when run from within the repository, and the system loader.

## Examples

[`examples/`](examples/) holds a server and a client in one process over loopback TCP, which needs no network access and no certificate, and its WebSocket counterpart:

```bash
uv run examples/loopback.py
```

```bash
uv run examples/websocket_loopback.py
```

## Links
- [crates.io](https://crates.io/crates/soyokaze/) - Rust crate
- [pypi.org](https://pypi.org/project/soyokaze/) - Python package
- [docs.rs](https://docs.rs/soyokaze/) - Documentation (for the Rust crate)
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
