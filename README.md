# Soyokaze
HTTP/1/2/3 Library Crate

## Overview

Soyokaze speaks HTTP/1.1, HTTP/2 and HTTP/3 through one set of types. A `Message` carries a request or a response regardless of the version that framed it, and every connection implements the same `Connection` trait, so code written once runs unchanged over any of the three. `Client` dials an origin and `Server` binds ports and accepts connections, negotiating the version by ALPN over TLS, by sniffing the HTTP/2 preface on plaintext, or by the port itself for QUIC — a handler never has to care which it was.

The crate is arranged in layers, each usable on its own: `api` for the entry points, `protocol` for the per-version connections over a shared vocabulary, and `helpers` for the codecs (Huffman, HPACK, QPACK) and small utilities the versions share. TLS runs on BoringSSL throughout, and a C ABI (`ffi`) exposes the same surface to callers outside Rust.

## Highlights

- **One API across three protocol versions** — HTTP/1.1, HTTP/2 and HTTP/3 (over QUIC) are driven through the same `Connection` and `AnyConnection` traits, with version negotiated automatically and corresponding pieces (client/server, request/response, encoder/decoder) kept as drop-in replacements for one another wherever the protocol allows it.
- **WebSocket over any version** — the handshake differs (`Upgrade` on HTTP/1.1, extended `CONNECT` on HTTP/2 and HTTP/3) but both hand back the same `WebSocketConnection`, with masking, control-frame and UTF-8 rules enforced in both directions.
- **TLS with Encrypted Client Hello** — built on BoringSSL, with ECH support so a watcher sees only the public server name, plus certificate/key loading that detects DER vs. PEM and unwraps PKCS#12 archives automatically.
- **Built-in admission control** — a `Gate` bounds total and per-address connection counts and sliding-window rate limits before a handler is ever reached, and `Cluster` runs one runtime per core under `SO_REUSEPORT` so the kernel spreads connections between them.
- **Cookies and HSTS handled for you** — `Client` keeps a `CookieJar` and an `HstsStore` by default, consulting and updating both automatically on every request.
- **A C ABI for other languages** — every symbol is `extern "C"` and prefixed `soyokaze_`, built as `libsoyokaze.so`/`.dylib`/`.dll` with a matching `include/soyokaze.h`, so the crate is usable from outside Rust without a second implementation to keep in sync.
- **Python bindings over that same ABI** — the `python/` package wraps the shared library through `ctypes`, mirroring the crate module for module (`soyokaze.Client`, `soyokaze.Server`, cookies, HSTS, TLS identities and ECH, WebSocket, and the HPACK/QPACK/Huffman codecs), so Python exercises exactly the surface the header promises.
- **Tested for both correctness and performance** — fuzz targets cover HPACK, QPACK, Huffman and full connection handling end to end, and dedicated benchmarks track the codecs and protocol pipeline.

## Requirements

- Linux / macOS
- Rust 1.88+ (including dependencies, The crate itself is 1.85+)
- CMake and C/C++ Toolchain (for building BoringSSL)

## Installation

```bash
cargo add soyokaze
```

The C ABI ships as part of the same crate. Prebuilt shared and static libraries, plus the matching [`include/soyokaze.h`](include/soyokaze.h), are attached to each [release](https://github.com/nercone-dev/soyokaze/releases) for Linux and macOS on x86_64 and aarch64 — or build them yourself with `cargo build --release --lib`.

The Python bindings in [`python/`](python/) wrap that same shared library through `ctypes` and are published on PyPI with the library bundled into the wheel:

```bash
uv pip install soyokaze
```

They locate the shared library through, in order: the `SOYOKAZE_LIBRARY` environment variable, the copy bundled with the package, the crate's own `target/{release,debug}` directory when run from within the repository, and the system loader.

## Development

```bash
cargo test
```

```bash
cargo bench
```

```bash
cargo +nightly fuzz run everything
```

The C ABI and Python bindings each have their own test suite. [`tests/ffi.c`](tests/ffi.c) links against the shared library through the header the way an external C caller would, checked alongside [`tests/ffi.rs`](tests/ffi.rs), which drives the same surface from Rust:

```bash
cargo build --lib
cc -std=c11 -Iinclude tests/ffi.c -Ltarget/debug -lsoyokaze -o ffi-test
LD_LIBRARY_PATH=target/debug ./ffi-test  # DYLD_LIBRARY_PATH=target/debug on macOS
```

```bash
cd python
uv run pytest
```

## Links
- [docs.rs](https://docs.rs/soyokaze/) - Documentation
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
