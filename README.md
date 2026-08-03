# Soyokaze
HTTP/1/2/3 Library Crate

## Overview

An HTTP/1/2/3 implementation written in Rust.

It uses BoringSSL (`boring`/`boring-sys`/`tokio-boring`) for TLS handling, and the BoringSSL-based Quiche (`quiche`/`tokio-quiche`) for QUIC handling.

C FFI and Python bindings are also available.

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
