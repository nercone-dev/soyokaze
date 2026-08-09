# soyokaze
HTTP/1/2/3 Library Crate

## Overview

An HTTP/1/2/3 implementation written in Rust.

It uses [`boring`](https://github.com/cloudflare/boring/) for TLS processing and [`quiche`](https://github.com/cloudflare/quiche/) for QUIC processing.

## Requirements

### soyokaze.rs

- Linux / macOS (x86_64, AArch64)
- Rust 1.88+ (including dependencies, The crate itself is 1.85+)
- CMake and C/C++ Toolchain (for building BoringSSL)

### soyokaze.h (libsoyokaze)

- Linux / macOS (x86_64, AArch64)
- Rust 1.88+ (including dependencies, The crate itself is 1.85+)
- CMake and C/C++ Toolchain

### soyokaze.py

- Linux / macOS (x86_64, AArch64)
- Python 3.9+

## Installation

```bash
cargo add soyokaze
```

```bash
uv add soyokaze
```

## Development

### soyokaze.rs

```bash
cargo test
```

```bash
cargo bench
```

```bash
cargo +nightly fuzz run everything
```

### soyokaze.h

```bash
cargo build --lib
cc -std=c11 -Iinclude tests/ffi.c -Ltarget/debug -lsoyokaze -o ffi-test
LD_LIBRARY_PATH=target/debug ./ffi-test  # DYLD_LIBRARY_PATH=target/debug on macOS
```

### soyokaze.py

```bash
cd python
uv run pytest
```

## Links
- [docs.rs](https://docs.rs/soyokaze/) - Documentation
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
