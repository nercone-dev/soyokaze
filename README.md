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
- Python 3.10+

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

Against the static library, which is how the release profile is exercised:

```bash
cargo build --release --lib
cc -std=c11 -Iinclude tests/ffi.c target/release/libsoyokaze.a \
    $(cargo rustc --release --lib --crate-type staticlib -- --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -n1) -o ffi-test
./ffi-test
```

### soyokaze.py

```bash
cd python
uv run pytest
```

## Links
- [crates.io](https://crates.io/crates/soyokaze/) - Rust crate
- [pypi.org](https://pypi.org/project/soyokaze/) - Python package
- [docs.rs](https://docs.rs/soyokaze/) - Documentation
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
