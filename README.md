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

Against the static library, which is how the release profile is exercised:

```bash
cargo build --release --lib
cc -std=c11 -Iinclude tests/ffi.c target/release/libsoyokaze.a \
    $(cargo rustc --release --lib --crate-type staticlib -- --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -n1) -o ffi-test
./ffi-test
```

#### The release cdylib is unusable on the macOS 27 toolchain

Linking against — or `dlopen`ing — `target/release/libsoyokaze.dylib` fails:

```
ld: mis-aligned LINKEDIT string pool, fileOffset=0x0047EDEC in 'target/release/libsoyokaze.dylib'
```

This is a defect in Apple's linker, not a soyokaze regression, and it reproduces on an unmodified
checkout. Use the release static library above; it carries the same `lto = true` codegen and is not
affected, because linking an archive never parses a Mach-O `__LINKEDIT` segment.

`LC_SYMTAB.stroff` has to be 8-byte aligned. `ld` writes the string pool directly behind the indirect
symbol table without padding, so the alignment is decided by `nindirectsyms`: the symbol table
contributes `nsyms * 16` bytes, which is always a multiple of 8, and each indirect symbol adds 4. The
release build has 293 of them and lands on a 4-byte boundary; the debug build has 298 and happens to
land correctly. `ld` then refuses to read back the file it just wrote, and so does `dyld`.

The debug dylib therefore works by coincidence, not by construction — a dependency bump that changes
the imported symbol set by one can break it and fix release just as easily. Investigated 2026-08-10
against `ld-27034` (Xcode 27.0.0 Beta 3) and `ld-27036.1` (Command Line Tools) on macOS 27.0, with
rustc 1.97.1; both linkers produce and then reject the file. Neither `lto = "thin"`, `lto = false`,
`codegen-units = 16`, nor `strip = "symbols"` changes the outcome — none of them alter the indirect
symbol count — and `-ld_classic` (removed in Xcode 27), `-fixup_chains`, `-Wl,-u`, and `strip(1)` do
not help either.

### soyokaze.py

```bash
cd python
uv run pytest
```

## Links
- [docs.rs](https://docs.rs/soyokaze/) - Documentation
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
