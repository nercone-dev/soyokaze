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

## Links
- [docs.rs](https://docs.rs/soyokaze/) - Documentation (for The Rust version)
- [deepwiki.com](https://deepwiki.com/nercone-dev/soyokaze/) - Documentation; Automatically generated.
