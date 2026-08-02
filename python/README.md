# soyokaze (Python bindings)

Python bindings for [soyokaze](https://github.com/nercone-dev/soyokaze/), an
HTTP/1, HTTP/2 and HTTP/3 library, reached through the shared library's C ABI.

The shared library is found through, in order: the `SOYOKAZE_LIBRARY`
environment variable, a copy inside the package, the crate's own
`target/{release,debug}` directory when the package sits in the repository,
and the system loader. Build it with `cargo build` (or `--release`) first.

```python
import soyokaze

client = soyokaze.Client()
response = client.get("https://example.com/")
print(response.status_code, response.body())
```

```python
server = soyokaze.Server()
handle = server.serve(lambda request: soyokaze.Message.text("hello"),
                      [soyokaze.Port.TCP(8080)])
...
handle.close()
```

Run the tests with `python -m pytest` from this directory.
