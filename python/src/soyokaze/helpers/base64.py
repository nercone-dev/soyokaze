"""Base64: the standard alphabet with padding.

Wraps the crate's own implementation, so what the library puts on the wire
is exactly what these produce.
"""

import ctypes

from .. import ffi
from ..errors import InvalidError
from ..ffi import library

def encode(data):
    """Encodes octets as base64 text."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_base64_encode(data, len(data)).take().decode()

def decode(text):
    """Decodes base64 text, raising :class:`InvalidError` when it is not valid."""
    encoded = ffi.Library.encoded(text)
    out = ffi.Buffer()
    if not library.soyokaze_base64_decode(encoded, len(encoded), ctypes.byref(out)):
        raise InvalidError("the text is not valid base64")
    return out.take()
