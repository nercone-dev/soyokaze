"""SHA-1.

Provided because the WebSocket handshake needs it; it is not a
general-purpose hash to build anything new on.
"""

from .. import ffi
from ..ffi import library

def sha1(data):
    """The SHA-1 digest of ``data``. Always 20 octets."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_sha1(data, len(data)).take()
