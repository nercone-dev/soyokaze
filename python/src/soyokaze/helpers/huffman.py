"""The HPACK and QPACK Huffman code.

One code serves both compression formats, as in the crate.
"""

import ctypes

from .. import ffi
from ..errors import ProtocolError
from ..ffi import library

def encode(data):
    """Huffman-encodes octets."""
    data = ffi.encoded(data)
    return ffi.take(library.soyokaze_huffman_encode(data, len(data)))

def decode(data):
    """Huffman-decodes octets, raising :class:`ProtocolError` on a bad sequence."""
    data = ffi.encoded(data)
    out = ffi.Buffer()
    if not library.soyokaze_huffman_decode(data, len(data), ctypes.byref(out)):
        raise ProtocolError("the octets are not a valid Huffman sequence")
    return ffi.take(out)
