"""Base64: the standard alphabet with padding.

Wraps the crate's own implementation, so what the library puts on the wire is
exactly what these produce. Encoding always pads; decoding is strict, so a
``Sec-WebSocket-Key`` cannot be written more than one way.
"""

import ctypes
import enum

from .. import ffi
from ..errors import InvalidError
from ..ffi import library

ALPHABET = library.soyokaze_base64_alphabet().bytes()
"""The standard alphabet, indexed by sextet value."""

PAD = library.soyokaze_base64_pad()
"""The padding symbol."""

INVALID = library.soyokaze_base64_invalid()
"""The :data:`VALUES` entry for an octet that is not in the alphabet."""

VALUES = library.soyokaze_base64_values().bytes()
"""The sextet value of each octet, or :data:`INVALID`."""

class DecodeError(enum.IntEnum):
    """Why base64 text would not decode."""

    OK = 0
    INVALID_LENGTH = 1
    INVALID_SYMBOL = 2
    INVALID_PADDING = 3
    INVALID = 4

    def message(self):
        """A fixed description of the error."""
        return library.soyokaze_base64_error_message(int(self)).text()

def symbol(value):
    """The symbol for a sextet; only the low six bits of ``value`` are read."""
    return library.soyokaze_base64_symbol(value)

def value(symbol):
    """The sextet a symbol stands for, or ``None`` when it is outside the alphabet."""
    sextet = library.soyokaze_base64_value(symbol)
    return None if sextet < 0 else sextet

def encoded_len(data):
    """How many octets :func:`encode` will produce, padding included."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_base64_encoded_len(data, len(data))

def sextets(group):
    """The 24 bits one four-symbol group stands for.

    Raises :class:`InvalidError` when the group is not four valid symbols.
    """
    group = ffi.Library.encoded(group)
    out, error, detail = ctypes.c_uint32(), ctypes.c_int32(), ctypes.c_uint64()
    if not library.soyokaze_base64_sextets(group, len(group), ctypes.byref(out), ctypes.byref(error), ctypes.byref(detail)):
        raise InvalidError(f"{DecodeError(error.value).message()} ({detail.value})")
    return out.value

def encode(data):
    """Encodes octets as base64 text."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_base64_encode(data, len(data)).take().decode()

def decode(text):
    """Decodes base64 text, raising :class:`InvalidError` when it is not valid."""
    encoded = ffi.Library.encoded(text)
    out, error, detail = ffi.Buffer(), ctypes.c_int32(), ctypes.c_uint64()
    if not library.soyokaze_base64_decode(encoded, len(encoded), ctypes.byref(out), ctypes.byref(error), ctypes.byref(detail)):
        raise InvalidError(f"{DecodeError(error.value).message()} ({detail.value})")
    return out.take()
