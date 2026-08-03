"""HPACK, the HTTP/2 field compression format.

An :class:`Encoder` and a :class:`Decoder` are stateful — each keeps a
dynamic table — so one of each serves one connection's lifetime, blocks fed
in the order they travel. Fields cross as lists of name and value pairs.
"""

import ctypes

from .. import ffi
from ..errors import error_out, raise_for
from ..ffi import library

def fields_argument(fields):
    """A C array of ``soyokaze_field_t`` and the slices keeping it alive."""
    slices = [(ffi.slice_of(ffi.encoded(name)), ffi.slice_of(ffi.encoded(value))) for name, value in fields]
    array = (ffi.Field * len(slices))(*[ffi.Field(name, value) for name, value in slices])
    return array, slices

def fields_taken(handle):
    """The pairs a ``soyokaze_fields_t`` holds, releasing it as they are read."""
    count = library.soyokaze_fields_count(handle)
    pairs = [
        (library.soyokaze_fields_name(handle, index).text(), library.soyokaze_fields_value(handle, index).text())
        for index in range(count)
    ]
    library.soyokaze_fields_free(handle)
    return pairs

class Encoder:
    """An HPACK encoder with its dynamic table."""

    def __init__(self):
        self.handle = library.soyokaze_hpack_encoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_hpack_encoder_free(self.handle)
            self.handle = None

    def set_dynamic_table_size(self, max_size):
        """Caps the dynamic table, as a ``SETTINGS_HEADER_TABLE_SIZE`` would."""
        library.soyokaze_hpack_encoder_set_dynamic_table_size(self.handle, max_size)

    def encode(self, fields):
        """Encodes one field section — pairs of name and value — as a block."""
        array, slices = fields_argument(fields)
        return ffi.take(library.soyokaze_hpack_encode(self.handle, array, len(fields)))

class Decoder:
    """An HPACK decoder with its dynamic table."""

    def __init__(self):
        self.handle = library.soyokaze_hpack_decoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_hpack_decoder_free(self.handle)
            self.handle = None

    def set_max_decoded_size(self, max_size):
        """Caps how large one decoded section may grow."""
        library.soyokaze_hpack_decoder_set_max_decoded_size(self.handle, max_size)

    def set_dynamic_table_size(self, max_size):
        """Caps the dynamic table, as a ``SETTINGS_HEADER_TABLE_SIZE`` would."""
        library.soyokaze_hpack_decoder_set_dynamic_table_size(self.handle, max_size)

    def decode(self, block):
        """Decodes one block into pairs of name and value."""
        out = ctypes.c_void_p()
        error = error_out()
        block = ffi.encoded(block)
        raise_for(library.soyokaze_hpack_decode(self.handle, block, len(block), ctypes.byref(out), ctypes.byref(error)), error)
        return fields_taken(out)
