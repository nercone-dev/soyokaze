"""HPACK, the HTTP/2 field compression format.

An :class:`Encoder` and a :class:`Decoder` are stateful — each keeps a
dynamic table — so one of each serves one connection's lifetime, blocks fed
in the order they travel. Fields cross as lists of name and value pairs,
the shared vocabulary in :mod:`.fields`.
"""

import ctypes

from .. import ffi
from ..errors import Error
from ..ffi import library
from .fields import Fields

class Encoder:
    """An HPACK encoder with its dynamic table."""

    def __init__(self):
        self.handle = library.soyokaze_hpack_encoder_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_hpack_encoder_free(self.handle)
            self.handle = None

    def set_max_capacity(self, max_capacity):
        """Records the peer's ``SETTINGS_HEADER_TABLE_SIZE``."""
        library.soyokaze_hpack_encoder_set_max_capacity(self.handle, max_capacity)

    def set_capacity_limit(self, capacity_limit):
        """Bounds the capacity the encoder keeps, whatever the peer permits."""
        library.soyokaze_hpack_encoder_set_capacity_limit(self.handle, capacity_limit)

    def encode(self, fields):
        """Encodes one field section — pairs of name and value — as a block."""
        array, slices = Fields.argument(fields)
        return library.soyokaze_hpack_encode(self.handle, array, len(fields)).take()

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

    def set_max_capacity(self, max_capacity):
        """Records this side's advertised ``SETTINGS_HEADER_TABLE_SIZE``."""
        library.soyokaze_hpack_decoder_set_max_capacity(self.handle, max_capacity)

    def decode(self, block):
        """Decodes one block into pairs of name and value."""
        out = ctypes.c_void_p()
        error = Error.out()
        block = ffi.Library.encoded(block)
        Error.raise_for(library.soyokaze_hpack_decode(self.handle, block, len(block), ctypes.byref(out), ctypes.byref(error)), error)
        return Fields.taken(out)
