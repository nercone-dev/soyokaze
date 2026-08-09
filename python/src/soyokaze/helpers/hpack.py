"""HPACK, the HTTP/2 field compression format.

An :class:`Encoder` and a :class:`Decoder` are stateful — each keeps a
:class:`DynamicTable` — so one of each serves one connection's lifetime, blocks
fed in the order they travel. Fields cross as lists of name and value pairs, the
shared vocabulary in :mod:`.fields`.

HPACK numbers its :class:`StaticTable` from one, which is the only way it
differs from QPACK here.
"""

import ctypes

from .. import ffi
from ..errors import Error
from ..ffi import library
from .fields import Fields, HeaderField, StaticIndex

class StaticTable:
    """The fixed table both ends already agree on."""

    BASE = library.soyokaze_hpack_static_base()
    """The lowest index the table is numbered from."""

    COUNT = library.soyokaze_hpack_static_count()
    """How many entries the table holds."""

    @classmethod
    def entries(cls):
        """Every entry, in wire order."""
        return [cls.get(index) for index in range(cls.BASE, cls.BASE + cls.COUNT)]

    @classmethod
    def get(cls, index):
        """The entry at ``index``, or ``None`` past the end."""
        name = library.soyokaze_hpack_static_name(index).text()
        if name is None:
            return None
        return HeaderField(name, library.soyokaze_hpack_static_value(index).text())

    @classmethod
    def index(cls):
        """The reverse index over the table."""
        return StaticIndex(library.soyokaze_hpack_static_index())

    @classmethod
    def find(cls, field):
        """Looks a field up, returning ``(index, exact)`` or ``None``."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact = ctypes.c_size_t(), ctypes.c_bool()
        if not library.soyokaze_hpack_static_find(name, len(name), value, len(value), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return out.value, exact.value

class DynamicTable:
    """The table an encoder and a decoder build up as they go.

    Borrowed from the encoder or decoder that owns it, and valid only until
    that handle is used again.
    """

    DEFAULT_CAPACITY = library.soyokaze_hpack_default_capacity()
    """The capacity a table starts at."""

    def __init__(self, handle):
        self.handle = handle

    def size(self):
        """How many octets the entries add up to."""
        return library.soyokaze_hpack_table_size(self.handle)

    def capacity(self):
        """What the table is currently sized to."""
        return library.soyokaze_hpack_table_capacity(self.handle)

    def len(self):
        """How many entries the table holds."""
        return library.soyokaze_hpack_table_len(self.handle)

    def is_empty(self):
        """Whether the table holds nothing."""
        return library.soyokaze_hpack_table_is_empty(self.handle)

    def get(self, index):
        """The entry at ``index``, counted from the most recent insertion."""
        name = library.soyokaze_hpack_table_name(self.handle, index).text()
        if name is None:
            return None
        return HeaderField(name, library.soyokaze_hpack_table_value(self.handle, index).text())

    def find(self, field):
        """Looks a field up, returning ``(index, exact)`` or ``None``."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact = ctypes.c_size_t(), ctypes.c_bool()
        if not library.soyokaze_hpack_table_find(self.handle, name, len(name), value, len(value), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return out.value, exact.value

    def __len__(self):
        return self.len()

class Encoder:
    """An HPACK encoder with its dynamic table."""

    DEFAULT_CAPACITY_LIMIT = library.soyokaze_hpack_default_capacity_limit()
    """The capacity the encoder bounds itself to unless told otherwise."""

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

    def capacity_limit(self):
        """What the encoder bounds its own table to."""
        return library.soyokaze_hpack_encoder_capacity_limit(self.handle)

    def max_capacity(self):
        """The peer's ``SETTINGS_HEADER_TABLE_SIZE``, as last recorded."""
        return library.soyokaze_hpack_encoder_max_capacity(self.handle)

    def dynamic_table(self):
        """The encoder's dynamic table."""
        return DynamicTable(library.soyokaze_hpack_encoder_table(self.handle))

    def reference(self, field):
        """What the encoder would reference a field by, across both tables.

        Returns ``(index, exact)`` or ``None``.
        """
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        out, exact = ctypes.c_size_t(), ctypes.c_bool()
        if not library.soyokaze_hpack_encoder_reference(self.handle, name, len(name), value, len(value), ctypes.byref(out), ctypes.byref(exact)):
            return None
        return out.value, exact.value

    def encode(self, headers):
        """Encodes one field section — pairs of name and value — as a block."""
        array, slices = Fields.argument(headers)
        return library.soyokaze_hpack_encode(self.handle, array, len(array)).take()

    def encode_field(self, field):
        """Encodes one field onto the end of a block."""
        name, value = ffi.Library.encoded(field.name), ffi.Library.encoded(field.value)
        return library.soyokaze_hpack_encode_field(self.handle, name, len(name), value, len(value)).take()

class Decoder:
    """An HPACK decoder with its dynamic table."""

    DEFAULT_MAX_DECODED_SIZE = library.soyokaze_hpack_default_max_decoded_size()
    """How large one decoded section may grow unless told otherwise."""

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

    def dynamic_table(self):
        """The decoder's dynamic table."""
        return DynamicTable(library.soyokaze_hpack_decoder_table(self.handle))

    def resolve(self, index):
        """The field an index addresses, across both tables, or ``None``."""
        name, value = ffi.Slice(), ffi.Slice()
        if not library.soyokaze_hpack_decoder_resolve(self.handle, index, ctypes.byref(name), ctypes.byref(value)):
            return None
        return HeaderField(name.text(), value.text())

    def decode(self, block):
        """Decodes one block into pairs of name and value."""
        out = ctypes.c_void_p()
        error = Error.out()
        block = ffi.Library.encoded(block)
        Error.raise_for(library.soyokaze_hpack_decode(self.handle, block, len(block), ctypes.byref(out), ctypes.byref(error)), error)
        return Fields.taken(out)
