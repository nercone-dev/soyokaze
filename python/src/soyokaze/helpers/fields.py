"""The field vocabulary HPACK and QPACK share.

One field crosses as a name and value pair; a decoded section comes back as a
list of them. :mod:`hpack` and :mod:`qpack` both cross the boundary with these.

The wire primitives the two formats are built out of are here as well:
:class:`Integer` is the prefixed integer, :class:`StringLiteral` is how either
format writes a name or a value, and :class:`StaticIndex` is the reverse index a
static table is looked up through.
"""

import ctypes
import enum

from .. import ffi
from ..errors import ProtocolError
from ..ffi import library

class Error(enum.IntEnum):
    """Why a wire primitive would not decode."""

    OK = 0
    INTEGER_OVERFLOW = 1
    INCOMPLETE = 2
    HUFFMAN_INVALID_PADDING = 3
    HUFFMAN_UNKNOWN_SYMBOL = 4
    INVALID = 5

    def message(self):
        """A fixed description of the error."""
        return library.soyokaze_fields_error_message(int(self)).text()

class HeaderField:
    """One field: a name and a value."""

    OVERHEAD = library.soyokaze_field_overhead()
    """How many octets a field is charged beyond its name and value."""

    SENSITIVE = tuple(
        library.soyokaze_field_sensitive_name(index).text()
        for index in range(library.soyokaze_field_sensitive_count())
    )
    """The field names that carry a credential and must never be indexed."""

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def size(self):
        """What the field costs the dynamic table: its octets plus the overhead."""
        name, value = ffi.Library.encoded(self.name), ffi.Library.encoded(self.value)
        return library.soyokaze_field_size(name, len(name), value, len(value))

    def sensitive(self):
        """Whether the field carries a credential and must never be indexed."""
        name = ffi.Library.encoded(self.name)
        return library.soyokaze_field_is_sensitive(name, len(name))

    def __eq__(self, other):
        return isinstance(other, HeaderField) and (self.name, self.value) == (other.name, other.value)

    def __iter__(self):
        return iter((self.name, self.value))

    def __repr__(self):
        return f"HeaderField({self.name!r}, {self.value!r})"

class Fields:
    """The name and value pairs an encoder takes and a decoder hands back."""

    @classmethod
    def argument(cls, fields):
        """A C array of ``soyokaze_field_t`` and the slices keeping it alive."""
        slices = [(ffi.Slice.of(ffi.Library.encoded(name)), ffi.Slice.of(ffi.Library.encoded(value))) for name, value in fields]
        array = (ffi.Field * len(slices))(*[ffi.Field(name, value) for name, value in slices])
        return array, slices

    @classmethod
    def taken(cls, handle):
        """The pairs a ``soyokaze_fields_t`` holds, releasing it as they are read."""
        count = library.soyokaze_fields_count(handle)
        pairs = [
            (library.soyokaze_fields_name(handle, index).text(), library.soyokaze_fields_value(handle, index).text())
            for index in range(count)
        ]
        library.soyokaze_fields_free(handle)
        return pairs

class Integer:
    """The prefixed integer representation both HPACK and QPACK are built out of."""

    @classmethod
    def limit(cls, prefix_bits):
        """The largest value a prefix of ``prefix_bits`` can hold on its own."""
        return library.soyokaze_integer_limit(prefix_bits)

    @classmethod
    def encode(cls, value, prefix_bits, flags=0):
        """Encodes a prefixed integer, ``flags`` filling the bits above the prefix."""
        return library.soyokaze_integer_encode(value, prefix_bits, flags).take()

    @classmethod
    def decode(cls, data, prefix_bits):
        """Decodes a prefixed integer, returning ``(read, value)``."""
        data = ffi.Library.encoded(data)
        out, read, error = ctypes.c_uint64(), ctypes.c_size_t(), ctypes.c_int32()
        if not library.soyokaze_integer_decode(data, len(data), prefix_bits, ctypes.byref(out), ctypes.byref(read), ctypes.byref(error)):
            raise ProtocolError(Error(error.value).message())
        return read.value, out.value

class StringLiteral:
    """How either format writes a field name or value out."""

    @classmethod
    def prefers_huffman(cls, value):
        """Whether Huffman coding would make the value shorter."""
        value = ffi.Library.encoded(value)
        return library.soyokaze_string_prefers_huffman(value, len(value))

    @classmethod
    def max_prefix_bits(cls):
        """The widest prefix a string literal can be written with.

        The bit just above the prefix carries the Huffman mark, so an
        eight-bit prefix would leave no room for it. Anything wider names no
        representation, and the calls below refuse it.
        """
        return library.soyokaze_string_max_prefix_bits()

    @classmethod
    def encode(cls, value, prefix_bits, flags=0, huffman=False):
        """Encodes a string literal with the coding ``huffman`` picks."""
        value = ffi.Library.encoded(value)
        return library.soyokaze_string_encode(value, len(value), prefix_bits, flags, huffman).take()

    @classmethod
    def encode_shorter(cls, value, prefix_bits, flags=0):
        """Encodes a string literal with whichever coding comes out shorter."""
        value = ffi.Library.encoded(value)
        return library.soyokaze_string_encode_shorter(value, len(value), prefix_bits, flags).take()

    @classmethod
    def decode(cls, data, prefix_bits):
        """Decodes a string literal, returning ``(read, octets)``."""
        data = ffi.Library.encoded(data)
        out, read, error = ffi.Buffer(), ctypes.c_size_t(), ctypes.c_int32()
        if not library.soyokaze_string_decode(data, len(data), prefix_bits, ctypes.byref(out), ctypes.byref(read), ctypes.byref(error)):
            raise ProtocolError(Error(error.value).message())
        return read.value, out.take()

class StaticIndex:
    """A reverse index over a static table: field to index.

    Borrowed from the library rather than owned, so nothing here is freed.
    """

    def __init__(self, handle):
        self.handle = handle

    def lookup(self, name, value):
        """Looks a field up.

        Returns ``(first, exact)``: the lowest index carrying the name, and the
        index carrying both name and value. Either is ``None`` when there is
        none.
        """
        name, value = ffi.Library.encoded(name), ffi.Library.encoded(value)
        first, exact = ctypes.c_int64(), ctypes.c_int64()
        library.soyokaze_static_index_lookup(self.handle, name, len(name), value, len(value), ctypes.byref(first), ctypes.byref(exact))
        return (None if first.value < 0 else first.value), (None if exact.value < 0 else exact.value)
