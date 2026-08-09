"""The compact string the crate holds field names and values in.

:class:`Text` stores a short string inside itself and a long one behind a
pointer, as the crate's ``helpers::text`` does. Text goes in as ``str`` or
``bytes`` everywhere else in these bindings, so a caller rarely needs one; the
crate's own surface is written in terms of it, so it is here whole.
"""

import ctypes

from .. import ffi
from ..errors import InvalidError
from ..ffi import library

INLINE = library.soyokaze_text_inline()
"""How many octets fit inside a :class:`Text` before it allocates."""

class Text:
    """A string held inline when it is short and behind a pointer when it is not."""

    def __init__(self, handle=None):
        """An empty text, or one wrapping a handle the library handed back."""
        self.handle = handle if handle is not None else library.soyokaze_text_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_text_free(self.handle)
            self.handle = None

    @classmethod
    def from_str(cls, text):
        """Copies a string, raising :class:`InvalidError` when it is not UTF-8."""
        encoded = ffi.Library.encoded(text)
        handle = library.soyokaze_text_from_utf8(encoded, len(encoded))
        if not handle:
            raise InvalidError("the octets are not UTF-8")
        return cls(handle)

    @classmethod
    def from_string(cls, text):
        """Takes ownership of a string. The same as :meth:`from_str` here."""
        return cls.from_str(text)

    @classmethod
    def from_utf8_lossy(cls, octets):
        """Copies octets, replacing whatever is not UTF-8."""
        octets = ffi.Library.encoded(octets)
        return cls(library.soyokaze_text_from_utf8_lossy(octets, len(octets)))

    @classmethod
    def from_ascii(cls, octets):
        """Copies octets that are expected to be ASCII, checking that they are."""
        octets = ffi.Library.encoded(octets)
        return cls(library.soyokaze_text_from_ascii(octets, len(octets)))

    @classmethod
    def from_ascii_lowercase(cls, octets):
        """As :meth:`from_ascii`, lowercasing as it goes."""
        octets = ffi.Library.encoded(octets)
        return cls(library.soyokaze_text_from_ascii_lowercase(octets, len(octets)))

    @classmethod
    def from_verified_ascii(cls, octets):
        """As :meth:`from_ascii`, skipping the check.

        Passing octets that are not ASCII is undefined behaviour.
        """
        octets = ffi.Library.encoded(octets)
        return cls(library.soyokaze_text_from_verified_ascii(octets, len(octets)))

    @classmethod
    def from_verified_ascii_lowercase(cls, octets):
        """As :meth:`from_verified_ascii`, lowercasing as it goes."""
        octets = ffi.Library.encoded(octets)
        return cls(library.soyokaze_text_from_verified_ascii_lowercase(octets, len(octets)))

    @classmethod
    def copy_inline(cls, octets):
        """The inline layout a short text holds, always :data:`INLINE` octets.

        Raises :class:`InvalidError` when the octets are too long to fit.
        """
        octets = ffi.Library.encoded(octets)
        out = (ctypes.c_uint8 * INLINE)()
        if not library.soyokaze_text_copy_inline(octets, len(octets), out):
            raise InvalidError(f"the octets are longer than {INLINE}")
        return bytes(out)

    def as_str(self):
        """The octets as text."""
        return library.soyokaze_text_bytes(self.handle).text()

    def as_bytes(self):
        """The octets."""
        return library.soyokaze_text_bytes(self.handle).bytes()

    def len(self):
        """How many octets there are."""
        return library.soyokaze_text_len(self.handle)

    def is_empty(self):
        """Whether there are no octets at all."""
        return library.soyokaze_text_is_empty(self.handle)

    def is_inline(self):
        """Whether the octets sit inside the handle rather than behind a pointer."""
        return library.soyokaze_text_is_inline(self.handle)

    def make_ascii_lowercase(self):
        """Lowercases the ASCII octets in place."""
        library.soyokaze_text_make_ascii_lowercase(self.handle)

    def into_string(self):
        """The octets as text, releasing the handle as they are read."""
        return self.into_bytes().decode()

    def into_bytes(self):
        """The octets, releasing the handle as they are read."""
        handle, self.handle = self.handle, None
        return library.soyokaze_text_into_bytes(handle).take()

    def __len__(self):
        return self.len()

    def __str__(self):
        return self.as_str()

    def __eq__(self, other):
        if isinstance(other, Text):
            return library.soyokaze_text_equals(self.handle, other.handle)
        if isinstance(other, (str, bytes)):
            return self.as_bytes() == ffi.Library.encoded(other)
        return NotImplemented

    def __lt__(self, other):
        return library.soyokaze_text_compare(self.handle, other.handle) < 0

    def __hash__(self):
        return hash(self.as_bytes())

    def __repr__(self):
        return f"Text({self.as_str()!r})"
