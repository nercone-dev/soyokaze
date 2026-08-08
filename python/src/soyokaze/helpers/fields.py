"""The field vocabulary HPACK and QPACK share.

One field crosses as a name and value pair; a decoded section comes back as
a list of them. :mod:`hpack` and :mod:`qpack` both cross the boundary with
these.
"""

from .. import ffi
from ..ffi import library

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
