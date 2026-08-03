"""The field vocabulary HPACK and QPACK share.

One field crosses as a name and value pair; a decoded section comes back as
a list of them. :mod:`hpack` and :mod:`qpack` both cross the boundary with
these.
"""

from .. import ffi
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
