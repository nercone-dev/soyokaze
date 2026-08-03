"""What the client and the server configure in common.

:class:`Limits` bounds what one connection is allowed to spend on the peer's
behalf, whichever side of it this end is, mirroring ``api::common::Limits``.
"""

import ctypes

from .. import ffi
from ..ffi import library

FIELDS = [name for name, kind in ffi.Limits._fields_]

class Limits:
    """What one connection is allowed to spend on the peer's behalf.

    Every attribute is a ceiling and mirrors its namesake in the crate;
    timeouts are in seconds and zero waits forever. Construct one with only
    the ceilings to change: ``Limits(max_header_count=32)``.
    """

    def __init__(self, **ceilings):
        defaults = library.soyokaze_limits_default()

        for name in FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    def build(self):
        """The ``soyokaze_limits_t`` this stands for."""
        struct = ffi.Limits()
        for name in FIELDS:
            setattr(struct, name, getattr(self, name))
        return struct

def limits_argument(limits):
    """The ``soyokaze_limits_t`` for an optional :class:`Limits`, or ``None``.

    The struct is returned itself rather than by reference, so the caller can
    keep it alive for as long as the call needs it.
    """
    return limits.build() if limits is not None else None

def limits_pointer(struct):
    """A pointer to an optional struct from :func:`limits_argument`."""
    return ctypes.byref(struct) if struct is not None else None
