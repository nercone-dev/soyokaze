"""Filling in the fields a message is expected to carry.

:class:`DateCache` renders the ``Date`` field, caching the rendering for a
whole second because a busy server stamps one on every response.
:class:`ResponseFinalizer` and :class:`RequestFinalizer` are the two halves
that put the finishing fields on a message before it goes out — the same pair
as the crate's ``finalizer`` module. A connection runs both itself, so nothing
here needs calling for an ordinary exchange; it is here for a caller driving
one by hand.
"""

import ctypes

from . import ffi
from .ffi import library

DATE_LENGTH = library.soyokaze_date_length()
"""How many octets an HTTP-date is: ``Sun, 06 Nov 1994 08:49:37 GMT``."""

DAY_NAMES = tuple(library.soyokaze_day_name(index).text() for index in range(7))
"""The abbreviated day names, Sunday first."""

MONTH_NAMES = tuple(library.soyokaze_month_name(index).text() for index in range(12))
"""The abbreviated month names, January first."""

class DateCache:
    """Where an HTTP date is formatted, as the crate's ``DateCache`` is.

    An instance renders at most once a second and hands the same date back in
    between; :meth:`format` renders every time it is called.
    """

    def __init__(self, handle=None):
        self.handle = handle if handle is not None else library.soyokaze_date_cache_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_date_cache_free(self.handle)
            self.handle = None

    @classmethod
    def shared(cls):
        """The cache the library keeps for itself, which is never freed."""
        cache = cls.__new__(cls)
        cache.handle = None
        return cache

    @classmethod
    def civil_from_days(cls, days):
        """The ``(year, month, day)`` a count of days since the epoch falls on."""
        year, month, day = ctypes.c_int64(), ctypes.c_uint32(), ctypes.c_uint32()
        library.soyokaze_civil_from_days(days, ctypes.byref(year), ctypes.byref(month), ctypes.byref(day))
        return year.value, month.value, day.value

    @classmethod
    def format(cls, unix_seconds):
        """The IMF-fixdate for a Unix timestamp: ``Sun, 06 Nov 1994 08:49:37 GMT``."""
        return library.soyokaze_http_date(int(unix_seconds)).take().decode()

    @classmethod
    def http_date(cls, unix_seconds):
        """The IMF-fixdate for a Unix timestamp. The same as :meth:`format`."""
        return cls.format(unix_seconds)

    def now(self):
        """The IMF-fixdate for now, rendered at most once a second."""
        return library.soyokaze_date_cache_now(self.handle).take().decode()

class ResponseFinalizer:
    """What a server puts on a response before it goes out."""

    def __init__(self, hsts=None):
        """A finalizer that stamps ``hsts`` on secure responses, or none."""
        self.hsts = hsts
        struct = None if hsts is None else ffi.HSTSPolicy(hsts.max_age, hsts.include_subdomains, hsts.preload)
        self.handle = library.soyokaze_response_finalizer_new(None if struct is None else ctypes.byref(struct))

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_response_finalizer_free(self.handle)
            self.handle = None

    def finalize(self, role, secure, message):
        """Puts the finishing fields on a message about to go out.

        Does nothing unless ``role`` answers requests and the message is a
        response.
        """
        library.soyokaze_response_finalizer_finalize(self.handle, int(role), secure, message.handle)

class RequestFinalizer:
    """What a client puts on a request before it goes out."""

    def __init__(self, authority=None, handle=None):
        """A finalizer that fills in ``authority``, or a wrapper around a handle."""
        if handle is None:
            encoded = None if authority is None else ffi.Library.encoded(authority)
            handle = library.soyokaze_request_finalizer_new(encoded, 0 if encoded is None else len(encoded))
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_request_finalizer_free(self.handle)
            self.handle = None

    @property
    def authority(self):
        """The authority the finalizer fills in, or ``None``."""
        return library.soyokaze_request_finalizer_authority(self.handle).text()

    def finalize(self, role, message):
        """Puts the finishing fields on a request about to go out.

        Does nothing unless ``role`` sends requests and the message is a
        request.
        """
        library.soyokaze_request_finalizer_finalize(self.handle, int(role), message.handle)
