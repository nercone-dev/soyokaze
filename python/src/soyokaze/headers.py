"""Cookies.

:class:`Cookie` and :class:`SetCookie` are the two sides of the exchange —
what a client sends and what a server sets — and :class:`CookieJar` is the
client-side store that turns one into the other across requests, mirroring
the crate's ``headers`` module.
"""

import ctypes
import enum

from . import ffi
from .api.common import limits_argument, limits_pointer
from .errors import InvalidError, error_out, raise_for
from .ffi import library

class SameSite(enum.IntEnum):
    """The ``SameSite`` attribute of a cookie, as the C ABI numbers it."""

    STRICT = 0
    LAX = 1
    NONE = 2

class Cookie:
    """The contents of a ``Cookie`` field: the pairs a client sends back."""

    def __init__(self, handle=None):
        """An empty set of pairs, or a wrapper around an existing handle."""
        self.handle = handle if handle is not None else library.soyokaze_cookie_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_cookie_free(self.handle)
            self.handle = None

    @classmethod
    def parse(cls, value):
        """Reads a ``Cookie`` field value.

        Parsing never fails — a malformed field yields whatever pairs could
        be read from it.
        """
        encoded = ffi.encoded(value)
        handle = library.soyokaze_cookie_parse(encoded, len(encoded))
        if not handle:
            raise InvalidError("the value was refused")
        return cls(handle=handle)

    def pairs(self):
        """The name and value pairs, in the order they were sent."""
        count = library.soyokaze_cookie_count(self.handle)
        return [
            (library.soyokaze_cookie_name(self.handle, index).text(), library.soyokaze_cookie_value(self.handle, index).text())
            for index in range(count)
        ]

    def get(self, name):
        """The value stored under this exact name, or ``None``."""
        encoded = ffi.encoded(name)
        return library.soyokaze_cookie_get(self.handle, encoded, len(encoded)).text()

    def append(self, name, value):
        """Adds a pair at the end."""
        name, value = ffi.encoded(name), ffi.encoded(value)
        if not library.soyokaze_cookie_append(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the pair was refused")

    def build(self):
        """Writes the pairs back out as a ``Cookie`` field value."""
        return ffi.take(library.soyokaze_cookie_build(self.handle)).decode()

    def __repr__(self):
        return f"Cookie({self.build()!r})"

class SetCookie:
    """One ``Set-Cookie`` field: the cookie a server asks a client to keep."""

    def __init__(self, name=None, value=None, handle=None):
        """A cookie with no attributes set, or a wrapper around a handle."""
        if handle is None:
            name, value = ffi.encoded(name), ffi.encoded(value if value is not None else "")
            handle = library.soyokaze_setcookie_new(name, len(name), value, len(value))
            if not handle:
                raise InvalidError("the name or value was refused")
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_setcookie_free(self.handle)
            self.handle = None

    @classmethod
    def parse(cls, value):
        """Reads a ``Set-Cookie`` field value."""
        handle = ctypes.c_void_p()
        error = error_out()
        encoded = ffi.encoded(value)
        raise_for(library.soyokaze_setcookie_parse(encoded, len(encoded), ctypes.byref(handle), ctypes.byref(error)), error)
        return cls(handle=handle)

    @property
    def name(self):
        """The cookie name, which must be a token."""
        return library.soyokaze_setcookie_name(self.handle).text()

    @property
    def value(self):
        """The cookie value."""
        return library.soyokaze_setcookie_value(self.handle).text()

    @value.setter
    def value(self, value):
        encoded = ffi.encoded(value)
        library.soyokaze_setcookie_set_value(self.handle, encoded, len(encoded))

    @property
    def expires(self):
        """The ``Expires`` attribute, kept verbatim, or ``None``."""
        return library.soyokaze_setcookie_expires(self.handle).text()

    @expires.setter
    def expires(self, value):
        encoded = None if value is None else ffi.encoded(value)
        library.soyokaze_setcookie_set_expires(self.handle, encoded, 0 if encoded is None else len(encoded))

    @property
    def max_age(self):
        """The ``Max-Age`` attribute in seconds, or ``None``."""
        out = ctypes.c_int64()
        if not library.soyokaze_setcookie_max_age(self.handle, ctypes.byref(out)):
            return None
        return out.value

    @max_age.setter
    def max_age(self, value):
        library.soyokaze_setcookie_set_max_age(self.handle, value is not None, value if value is not None else 0)

    @property
    def domain(self):
        """The ``Domain`` attribute, or ``None`` when the cookie is host-only."""
        return library.soyokaze_setcookie_domain(self.handle).text()

    @domain.setter
    def domain(self, value):
        encoded = None if value is None else ffi.encoded(value)
        library.soyokaze_setcookie_set_domain(self.handle, encoded, 0 if encoded is None else len(encoded))

    @property
    def path(self):
        """The ``Path`` attribute, or ``None`` when the default path applies."""
        return library.soyokaze_setcookie_path(self.handle).text()

    @path.setter
    def path(self, value):
        encoded = None if value is None else ffi.encoded(value)
        library.soyokaze_setcookie_set_path(self.handle, encoded, 0 if encoded is None else len(encoded))

    @property
    def secure(self):
        """The ``Secure`` attribute, which confines the cookie to secure transports."""
        return library.soyokaze_setcookie_secure(self.handle)

    @secure.setter
    def secure(self, value):
        library.soyokaze_setcookie_set_secure(self.handle, value)

    @property
    def httponly(self):
        """The ``HttpOnly`` attribute, which hides the cookie from scripts."""
        return library.soyokaze_setcookie_httponly(self.handle)

    @httponly.setter
    def httponly(self, value):
        library.soyokaze_setcookie_set_httponly(self.handle, value)

    @property
    def samesite(self):
        """The ``SameSite`` attribute, or ``None``."""
        code = library.soyokaze_setcookie_samesite(self.handle)
        return None if code < 0 else SameSite(code)

    @samesite.setter
    def samesite(self, value):
        library.soyokaze_setcookie_set_samesite(self.handle, -1 if value is None else int(SameSite(value)))

    def build(self):
        """Writes the cookie out as a ``Set-Cookie`` field value."""
        out = ffi.Buffer()
        error = error_out()
        raise_for(library.soyokaze_setcookie_build(self.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return ffi.take(out).decode()

    def __repr__(self):
        return f"SetCookie({self.name!r})"

class CookieJar:
    """A client-side cookie store.

    The jar reads the clock itself, so lifetimes count from the moment a
    cookie is learned. A :class:`Client` keeps its own jar; this standalone
    one is for driving the exchange by hand.

    :class:`Client`: soyokaze.client.Client
    """

    def __init__(self, limits=None):
        """An empty jar, bounded by ``limits`` or the defaults."""
        struct = limits_argument(limits)
        self.handle = library.soyokaze_cookiejar_new(limits_pointer(struct))

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_cookiejar_free(self.handle)
            self.handle = None

    def learn(self, url, values):
        """Takes in the ``Set-Cookie`` values a response for ``url`` carried.

        Values that do not parse are skipped rather than failing the batch.
        """
        slices = [ffi.slice_of(ffi.encoded(value)) for value in values]
        array = (ffi.Slice * len(slices))(*slices)
        if not library.soyokaze_cookiejar_learn(self.handle, url.handle, array, len(slices)):
            raise InvalidError("the values were refused")

    def cookie(self, url):
        """The ``Cookie`` field value for a request to ``url``, or ``None``."""
        octets = ffi.taken(library.soyokaze_cookiejar_cookie(self.handle, url.handle))
        return None if octets is None else octets.decode()

    def prune(self):
        """Drops every cookie that has expired."""
        library.soyokaze_cookiejar_prune(self.handle)
