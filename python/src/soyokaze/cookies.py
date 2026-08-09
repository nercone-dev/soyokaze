"""Cookies.

:class:`Cookie` and :class:`SetCookie` are the two sides of the exchange —
what a client sends and what a server sets — and :class:`CookieJar` is the
client-side store that turns one into the other across requests, mirroring
the crate's ``headers`` module.
"""

import ctypes
import enum

from . import ffi
from .models import Limits
from .errors import Error, InvalidError
from .ffi import library

class SameSite(enum.IntEnum):
    """The ``SameSite`` attribute of a cookie, as the C ABI numbers it."""

    STRICT = 0
    LAX = 1
    NONE = 2

    def as_str(self):
        """How the attribute is written out."""
        return library.soyokaze_samesite_name(int(self)).text()

    @classmethod
    def parse(cls, name):
        """The attribute a name spells out, or ``None``.

        The name is matched case-insensitively, as the attribute is written.
        """
        name = ffi.Library.encoded(name)
        samesite = library.soyokaze_samesite_parse(name, len(name))
        return None if samesite < 0 else cls(samesite)

    def __str__(self):
        return self.as_str()

class CookieLimits:
    """What one :class:`CookieJar` may hold."""

    max_cookies = library.soyokaze_cookie_default_max_cookies()
    """How many cookies a jar may hold unless told otherwise."""

    max_cookies_per_domain = library.soyokaze_cookie_default_max_cookies_per_domain()
    """How many cookies a jar may hold per domain unless told otherwise."""

    def __init__(self, max_cookies=None, max_cookies_per_domain=None):
        if max_cookies is not None:
            self.max_cookies = max_cookies
        if max_cookies_per_domain is not None:
            self.max_cookies_per_domain = max_cookies_per_domain

    def __repr__(self):
        return f"CookieLimits({self.max_cookies}, {self.max_cookies_per_domain})"

class StoredCookie:
    """A cookie as a :class:`CookieJar` holds it.

    ``expires_in`` is how many seconds are left before it expires, or ``None``
    when it lasts the session.
    """

    @classmethod
    def path_matches(cls, target, cookie_path):
        """Whether a cookie's ``Path`` covers a request target."""
        target, cookie_path = ffi.Library.encoded(target), ffi.Library.encoded(cookie_path)
        return library.soyokaze_cookie_path_matches(target, len(target), cookie_path, len(cookie_path))

    @classmethod
    def default_path(cls, target):
        """The ``Path`` a cookie takes when the attribute is absent."""
        target = ffi.Library.encoded(target)
        return library.soyokaze_cookie_default_path(target, len(target)).take().decode()

    def __init__(self, name, value, domain, host_only, path, secure, expires_in):
        self.name = name
        self.value = value
        self.domain = domain
        self.host_only = host_only
        self.path = path
        self.secure = secure
        self.expires_in = expires_in

    def __repr__(self):
        return f"StoredCookie({self.name!r}, {self.value!r}, domain={self.domain!r}, path={self.path!r})"

class Cookie:
    """The contents of a ``Cookie`` field: the pairs a client sends back."""

    @classmethod
    def is_separator(cls, octet):
        """Whether an octet separates pairs rather than belonging to one."""
        return library.soyokaze_cookie_is_separator(octet)

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
        encoded = ffi.Library.encoded(value)
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
        encoded = ffi.Library.encoded(name)
        return library.soyokaze_cookie_get(self.handle, encoded, len(encoded)).text()

    def append(self, name, value):
        """Adds a pair at the end."""
        name, value = ffi.Library.encoded(name), ffi.Library.encoded(value)
        if not library.soyokaze_cookie_append(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the pair was refused")

    def build(self):
        """Writes the pairs back out as a ``Cookie`` field value."""
        return library.soyokaze_cookie_build(self.handle).take().decode()

    def __repr__(self):
        return f"Cookie({self.build()!r})"

class SetCookie:
    """One ``Set-Cookie`` field: the cookie a server asks a client to keep."""

    def __init__(self, name=None, value=None, handle=None):
        """A cookie with no attributes set, or a wrapper around a handle."""
        if handle is None:
            name, value = ffi.Library.encoded(name), ffi.Library.encoded(value if value is not None else "")
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
        error = Error.out()
        encoded = ffi.Library.encoded(value)
        Error.raise_for(library.soyokaze_setcookie_parse(encoded, len(encoded), ctypes.byref(handle), ctypes.byref(error)), error)
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
        encoded = ffi.Library.encoded(value)
        library.soyokaze_setcookie_set_value(self.handle, encoded, len(encoded))

    @property
    def expires(self):
        """The ``Expires`` attribute, kept verbatim, or ``None``."""
        return library.soyokaze_setcookie_expires(self.handle).text()

    @expires.setter
    def expires(self, value):
        encoded = None if value is None else ffi.Library.encoded(value)
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
        encoded = None if value is None else ffi.Library.encoded(value)
        library.soyokaze_setcookie_set_domain(self.handle, encoded, 0 if encoded is None else len(encoded))

    @property
    def path(self):
        """The ``Path`` attribute, or ``None`` when the default path applies."""
        return library.soyokaze_setcookie_path(self.handle).text()

    @path.setter
    def path(self, value):
        encoded = None if value is None else ffi.Library.encoded(value)
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
        error = Error.out()
        Error.raise_for(library.soyokaze_setcookie_build(self.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return out.take().decode()

    def __repr__(self):
        return f"SetCookie({self.name!r})"

class CookieJar:
    """A client-side cookie store.

    The jar reads the clock itself, so lifetimes count from the moment a
    cookie is learned. A :class:`Client` keeps its own jar; this standalone
    one is for driving the exchange by hand.

    :class:`Client`: soyokaze.client.Client
    """

    def __init__(self, limits=None, handle=None):
        """An empty jar bounded by ``limits``, or a view of one already built.

        A jar reached through :attr:`Client.jar <soyokaze.api.client.Client.jar>`
        belongs to that client: it is borrowed rather than owned, and is valid
        only for as long as the client is.
        """
        self.owned = handle is None
        self.handle = handle if handle is not None else library.soyokaze_cookiejar_new(Limits.pointer(Limits.argument(limits)))

    def __del__(self):
        if getattr(self, "owned", False) and getattr(self, "handle", None):
            library.soyokaze_cookiejar_free(self.handle)
            self.handle = None

    @property
    def limits(self):
        """What this jar may hold."""
        return CookieLimits(
            library.soyokaze_cookiejar_max_cookies(self.handle),
            library.soyokaze_cookiejar_max_cookies_per_domain(self.handle),
        )

    def entries(self):
        """Every cookie the jar is holding, as :class:`StoredCookie` values."""
        stored = []

        for index in range(library.soyokaze_cookiejar_count(self.handle)):
            entry, storage = ffi.StoredCookie(), ffi.Buffer()
            if not library.soyokaze_cookiejar_entry(self.handle, index, ctypes.byref(entry), ctypes.byref(storage)):
                break

            stored.append(StoredCookie(
                entry.name.text(),
                entry.value.text(),
                entry.domain.text(),
                entry.host_only,
                entry.path.text(),
                entry.secure,
                None if entry.expires_in < 0 else entry.expires_in,
            ))
            storage.take()

        return stored

    def __len__(self):
        return library.soyokaze_cookiejar_count(self.handle)

    def learn(self, url, values):
        """Takes in the ``Set-Cookie`` values a response for ``url`` carried.

        Values that do not parse are skipped rather than failing the batch.
        """
        slices = [ffi.Slice.of(ffi.Library.encoded(value)) for value in values]
        array = (ffi.Slice * len(slices))(*slices)
        if not library.soyokaze_cookiejar_learn(self.handle, url.handle, array, len(slices)):
            raise InvalidError("the values were refused")

    def cookie(self, url):
        """The ``Cookie`` field value for a request to ``url``, or ``None``."""
        octets = library.soyokaze_cookiejar_cookie(self.handle, url.handle).taken()
        return None if octets is None else octets.decode()

    def prune(self):
        """Drops every cookie that has expired."""
        library.soyokaze_cookiejar_prune(self.handle)
