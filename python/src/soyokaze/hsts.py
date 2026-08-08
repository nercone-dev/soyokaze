"""HTTP Strict Transport Security.

:class:`HstsPolicy` is the ``Strict-Transport-Security`` field itself — a
server builds one to send, a client parses one it received — and
:class:`HstsStore` is the client-side memory of which hosts insist on TLS.
"""

import ctypes

from . import ffi
from .models import limits_argument, limits_pointer
from .errors import ProtocolError
from .ffi import library

class HstsPolicy:
    """One ``Strict-Transport-Security`` policy."""

    def __init__(self, max_age, include_subdomains=False, preload=False):
        self.max_age = max_age
        self.include_subdomains = include_subdomains
        self.preload = preload

    @classmethod
    def parse(cls, value):
        """Reads a field value, raising :class:`ProtocolError` when it cannot be trusted."""
        out = ffi.HstsPolicy()
        encoded = ffi.encoded(value)
        if not library.soyokaze_hsts_policy_parse(encoded, len(encoded), ctypes.byref(out)):
            raise ProtocolError("the policy cannot be trusted")
        return cls(out.max_age, out.include_subdomains, out.preload)

    def build(self):
        """The field value as text."""
        struct = ffi.HstsPolicy(self.max_age, self.include_subdomains, self.preload)
        return ffi.take(library.soyokaze_hsts_policy_build(ctypes.byref(struct))).decode()

    def __repr__(self):
        return f"HstsPolicy({self.build()!r})"

class HstsStore:
    """A client-side record of which hosts insist on TLS.

    The store reads the clock itself, so lifetimes count from the moment a
    policy is learned. A :class:`Client` keeps its own store; this
    standalone one is for driving the exchange by hand.

    :class:`Client`: soyokaze.client.Client
    """

    def __init__(self, limits=None):
        """An empty store, bounded by ``limits`` or the defaults."""
        struct = limits_argument(limits)
        self.handle = library.soyokaze_hsts_store_new(limits_pointer(struct))

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_hsts_store_free(self.handle)
            self.handle = None

    def learn(self, host, header, secure=True):
        """Takes in the field a response carried.

        Ignored outright unless the response arrived over a secure
        transport, since otherwise the field could have been injected.
        """
        host, header = ffi.encoded(host), ffi.encoded(header)
        library.soyokaze_hsts_store_learn(self.handle, host, len(host), header, len(header), secure)

    def secure(self, host):
        """Whether ``host`` must be reached over TLS."""
        encoded = ffi.encoded(host)
        return library.soyokaze_hsts_store_secure(self.handle, encoded, len(encoded))

    def prune(self):
        """Drops every entry that has expired."""
        library.soyokaze_hsts_store_prune(self.handle)
