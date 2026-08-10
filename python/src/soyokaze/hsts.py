"""HTTP Strict Transport Security.

:class:`HSTSPolicy` is the ``Strict-Transport-Security`` field itself — a
server builds one to send, a client parses one it received — and
:class:`HSTSStore` is the client-side memory of which hosts insist on TLS.
"""

import ctypes

from . import ffi
from .models import Limits
from .errors import ProtocolError
from .ffi import library

class HSTSLimits:
    """What one :class:`HSTSStore` may remember."""

    max_hsts_entries = library.soyokaze_hsts_default_max_entries()
    """How many hosts a store may remember unless told otherwise."""

    def __init__(self, max_hsts_entries=None):
        if max_hsts_entries is not None:
            self.max_hsts_entries = max_hsts_entries

    def __repr__(self):
        return f"HSTSLimits({self.max_hsts_entries})"

class HSTSPolicy:
    """One ``Strict-Transport-Security`` policy."""

    def __init__(self, max_age, include_subdomains=False, preload=False):
        self.max_age = max_age
        self.include_subdomains = include_subdomains
        self.preload = preload

    @classmethod
    def parse(cls, value):
        """Reads a field value, raising :class:`ProtocolError` when it cannot be trusted."""
        out = ffi.HSTSPolicy()
        encoded = ffi.Library.encoded(value)
        if not library.soyokaze_hsts_policy_parse(encoded, len(encoded), ctypes.byref(out)):
            raise ProtocolError("the policy cannot be trusted")
        return cls(out.max_age, out.include_subdomains, out.preload)

    def build(self):
        """The field value as text."""
        struct = ffi.HSTSPolicy(self.max_age, self.include_subdomains, self.preload)
        return library.soyokaze_hsts_policy_build(ctypes.byref(struct)).take().decode()

    def value(self):
        """The field value. The same as :meth:`build`."""
        return self.build()

    def __repr__(self):
        return f"HSTSPolicy({self.build()!r})"

class HSTSStore:
    """A client-side record of which hosts insist on TLS.

    The store reads the clock itself, so lifetimes count from the moment a
    policy is learned. A :class:`Client` keeps its own store; this
    standalone one is for driving the exchange by hand.

    :class:`Client`: soyokaze.client.Client
    """

    def __init__(self, limits=None, handle=None, owner=None):
        """An empty store bounded by ``limits``, or a view of one already built.

        A store reached through
        :attr:`Client.store <soyokaze.api.client.Client.store>` belongs to that
        client: it is borrowed rather than owned. ``owner`` is that client,
        held here so the store cannot outlive what it points into.
        """
        self.owned = handle is None
        self.owner = owner
        self.handle = handle if handle is not None else library.soyokaze_hsts_store_new(Limits.pointer(Limits.argument(limits)))

    def __del__(self):
        if getattr(self, "owned", False) and getattr(self, "handle", None):
            library.soyokaze_hsts_store_free(self.handle)
        self.handle = None

    def learn(self, host, header, secure=True):
        """Takes in the field a response carried.

        Ignored outright unless the response arrived over a secure
        transport, since otherwise the field could have been injected.
        """
        host, header = ffi.Library.encoded(host), ffi.Library.encoded(header)
        library.soyokaze_hsts_store_learn(self.handle, host, len(host), header, len(header), secure)

    def secure(self, host):
        """Whether ``host`` must be reached over TLS."""
        encoded = ffi.Library.encoded(host)
        return library.soyokaze_hsts_store_secure(self.handle, encoded, len(encoded))

    @classmethod
    def normalize(cls, host):
        """The form of a host name the store keys on, or ``None``.

        Strips surrounding brackets and any trailing root dot, and lowercases
        the rest. ``None`` for an empty name and for an IP address, since HSTS
        applies to host names only.
        """
        host = ffi.Library.encoded(host)
        normalized = library.soyokaze_hsts_normalize(host, len(host)).taken()
        return None if normalized is None else normalized.decode()

    @property
    def limits(self):
        """What this store may remember."""
        return HSTSLimits(library.soyokaze_hsts_store_max_entries(self.handle))

    def __len__(self):
        return library.soyokaze_hsts_store_len(self.handle)

    def prune(self):
        """Drops every entry that has expired."""
        library.soyokaze_hsts_store_prune(self.handle)
