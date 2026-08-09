"""The server's admission control.

A :class:`Gate` decides whether one more connection is let in: how many are
open, how many one address may hold, and how fast one address may open them. A
:class:`Server <soyokaze.api.server.Server>` builds its own from its
:class:`ServerLimits <soyokaze.api.server.ServerLimits>`, so nothing here needs
calling for an ordinary server; it is here for a caller that admits connections
itself, and for reading what a running server's gate is doing.

An admitted connection hands back a :class:`Permit`, which releases its place
when it is dropped.
"""

import ctypes

from .. import ffi
from ..ffi import library

class Permit:
    """A place in a :class:`Gate`, released when it is dropped."""

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_permit_free(self.handle)
            self.handle = None

    @property
    def ip(self):
        """The address the permit was admitted for, or ``None``."""
        address = library.soyokaze_permit_address(self.handle).taken()
        return None if address is None else address.decode()

    @property
    def gate(self):
        """The gate the permit was admitted through."""
        return Gate(handle=library.soyokaze_permit_gate(self.handle))

    def release(self):
        """Gives the place back at once, rather than waiting to be dropped."""
        if self.handle:
            library.soyokaze_permit_free(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *failure):
        self.release()
        return False

    def __repr__(self):
        return f"Permit({self.ip!r})"

class Gate:
    """What decides whether one more connection is let in.

    A ``max_connections`` or ``max_connections_per_ip`` of zero lets any number
    through, and an empty ``max_connection_rate`` rate-limits nothing.
    ``max_connection_history`` bounds how many addresses are remembered for rate
    limiting, so the memory a gate uses stays bounded whatever the peer does.
    """

    def __init__(self, max_connections=0, max_connections_per_ip=0, max_connection_rate=(), max_connection_history=0, handle=None):
        if handle is None:
            rates = list(max_connection_rate)
            array = (ffi.Rate * len(rates))(*[ffi.Rate(period, count) for period, count in rates])
            handle = library.soyokaze_gate_new(max_connections, max_connections_per_ip, array, len(rates), max_connection_history)
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_gate_free(self.handle)
            self.handle = None

    @property
    def max_connections(self):
        """How many connections may be open at once, or zero for no ceiling."""
        return library.soyokaze_gate_max_connections(self.handle)

    @property
    def max_connections_per_ip(self):
        """How many connections one address may hold, or zero for no ceiling."""
        return library.soyokaze_gate_max_connections_per_ip(self.handle)

    @property
    def max_connection_history(self):
        """How many addresses are remembered for rate limiting."""
        return library.soyokaze_gate_max_connection_history(self.handle)

    @property
    def max_connection_rate(self):
        """The rate limits, as ``(period, count)`` pairs."""
        count = library.soyokaze_gate_rate_count(self.handle)
        rates = []

        for index in range(count):
            rate = library.soyokaze_gate_rate(self.handle, index)
            rates.append((rate.period, rate.count))

        return rates

    def count(self, ip=None):
        """How many connections are open, in total or for one address."""
        if ip is None:
            return library.soyokaze_gate_count(self.handle)
        encoded = ffi.Library.encoded(ip)
        return library.soyokaze_gate_count_for(self.handle, encoded, len(encoded))

    def window(self):
        """The longest window any rate limit spans, in seconds."""
        return library.soyokaze_gate_window(self.handle)

    def admit(self, ip=None):
        """Admits one more connection, or ``None`` when it is turned away.

        An ``ip`` of ``None`` admits without an address, which counts against
        the total but against no per-address ceiling.
        """
        encoded = None if ip is None else ffi.Library.encoded(ip)
        handle = library.soyokaze_gate_admit(self.handle, encoded, 0 if encoded is None else len(encoded))
        return None if not handle else Permit(handle)

    def sweep(self):
        """Drops every address whose history has fallen outside the window."""
        library.soyokaze_gate_sweep(self.handle)

    def __repr__(self):
        return f"Gate({self.count()}/{self.max_connections})"
