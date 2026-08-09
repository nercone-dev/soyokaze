"""Deadlines.

:class:`Timeout` reads the timeouts the :class:`Limits` fields describe — when
one arms a deadline at all, and how long that deadline is — and :class:`Elapsed`
is what a deadline that passed reports. The crate's ``Lock`` has no counterpart
here: it hands back a guard, which is a Rust lifetime and nothing these bindings
could hold.

:class:`Limits`: soyokaze.models.Limits
"""

from ..errors import TimeoutError
from ..ffi import library

class Elapsed(TimeoutError):
    """An operation did not finish within the seconds it was given."""

    def __init__(self, seconds):
        super().__init__(library.soyokaze_elapsed_message(seconds).take().decode())
        self.seconds = seconds

class Timeout:
    """The deadlines the :class:`Limits` fields describe.

    :class:`Limits`: soyokaze.models.Limits
    """

    @classmethod
    def armed(cls, seconds):
        """Whether a timeout in seconds asks for a deadline at all.

        Zero, negative and non-finite values all disable the timeout.
        """
        return library.soyokaze_timeout_armed(seconds)

    @classmethod
    def duration(cls, seconds):
        """How long the deadline is, in seconds, or ``None`` when it arms none."""
        nanos = library.soyokaze_timeout_nanos(seconds)
        return None if nanos < 0 else nanos / 1_000_000_000
