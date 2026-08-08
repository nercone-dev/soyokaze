"""Date formatting.

The one piece of the crate's ``finalizer`` module a binding user reaches
for: rendering an HTTP-date. The ``Date`` field itself is stamped onto
server responses by the library, so nothing here needs calling for that.
"""

from .ffi import library

class DateCache:
    """Where an HTTP date is formatted, as the crate's ``DateCache`` is."""

    @classmethod
    def http_date(cls, unix_seconds):
        """The IMF-fixdate for a Unix timestamp: ``Sun, 06 Nov 1994 08:49:37 GMT``."""
        return library.soyokaze_http_date(int(unix_seconds)).take().decode()
