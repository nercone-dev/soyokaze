"""Date formatting.

The one piece of the crate's ``finalizer`` module a binding user reaches
for: rendering an HTTP-date. The ``Date`` field itself is stamped onto
server responses by the library, so nothing here needs calling for that.
"""

from . import ffi
from .ffi import library

def http_date(unix_seconds):
    """The IMF-fixdate for a Unix timestamp: ``Sun, 06 Nov 1994 08:49:37 GMT``."""
    return ffi.take(library.soyokaze_http_date(int(unix_seconds))).decode()
