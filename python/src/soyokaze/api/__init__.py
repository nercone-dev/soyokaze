"""The two entry points a caller of the library reaches for first.

:mod:`client` dials an origin, :mod:`server` binds ports and accepts
connections, and :mod:`common` holds what the two configure in common. Each
module wraps its namesake in the crate's ``api``.
"""

from . import client, common, server
