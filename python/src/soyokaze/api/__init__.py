"""The two entry points a caller of the library reaches for first.

:mod:`client` dials an origin, :mod:`server` binds ports and accepts
connections, and :mod:`common` holds what the two configure in common.
:mod:`gate` is the server's admission control, and :mod:`cluster` runs the
server across worker threads. Each module wraps its namesake in the crate's
``api``.
"""

from . import client, cluster, common, gate, server
