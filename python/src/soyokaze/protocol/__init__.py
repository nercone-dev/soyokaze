"""One connection type per HTTP version, over a shared vocabulary.

Each module wraps its namesake in the crate's ``protocol``: :mod:`common` is
what every version shares, :mod:`quic` is the seam QUIC is consumed through,
and :mod:`h1`, :mod:`h2` and :mod:`h3` each hold one version's wire format.

What is here is the framing on its own — frames, field sections, start lines,
chunks — rather than the connections themselves, which come out of
:class:`Client <soyokaze.api.client.Client>` and
:class:`Server <soyokaze.api.server.Server>` as one kind of object whichever
version framed them.
"""

from . import common, h1, h2, h3, quic
