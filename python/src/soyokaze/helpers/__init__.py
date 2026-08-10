"""The codecs and utilities the protocol implementations share.

Each module wraps its namesake in the crate's ``helpers``: :mod:`huffman`,
:mod:`hpack` and :mod:`qpack` are the field compression formats, over the
shared vocabulary in :mod:`fields`; :mod:`compression` is the other kind, the
content codings a body is carried in; :mod:`base64` and :mod:`sha1` are what
the WebSocket handshake needs; and :mod:`text`, :mod:`scan` and :mod:`sync` are
the small pieces the parsers lean on.
"""

from . import base64, compression, fields, hpack, huffman, qpack, scan, sha1, sync, text
