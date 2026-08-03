"""The codecs and utilities the protocol implementations share.

Each module wraps its namesake in the crate's ``helpers``: :mod:`huffman`,
:mod:`hpack` and :mod:`qpack` are the field compression formats, over the
shared vocabulary in :mod:`fields`; :mod:`base64` and :mod:`sha1` are what
the WebSocket handshake needs.
"""

from . import base64, fields, hpack, huffman, qpack, sha1
