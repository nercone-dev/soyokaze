"""The codecs and utilities the protocol implementations share.

Each module wraps its namesake in the crate's ``helpers``: :mod:`huffman`,
:mod:`hpack` and :mod:`qpack` are the field compression formats,
:mod:`base64` and :mod:`sha1` are what the WebSocket handshake needs, and
:mod:`hsts` holds the Strict-Transport-Security policy types.
"""

from . import base64, hpack, hsts, huffman, qpack, sha1
