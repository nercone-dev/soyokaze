"""SHA-1.

Provided because the WebSocket handshake needs it; it is not a
general-purpose hash to build anything new on. :func:`sha1` hashes an input in
one call, and :class:`Sha1` is the same hash driven a block at a time.
"""

import ctypes

from .. import ffi
from ..ffi import library

BLOCK_SIZE = library.soyokaze_sha1_block_size()
"""How many octets one compression block holds."""

DIGEST_SIZE = library.soyokaze_sha1_digest_size()
"""How many octets a digest is."""

INITIAL_STATE = tuple(library.soyokaze_sha1_initial_state()[index] for index in range(5))
"""The five words the state starts at."""

CONSTANTS = tuple(library.soyokaze_sha1_constants()[index] for index in range(4))
"""The four round constants."""

class Sha1:
    """A SHA-1 hash with nothing fed in yet."""

    def __init__(self):
        self.handle = library.soyokaze_sha1_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_sha1_free(self.handle)
            self.handle = None

    def update(self, data):
        """Feeds octets in."""
        data = ffi.Library.encoded(data)
        library.soyokaze_sha1_update(self.handle, data, len(data))

    def compress(self, block):
        """Runs one :data:`BLOCK_SIZE` block through the state.

        The octets are not counted towards the length the padding carries, so
        a caller driving the hash by hand counts them itself; :meth:`update` is
        what an ordinary caller wants.
        """
        block = ffi.Library.encoded(block)
        library.soyokaze_sha1_compress(self.handle, block, len(block))

    def finish(self):
        """The digest, releasing the hash as it is read. Always 20 octets."""
        handle, self.handle = self.handle, None
        out = ffi.Buffer()
        library.soyokaze_sha1_finish(handle, ctypes.byref(out))
        return out.take()

def sha1(data):
    """The SHA-1 digest of ``data``. Always 20 octets."""
    data = ffi.Library.encoded(data)
    return library.soyokaze_sha1(data, len(data)).take()
