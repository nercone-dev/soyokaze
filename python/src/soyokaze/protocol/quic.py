"""The seam QUIC is consumed through.

What HTTP/3 needs of QUIC and nothing more: :class:`Varint` is the
variable-length integer every HTTP/3 and QPACK field is written as,
:class:`QUICStreamID` is how stream identifiers are numbered, and
:class:`Handshake` is what a completed handshake settled on. The transport
itself is driven by the library, so nothing here opens a connection.
"""

import ctypes

from .. import ffi
from ..errors import Error
from ..ffi import library
from ..models import Version
from ..tls import Security

class Varint:
    """The QUIC variable-length integer."""

    MAXIMUM = library.soyokaze_varint_maximum()
    """The largest value one can hold."""

    MAX_SIZE = library.soyokaze_varint_max_size()
    """The most octets one takes."""

    @classmethod
    def len(cls, value):
        """How many octets a value takes when it is written out."""
        return library.soyokaze_varint_len(value)

    @classmethod
    def encode(cls, value):
        """The value as it sits on the wire."""
        return library.soyokaze_varint_encode(value).take()

    @classmethod
    def decode(cls, data):
        """Reads one integer, returning ``(read, value)``.

        A truncated integer reads as ``(0, 0)``, which is how the crate reports
        one too.
        """
        data = ffi.Library.encoded(data)
        out, read = ctypes.c_uint64(), ctypes.c_size_t()
        if not library.soyokaze_varint_decode(data, len(data), ctypes.byref(out), ctypes.byref(read)):
            return 0, 0
        return read.value, out.value

    @classmethod
    def only(cls, payload, name):
        """Reads a payload that must be exactly one integer.

        ``name`` is what the failure calls the frame, so a caller reads which
        frame was malformed rather than that one was.
        """
        payload, name = ffi.Library.encoded(payload), ffi.Library.encoded(name)
        out, error = ctypes.c_uint64(), Error.out()
        Error.raise_for(library.soyokaze_varint_only(payload, len(payload), name, len(name), ctypes.byref(out), ctypes.byref(error)), error)
        return out.value

class QUICStreamID:
    """How QUIC numbers its streams."""

    STEP = library.soyokaze_quic_stream_step()
    """How far apart two stream identifiers of the same kind are."""

    @classmethod
    def is_bidi(cls, stream_id):
        """Whether an identifier names a bidirectional stream."""
        return library.soyokaze_quic_stream_is_bidi(stream_id)

    @classmethod
    def is_uni(cls, stream_id):
        """Whether an identifier names a unidirectional stream."""
        return library.soyokaze_quic_stream_is_uni(stream_id)

    @classmethod
    def client_initiated(cls, stream_id):
        """Whether an identifier names one the client opened."""
        return library.soyokaze_quic_stream_client_initiated(stream_id)

    @classmethod
    def first_bidi(cls, role):
        """The first bidirectional stream a role may open."""
        return library.soyokaze_quic_stream_first_bidi(int(role))

    @classmethod
    def first_uni(cls, role):
        """The first unidirectional stream a role may open."""
        return library.soyokaze_quic_stream_first_uni(int(role))

class Handshake:
    """What a completed QUIC handshake settled on."""

    def __init__(self, alpn=b"", version=0):
        self.alpn = alpn
        self.version = version

    def negotiated(self, versions):
        """The version the agreed ALPN identifier settles on.

        Over QUIC a handshake that agreed on nothing is always a failure: there
        is no version to fall back to.
        """
        array = (ctypes.c_int32 * len(versions))(*[int(version) for version in versions])
        alpn = None if not self.alpn else ffi.Library.encoded(self.alpn)
        out, error = ctypes.c_int32(), Error.out()
        Error.raise_for(
            library.soyokaze_quic_handshake_negotiated(alpn, 0 if alpn is None else len(alpn), array, len(versions), ctypes.byref(out), ctypes.byref(error)),
            error,
        )
        return Version(out.value)

    def security(self):
        """What the handshake reports as its security."""
        return Security.taken(library.soyokaze_quic_handshake_security(self.version))

    def __repr__(self):
        return f"Handshake({self.alpn!r}, {self.version})"
