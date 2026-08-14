"""The content codings a message body may be carried in.

Wraps the crate's own implementation, so what a body is coded as here is
exactly what the library puts on the wire. :class:`Compression` is both the
vocabulary — the tokens ``Content-Encoding`` and ``Accept-Encoding`` are
written in — and the codec those tokens stand for.

:attr:`Compression.AUTO` names nothing on the wire: it is a choice, settled
against what the peer said it accepts just before the body goes out.
"""

import ctypes
import enum

from .. import ffi
from ..errors import Error
from ..ffi import library

class Compression(enum.IntEnum):
    """A content coding a body may be carried in."""

    AUTO = 0
    ZSTD = 1
    BROTLI = 2
    GZIP = 3
    DEFLATE = 4

    def as_str(self):
        """The coding's token, as ``Content-Encoding`` spells it.

        Empty for :attr:`AUTO`, which names no coding and never appears on the
        wire.
        """
        return library.soyokaze_compression_name(int(self)).text()

    @classmethod
    def parse(cls, token):
        """The coding a token names, ignoring case, or ``None`` for none.

        Never answers :attr:`AUTO`. ``x-gzip`` is read as ``gzip``; a coding
        the library does not implement — ``compress`` and ``identity`` among
        them — names nothing.
        """
        encoded = ffi.Library.encoded(token)
        coding = library.soyokaze_compression_parse(encoded, len(encoded))
        return None if coding < 0 else cls(coding)

    @classmethod
    def codings(cls):
        """Every coding that names something, in order of preference."""
        return tuple(cls(library.soyokaze_compression_coding(index)) for index in range(library.soyokaze_compression_count()))

    @classmethod
    def accepted_field(cls):
        """:meth:`codings` written as an ``Accept-Encoding`` field value."""
        return library.soyokaze_compression_accepted_field().text()

    @classmethod
    def accepted(cls, headers):
        """The best coding a field section's ``Accept-Encoding`` permits.

        A coding at ``q=0`` is refused, ``*`` stands for every coding the field
        does not name, and among what is left the first of :meth:`codings`
        wins. ``None`` when nothing is permitted, which is also what an absent
        field means.
        """
        coding = library.soyokaze_compression_accepted(headers.handle)
        return None if coding < 0 else cls(coding)

    @classmethod
    def applied(cls, headers):
        """The coding a field section's ``Content-Encoding`` applied.

        ``None`` when the field is absent, names only ``identity``, names a
        coding the library does not implement, or names more than one — in each
        of those cases the body cannot be decoded and is handed on as it came.
        """
        coding = library.soyokaze_compression_applied(headers.handle)
        return None if coding < 0 else cls(coding)

    @classmethod
    def encoded(cls, headers):
        """Whether a field section says the body is coded at all.

        Stays true for a coding the library does not decode, which is what
        makes it the question "is the body still compressed".
        """
        return library.soyokaze_compression_encoded(headers.handle)

    @classmethod
    def quality(cls, entry):
        """The quality one entry of a coding list carries.

        An entry with no ``q`` parameter is fully acceptable and reads as 1.
        """
        encoded = ffi.Library.encoded(entry)
        return library.soyokaze_compression_quality(encoded, len(encoded))

    @classmethod
    def qvalue(cls, text):
        """The quality a ``qvalue`` text names on its own.

        ``None`` for anything outside the grammar RFC 9110 §12.4.2 gives one;
        :meth:`quality` reads the quality a whole list entry carries.
        """
        encoded = ffi.Library.encoded(text)
        read = library.soyokaze_compression_qvalue(encoded, len(encoded))
        return None if read < 0 else read

    def encode(self, data):
        """Codes octets in this coding.

        Raises :class:`ProtocolError` for :attr:`AUTO`, which names no coding
        to code in.
        """
        data = ffi.Library.encoded(data)
        out, error = ffi.Buffer(), Error.out()
        status = library.soyokaze_compression_encode(int(self), data, len(data), ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return out.take()

    def decode(self, data, max):
        """Undoes this coding, producing at most ``max`` octets.

        Raises :class:`LimitError` once the decoded body would pass ``max``,
        which is what stops a small coded body decoding into an enormous one.
        """
        data = ffi.Library.encoded(data)
        out, error = ffi.Buffer(), Error.out()
        status = library.soyokaze_compression_decode(int(self), data, len(data), max, ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return out.take()

    def __str__(self):
        return self.as_str()
