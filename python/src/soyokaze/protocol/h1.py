"""HTTP/1.x.

The wire format on its own: :class:`StartLine`, one :class:`Field`, one
:class:`Chunk`, and :class:`BodyLength` for how a body's length is worked out.
Nothing here touches a connection, so a caller can frame and parse HTTP/1.x
messages without opening one.
"""

import ctypes
import enum

from .. import ffi
from ..errors import Error, Status
from ..ffi import library
from ..models import HeaderCase, Headers, Limits, Message, Method, Version

class H1Limits:
    """What one HTTP/1.x connection may spend on the peer's behalf.

    Derived from a :class:`Limits <soyokaze.models.Limits>` when a connection
    is built, so a caller sets these through that rather than here.
    """

    FIELDS = [name for name, kind in ffi.H1Limits._fields_]

    def __init__(self, **ceilings):
        defaults = library.soyokaze_h1_limits_default()

        for name in self.FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in self.FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    @classmethod
    def taken(cls, struct):
        """The :class:`H1Limits` a ``soyokaze_h1_limits_t`` stands for."""
        return cls(**{name: getattr(struct, name) for name in cls.FIELDS})

    @classmethod
    def of(cls, limits):
        """The limits a :class:`Limits <soyokaze.models.Limits>` narrows a connection to."""
        struct = Limits.argument(limits)
        return cls.taken(library.soyokaze_h1_limits_of(Limits.pointer(struct)))

    def __repr__(self):
        return f"H1Limits(max_message_size={self.max_message_size})"

class Octets:
    """Which octets may appear where in an HTTP/1.x message."""

    TOKEN = library.soyokaze_h1_token()
    """The classification bit for an octet that may appear in a token."""

    FIELD = library.soyokaze_h1_field()
    """The classification bit for an octet that may appear in a field value."""

    TABLE = library.soyokaze_h1_octet_table().bytes()
    """The 256-entry classification table the parsers walk."""

    @classmethod
    def is_control(cls, octet):
        """Whether an octet is a control character, which no field may carry."""
        return library.soyokaze_h1_is_control(octet)

    @classmethod
    def is_token(cls, text):
        """Whether every octet may appear in a token."""
        text = ffi.Library.encoded(text)
        return library.soyokaze_h1_is_token(text, len(text))

    @classmethod
    def is_token_bytes(cls, text):
        """Whether every octet may appear in a token. The same as :meth:`is_token`."""
        return cls.is_token(text)

class Persistence:
    """Whether a connection survives the message on it."""

    @classmethod
    def keep_alive(cls, headers, version=Version.V1_1):
        """Whether a message may be followed by another on the same connection."""
        return library.soyokaze_h1_keep_alive(None if headers is None else headers.handle, int(version))

class StartLine:
    """The first line of a request or a response."""

    @classmethod
    def encode(cls, message):
        """The start line a message opens with."""
        return library.soyokaze_h1_start_line_encode(message.handle).take().decode()

    @classmethod
    def parse(cls, line):
        """A message with the start line read in and nothing else filled in."""
        line = ffi.Library.encoded(line)
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_h1_start_line_parse(line, len(line), ctypes.byref(out), ctypes.byref(error)), error)
        return Message(handle=out)

    @classmethod
    def parse_bytes(cls, line):
        """As :meth:`parse`, taking octets."""
        return cls.parse(line)

    @classmethod
    def error_status(cls, line):
        """The status code a malformed start line is answered with.

        A method this end does not know earns ``501``, a version it will not
        speak ``505``, and everything else ``400``.
        """
        line = ffi.Library.encoded(line)
        return library.soyokaze_h1_start_line_error_status(line, len(line))

    @classmethod
    def error_status_bytes(cls, line):
        """As :meth:`error_status`, taking octets."""
        return cls.error_status(line)

    @classmethod
    def version(cls, text):
        """The version an ``HTTP/x.y`` token names."""
        text = ffi.Library.encoded(text)
        out, error = ctypes.c_int32(), Error.out()
        Error.raise_for(library.soyokaze_h1_version_parse(text, len(text), ctypes.byref(out), ctypes.byref(error)), error)
        return Version(out.value)

class Field:
    """One field line, and the block of them a message carries."""

    @classmethod
    def encode(cls, name, value, header_case=HeaderCase.TITLE):
        """One field line, terminator included."""
        name, value = ffi.Library.encoded(name), ffi.Library.encoded(value)
        return library.soyokaze_h1_field_encode(name, len(name), value, len(value), int(header_case)).take().decode()

    @classmethod
    def encode_all(cls, headers, header_case=HeaderCase.TITLE):
        """A whole field section, one line per field."""
        return library.soyokaze_h1_field_encode_all(headers.handle, int(header_case)).take().decode()

    @classmethod
    def size(cls, headers):
        """How many octets a field section costs against the headers ceiling."""
        return library.soyokaze_h1_field_size(headers.handle)

    @classmethod
    def parse(cls, line):
        """One field line, as a ``(name, value)`` pair."""
        line = ffi.Library.encoded(line)
        name, value, error = ffi.Buffer(), ffi.Buffer(), Error.out()
        Error.raise_for(library.soyokaze_h1_field_parse(line, len(line), ctypes.byref(name), ctypes.byref(value), ctypes.byref(error)), error)
        return name.take().decode(), value.take().decode()

    @classmethod
    def parse_bytes(cls, line):
        """As :meth:`parse`, taking octets."""
        return cls.parse(line)

    @classmethod
    def parse_block(cls, block, max_count):
        """A whole field block, as a :class:`Headers <soyokaze.models.Headers>`.

        The block is the octets between the start line and the empty line that
        ends the section, the terminator not included. ``max_count`` is how
        many fields the section may hold — a section with more is refused, so a
        peer cannot spend this end's memory a field at a time.
        """
        block = ffi.Library.encoded(block)
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_h1_field_parse_block(block, len(block), max_count, ctypes.byref(out), ctypes.byref(error)), error)
        return Headers(handle=out, owned=True)

    @classmethod
    def block_end(cls, data, searched=0):
        """Where a field block ends, if it has.

        Returns ``(searched, fields_end, section_end)``: how far this call
        looked, where the field lines stop, and where the section as a whole
        ends with the blank line included. The last two are ``None`` while the
        section is still incomplete. Feed ``searched`` back so repeated calls
        stay linear.
        """
        data = ffi.Library.encoded(data)
        looked = ctypes.c_size_t(searched)
        fields_end, section_end = ctypes.c_size_t(), ctypes.c_size_t()
        found = library.soyokaze_h1_field_block_end(data, len(data), ctypes.byref(looked), ctypes.byref(fields_end), ctypes.byref(section_end))
        if not found:
            return looked.value, None, None
        return looked.value, fields_end.value, section_end.value

class Chunk:
    """One chunk of a chunked body."""

    @classmethod
    def encode(cls, data):
        """One chunk, header and terminator included."""
        data = ffi.Library.encoded(data)
        return library.soyokaze_h1_chunk_encode(data, len(data)).take()

    @classmethod
    def parse_size(cls, data):
        """The chunk header, as ``(size, read)``, or ``None`` while incomplete."""
        data = ffi.Library.encoded(data)
        size, read, error = ctypes.c_size_t(), ctypes.c_size_t(), Error.out()
        status = library.soyokaze_h1_chunk_parse_size(data, len(data), ctypes.byref(size), ctypes.byref(read), ctypes.byref(error))
        if Status(status) == Status.CLOSED:
            return None
        Error.raise_for(status, error)
        return size.value, read.value

    @classmethod
    def decode(cls, data):
        """One whole chunk, as ``(read, start, end)``."""
        data = ffi.Library.encoded(data)
        start, end, read, error = ctypes.c_size_t(), ctypes.c_size_t(), ctypes.c_size_t(), Error.out()
        Error.raise_for(library.soyokaze_h1_chunk_decode(data, len(data), ctypes.byref(start), ctypes.byref(end), ctypes.byref(read), ctypes.byref(error)), error)
        return read.value, start.value, end.value

class BodyKind(enum.IntEnum):
    """How the length of a message body is determined."""

    NONE = 0
    CHUNKED = 1
    FIXED = 2
    CLOSE = 3

class BodyLength:
    """How a message's body is framed.

    ``kind`` says which way, and ``length`` is the octet count for
    :attr:`BodyKind.FIXED` and zero otherwise.
    """

    def __init__(self, kind, length=0):
        self.kind = BodyKind(kind)
        self.length = length

    @classmethod
    def of(cls, message, method=None):
        """How a message's body is framed.

        ``method`` is the method of the request a response answers, which some
        responses need in order to be framed at all: a response to ``HEAD`` has
        no body however it is labelled, and a successful response to
        ``CONNECT`` is followed by tunnelled octets rather than a body. Pass
        ``None`` for a request.
        """
        kind, length, error = ctypes.c_int32(), ctypes.c_uint64(), Error.out()
        Error.raise_for(
            library.soyokaze_h1_body_length(message.handle, -1 if method is None else int(Method(method)), ctypes.byref(kind), ctypes.byref(length), ctypes.byref(error)),
            error,
        )
        return cls(kind.value, length.value)

    @classmethod
    def content_length(cls, value):
        """A ``Content-Length`` field value as a number."""
        value = ffi.Library.encoded(value)
        out, error = ctypes.c_uint64(), Error.out()
        Error.raise_for(library.soyokaze_h1_content_length(value, len(value), ctypes.byref(out), ctypes.byref(error)), error)
        return out.value

    def __repr__(self):
        if self.kind == BodyKind.FIXED:
            return f"BodyLength(FIXED, {self.length})"
        return f"BodyLength({self.kind.name})"

class Number:
    """How numbers are written into an HTTP/1.x message."""

    @classmethod
    def decimal(cls, value):
        """A decimal number, as it is written into a ``Content-Length``."""
        return library.soyokaze_h1_decimal(value).take()

    @classmethod
    def hexadecimal(cls, value):
        """A hexadecimal number, as it is written into a chunk header."""
        return library.soyokaze_h1_hexadecimal(value).take()
