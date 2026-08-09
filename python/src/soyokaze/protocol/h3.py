"""HTTP/3.

The wire format on its own: every :class:`Frame`, the :class:`StreamKind` a
unidirectional stream announces itself as, and the :class:`Settings` both ends
exchange. A frame is built and read exactly as an HTTP/2 one is — the two
versions are kept interchangeable here on purpose.
"""

import ctypes
import enum

from .. import ffi
from ..errors import Error, Status
from ..ffi import library
from ..models import Limits

class H3Limits:
    """What one HTTP/3 connection may spend on the peer's behalf."""

    FIELDS = [name for name, kind in ffi.H3Limits._fields_]

    def __init__(self, **ceilings):
        defaults = library.soyokaze_h3_limits_default()

        for name in self.FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in self.FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    @classmethod
    def taken(cls, struct):
        """The :class:`H3Limits` a ``soyokaze_h3_limits_t`` stands for."""
        return cls(**{name: getattr(struct, name) for name in cls.FIELDS})

    @classmethod
    def of(cls, limits):
        """The limits a :class:`Limits <soyokaze.models.Limits>` narrows a connection to."""
        struct = Limits.argument(limits)
        return cls.taken(library.soyokaze_h3_limits_of(Limits.pointer(struct)))

    def __repr__(self):
        return f"H3Limits(max_concurrent_streams={self.max_concurrent_streams})"

class Code(enum.IntEnum):
    """The HTTP/3 and QPACK error codes, as they close a stream or a connection."""

    NO_ERROR = 0x0100
    GENERAL_PROTOCOL_ERROR = 0x0101
    INTERNAL_ERROR = 0x0102
    STREAM_CREATION_ERROR = 0x0103
    CLOSED_CRITICAL_STREAM = 0x0104
    FRAME_UNEXPECTED = 0x0105
    FRAME_ERROR = 0x0106
    EXCESSIVE_LOAD = 0x0107
    ID_ERROR = 0x0108
    SETTINGS_ERROR = 0x0109
    MISSING_SETTINGS = 0x010A
    REQUEST_REJECTED = 0x010B
    REQUEST_CANCELLED = 0x010C
    REQUEST_INCOMPLETE = 0x010D
    MESSAGE_ERROR = 0x010E
    CONNECT_ERROR = 0x010F
    VERSION_FALLBACK = 0x0110
    QPACK_DECOMPRESSION_FAILED = 0x0200
    QPACK_ENCODER_STREAM_ERROR = 0x0201
    QPACK_DECODER_STREAM_ERROR = 0x0202

    def name_of(self):
        """A fixed name for the code."""
        return library.soyokaze_h3_error_code_name(int(self)).text()

class StreamKind(enum.IntEnum):
    """What a unidirectional stream announces itself as.

    A request stream is bidirectional and announces nothing, so it has no wire
    number of its own.
    """

    CONTROL = 0x00
    PUSH = 0x01
    QPACK_ENCODER = 0x02
    QPACK_DECODER = 0x03
    REQUEST = 0x04

    def code(self):
        """The code the stream announces itself with, or ``None``."""
        code = library.soyokaze_h3_stream_kind_code(int(self))
        return None if code < 0 else code

    @classmethod
    def from_code(cls, code):
        """The stream kind a code names, or ``None``."""
        kind = library.soyokaze_h3_stream_kind_from_code(code)
        return None if kind < 0 else cls(kind)

class FrameType(enum.IntEnum):
    """Which frame this is, as the wire numbers them."""

    DATA = 0x00
    HEADERS = 0x01
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0D

    def code(self):
        """The wire number of this frame type."""
        return int(self)

    @classmethod
    def from_code(cls, code):
        """The frame type a wire number names, or ``None``."""
        return cls(code) if library.soyokaze_h3_frame_type_known(code) else None

FrameType.RESERVED = tuple(
    library.soyokaze_h3_reserved_frame(index)
    for index in range(library.soyokaze_h3_reserved_frame_count())
)
"""The frame types reserved to catch a peer that is speaking HTTP/2."""

class Settings:
    """The parameters one end of a connection has announced.

    ``max_field_section_size`` is ``None`` when the peer sets no ceiling.
    """

    QPACK_MAX_TABLE_CAPACITY = library.soyokaze_h3_setting_qpack_max_table_capacity()
    MAX_FIELD_SECTION_SIZE = library.soyokaze_h3_setting_max_field_section_size()
    QPACK_BLOCKED_STREAMS = library.soyokaze_h3_setting_qpack_blocked_streams()
    ENABLE_CONNECT_PROTOCOL = library.soyokaze_h3_setting_enable_connect_protocol()

    RESERVED = tuple(
        library.soyokaze_h3_reserved_setting(index)
        for index in range(library.soyokaze_h3_reserved_setting_count())
    )
    """The settings identifiers reserved to catch a peer that is speaking HTTP/2."""

    def __init__(self, qpack_max_table_capacity=None, qpack_blocked_streams=None, max_field_section_size=None, enable_connect_protocol=None):
        defaults = library.soyokaze_h3_settings_default()
        self.qpack_max_table_capacity = defaults.qpack_max_table_capacity if qpack_max_table_capacity is None else qpack_max_table_capacity
        self.qpack_blocked_streams = defaults.qpack_blocked_streams if qpack_blocked_streams is None else qpack_blocked_streams
        self.max_field_section_size = max_field_section_size
        self.enable_connect_protocol = defaults.enable_connect_protocol if enable_connect_protocol is None else enable_connect_protocol

    @classmethod
    def taken(cls, struct):
        """The :class:`Settings` a ``soyokaze_h3_settings_t`` stands for."""
        return cls(
            struct.qpack_max_table_capacity,
            struct.qpack_blocked_streams,
            None if struct.max_field_section_size < 0 else struct.max_field_section_size,
            struct.enable_connect_protocol,
        )

    @classmethod
    def peer(cls):
        """The settings a peer is assumed to hold until it says otherwise."""
        return cls.taken(library.soyokaze_h3_settings_peer())

    def build(self):
        """The ``soyokaze_h3_settings_t`` this stands for."""
        return ffi.H3Settings(
            self.qpack_max_table_capacity,
            self.qpack_blocked_streams,
            -1 if self.max_field_section_size is None else self.max_field_section_size,
            self.enable_connect_protocol,
        )

    def parameters(self):
        """The identifier and value pairs these settings would be sent as."""
        struct = self.build()
        count = library.soyokaze_h3_settings_parameter_count(ctypes.byref(struct))
        pairs = []

        for index in range(count):
            parameter = library.soyokaze_h3_settings_parameter(ctypes.byref(struct), index)
            pairs.append((parameter.id, parameter.value))

        return pairs

    def apply(self, id, value):
        """Applies one parameter the peer sent.

        A parameter this library does not know is accepted and ignored, which
        is what the protocol asks for; a reserved one ends the connection,
        since it means the peer is speaking HTTP/2.
        """
        struct = self.build()
        error = Error.out()
        Error.raise_for(library.soyokaze_h3_settings_apply(ctypes.byref(struct), id, value, ctypes.byref(error)), error)

        applied = self.taken(struct)
        for name in ("qpack_max_table_capacity", "qpack_blocked_streams", "max_field_section_size", "enable_connect_protocol"):
            setattr(self, name, getattr(applied, name))

    def __repr__(self):
        return f"Settings(qpack_max_table_capacity={self.qpack_max_table_capacity})"

class Frame:
    """One HTTP/3 frame.

    Built by the constructor that names it and read back through the
    accessors, exactly as an HTTP/2 frame is.
    """

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_h3_frame_free(self.handle)
            self.handle = None

    @classmethod
    def Data(cls, data=b""):
        """Message body octets."""
        data = ffi.Library.encoded(data)
        return cls(library.soyokaze_h3_frame_data(data, len(data)))

    @classmethod
    def Headers(cls, block=b""):
        """A QPACK-compressed field section."""
        block = ffi.Library.encoded(block)
        return cls(library.soyokaze_h3_frame_headers(block, len(block)))

    @classmethod
    def CancelPush(cls, push_id):
        """A promised push is no longer wanted."""
        return cls(library.soyokaze_h3_frame_cancel_push(push_id))

    @classmethod
    def Settings(cls, params=()):
        """Connection parameters, as identifier and value pairs."""
        array = (ffi.H3Parameter * len(params))(*[ffi.H3Parameter(id, value) for id, value in params])
        return cls(library.soyokaze_h3_frame_settings(array, len(params)))

    @classmethod
    def PushPromise(cls, push_id, block=b""):
        """A promised stream. Refused here, since push is disabled."""
        block = ffi.Library.encoded(block)
        return cls(library.soyokaze_h3_frame_push_promise(push_id, block, len(block)))

    @classmethod
    def GoAway(cls, id):
        """No further requests will be accepted."""
        return cls(library.soyokaze_h3_frame_goaway(id))

    @classmethod
    def MaxPushID(cls, push_id):
        """How far push identifiers may go."""
        return cls(library.soyokaze_h3_frame_max_push_id(push_id))

    @classmethod
    def parse(cls, data):
        """Reads one frame, returning ``(read, frame)``.

        ``frame`` is ``None`` when more octets are needed; a non-zero ``read``
        alongside it means a frame type this library does not know was skipped.
        """
        data = ffi.Library.encoded(data)
        out, read, error = ctypes.c_void_p(), ctypes.c_size_t(), Error.out()
        status = library.soyokaze_h3_frame_decode(data, len(data), ctypes.byref(out), ctypes.byref(read), ctypes.byref(error))
        if Status(status) == Status.CLOSED:
            return read.value, None
        Error.raise_for(status, error)
        return read.value, cls(out)

    def kind(self):
        """Which frame this is."""
        return FrameType(library.soyokaze_h3_frame_kind(self.handle))

    def bytes(self):
        """The octets the frame carries, or ``None`` when it carries none."""
        return library.soyokaze_h3_frame_bytes(self.handle).bytes()

    def id(self):
        """The identifier the frame carries, or ``None``."""
        id = library.soyokaze_h3_frame_id(self.handle)
        return None if id < 0 else id

    def parameters(self):
        """The identifier and value pairs a ``SETTINGS`` frame carries."""
        count = library.soyokaze_h3_frame_parameter_count(self.handle)
        pairs = []

        for index in range(count):
            parameter = library.soyokaze_h3_frame_parameter(self.handle, index)
            pairs.append((parameter.id, parameter.value))

        return pairs

    def payload_len(self):
        """How long the frame's payload is."""
        return library.soyokaze_h3_frame_payload_len(self.handle)

    def encode(self):
        """The frame as it sits on the wire, type and length included."""
        return library.soyokaze_h3_frame_encode(self.handle).take()

    def payload(self):
        """The frame's payload alone."""
        return library.soyokaze_h3_frame_payload(self.handle).take()

    def __repr__(self):
        return f"Frame({self.kind().name})"
