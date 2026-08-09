"""HTTP/2.

The wire format on its own: the connection :data:`PREFACE`, the
:class:`FrameHeader`, every :class:`Frame`, and the :class:`Settings` both ends
exchange. A frame is built by the constructor that names it and read back
through the accessors, since each kind carries different fields.
"""

import ctypes
import enum

from .. import ffi
from ..errors import Error, Status
from ..ffi import library
from ..models import Limits

PREFACE = library.soyokaze_h2_preface().bytes()
"""The octets an HTTP/2 connection opens with."""

class H2Limits:
    """What one HTTP/2 connection may spend on the peer's behalf."""

    FIELDS = [name for name, kind in ffi.H2Limits._fields_]

    def __init__(self, **ceilings):
        defaults = library.soyokaze_h2_limits_default()

        for name in self.FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in self.FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    @classmethod
    def taken(cls, struct):
        """The :class:`H2Limits` a ``soyokaze_h2_limits_t`` stands for."""
        return cls(**{name: getattr(struct, name) for name in cls.FIELDS})

    @classmethod
    def of(cls, limits):
        """The limits a :class:`Limits <soyokaze.models.Limits>` narrows a connection to."""
        struct = Limits.argument(limits)
        return cls.taken(library.soyokaze_h2_limits_of(Limits.pointer(struct)))

    def __repr__(self):
        return f"H2Limits(max_concurrent_streams={self.max_concurrent_streams})"

class Code(enum.IntEnum):
    """The HTTP/2 error codes, as they travel in ``RST_STREAM`` and ``GOAWAY``."""

    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xA
    ENHANCE_YOUR_CALM = 0xB
    INADEQUATE_SECURITY = 0xC
    HTTP_1_1_REQUIRED = 0xD

    def name_of(self):
        """A fixed name for the code."""
        return library.soyokaze_h2_error_code_name(int(self)).text()

class Flag:
    """The flags a frame header carries."""

    END_STREAM = library.soyokaze_h2_flag_end_stream()
    """The message ends with this frame."""

    ACK = library.soyokaze_h2_flag_ack()
    """This ``SETTINGS`` or ``PING`` answers the peer's rather than being one."""

    END_HEADERS = library.soyokaze_h2_flag_end_headers()
    """The field section is complete."""

    PADDED = library.soyokaze_h2_flag_padded()
    """A padding length leads the payload."""

    PRIORITY = library.soyokaze_h2_flag_priority()
    """Priority information leads the field block."""

class FrameType(enum.IntEnum):
    """Which frame this is, as the wire numbers them."""

    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9

    def code(self):
        """The wire number of this frame type."""
        return int(self)

    @classmethod
    def from_code(cls, code):
        """The frame type a wire number names, or ``None``."""
        return cls(code) if library.soyokaze_h2_frame_type_known(code) else None

    def streamed(self):
        """Whether the frame belongs on a stream.

        ``True`` for a frame that must name one, ``False`` for one that must
        not, and ``None`` for the two that may go either way.
        """
        answer = library.soyokaze_h2_frame_type_streamed(int(self))
        return None if answer < 0 else bool(answer)

class FrameHeader:
    """The head of a frame, as it sits on the wire."""

    SIZE = library.soyokaze_h2_header_size()
    """How many octets a frame header is."""

    def __init__(self, length, kind, flags, stream_id):
        self.length = length
        self.kind = FrameType(kind)
        self.flags = flags
        self.stream_id = stream_id

    def encode(self):
        """The header as it sits on the wire. Always :data:`SIZE` octets."""
        struct = ffi.H2FrameHeader(self.length, int(self.kind), self.flags, self.stream_id)
        return library.soyokaze_h2_header_encode(struct).take()

    @classmethod
    def decode(cls, data):
        """Reads a header, returning ``(length, header)``.

        The length is always there, even for a frame kind this library does not
        know, so a caller can skip past one it cannot read; ``header`` is
        ``None`` in that case.
        """
        data = ffi.Library.encoded(data)
        out, length = ffi.H2FrameHeader(), ctypes.c_uint32()
        known = library.soyokaze_h2_header_decode(data, len(data), ctypes.byref(out), ctypes.byref(length))
        if not known:
            return length.value, None
        return length.value, cls(out.length, out.kind, out.flags, out.stream_id)

    def __repr__(self):
        return f"FrameHeader({self.kind.name}, {self.length} octets, stream {self.stream_id})"

class Settings:
    """The connection parameters both ends exchange.

    ``max_concurrent_streams`` and ``max_header_list_size`` are ``None`` when
    the peer sets no ceiling.
    """

    HEADER_TABLE_SIZE = library.soyokaze_h2_setting_header_table_size()
    ENABLE_PUSH = library.soyokaze_h2_setting_enable_push()
    MAX_CONCURRENT_STREAMS = library.soyokaze_h2_setting_max_concurrent_streams()
    INITIAL_WINDOW_SIZE = library.soyokaze_h2_setting_initial_window_size()
    MAX_FRAME_SIZE = library.soyokaze_h2_setting_max_frame_size()
    MAX_HEADER_LIST_SIZE = library.soyokaze_h2_setting_max_header_list_size()
    ENABLE_CONNECT_PROTOCOL = library.soyokaze_h2_setting_enable_connect_protocol()

    DEFAULT_INITIAL_WINDOW_SIZE = library.soyokaze_h2_default_initial_window_size()
    DEFAULT_MAX_FRAME_SIZE = library.soyokaze_h2_default_max_frame_size()
    MAXIMUM_FRAME_SIZE = library.soyokaze_h2_maximum_frame_size()
    MAXIMUM_WINDOW_SIZE = library.soyokaze_h2_maximum_window_size()

    def __init__(self, header_table_size=None, enable_push=None, max_concurrent_streams=None, initial_window_size=None, max_frame_size=None, max_header_list_size=None, enable_connect_protocol=None):
        defaults = library.soyokaze_h2_settings_default()
        self.header_table_size = defaults.header_table_size if header_table_size is None else header_table_size
        self.enable_push = defaults.enable_push if enable_push is None else enable_push
        self.max_concurrent_streams = max_concurrent_streams
        self.initial_window_size = defaults.initial_window_size if initial_window_size is None else initial_window_size
        self.max_frame_size = defaults.max_frame_size if max_frame_size is None else max_frame_size
        self.max_header_list_size = max_header_list_size
        self.enable_connect_protocol = defaults.enable_connect_protocol if enable_connect_protocol is None else enable_connect_protocol

    @classmethod
    def taken(cls, struct):
        """The :class:`Settings` a ``soyokaze_h2_settings_t`` stands for."""
        return cls(
            struct.header_table_size,
            struct.enable_push,
            None if struct.max_concurrent_streams < 0 else struct.max_concurrent_streams,
            struct.initial_window_size,
            struct.max_frame_size,
            None if struct.max_header_list_size < 0 else struct.max_header_list_size,
            struct.enable_connect_protocol,
        )

    @classmethod
    def peer(cls):
        """The settings a peer is assumed to hold until it says otherwise."""
        return cls.taken(library.soyokaze_h2_settings_peer())

    def build(self):
        """The ``soyokaze_h2_settings_t`` this stands for."""
        return ffi.H2Settings(
            self.header_table_size,
            self.enable_push,
            -1 if self.max_concurrent_streams is None else self.max_concurrent_streams,
            self.initial_window_size,
            self.max_frame_size,
            -1 if self.max_header_list_size is None else self.max_header_list_size,
            self.enable_connect_protocol,
        )

    def parameters(self):
        """The identifier and value pairs these settings would be sent as."""
        struct = self.build()
        count = library.soyokaze_h2_settings_parameter_count(ctypes.byref(struct))
        pairs = []

        for index in range(count):
            parameter = library.soyokaze_h2_settings_parameter(ctypes.byref(struct), index)
            pairs.append((parameter.id, parameter.value))

        return pairs

    def apply(self, id, value):
        """Applies one parameter the peer sent.

        Returns how much every open stream's flow control window moves as a
        result; only ``SETTINGS_INITIAL_WINDOW_SIZE`` moves one. A parameter
        this library does not know is accepted and ignored, which is what the
        protocol asks for.
        """
        struct = self.build()
        delta, error = ctypes.c_int64(), Error.out()
        Error.raise_for(library.soyokaze_h2_settings_apply(ctypes.byref(struct), id, value, ctypes.byref(delta), ctypes.byref(error)), error)

        applied = self.taken(struct)
        for name in ("header_table_size", "enable_push", "max_concurrent_streams", "initial_window_size", "max_frame_size", "max_header_list_size", "enable_connect_protocol"):
            setattr(self, name, getattr(applied, name))

        return delta.value

    def __repr__(self):
        return f"Settings(max_frame_size={self.max_frame_size}, initial_window_size={self.initial_window_size})"

class Frame:
    """One HTTP/2 frame.

    Built by the constructor that names it — :meth:`Data`, :meth:`Headers` and
    the rest — and read back through the accessors.
    """

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_h2_frame_free(self.handle)
            self.handle = None

    @classmethod
    def Data(cls, stream_id, data=b"", end_stream=False):
        """Message body octets."""
        data = ffi.Library.encoded(data)
        return cls(library.soyokaze_h2_frame_data(stream_id, end_stream, data, len(data)))

    @classmethod
    def Headers(cls, stream_id, block=b"", end_stream=False, end_headers=True):
        """A compressed field section."""
        block = ffi.Library.encoded(block)
        return cls(library.soyokaze_h2_frame_headers(stream_id, end_stream, end_headers, block, len(block)))

    @classmethod
    def Priority(cls, stream_id, dependency=0, exclusive=False, weight=0):
        """A priority hint, which this implementation reads and ignores."""
        return cls(library.soyokaze_h2_frame_priority(stream_id, dependency, exclusive, weight))

    @classmethod
    def RstStream(cls, stream_id, error_code=Code.CANCEL):
        """Abandon one stream."""
        return cls(library.soyokaze_h2_frame_rst_stream(stream_id, int(error_code)))

    @classmethod
    def Settings(cls, params=(), ack=False):
        """Connection parameters, or their acknowledgement."""
        array = (ffi.H2Parameter * len(params))(*[ffi.H2Parameter(id, value) for id, value in params])
        return cls(library.soyokaze_h2_frame_settings(ack, array, len(params)))

    @classmethod
    def PushPromise(cls, stream_id, promised_stream_id, block=b""):
        """A promised stream. Refused here, since push is disabled."""
        block = ffi.Library.encoded(block)
        return cls(library.soyokaze_h2_frame_push_promise(stream_id, promised_stream_id, block, len(block)))

    @classmethod
    def Ping(cls, payload=b"\x00" * 8, ack=False):
        """A liveness probe, or its acknowledgement. Eight octets."""
        payload = ffi.Library.encoded(payload)
        return cls(library.soyokaze_h2_frame_ping(ack, payload))

    @classmethod
    def GoAway(cls, last_stream_id, error_code=Code.NO_ERROR, debug_data=b""):
        """No further streams will be accepted."""
        debug_data = ffi.Library.encoded(debug_data)
        return cls(library.soyokaze_h2_frame_goaway(last_stream_id, int(error_code), debug_data, len(debug_data)))

    @classmethod
    def WindowUpdate(cls, stream_id, increment):
        """More flow control credit."""
        return cls(library.soyokaze_h2_frame_window_update(stream_id, increment))

    @classmethod
    def Continuation(cls, stream_id, block=b"", end_headers=True):
        """More of the field section a ``HEADERS`` frame began."""
        block = ffi.Library.encoded(block)
        return cls(library.soyokaze_h2_frame_continuation(stream_id, end_headers, block, len(block)))

    @classmethod
    def parse(cls, data, max_frame_size=None):
        """Reads one frame, returning ``(read, frame)``.

        ``frame`` is ``None`` when more octets are needed; a non-zero ``read``
        alongside it means a frame kind this library does not know was skipped.
        """
        data = ffi.Library.encoded(data)
        max_frame_size = Settings.DEFAULT_MAX_FRAME_SIZE if max_frame_size is None else max_frame_size
        out, read, error = ctypes.c_void_p(), ctypes.c_size_t(), Error.out()
        status = library.soyokaze_h2_frame_decode(data, len(data), max_frame_size, ctypes.byref(out), ctypes.byref(read), ctypes.byref(error))
        if Status(status) == Status.CLOSED:
            return read.value, None
        Error.raise_for(status, error)
        return read.value, cls(out)

    def kind(self):
        """Which frame this is."""
        return FrameType(library.soyokaze_h2_frame_kind(self.handle))

    def stream_id(self):
        """The stream the frame names, or zero for the connection as a whole."""
        return library.soyokaze_h2_frame_stream_id(self.handle)

    def flags(self):
        """The flags the frame carries."""
        return library.soyokaze_h2_frame_flags(self.handle)

    def bytes(self):
        """The octets the frame carries, or ``None`` when it carries none."""
        return library.soyokaze_h2_frame_bytes(self.handle).bytes()

    def error_code(self):
        """The error code a ``RST_STREAM`` or ``GOAWAY`` carries, or ``None``."""
        code = library.soyokaze_h2_frame_error_code(self.handle)
        return None if code < 0 else code

    def other_stream_id(self):
        """The second stream a ``GOAWAY``, ``PUSH_PROMISE`` or ``PRIORITY`` names."""
        stream_id = library.soyokaze_h2_frame_other_stream_id(self.handle)
        return None if stream_id < 0 else stream_id

    def increment(self):
        """The credit a ``WINDOW_UPDATE`` adds, or ``None``."""
        increment = library.soyokaze_h2_frame_increment(self.handle)
        return None if increment < 0 else increment

    def weight(self):
        """The weight a ``PRIORITY`` carries, or ``None``."""
        weight = library.soyokaze_h2_frame_weight(self.handle)
        return None if weight < 0 else weight

    def exclusive(self):
        """Whether a ``PRIORITY`` calls its dependency exclusive."""
        return library.soyokaze_h2_frame_exclusive(self.handle)

    def parameters(self):
        """The identifier and value pairs a ``SETTINGS`` frame carries."""
        count = library.soyokaze_h2_frame_parameter_count(self.handle)
        pairs = []

        for index in range(count):
            parameter = library.soyokaze_h2_frame_parameter(self.handle, index)
            pairs.append((parameter.id, parameter.value))

        return pairs

    def encode(self):
        """The frame as it sits on the wire, header and payload."""
        return library.soyokaze_h2_frame_encode(self.handle).take()

    def payload(self):
        """The frame's payload alone."""
        return library.soyokaze_h2_frame_payload(self.handle).take()

    def __repr__(self):
        return f"Frame({self.kind().name}, stream {self.stream_id()})"
