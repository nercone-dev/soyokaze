"""The WebSocket protocol, over all three versions of HTTP.

A :class:`WebSocketConnection` comes out of ``Client.websocket``,
``Connection.open_websocket``, or a server's ``on_websocket`` callback, and
is driven the same way whichever side produced it — the same symmetry the
crate's ``websocket`` module keeps.
"""

import ctypes
import enum

from . import ffi
from .errors import Error, InvalidError, Status, TLSError
from .ffi import library
from .models import Limits, Message, Role, Version

GUID = library.soyokaze_websocket_guid().text()
"""The fixed string a ``Sec-WebSocket-Accept`` is derived with."""

VERSION = library.soyokaze_websocket_version().text()
"""The one protocol version this library speaks."""

PROTOCOL = library.soyokaze_websocket_protocol().text()
"""The token an upgrade names the protocol by."""

MAXIMUM_CONTROL_PAYLOAD = library.soyokaze_websocket_maximum_control_payload()
"""How large a control frame's payload may be."""

class Opcode(enum.IntEnum):
    """What a frame is, as its wire number."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

    def code(self):
        """The wire number of this opcode."""
        return int(self)

    @classmethod
    def from_code(cls, code):
        """The opcode a wire number names, or ``None``."""
        return cls(code) if library.soyokaze_websocket_opcode_known(code) else None

    def control(self):
        """Whether this is a control frame, which must be short and unfragmented."""
        return library.soyokaze_websocket_opcode_control(int(self))

class CloseCode(enum.IntEnum):
    """Why a connection is being closed, as its wire number."""

    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011

    def code(self):
        """The wire number of this close code."""
        return int(self)

    @classmethod
    def from_code(cls, code):
        """The close code a wire number names, or ``None``."""
        return cls(code) if library.soyokaze_websocket_close_code_known(code) else None

    @classmethod
    def permitted(cls, code):
        """Whether a close code may be sent on the wire.

        The codes reserved for local use are refused, as are codes outside the
        ranges the protocol sets aside.
        """
        return library.soyokaze_websocket_close_code_permitted(code)

class FrameHead:
    """The head of a frame, as it sits on the wire."""

    def __init__(self, fin, opcode, mask, start, length):
        self.fin = fin
        self.opcode = Opcode(opcode)
        self.mask = mask
        self.start = start
        self.length = length

    @classmethod
    def taken(cls, struct):
        """The :class:`FrameHead` a ``soyokaze_websocket_frame_head_t`` stands for."""
        return cls(struct.fin, struct.opcode, bytes(struct.mask) if struct.masked else None, struct.start, struct.length)

    @classmethod
    def decode(cls, data):
        """Reads the head of a frame, or ``None`` when more octets are needed."""
        data = ffi.Library.encoded(data)
        out, error = ffi.WebSocketFrameHead(), Error.out()
        status = library.soyokaze_websocket_frame_head(data, len(data), ctypes.byref(out), ctypes.byref(error))
        if Status(status) == Status.CLOSED:
            return None
        Error.raise_for(status, error)
        return cls.taken(out)

    def __repr__(self):
        return f"FrameHead({self.opcode.name}, {self.length} octets{'' if self.fin else ', continued'})"

class Frame:
    """One WebSocket frame, with its payload always unmasked.

    Masking is applied on the way out and undone on the way in, so nothing
    above the framing layer sees it.
    """

    def __init__(self, opcode, payload=b"", fin=True, mask=None):
        self.opcode = Opcode(opcode)
        self.payload = payload
        self.fin = fin
        self.mask = mask

    @classmethod
    def random(cls, count):
        """``count`` cryptographically secure random octets."""
        out = (ctypes.c_uint8 * count)()
        if not library.soyokaze_websocket_random(out, count):
            raise TLSError("no source of randomness is reachable")
        return bytes(out)

    @classmethod
    def masking_key(cls):
        """A fresh masking key: four unpredictable octets.

        It has to be unpredictable: masking exists so that a client cannot be
        tricked into putting attacker-chosen octets on the wire verbatim,
        which a guessable key would undo.
        """
        key = library.soyokaze_websocket_masking_key().taken()
        if key is None:
            raise TLSError("no source of randomness is reachable")
        return key

    @classmethod
    def apply_mask(cls, mask, payload):
        """Applies a masking key, which also removes one."""
        payload = (ctypes.c_uint8 * len(payload)).from_buffer_copy(ffi.Library.encoded(payload))
        library.soyokaze_websocket_apply_mask(ffi.Library.encoded(mask), payload, len(payload))
        return bytes(payload)

    @classmethod
    def decode(cls, data):
        """Reads one frame, or ``None`` when more octets are needed.

        Returns ``(read, frame)``.
        """
        data = ffi.Library.encoded(data)
        head, payload, read, error = ffi.WebSocketFrameHead(), ffi.Buffer(), ctypes.c_size_t(), Error.out()
        status = library.soyokaze_websocket_frame_decode(data, len(data), ctypes.byref(head), ctypes.byref(payload), ctypes.byref(read), ctypes.byref(error))
        if Status(status) == Status.CLOSED:
            return None
        Error.raise_for(status, error)
        return read.value, cls(head.opcode, payload.take(), head.fin, bytes(head.mask) if head.masked else None)

    def encode(self):
        """The frame as it sits on the wire."""
        payload = ffi.Library.encoded(self.payload)
        mask = None if self.mask is None else ffi.Library.encoded(self.mask)
        return library.soyokaze_websocket_frame_encode(self.fin, int(self.opcode), mask, payload, len(payload)).take()

    def __repr__(self):
        return f"Frame({self.opcode.name}, {len(self.payload)} octets{'' if self.fin else ', continued'})"

class WebSocketConnection:
    """A WebSocket connection.

    Work in messages with :meth:`receive_message`, which reassembles
    fragments and answers pings on its own, or in frames with
    :meth:`receive` where that control is wanted.
    """

    def __init__(self, handle):
        """Wraps a native socket handle, taking ownership of it."""
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_websocket_free(self.handle)
            self.handle = None

    @property
    def role(self):
        """Which end of the connection this is, which decides masking."""
        return Role(library.soyokaze_websocket_role(self.handle))

    def closing(self):
        """Whether the closing handshake has begun."""
        return library.soyokaze_websocket_closing(self.handle)

    def id(self):
        """The identifier of the connection this came from."""
        return library.soyokaze_websocket_id(self.handle).take()

    def send(self, frame):
        """Sends one frame. The mask is set from the role."""
        payload = ffi.Library.encoded(frame.payload)
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_send(self.handle, frame.fin, int(frame.opcode), payload, len(payload), ctypes.byref(error)), error)

    def receive(self):
        """Receives one frame, without reassembling or answering anything."""
        fin = ctypes.c_bool()
        opcode = ctypes.c_uint8()
        out = ffi.Buffer()
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_receive(self.handle, ctypes.byref(fin), ctypes.byref(opcode), ctypes.byref(out), ctypes.byref(error)), error)
        return Frame(Opcode(opcode.value), out.take(), fin.value)

    def send_message(self, opcode, payload):
        """Sends a whole message as one unfragmented frame.

        The mirror of :meth:`receive_message`, which hands back the same pair
        in the same order, so what one returns the other takes. An ``opcode``
        of ``None`` takes it from the payload: ``str`` goes as text and
        ``bytes`` as binary.
        """
        if opcode is None:
            opcode = Opcode.TEXT if isinstance(payload, str) else Opcode.BINARY

        payload = ffi.Library.encoded(payload)
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_send_message(self.handle, int(Opcode(opcode)), payload, len(payload), ctypes.byref(error)), error)

    def receive_message(self):
        """Receives one whole message, reassembling fragments.

        A ping is answered with a pong along the way, and a close is echoed
        back and then returned as ``(Opcode.CLOSE, payload)`` so the caller
        knows the connection is finishing.
        """
        opcode = ctypes.c_uint8()
        out = ffi.Buffer()
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_receive_message(self.handle, ctypes.byref(opcode), ctypes.byref(out), ctypes.byref(error)), error)
        return Opcode(opcode.value), out.take()

    def limits(self):
        """The limits this connection is running under."""
        return WebSocketLimits.taken(library.soyokaze_websocket_limits(self.handle))

    def close(self, code=CloseCode.NORMAL, reason=""):
        """Closes the connection, running the closing handshake."""
        encoded = ffi.Library.encoded(reason)
        if not library.soyokaze_websocket_close(self.handle, int(CloseCode(code)), encoded, len(encoded)):
            raise InvalidError("the close was refused")

class Upgrade:
    """The HTTP/1.1 ``Upgrade`` handshake.

    The client offers a nonce and the server answers with the accept key
    derived from it, which is what shows the peer read the request rather than
    having stumbled onto the port.
    """

    @classmethod
    def accept_key(cls, key):
        """The ``Sec-WebSocket-Accept`` value for a client's ``Sec-WebSocket-Key``.

        This is not a security mechanism — it only shows the peer read the
        request and is speaking WebSocket rather than something that stumbled
        onto the port.
        """
        key = ffi.Library.encoded(key)
        return library.soyokaze_websocket_accept_key(key, len(key)).take().decode()

    @classmethod
    def nonce(cls):
        """A fresh ``Sec-WebSocket-Key``: sixteen random octets, base64 encoded."""
        nonce = library.soyokaze_websocket_nonce().taken()
        if nonce is None:
            raise TLSError("no source of randomness is reachable")
        return nonce.decode()

    @classmethod
    def request(cls, host, target, key, version=Version.V1_1):
        """The upgrade request that opens a WebSocket."""
        host, target, key = ffi.Library.encoded(host), ffi.Library.encoded(target), ffi.Library.encoded(key)
        handle = library.soyokaze_websocket_upgrade_request(host, len(host), target, len(target), key, len(key), int(version))
        if not handle:
            raise InvalidError("the request was refused")
        return Message(handle=handle)

    @classmethod
    def response(cls, key, version=Version.V1_1):
        """The ``101 Switching Protocols`` that accepts an upgrade."""
        key = ffi.Library.encoded(key)
        handle = library.soyokaze_websocket_upgrade_response(key, len(key), int(version))
        if not handle:
            raise InvalidError("the key was refused")
        return Message(handle=handle)

    @classmethod
    def verify_request(cls, request):
        """Checks an upgrade request, handing back the key it carried."""
        key, error = ffi.Buffer(), Error.out()
        Error.raise_for(library.soyokaze_websocket_verify_upgrade_request(request.handle, ctypes.byref(key), ctypes.byref(error)), error)
        return key.take().decode()

    @classmethod
    def verify_response(cls, response, key):
        """Checks the response to an upgrade request against the key that was sent."""
        key, error = ffi.Library.encoded(key), Error.out()
        Error.raise_for(library.soyokaze_websocket_verify_upgrade_response(response.handle, key, len(key), ctypes.byref(error)), error)

class Connect:
    """The extended CONNECT handshake, which HTTP/2 and HTTP/3 use instead.

    There is no nonce and no accept key: the stream itself is the tunnel, so
    nothing has to prove the peer read the request.
    """

    @classmethod
    def request(cls, authority, target, version=Version.V2_0):
        """The extended CONNECT request that opens a WebSocket."""
        authority, target = ffi.Library.encoded(authority), ffi.Library.encoded(target)
        handle = library.soyokaze_websocket_connect_request(authority, len(authority), target, len(target), int(version))
        if not handle:
            raise InvalidError("the request was refused")
        return Message(handle=handle)

    @classmethod
    def response(cls, version=Version.V2_0):
        """The ``200 OK`` that accepts an extended CONNECT."""
        return Message(handle=library.soyokaze_websocket_connect_response(int(version)))

    @classmethod
    def verify_request(cls, request):
        """Checks an extended CONNECT request."""
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_verify_connect_request(request.handle, ctypes.byref(error)), error)

    @classmethod
    def verify_response(cls, response):
        """Checks the response to an extended CONNECT."""
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_verify_connect_response(response.handle, ctypes.byref(error)), error)

class Handshake:
    """Whichever shape the handshake takes, read as one thing.

    A server asks :meth:`requested` whether a request is opening a WebSocket
    at all, and :meth:`verify` whether it is one that may be accepted.
    """

    @classmethod
    def requested(cls, request):
        """Whether a request is asking to open a WebSocket at all."""
        return library.soyokaze_websocket_requested(request.handle)

    @classmethod
    def verify(cls, request):
        """Checks a handshake request, whichever shape it takes."""
        error = Error.out()
        Error.raise_for(library.soyokaze_websocket_verify(request.handle, ctypes.byref(error)), error)

    @classmethod
    def refusal(cls, request, version=None):
        """The response that turns a handshake away."""
        version = request.version if version is None else version
        return Message(handle=library.soyokaze_websocket_refusal(request.handle, int(version)))

    @classmethod
    def token_present(cls, headers, name, token):
        """Whether a comma-separated field carries a token, matched case-insensitively."""
        name, token = ffi.Library.encoded(name), ffi.Library.encoded(token)
        return library.soyokaze_websocket_token_present(headers.handle, name, len(name), token, len(token))

class WebSocketLimits:
    """What one WebSocket connection may spend on the peer's behalf.

    Derived from a :class:`Limits <soyokaze.models.Limits>` when a connection
    is built, so a caller sets these through that rather than here.
    """

    FIELDS = [name for name, kind in ffi.WebSocketLimits._fields_]

    def __init__(self, **ceilings):
        defaults = library.soyokaze_websocket_limits_default()

        for name in self.FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in self.FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    @classmethod
    def taken(cls, struct):
        """The :class:`WebSocketLimits` a ``soyokaze_websocket_limits_t`` stands for."""
        return cls(**{name: getattr(struct, name) for name in cls.FIELDS})

    @classmethod
    def of(cls, limits):
        """The limits a :class:`Limits <soyokaze.models.Limits>` narrows a connection to."""
        struct = Limits.argument(limits)
        return cls.taken(library.soyokaze_websocket_limits_of(Limits.pointer(struct)))

    def __repr__(self):
        return f"WebSocketLimits(max_message_size={self.max_message_size})"
