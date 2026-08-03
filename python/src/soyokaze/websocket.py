"""The WebSocket protocol, over all three versions of HTTP.

A :class:`WebSocketConnection` comes out of ``Client.websocket``,
``Connection.open_websocket``, or a server's ``on_websocket`` callback, and
is driven the same way whichever side produced it — the same symmetry the
crate's ``websocket`` module keeps.
"""

import ctypes
import enum

from . import ffi
from .errors import InvalidError, error_out, raise_for
from .ffi import library
from .models import Role

class Opcode(enum.IntEnum):
    """What a frame is, as its wire number."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

    def control(self):
        """Whether this is a control frame, which must be short and unfragmented."""
        return bool(self.value & 0x8)

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

class Frame:
    """One WebSocket frame, with its payload always unmasked."""

    def __init__(self, opcode, payload=b"", fin=True):
        self.opcode = Opcode(opcode)
        self.payload = payload
        self.fin = fin

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
        return ffi.take(library.soyokaze_websocket_id(self.handle))

    def send(self, frame):
        """Sends one frame. The mask is set from the role."""
        payload = ffi.encoded(frame.payload)
        error = error_out()
        raise_for(library.soyokaze_websocket_send(self.handle, frame.fin, int(frame.opcode), payload, len(payload), ctypes.byref(error)), error)

    def receive(self):
        """Receives one frame, without reassembling or answering anything."""
        fin = ctypes.c_bool()
        opcode = ctypes.c_uint8()
        out = ffi.Buffer()
        error = error_out()
        raise_for(library.soyokaze_websocket_receive(self.handle, ctypes.byref(fin), ctypes.byref(opcode), ctypes.byref(out), ctypes.byref(error)), error)
        return Frame(Opcode(opcode.value), ffi.take(out), fin.value)

    def send_message(self, opcode, payload):
        """Sends a whole message as one unfragmented frame.

        The mirror of :meth:`receive_message`, which hands back the same pair
        in the same order, so what one returns the other takes. An ``opcode``
        of ``None`` takes it from the payload: ``str`` goes as text and
        ``bytes`` as binary.
        """
        if opcode is None:
            opcode = Opcode.TEXT if isinstance(payload, str) else Opcode.BINARY

        payload = ffi.encoded(payload)
        error = error_out()
        raise_for(library.soyokaze_websocket_send_message(self.handle, int(Opcode(opcode)), payload, len(payload), ctypes.byref(error)), error)

    def receive_message(self):
        """Receives one whole message, reassembling fragments.

        A ping is answered with a pong along the way, and a close is echoed
        back and then returned as ``(Opcode.CLOSE, payload)`` so the caller
        knows the connection is finishing.
        """
        opcode = ctypes.c_uint8()
        out = ffi.Buffer()
        error = error_out()
        raise_for(library.soyokaze_websocket_receive_message(self.handle, ctypes.byref(opcode), ctypes.byref(out), ctypes.byref(error)), error)
        return Opcode(opcode.value), ffi.take(out)

    def close(self, code=CloseCode.NORMAL, reason=""):
        """Closes the connection, running the closing handshake."""
        encoded = ffi.encoded(reason)
        if not library.soyokaze_websocket_close(self.handle, int(CloseCode(code)), encoded, len(encoded)):
            raise InvalidError("the close was refused")
