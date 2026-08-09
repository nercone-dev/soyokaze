"""The error every fallible operation in the bindings reports.

:class:`Status` mirrors ``soyokaze_status_t``, and each failing status has an
exception class of its own, all under :class:`Error` — the same grading as the
crate's ``Error`` enum, plus the two statuses the boundary itself raises.
"""

import ctypes
import enum

from .ffi import library

class Status(enum.IntEnum):
    """What a call did, as the C ABI reports it."""

    OK = 0
    CLOSED = 1
    PROTOCOL = 2
    LIMIT = 3
    STREAM = 4
    TIMEOUT = 5
    TLS = 6
    VERSION = 7
    IO = 8
    INVALID = 9
    RUNTIME = 10

    def message(self):
        """A fixed description of the status."""
        return library.soyokaze_status_message(int(self)).text()

class Error(Exception):
    """A failure, with the status and message that go with it.

    ``stream_id`` and ``code`` are set on a :class:`StreamError`, which names
    the one stream that failed and the protocol error code it was reset with;
    on every other failure they are ``None``.
    """

    status = Status.INVALID

    def __init__(self, message=None, status=None, stream_id=None, code=None, reason=None):
        if status is not None:
            self.status = Status(status)
        self.stream_id = stream_id
        self.code = code
        self.reason = reason if reason is not None else message
        super().__init__(message if message is not None else self.status.message())

    @classmethod
    def tls(cls, reason):
        """A TLS failure, as the crate raises one."""
        return TLSError(reason)

    @classmethod
    def quic(cls, reason):
        """A failure from the QUIC layer, which reads as an I/O failure."""
        return IOError(reason)

    @classmethod
    def stream(cls, stream_id, code, reason):
        """A failure that takes one stream down and leaves the connection running."""
        return StreamError(reason, stream_id=stream_id, code=code)

    def on_stream(self, stream_id, code):
        """Narrows a connection-wide failure to one stream.

        A protocol or limit failure becomes a :class:`StreamError`, so the
        stream is reset instead of the connection; everything else comes back
        unchanged, because it is not something one stream can absorb.
        """
        if self.status not in (Status.PROTOCOL, Status.LIMIT):
            return self
        return StreamError(str(self), stream_id=stream_id, code=code)

    @classmethod
    def of(cls, status):
        """The class a failing status is reported as.

        Read off the subclasses themselves, so a status gains an exception of
        its own simply by something subclassing this and naming it.
        """
        for subclass in cls.__subclasses__():
            if subclass.status == status:
                return subclass
        return cls

    @classmethod
    def out(cls):
        """A fresh ``error`` out parameter, to pass by reference."""
        return ctypes.c_void_p()

    @classmethod
    def raise_for(cls, status, error):
        """Raises what a failing call reported, or returns on success.

        ``error`` is the ``ctypes.c_void_p`` an ``error`` out parameter was
        written through; the handle is read and freed here.
        """
        status = Status(status)

        if status == Status.OK:
            return

        message, reason, stream_id, code = None, None, None, None
        if error and error.value:
            message = library.soyokaze_error_message(error).text()
            reason = library.soyokaze_error_reason(error).text()
            stream_id = library.soyokaze_error_stream_id(error)
            code = library.soyokaze_error_code(error)
            library.soyokaze_error_free(error)

        raise cls.of(status)(
            message,
            status,
            None if stream_id is None or stream_id < 0 else stream_id,
            None if code is None or code < 0 else code,
            reason,
        )

class ClosedError(Error):
    """The peer closed the connection, or it was closed under us."""

    status = Status.CLOSED

class ProtocolError(Error):
    """The peer broke the protocol."""

    status = Status.PROTOCOL

class LimitError(Error):
    """The peer went past one of the ceilings in the limits."""

    status = Status.LIMIT

class StreamError(Error):
    """One stream failed; the connection itself stays usable."""

    status = Status.STREAM

class TimeoutError(Error):
    """An operation ran past its deadline."""

    status = Status.TIMEOUT

class TLSError(Error):
    """The TLS handshake failed, or a TLS object could not be built."""

    status = Status.TLS

class VersionError(Error):
    """No usable HTTP version could be agreed on."""

    status = Status.VERSION

class IOError(Error):
    """The transport underneath failed."""

    status = Status.IO

class InvalidError(Error):
    """An argument was refused by the boundary itself."""

    status = Status.INVALID

class RuntimeError(Error):
    """The runtime could not be built, or the call was made without one."""

    status = Status.RUNTIME
