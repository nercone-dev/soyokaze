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

    def __init__(self, message=None, status=None, stream_id=None, code=None):
        if status is not None:
            self.status = Status(status)
        self.stream_id = stream_id
        self.code = code
        super().__init__(message if message is not None else self.status.message())

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

class TlsError(Error):
    """The TLS handshake failed, or a TLS object could not be built."""

    status = Status.TLS

class VersionError(Error):
    """No usable HTTP version could be agreed on."""

    status = Status.VERSION

class IoError(Error):
    """The transport underneath failed."""

    status = Status.IO

class InvalidError(Error):
    """An argument was refused by the boundary itself."""

    status = Status.INVALID

class RuntimeError(Error):
    """The runtime could not be built, or the call was made without one."""

    status = Status.RUNTIME

CLASSES = {
    Status.CLOSED: ClosedError,
    Status.PROTOCOL: ProtocolError,
    Status.LIMIT: LimitError,
    Status.STREAM: StreamError,
    Status.TIMEOUT: TimeoutError,
    Status.TLS: TlsError,
    Status.VERSION: VersionError,
    Status.IO: IoError,
    Status.INVALID: InvalidError,
    Status.RUNTIME: RuntimeError,
}

def raise_for(status, error):
    """Raises the exception a failing call reported, or returns on success.

    ``error`` is the ``ctypes.c_void_p`` an ``error`` out parameter was
    written through; the handle is read and freed here.
    """
    status = Status(status)

    if status == Status.OK:
        return

    message, stream_id, code = None, None, None
    if error and error.value:
        message = library.soyokaze_error_message(error).text()
        stream_id = library.soyokaze_error_stream_id(error)
        code = library.soyokaze_error_code(error)
        library.soyokaze_error_free(error)

    raise CLASSES[status](message, status, None if stream_id is None or stream_id < 0 else stream_id, None if code is None or code < 0 else code)

def error_out():
    """A fresh ``error`` out parameter, to pass by reference."""
    return ctypes.c_void_p()
