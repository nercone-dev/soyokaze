"""What every HTTP version shares.

:class:`Buffer` is the read buffer a connection fills from its transport, and
:class:`Fields` is the pseudo-field vocabulary HTTP/2 and HTTP/3 turn a message
into and back. The read buffer is here because a caller resuming a connection
by hand has to hand back whatever was read past the end of the last message.
"""

import ctypes

from .. import ffi
from ..errors import Error
from ..ffi import library
from ..helpers.fields import Fields as FieldSection
from ..models import Message, Version

class Buffer:
    """The read buffer a connection fills from its transport."""

    DEFAULT_CHUNK_SIZE = library.soyokaze_read_buffer_default_chunk_size()
    """How many octets one read asks the transport for unless told otherwise."""

    CHUNK_RAMP = library.soyokaze_read_buffer_chunk_ramp()
    """How many times the chunk size may double as a body keeps arriving."""

    @classmethod
    def oversized(cls, capacity, len, idle_capacity):
        """Whether a buffer of this shape is worth shrinking back."""
        return library.soyokaze_read_buffer_oversized(capacity, len, idle_capacity)

    @classmethod
    def with_chunk_size(cls, chunk_size):
        """An empty buffer that asks the transport for ``chunk_size`` octets."""
        return cls(handle=library.soyokaze_read_buffer_with_chunk_size(chunk_size))

    def __init__(self, handle=None):
        """An empty buffer, or a wrapper around an existing handle."""
        self.handle = handle if handle is not None else library.soyokaze_read_buffer_new()

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_read_buffer_free(self.handle)
            self.handle = None

    def take_handle(self):
        """Hands the native handle over to a consuming call."""
        handle, self.handle = self.handle, None
        return handle

    def chunk_size(self):
        """How many octets one read asks the transport for."""
        return library.soyokaze_read_buffer_chunk_size(self.handle)

    def set_chunk_size(self, chunk_size):
        """Sets how many octets one read asks the transport for."""
        library.soyokaze_read_buffer_set_chunk_size(self.handle, chunk_size)

    def len(self):
        """How many octets are waiting to be read out."""
        return library.soyokaze_read_buffer_len(self.handle)

    def is_empty(self):
        """Whether nothing is waiting to be read out."""
        return library.soyokaze_read_buffer_is_empty(self.handle)

    def eof(self):
        """Whether the transport underneath has ended."""
        return library.soyokaze_read_buffer_eof(self.handle)

    def capacity(self):
        """How many octets the buffer has room for without growing."""
        return library.soyokaze_read_buffer_capacity(self.handle)

    def as_slice(self):
        """What is waiting to be read out."""
        return library.soyokaze_read_buffer_bytes(self.handle).bytes()

    def extend(self, data):
        """Adds octets, as a read from the transport would."""
        data = ffi.Library.encoded(data)
        library.soyokaze_read_buffer_extend(self.handle, data, len(data))

    def consume(self, count):
        """Drops the first ``count`` octets, which have been dealt with."""
        library.soyokaze_read_buffer_consume(self.handle, count)

    def take(self, count):
        """Takes the first ``count`` octets out."""
        return library.soyokaze_read_buffer_take(self.handle, count).take()

    def reclaim(self, idle_capacity):
        """Shrinks the buffer back when it has grown past ``idle_capacity``."""
        library.soyokaze_read_buffer_reclaim(self.handle, idle_capacity)

    def __len__(self):
        return self.len()

    def __repr__(self):
        return f"Buffer({self.len()} octets)"

class Fields:
    """The pseudo-field vocabulary HTTP/2 and HTTP/3 send a message as."""

    PSEUDO_REQUEST = tuple(
        library.soyokaze_pseudo_request_name(index).text()
        for index in range(library.soyokaze_pseudo_request_count())
    )
    """The pseudo-fields a request carries, in the order they are sent."""

    PSEUDO_RESPONSE = tuple(
        library.soyokaze_pseudo_response_name(index).text()
        for index in range(library.soyokaze_pseudo_response_count())
    )
    """The pseudo-fields a response carries."""

    CONNECTION_SPECIFIC = tuple(
        library.soyokaze_connection_specific_name(index).text()
        for index in range(library.soyokaze_connection_specific_count())
    )
    """The fields that belong to one HTTP/1.x connection and never travel above it."""

    @classmethod
    def connection_specific(cls, name):
        """Whether a field belongs to one HTTP/1.x connection."""
        name = ffi.Library.encoded(name)
        return library.soyokaze_connection_specific(name, len(name))

    @classmethod
    def status(cls, status_code):
        """A status code as a ``:status`` value."""
        return library.soyokaze_pseudo_status(status_code).take().decode()

    @classmethod
    def of(cls, message):
        """The field section a message is sent as.

        Pseudo-fields come first, then the ordinary fields with the
        connection-specific ones dropped.
        """
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_fields_of_message(message.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return FieldSection.taken(out)

    @classmethod
    def message(cls, fields, version=Version.V2_0):
        """The message a decoded field section stands for."""
        section = library.soyokaze_fields_new()
        for name, value in fields:
            name, value = ffi.Library.encoded(name), ffi.Library.encoded(value)
            library.soyokaze_fields_append(section, name, len(name), value, len(value))

        out, error = ctypes.c_void_p(), Error.out()
        status = library.soyokaze_fields_to_message(section, int(version), ctypes.byref(out), ctypes.byref(error))
        library.soyokaze_fields_free(section)
        Error.raise_for(status, error)
        return Message(handle=out)

    @classmethod
    def into_message(cls, fields, version=Version.V2_0):
        """The message a decoded field section stands for. The same as :meth:`message`."""
        return cls.message(fields, version)
