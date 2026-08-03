"""The types every HTTP version shares.

:class:`Message` is a request or a response, whichever version framed it, and
:class:`Url`, :class:`Version`, :class:`Method` and :class:`Port` are the
pieces around it — the same vocabulary as the crate's ``models`` module.
:class:`Message` also extends with the constructors in :mod:`responses`, the
same way it does in the crate.
"""

import ctypes
import enum
import pathlib

from . import ffi
from .errors import InvalidError, error_out, raise_for
from .ffi import library
from .runtime import default_runtime

class Version(enum.IntEnum):
    """An HTTP version."""

    V1_0 = 0
    V1_1 = 1
    V2_0 = 2
    V3_0 = 3

    def major(self):
        """The major version number."""
        return {Version.V1_0: 1, Version.V1_1: 1, Version.V2_0: 2, Version.V3_0: 3}[self]

    def __str__(self):
        return {Version.V1_0: "HTTP/1.0", Version.V1_1: "HTTP/1.1", Version.V2_0: "HTTP/2", Version.V3_0: "HTTP/3"}[self]

class Method(enum.IntEnum):
    """A request method."""

    GET = 0
    HEAD = 1
    POST = 2
    PUT = 3
    DELETE = 4
    CONNECT = 5
    OPTIONS = 6
    TRACE = 7
    PATCH = 8

    def safe(self):
        """Whether the method is read-only, so that issuing it changes nothing."""
        return self in (Method.GET, Method.HEAD, Method.OPTIONS, Method.TRACE)

    def idempotent(self):
        """Whether repeating the method has the same effect as issuing it once."""
        return self.safe() or self in (Method.PUT, Method.DELETE)

class Role(enum.IntEnum):
    """What one end of a connection is doing on it."""

    USER_AGENT = 0
    ORIGIN = 1
    PROXY = 2
    GATEWAY = 3
    TUNNEL = 4

    def is_client(self):
        """Whether this role sends requests and reads responses."""
        return self in (Role.USER_AGENT, Role.PROXY)

    def is_server(self):
        """Whether this role reads requests and sends responses."""
        return self in (Role.ORIGIN, Role.GATEWAY)

class PortKind(enum.IntEnum):
    """Which transport a port names."""

    UDS = 0
    TCP = 1
    QUIC = 2

class Port:
    """Somewhere a server listens or a client dials.

    The kind picks the transport, which in turn bounds the HTTP versions that
    can be negotiated: a QUIC port carries HTTP/3 and nothing else, while a
    TCP port or a Unix socket carries HTTP/1.x and HTTP/2.
    """

    def __init__(self, kind, number=0, path=None):
        self.kind = PortKind(kind)
        self.number = number
        self.path = path

    @classmethod
    def TCP(cls, number):
        """A TCP port."""
        return cls(PortKind.TCP, number=number)

    @classmethod
    def QUIC(cls, number):
        """A UDP port carrying QUIC."""
        return cls(PortKind.QUIC, number=number)

    @classmethod
    def UDS(cls, path):
        """A Unix domain socket at the given filesystem path."""
        return cls(PortKind.UDS, path=str(path))

    def build(self):
        """The ``soyokaze_port_t`` this stands for.

        The returned struct keeps the encoded path alive on itself.
        """
        struct = ffi.Port()
        struct.kind = int(self.kind)
        struct.number = self.number

        if self.path is not None:
            encoded = ffi.encoded(self.path)
            struct.path = encoded
            struct.path_len = len(encoded)
            struct.keepalive = encoded
        else:
            struct.path = None
            struct.path_len = 0

        return struct

    def __repr__(self):
        if self.kind == PortKind.UDS:
            return f"Port.UDS({self.path!r})"
        return f"Port.{self.kind.name}({self.number})"

def ports_argument(ports):
    """A C array of ``soyokaze_port_t`` and the structs keeping it alive."""
    structs = [port.build() for port in ports]
    array = (ffi.Port * len(structs))(*structs)
    return array, structs

class Url:
    """An absolute URL, split into the parts a request needs."""

    def __init__(self, url):
        """Parses an absolute URL, raising :class:`ProtocolError` when it will not."""
        handle = ctypes.c_void_p()
        error = error_out()
        text = ffi.encoded(url)
        raise_for(library.soyokaze_url_parse(text, len(text), ctypes.byref(handle), ctypes.byref(error)), error)
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_url_free(self.handle)
            self.handle = None

    @property
    def scheme(self):
        """The scheme, lowercased."""
        return library.soyokaze_url_scheme(self.handle).text()

    @property
    def host(self):
        """The host, without the brackets an IPv6 literal wears in a URL."""
        return library.soyokaze_url_host(self.handle).text()

    @property
    def target(self):
        """The request target — path, query and fragment — beginning with ``/``."""
        return library.soyokaze_url_target(self.handle).text()

    @property
    def port(self):
        """The port, defaulted from the scheme when the URL omits one."""
        return library.soyokaze_url_port(self.handle)

    def secure(self):
        """Whether the scheme asks for TLS."""
        return library.soyokaze_url_secure(self.handle)

    def authority(self):
        """The authority as it belongs in a ``Host`` field."""
        return ffi.take(library.soyokaze_url_authority(self.handle)).decode()

    def __repr__(self):
        return f"Url({self.scheme}://{self.authority()}{self.target})"

def body_setter(message, body):
    """Sets a message body from whatever Python value stands for one.

    ``bytes`` become an in-memory data body, ``str`` an in-memory text body,
    and :class:`pathlib.Path` a file read only when the body is sent — the
    three variants of the crate's ``Body``.
    """
    if isinstance(body, pathlib.Path):
        encoded = ffi.encoded(str(body))
        accepted = library.soyokaze_message_set_body_file(message.handle, encoded, len(encoded))
    elif isinstance(body, str):
        encoded = body.encode()
        accepted = library.soyokaze_message_set_body_text(message.handle, encoded, len(encoded))
    else:
        encoded = bytes(body)
        accepted = library.soyokaze_message_set_body_data(message.handle, encoded, len(encoded))

    if not accepted:
        raise InvalidError("the body was refused")

# Imported here, after Version, since responses.py needs it and would
# otherwise see this module only partially initialized.
from .responses import ResponseMixin

class Message(ResponseMixin):
    """One HTTP request or response, whichever version framed it.

    Wraps a native message handle and owns it until a call documented as
    consuming the message takes it over — sending it, most of all — after
    which the object is spent and must not be used again.
    """

    def __init__(self, version=Version.V1_1, handle=None):
        """An empty message, or a wrapper around an existing native handle."""
        handle = getattr(handle, "value", handle)
        self.handle = handle if handle is not None else library.soyokaze_message_new(int(version))

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_message_free(self.handle)
            self.handle = None

    def take(self):
        """Hands the native handle over to a consuming call."""
        handle = self.handle
        if not handle:
            raise InvalidError("the message was already consumed")
        self.handle = None
        return handle

    @classmethod
    def request(cls, method, target, version=Version.V1_1):
        """A request for ``target``."""
        encoded = ffi.encoded(target)
        handle = library.soyokaze_message_request(int(Method(method)), encoded, len(encoded), int(version))
        if not handle:
            raise InvalidError("the target was refused")
        return cls(handle=handle)

    @classmethod
    def response(cls, status_code, version=Version.V1_1):
        """A response carrying ``status_code``."""
        return cls(handle=library.soyokaze_message_response(status_code, int(version)))

    @property
    def version(self):
        """The version that framed this message, or is about to."""
        return Version(library.soyokaze_message_version(self.handle))

    @property
    def method(self):
        """The request method, or ``None`` on a response."""
        method = library.soyokaze_message_method(self.handle)
        return None if method < 0 else Method(method)

    @property
    def status_code(self):
        """The status code, or ``None`` on a request."""
        status_code = library.soyokaze_message_status_code(self.handle)
        return None if status_code < 0 else status_code

    @property
    def target(self):
        """The request target, or ``None`` on a response."""
        return library.soyokaze_message_target(self.handle).text()

    def is_request(self):
        """Whether this message is a request."""
        return library.soyokaze_message_is_request(self.handle)

    def is_response(self):
        """Whether this message is a response."""
        return library.soyokaze_message_is_response(self.handle)

    def is_informational(self):
        """Whether this is a 1xx response, which precedes the real one."""
        return library.soyokaze_message_is_informational(self.handle)

    @property
    def secure(self):
        """Whether the message travelled over a secure transport."""
        return library.soyokaze_message_secure(self.handle)

    @secure.setter
    def secure(self, secure):
        library.soyokaze_message_set_secure(self.handle, secure)

    @property
    def stream_id(self):
        """The stream this message belongs to, for HTTP/2 and HTTP/3."""
        stream_id = library.soyokaze_message_stream_id(self.handle)
        return None if stream_id < 0 else stream_id

    @stream_id.setter
    def stream_id(self, stream_id):
        library.soyokaze_message_set_stream_id(self.handle, -1 if stream_id is None else stream_id)

    @property
    def connection_id(self):
        """The identifier of the connection the message arrived on, if any."""
        return library.soyokaze_message_connection_id(self.handle).bytes()

    @property
    def early_data(self):
        """Whether the request arrived in TLS early data, and so may be a replay."""
        return library.soyokaze_message_early_data(self.handle)

    @property
    def tls(self):
        """Whether the transport underneath was TLS."""
        return library.soyokaze_message_tls(self.handle)

    @property
    def tls_version(self):
        """The negotiated TLS version's wire code, or ``None``."""
        code = library.soyokaze_message_tls_version(self.handle)
        return None if code < 0 else code

    @property
    def tls_group(self):
        """The negotiated TLS named group's wire code, or ``None``."""
        code = library.soyokaze_message_tls_group(self.handle)
        return None if code < 0 else code

    @property
    def tls_cipher(self):
        """The negotiated TLS cipher suite's wire code, or ``None``."""
        code = library.soyokaze_message_tls_cipher(self.handle)
        return None if code < 0 else code

    @property
    def quic(self):
        """Whether the transport underneath was QUIC."""
        return library.soyokaze_message_quic(self.handle)

    @property
    def quic_version(self):
        """The negotiated QUIC version, or ``None``."""
        version = library.soyokaze_message_quic_version(self.handle)
        return None if version < 0 else version

    def headers(self):
        """Every header field in order, as name and value pairs."""
        count = library.soyokaze_message_header_count(self.handle)
        return [
            (library.soyokaze_message_header_name(self.handle, index).text(), library.soyokaze_message_header_value(self.handle, index).text())
            for index in range(count)
        ]

    def header(self, name):
        """The first header value stored under ``name``, or ``None``.

        The name is matched case-insensitively; an absent field is ``None``,
        which is not the same as a field that is there and empty.
        """
        encoded = ffi.encoded(name)
        return library.soyokaze_message_header(self.handle, encoded, len(encoded)).text()

    def append_header(self, name, value):
        """Adds a header field, keeping any already stored under the same name."""
        name, value = ffi.encoded(name), ffi.encoded(value)
        if not library.soyokaze_message_append_header(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the field was refused")

    def insert_header(self, name, value):
        """Adds a header field, dropping any already stored under the same name."""
        name, value = ffi.encoded(name), ffi.encoded(value)
        if not library.soyokaze_message_insert_header(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the field was refused")

    def remove_header(self, name):
        """Drops every header field stored under ``name``, reporting whether any were there."""
        encoded = ffi.encoded(name)
        return library.soyokaze_message_remove_header(self.handle, encoded, len(encoded))

    def trailers(self):
        """Every trailer field in order, as name and value pairs."""
        count = library.soyokaze_message_trailer_count(self.handle)
        return [
            (library.soyokaze_message_trailer_name(self.handle, index).text(), library.soyokaze_message_trailer_value(self.handle, index).text())
            for index in range(count)
        ]

    def trailer(self, name):
        """The first trailer value stored under ``name``, or ``None``."""
        encoded = ffi.encoded(name)
        return library.soyokaze_message_trailer(self.handle, encoded, len(encoded)).text()

    def append_trailer(self, name, value):
        """Adds a trailer field, keeping any already stored under the same name."""
        name, value = ffi.encoded(name), ffi.encoded(value)
        if not library.soyokaze_message_append_trailer(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the field was refused")

    def insert_trailer(self, name, value):
        """Adds a trailer field, dropping any already stored under the same name."""
        name, value = ffi.encoded(name), ffi.encoded(value)
        if not library.soyokaze_message_insert_trailer(self.handle, name, len(name), value, len(value)):
            raise InvalidError("the field was refused")

    def remove_trailer(self, name):
        """Drops every trailer field stored under ``name``, reporting whether any were there."""
        encoded = ffi.encoded(name)
        return library.soyokaze_message_remove_trailer(self.handle, encoded, len(encoded))

    def set_body(self, body):
        """Sets the payload; see :func:`body_setter` for what a value means."""
        body_setter(self, body)

    def body_len(self):
        """How long the body is, or ``None`` when there is none or it is an unread file."""
        length = library.soyokaze_message_body_len(self.handle)
        return None if length < 0 else length

    def body(self, runtime=None):
        """The body as octets, reading the file behind it if there is one."""
        runtime = runtime if runtime is not None else default_runtime()
        out = ffi.Buffer()
        error = error_out()
        raise_for(library.soyokaze_message_body(runtime.handle, self.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return ffi.take(out)

    def __repr__(self):
        if self.is_request():
            return f"Message({self.method.name} {self.target} {self.version})"
        if self.is_response():
            return f"Message({self.status_code} {self.version})"
        return f"Message({self.version})"

FIELDS = [name for name, kind in ffi.Limits._fields_]

class Limits:
    """What one connection is allowed to spend on the peer's behalf.

    Every attribute is a ceiling and mirrors its namesake in the crate;
    timeouts are in seconds and zero waits forever. Construct one with only
    the ceilings to change: ``Limits(max_header_count=32)``.
    """

    def __init__(self, **ceilings):
        defaults = library.soyokaze_limits_default()

        for name in FIELDS:
            setattr(self, name, getattr(defaults, name))

        for name, value in ceilings.items():
            if name not in FIELDS:
                raise TypeError(f"{name!r} is not a limit")
            setattr(self, name, value)

    def build(self):
        """The ``soyokaze_limits_t`` this stands for."""
        struct = ffi.Limits()
        for name in FIELDS:
            setattr(struct, name, getattr(self, name))
        return struct

def limits_argument(limits):
    """The ``soyokaze_limits_t`` for an optional :class:`Limits`, or ``None``.

    The struct is returned itself rather than by reference, so the caller can
    keep it alive for as long as the call needs it.
    """
    return limits.build() if limits is not None else None

def limits_pointer(struct):
    """A pointer to an optional struct from :func:`limits_argument`."""
    return ctypes.byref(struct) if struct is not None else None
