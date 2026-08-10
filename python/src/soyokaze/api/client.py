"""Dialling an origin and issuing requests.

:class:`Client` is the entry point. Build one from a :class:`ClientConfig` —
or with no arguments to take every default — then await :meth:`Client.get`
and friends for one-off requests, or :meth:`Client.connect` when the
connection itself is wanted, mirroring the crate's ``api::client`` module.

Every call that waits is a coroutine: the exchange runs on a worker thread
and the event loop is handed back until it finishes, so requests may be
awaited alongside each other with :func:`asyncio.gather` and anything else
the loop is running keeps running. What only reads what the client already
knows — :meth:`Client.authority`, :meth:`Client.versions` — waits for
nothing and stays an ordinary call.
"""

import ctypes

from .. import ffi
from ..errors import Error, InvalidError
from ..ffi import library
from ..cookies import CookieJar
from ..finalizer import RequestFinalizer
from ..hsts import HSTSStore
from ..models import Limits, Message, Method, Role, Version
from ..runtime import Runtime, offload
from ..websocket import WebSocketConnection

class ClientLimits:
    """The limits a client applies on top of the per-message :class:`Limits`."""

    def __init__(self, message=None, connection_timeout=None):
        defaults = library.soyokaze_client_limits_default()
        self.message = message if message is not None else Limits()
        self.connection_timeout = connection_timeout if connection_timeout is not None else defaults.connection_timeout

    def build(self):
        """The ``soyokaze_client_limits_t`` this stands for."""
        return ffi.ClientLimits(self.message.build(), self.connection_timeout)

class ClientConfig:
    """How a :class:`Client` is configured.

    Every field has a working default: every supported version offered, TLS
    on, cookies kept, HSTS remembered, and the platform trust store.
    """

    def __init__(self, versions=None, limits=None, secure=True, roots=None, tls=None, ech=None, cookies=True, hsts=True):
        self.versions = versions
        self.limits = limits
        self.secure = secure
        self.roots = roots
        self.tls = tls
        self.ech = ech
        self.cookies = cookies
        self.hsts = hsts

    def build(self):
        """The ``soyokaze_client_config_t`` this stands for.

        The struct keeps everything it points at alive on itself.
        """
        struct = ffi.ClientConfig()
        keepalive = []

        if self.versions is not None:
            versions = (ctypes.c_int32 * len(self.versions))(*[int(Version(version)) for version in self.versions])
            keepalive.append(versions)
            struct.versions = versions
            struct.version_count = len(self.versions)

        if self.limits is not None:
            limits = self.limits.build()
            keepalive.append(limits)
            struct.limits = ctypes.pointer(limits)

        struct.secure = self.secure
        struct.cookies = self.cookies
        struct.hsts = self.hsts

        if self.roots is not None:
            slices = [ffi.Slice.of(ffi.Library.encoded(root)) for root in self.roots]
            array = (ffi.Slice * len(slices))(*slices)
            keepalive.extend((slices, array))
            struct.roots = array
            struct.root_count = len(slices)

        if self.tls is not None:
            tls = self.tls.build()
            keepalive.append(tls)
            struct.tls = ctypes.pointer(tls)

        if self.ech is not None:
            entries = []
            for host, config_list in self.ech.items():
                entry = ffi.ECHEntry(ffi.Slice.of(ffi.Library.encoded(host)), ffi.Slice.of(ffi.Library.encoded(config_list)))
                entries.append(entry)
            array = (ffi.ECHEntry * len(entries))(*entries)
            keepalive.extend((entries, array))
            struct.ech = array
            struct.ech_count = len(entries)

        struct.keepalive = keepalive
        return struct

class Connection:
    """A connection of whichever version was negotiated.

    What :meth:`Client.open` and :meth:`Client.connect` hand back; several
    messages may go over one. Usable as an async context manager, which
    closes it on the way out::

        async with await client.open(url) as connection:
            ...
    """

    def __init__(self, handle, runtime):
        self.handle = handle
        self.runtime = runtime

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_connection_free(self.handle)
            self.handle = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, kind, value, traceback):
        await self.close()
        return False

    @property
    def version(self):
        """The version the connection settled on."""
        return Version(library.soyokaze_connection_version(self.handle))

    @property
    def role(self):
        """Which end of the connection this is."""
        return Role(library.soyokaze_connection_role(self.handle))

    def id(self):
        """The connection's identifier."""
        return library.soyokaze_connection_id(self.handle).take()

    def client(self):
        """The address the peer connected from, and its port, as text.

        ``None`` on a client connection, and over a Unix socket, whose accepted
        address names nothing. This is what every request the connection
        receives is stamped with.
        """
        client = library.soyokaze_connection_client(self.handle).take()
        return None if not client else client.decode()

    def reusable(self):
        """Whether another message may go over the connection."""
        return library.soyokaze_connection_reusable(self.handle)

    async def send(self, message):
        """Sends one message, without waiting for anything back.

        The raw half of :meth:`Client.request`, for pipelining requests or
        streaming responses by hand. ``message`` is consumed. Waiting for
        nothing back is not the same as not waiting: the octets still have to
        reach the peer, so this is awaited like anything else.
        """
        error = Error.out()
        status = await offload(library.soyokaze_connection_send, self.runtime.handle, self.handle, message.take(), ctypes.byref(error))
        Error.raise_for(status, error)

    async def receive(self):
        """Receives the next message.

        Unlike :meth:`Client.request`, informational (1xx) responses are
        handed over rather than read past.
        """
        out = ctypes.c_void_p()
        error = Error.out()
        status = await offload(library.soyokaze_connection_receive, self.runtime.handle, self.handle, ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return Message(handle=out)

    async def open_websocket(self, authority, target, limits=None):
        """Opens a WebSocket and takes the connection over.

        The connection is consumed whether the handshake succeeds or not.
        """
        handle = self.handle
        if not handle:
            raise InvalidError("the connection was already consumed")
        self.handle = None

        out = ctypes.c_void_p()
        error = Error.out()
        authority, target = ffi.Library.encoded(authority), ffi.Library.encoded(target)
        status = await offload(library.soyokaze_connection_open_websocket, self.runtime.handle, handle, authority, len(authority), target, len(target), ctypes.byref(limits) if limits is not None else None, ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return WebSocketConnection(out)

    async def close(self):
        """Closes the connection, leaving the object to be dropped."""
        if self.handle:
            await offload(library.soyokaze_connection_close, self.runtime.handle, self.handle)

class Client:
    """An HTTP client.

    Holds the configuration a connection is made with, and the cookie and
    HSTS state that outlives one request. It does not pool connections: each
    :meth:`fetch` dials, exchanges, and closes.
    """

    def __init__(self, config=None, runtime=None):
        self.runtime = runtime if runtime is not None else Runtime.default()

        struct = config.build() if config is not None else None
        self.handle = library.soyokaze_client_new(ctypes.byref(struct) if struct is not None else None)
        if not self.handle:
            raise InvalidError("the configuration was refused")

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_client_free(self.handle)
            self.handle = None

    async def fetch(self, method, url, headers=None, body=None):
        """Makes one request and returns the response.

        Dials, exchanges, and closes the connection. ``Host`` and ``Cookie``
        are filled in unless ``headers`` carries them, and redirects are not
        followed — the response is returned as it came.

        ``headers`` is an iterable of name and value pairs, and ``body`` is
        whatever :meth:`Message.set_body` accepts.
        """
        request = Message.argument(headers, body, Version.V1_1)

        out = ctypes.c_void_p()
        error = Error.out()
        encoded = ffi.Library.encoded(url)
        status = await offload(library.soyokaze_client_fetch, self.runtime.handle, self.handle, int(Method(method)), encoded, len(encoded), request, ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return Message(handle=out)

    async def get(self, url):
        """A ``GET``; see :meth:`fetch`."""
        return await self.fetch(Method.GET, url)

    async def head(self, url):
        """A ``HEAD``; see :meth:`fetch`."""
        return await self.fetch(Method.HEAD, url)

    async def post(self, url, body):
        """A ``POST``; see :meth:`fetch`."""
        return await self.fetch(Method.POST, url, body=body)

    async def put(self, url, body):
        """A ``PUT``; see :meth:`fetch`."""
        return await self.fetch(Method.PUT, url, body=body)

    async def delete(self, url):
        """A ``DELETE``; see :meth:`fetch`."""
        return await self.fetch(Method.DELETE, url)

    async def open(self, url):
        """Opens a connection for a :class:`URL`, taking the transport from its scheme."""
        out = ctypes.c_void_p()
        error = Error.out()
        status = await offload(library.soyokaze_client_open, self.runtime.handle, self.handle, url.handle, ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return Connection(out, self.runtime)

    async def connect(self, host, port):
        """Opens a connection to a host on a given :class:`Port`.

        The port decides the transport, and so which versions are available.
        """
        out = ctypes.c_void_p()
        error = Error.out()
        encoded = ffi.Library.encoded(host)
        struct = port.build()
        status = await offload(library.soyokaze_client_connect, self.runtime.handle, self.handle, encoded, len(encoded), ctypes.byref(struct), ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return Connection(out, self.runtime)

    async def request(self, connection, request):
        """Sends a request over an open connection and waits for the response.

        Informational (1xx) responses are read past. ``request`` is consumed.
        """
        out = ctypes.c_void_p()
        error = Error.out()
        status = await offload(library.soyokaze_client_request, self.runtime.handle, self.handle, connection.handle, request.take(), ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return Message(handle=out)

    async def websocket(self, url):
        """Opens a WebSocket connection.

        The handshake follows whichever version is negotiated: an HTTP/1.1
        upgrade, or extended CONNECT over HTTP/2 and HTTP/3.
        """
        out = ctypes.c_void_p()
        error = Error.out()
        encoded = ffi.Library.encoded(url)
        status = await offload(library.soyokaze_client_websocket, self.runtime.handle, self.handle, encoded, len(encoded), ctypes.byref(out), ctypes.byref(error))
        Error.raise_for(status, error)
        return WebSocketConnection(out)

    def id(self, host, target):
        """The connection identifier this client would give a connection.

        The same identifier every message on that connection carries, so a
        caller can key its own bookkeeping on what the library will use.
        """
        encoded, struct = ffi.Library.encoded(host), target.build()
        return library.soyokaze_client_id(self.handle, encoded, len(encoded), ctypes.byref(struct)).take()

    def authority(self, host, target):
        """The authority this client would send for a host and port.

        The port is left off when it is the scheme's default, which is what an
        origin expects to see in ``Host`` or ``:authority``.
        """
        encoded, struct = ffi.Library.encoded(host), target.build()
        return library.soyokaze_client_authority(self.handle, encoded, len(encoded), ctypes.byref(struct)).take().decode()

    def ech(self, host):
        """The ECH configuration list this client would use for a host, or ``None``."""
        encoded = ffi.Library.encoded(host)
        return library.soyokaze_client_ech(self.handle, encoded, len(encoded)).bytes()

    def prior_version(self):
        """The version this client would use without negotiating one.

        A plain connection has no ALPN to settle a version with, so the client
        must have been given exactly one version to offer.
        """
        out, error = ctypes.c_int32(), Error.out()
        Error.raise_for(library.soyokaze_client_prior_version(self.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return Version(out.value)

    def only_quic(self):
        """Whether every version this client offers runs over QUIC."""
        return library.soyokaze_client_only_quic(self.handle)

    def versions(self):
        """The versions this client offers, in the order it offers them."""
        count = library.soyokaze_client_version_count(self.handle)
        return [Version(library.soyokaze_client_version_at(self.handle, index)) for index in range(count)]

    @property
    def jar(self):
        """This client's cookie jar, or ``None`` when it keeps none.

        Borrowed from the client and valid only for as long as it is.
        """
        handle = library.soyokaze_client_jar(self.handle)
        return None if not handle else CookieJar(handle=handle, owner=self)

    @property
    def store(self):
        """This client's HSTS store, or ``None`` when it keeps none.

        As :attr:`jar`, for the store.
        """
        handle = library.soyokaze_client_store(self.handle)
        return None if not handle else HSTSStore(handle=handle, owner=self)

    def apply_hsts(self, url):
        """Rewrites a URL to ``https`` when this client's store insists on it.

        Returns whether the URL was rewritten.
        """
        return library.soyokaze_client_apply_hsts(self.handle, url.handle)

    def request_finalizer(self, authority):
        """The request finalizer this client would use for an authority."""
        encoded = ffi.Library.encoded(authority)
        return RequestFinalizer(handle=library.soyokaze_client_request_finalizer(self.handle, encoded, len(encoded)))
