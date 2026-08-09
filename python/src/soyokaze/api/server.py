"""Binding ports, accepting connections and dispatching to a handler.

:class:`Server` holds a :class:`ServerConfig`; :meth:`Server.serve` binds
ports and runs accept loops on a runtime, and :meth:`Server.run` runs one
runtime per worker thread instead, mirroring the crate's ``api::server``.

A handler is an ordinary callable taking a :class:`Message` request and
returning a :class:`Message` response; a WebSocket handler takes a
:class:`WebSocketConnection` and drives it until it is done.
"""

import ctypes
import traceback

from .. import ffi
from ..errors import Error, InvalidError
from ..ffi import library
from ..models import Limits, Message, Port, Version
from ..runtime import Runtime
from ..websocket import WebSocketConnection
from .cluster import Cluster
from .gate import Gate

class ServerLimits:
    """The limits a server applies on top of the per-message :class:`Limits`.

    The defaults leave admission unbounded, so a server limits nothing it
    was not asked to. ``max_connection_rate`` is a list of
    ``(period_seconds, count)`` pairs, every one of which must be satisfied.
    """

    def __init__(self, message=None, backlog=None, max_connections=None, max_connections_per_ip=None, max_connection_rate=None, max_connection_history=None, worker_stack_size=None):
        defaults = library.soyokaze_server_limits_default()
        self.message = message if message is not None else Limits()
        self.backlog = backlog if backlog is not None else defaults.backlog
        self.max_connections = max_connections if max_connections is not None else defaults.max_connections
        self.max_connections_per_ip = max_connections_per_ip if max_connections_per_ip is not None else defaults.max_connections_per_ip
        self.max_connection_rate = max_connection_rate if max_connection_rate is not None else []
        self.max_connection_history = max_connection_history if max_connection_history is not None else defaults.max_connection_history
        self.worker_stack_size = worker_stack_size if worker_stack_size is not None else defaults.worker_stack_size

    def gate(self):
        """The admission gate these limits describe.

        The same gate a server built from these limits would admit connections
        through.
        """
        struct = self.build()
        return Gate(handle=library.soyokaze_server_limits_gate(ctypes.byref(struct)))

    def build(self):
        """The ``soyokaze_server_limits_t`` this stands for.

        The struct keeps its rate array alive on itself.
        """
        struct = ffi.ServerLimits()
        struct.message = self.message.build()
        struct.backlog = self.backlog
        struct.max_connections = self.max_connections
        struct.max_connections_per_ip = self.max_connections_per_ip
        struct.max_connection_history = self.max_connection_history
        struct.worker_stack_size = self.worker_stack_size

        if self.max_connection_rate:
            rates = (ffi.Rate * len(self.max_connection_rate))(*[ffi.Rate(period, count) for period, count in self.max_connection_rate])
            struct.max_connection_rate = rates
            struct.rate_count = len(self.max_connection_rate)
            struct.keepalive = rates

        return struct

class ServerConfig:
    """How a :class:`Server` is configured.

    Every field has a working default: every supported version offered, no
    admission limits, ``SO_REUSEPORT`` on, and no identity, which leaves a
    TCP port in plaintext and a QUIC port unservable.

    ``identity`` is an :class:`Identity`, ``tls`` a :class:`TLSConfig`,
    ``ech`` an :class:`ECHKeys`, and ``hsts`` an :class:`HSTSPolicy`;
    ``certificate`` and ``key`` are the blob shorthand for an identity of one
    chain entry.

    :class:`Identity`: soyokaze.tls.Identity
    :class:`TLSConfig`: soyokaze.tls.TLSConfig
    :class:`ECHKeys`: soyokaze.tls.ECHKeys
    :class:`HSTSPolicy`: soyokaze.hsts.HSTSPolicy
    """

    def __init__(self, versions=None, limits=None, identity=None, certificate=None, key=None, tls=None, ech=None, hsts=None, reuseport=True):
        self.versions = versions
        self.limits = limits
        self.identity = identity
        self.certificate = certificate
        self.key = key
        self.tls = tls
        self.ech = ech
        self.hsts = hsts
        self.reuseport = reuseport

    def build(self):
        """The ``soyokaze_server_config_t`` this stands for.

        The struct keeps everything it points at alive on itself; the
        identity and ECH handles are borrowed, so those objects must outlive
        the ``soyokaze_server_new`` call, which copies what it needs.
        """
        struct = ffi.ServerConfig()
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

        if self.identity is not None:
            struct.identity = self.identity.handle

        if self.certificate is not None:
            certificate = ffi.Slice.of(ffi.Library.encoded(self.certificate))
            keepalive.append(certificate)
            struct.certificate = certificate

        if self.key is not None:
            key = ffi.Slice.of(ffi.Library.encoded(self.key))
            keepalive.append(key)
            struct.key = key

        if self.tls is not None:
            tls = self.tls.build()
            keepalive.append(tls)
            struct.tls = ctypes.pointer(tls)

        if self.ech is not None:
            struct.ech = self.ech.handle

        if self.hsts is not None:
            hsts = ffi.HSTSPolicy(self.hsts.max_age, self.hsts.include_subdomains, self.hsts.preload)
            keepalive.append(hsts)
            struct.hsts = ctypes.pointer(hsts)

        struct.reuseport = self.reuseport
        struct.keepalive = keepalive
        return struct

class ServerHandle:
    """A running server, as :meth:`Server.serve` returns it.

    Everything runs on the runtime the server was served on. Dropping this
    leaves the server running; call :meth:`close` to wind it down. The
    callbacks live on the handle, so it must outlive the server's use of
    them — close it before letting it go.
    """

    def __init__(self, handle, runtime, callbacks):
        self.handle = handle
        self.runtime = runtime
        self.callbacks = callbacks

    @property
    def port(self):
        """The port the first listener actually bound.

        This is how to find a port the kernel chose, when zero was asked for.
        """
        return library.soyokaze_server_handle_port(self.handle)

    def ports(self):
        """The port of every bound address."""
        count = library.soyokaze_server_handle_address_count(self.handle)
        return [library.soyokaze_server_handle_port_at(self.handle, index) for index in range(count)]

    def addresses(self):
        """Every address the server bound, as text."""
        count = library.soyokaze_server_handle_address_count(self.handle)
        return [library.soyokaze_server_handle_address_at(self.handle, index).take().decode() for index in range(count)]

    def close(self, timeout=None):
        """Stops accepting and waits for connections to finish.

        ``timeout`` bounds the wait in seconds; connections still running
        when it passes are aborted. ``None`` waits as long as it takes.
        """
        if self.handle:
            library.soyokaze_server_handle_close(self.runtime.handle, self.handle, -1.0 if timeout is None else timeout)
            self.handle = None

class RawSocket:
    """A bound socket that no runtime has adopted yet.

    Sockets are opened before worker threads start, so this is deliberately
    runtime-free. A caller that wants to bind its ports itself — to drop
    privileges after binding, or to hand a socket to another process — opens
    one with :meth:`Server.open` and reads the descriptor off it.

    The handle owns the descriptor: dropping it closes the socket.
    """

    def __init__(self, handle):
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_raw_socket_free(self.handle)
            self.handle = None

    def address(self):
        """The address the socket is bound to, or ``None``.

        A Unix socket has none, so it always reads as ``None``.
        """
        address = library.soyokaze_raw_socket_address(self.handle).taken()
        return None if address is None else address.decode()

    @property
    def port(self):
        """The port the socket is bound to, or zero when it has none."""
        return library.soyokaze_raw_socket_port(self.handle)

    @property
    def descriptor(self):
        """The descriptor underneath, for a caller handing the socket elsewhere.

        The socket still owns it: dropping this object closes the descriptor,
        so a caller that passes it on must keep the object alive.
        """
        return library.soyokaze_raw_socket_descriptor(self.handle)

    def share(self):
        """Duplicates the descriptor, so several workers may accept from one socket.

        This is the fallback when ``SO_REUSEPORT`` is off, and the only way for
        a Unix socket, which cannot be bound twice.
        """
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_raw_socket_share(self.handle, ctypes.byref(out), ctypes.byref(error)), error)
        return RawSocket(out)

    def __repr__(self):
        return f"RawSocket({self.address()!r})"

class Server:
    """An HTTP server.

    Holds the :class:`ServerConfig` a listener is built from.
    """

    def __init__(self, config=None):
        struct = config.build() if config is not None else None
        self.handle = library.soyokaze_server_new(ctypes.byref(struct) if struct is not None else None)
        if not self.handle:
            raise InvalidError("the configuration was refused")

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_server_free(self.handle)
            self.handle = None

    @classmethod
    def request_callback(cls, handler):
        """The C callback that hands each request to ``handler``.

        A handler that raises answers with a bare ``500``, the way a null
        response does, and the traceback goes to stderr rather than vanishing.
        """

        def answer(context, request):
            try:
                response = handler(Message(handle=request))
                return response.take()
            except BaseException:
                traceback.print_exc()
                return None

        return ffi.ON_REQUEST(answer)

    @classmethod
    def websocket_callback(cls, handler):
        """The C callback that hands each accepted WebSocket to ``handler``.

        The socket is closed and freed when the handler returns without having
        done so itself, so a handler may simply return when it is done.
        """
        if handler is None:
            return ffi.ON_WEBSOCKET()

        def run(context, socket):
            connection = WebSocketConnection(socket)
            try:
                handler(connection)
            except BaseException:
                traceback.print_exc()
            finally:
                if connection.handle and not connection.closing():
                    connection.close()

        return ffi.ON_WEBSOCKET(run)

    def versions(self):
        """The versions this server accepts, in the order it accepts them."""
        count = library.soyokaze_server_version_count(self.handle)
        return [Version(library.soyokaze_server_version_at(self.handle, index)) for index in range(count)]

    @property
    def reuseport(self):
        """Whether each worker's socket is bound with ``SO_REUSEPORT``."""
        return library.soyokaze_server_reuseport(self.handle)

    def open(self, target):
        """Binds one port without starting anything on it.

        The socket is bound and, for a stream port, listening, but nothing
        accepts from it until a server adopts it.
        """
        struct = target.build()
        out, error = ctypes.c_void_p(), Error.out()
        Error.raise_for(library.soyokaze_server_open(self.handle, ctypes.byref(struct), ctypes.byref(out), ctypes.byref(error)), error)
        return RawSocket(out)

    def serve(self, handler, ports, on_websocket=None, runtime=None):
        """Binds every port and starts serving.

        Returns a :class:`ServerHandle` as soon as the ports are bound; the
        accept loops keep running on ``runtime``, which must outlive the
        handle. ``handler`` answers each request; ``on_websocket``, when
        given, runs each accepted WebSocket, and upgrade requests are
        otherwise handed to ``handler`` like any other.
        """
        runtime = runtime if runtime is not None else Runtime.default()
        callbacks = (self.request_callback(handler), self.websocket_callback(on_websocket))
        array, structs = Port.array(ports)

        out = ctypes.c_void_p()
        error = Error.out()
        Error.raise_for(library.soyokaze_server_serve(runtime.handle, self.handle, callbacks[0], callbacks[1], None, array, len(ports), ctypes.byref(out), ctypes.byref(error)), error)
        return ServerHandle(out.value, runtime, callbacks)

    def run(self, handler, ports, workers=0, on_websocket=None):
        """Runs the server across several threads, each with its own runtime.

        The multi-worker counterpart of :meth:`serve`; a ``workers`` of zero
        takes one per core. Returns a :class:`Cluster` once every worker is
        ready, so a bind failure surfaces here.
        """
        callbacks = (self.request_callback(handler), self.websocket_callback(on_websocket))
        array, structs = Port.array(ports)

        out = ctypes.c_void_p()
        error = Error.out()
        Error.raise_for(library.soyokaze_server_run(self.handle, callbacks[0], callbacks[1], None, array, len(ports), workers, ctypes.byref(out), ctypes.byref(error)), error)
        return Cluster(out.value, callbacks)
