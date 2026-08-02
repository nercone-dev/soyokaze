"""An HTTP/1, HTTP/2 and HTTP/3 library.

Python bindings over the soyokaze shared library, reached through its C ABI
the way any C caller would reach it. The modules mirror the crate:
:mod:`models` holds :class:`Message` and the vocabulary around it, :mod:`api`
holds the entry points, :mod:`headers` holds cookies, :mod:`tls` identities
and Encrypted Client Hello, :mod:`websocket` the WebSocket connection, and
:mod:`helpers` the codecs.

Fetch a resource::

    client = soyokaze.Client()
    response = client.get("https://example.com/")
    print(response.status_code)

Serve one::

    server = soyokaze.Server()
    handle = server.serve(lambda request: soyokaze.Message.text("hello"), [soyokaze.Port.TCP(8080)])
    ...
    handle.close()
"""

from . import api, errors, ffi, finalizer, headers, helpers, models, tls, websocket
from .api.client import Client, ClientConfig, ClientLimits, Connection
from .api.common import Limits
from .api.server import Cluster, Server, ServerConfig, ServerHandle, ServerLimits, cores
from .errors import ClosedError, Error, InvalidError, IoError, LimitError, ProtocolError, Status, StreamError, TimeoutError, TlsError, VersionError
from .finalizer import http_date
from .headers import Cookie, CookieJar, SameSite, SetCookie
from .helpers.hsts import HstsPolicy, HstsStore
from .models import Message, Method, Port, PortKind, Role, Url, Version
from .runtime import Runtime, default_runtime
from .tls import EchConfig, EchConfigList, EchKeys, Identity
from .websocket import CloseCode, Frame, Opcode, WebSocketConnection

version = ffi.version()
