"""An HTTP/1, HTTP/2 and HTTP/3 library.

Python bindings over the soyokaze shared library, reached through its C ABI
the way any C caller would reach it. The modules mirror the crate:
:mod:`models` holds :class:`Message` and the vocabulary around it, :mod:`api`
holds the entry points, :mod:`cookies` holds cookies, :mod:`hsts` the
HSTS policy, :mod:`tls` identities
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

from . import api, cookies, errors, ffi, finalizer, helpers, hsts, models, tls, websocket
from .api.client import Client, ClientConfig, ClientLimits, Connection
from .api.cluster import Cluster
from .api.common import VERSIONS
from .api.server import Server, ServerConfig, ServerHandle, ServerLimits
from .errors import ClosedError, Error, InvalidError, IOError, LimitError, ProtocolError, Status, StreamError, TimeoutError, TLSError, VersionError
from .finalizer import DateCache
from .cookies import Cookie, CookieJar, SameSite, SetCookie
from .hsts import HSTSPolicy, HSTSStore
from .models import Limits, Message, Method, Port, PortKind, Role, URL, Version
from .runtime import Runtime
from .tls import ECHConfig, ECHConfigList, ECHKeys, Identity, TLSConfig
from .websocket import CloseCode, Frame, Opcode, WebSocketConnection

version = ffi.Library.version()
