"""The C ABI underneath the Python bindings.

Loads the shared library the crate builds as and declares every symbol it
exports, mirroring ``include/soyokaze.h``. The higher modules call through
:data:`library` exactly the way a C caller would, so the bindings exercise the
same surface the header promises.

The library is found through, in order: the ``SOYOKAZE_LIBRARY`` environment
variable, a copy shipped inside this package, the crate's own ``target``
directory when the package sits in the repository, and the system loader.
"""

import ctypes
import ctypes.util
import os
import pathlib
import sys

from ctypes import CFUNCTYPE, POINTER, Structure, c_bool, c_char_p, c_double, c_int32, c_int64, c_size_t, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p

class Slice(Structure):
    """A borrowed view of octets: ``soyokaze_slice_t``.

    A ``data`` of null means the value was absent, which is how a lookup that
    found nothing is told apart from one that found an empty value.
    """

    _fields_ = [("data", POINTER(c_uint8)), ("len", c_size_t)]

    def bytes(self):
        """The octets, or ``None`` when the value was absent."""
        if not self.data:
            return None
        return ctypes.string_at(self.data, self.len)

    def text(self):
        """The octets as text, or ``None`` when the value was absent."""
        octets = self.bytes()
        return None if octets is None else octets.decode()

class Buffer(Structure):
    """Octets owned by the caller: ``soyokaze_buffer_t``."""

    _fields_ = [("data", POINTER(c_uint8)), ("len", c_size_t), ("capacity", c_size_t)]

class Port(Structure):
    """A port to dial or bind: ``soyokaze_port_t``."""

    _fields_ = [("kind", c_int32), ("number", c_uint16), ("path", c_char_p), ("path_len", c_size_t)]

class Limits(Structure):
    """What one connection may spend on the peer's behalf: ``soyokaze_limits_t``."""

    _fields_ = [
        ("max_message_size", c_uint64),
        ("max_message_body_size", c_uint64),
        ("max_startline_size", c_uint32),
        ("max_headers_size", c_uint64),
        ("max_header_count", c_uint16),
        ("max_chunk_header_size", c_uint32),
        ("read_chunk_size", c_uint64),
        ("idle_capacity", c_uint64),
        ("max_pending_handshakes", c_uint32),
        ("read_timeout", c_double),
        ("write_timeout", c_double),
        ("receive_timeout", c_double),
        ("send_timeout", c_double),
        ("inline_body_size", c_uint64),
        ("max_concurrent_streams", c_uint32),
        ("max_connection_buffer_size", c_uint64),
        ("max_premature_resets", c_uint32),
        ("max_encoder_table_size", c_uint64),
        ("max_idle_frames", c_uint32),
        ("output_high_water", c_uint64),
        ("qpack_block_timeout", c_double),
        ("max_peer_uni_streams", c_uint32),
        ("max_outstanding_sections", c_uint32),
        ("max_blocked_streams", c_uint32),
        ("tunnel_backlog", c_uint32),
        ("command_backlog", c_uint32),
        ("ws_linger_timeout", c_double),
        ("ws_max_fragments", c_uint16),
        ("max_cookies", c_uint32),
        ("max_cookies_per_domain", c_uint16),
        ("max_hsts_entries", c_uint32),
    ]

class ClientLimits(Structure):
    """The limits a client adds on top: ``soyokaze_client_limits_t``."""

    _fields_ = [("message", Limits), ("connection_timeout", c_double)]

class Rate(Structure):
    """One sliding-window rate limit: ``soyokaze_rate_t``."""

    _fields_ = [("period", c_double), ("count", c_uint32)]

class ServerLimits(Structure):
    """The limits a server adds on top: ``soyokaze_server_limits_t``."""

    _fields_ = [
        ("message", Limits),
        ("backlog", c_uint32),
        ("max_connections", c_uint32),
        ("max_connections_per_ip", c_uint32),
        ("max_connection_rate", POINTER(Rate)),
        ("rate_count", c_size_t),
        ("max_connection_history", c_size_t),
        ("worker_stack_size", c_size_t),
    ]

class TlsConfig(Structure):
    """The TLS details a context is built with: ``soyokaze_tls_config_t``."""

    _fields_ = [
        ("ciphers", Slice),
        ("groups", Slice),
        ("signature_algorithms", Slice),
        ("prefer_server_ciphers", c_bool),
        ("session_tickets", c_bool),
        ("early_data", c_bool),
        ("certificate_compression", c_bool),
    ]

class EchEntry(Structure):
    """One host's ECH configuration list: ``soyokaze_ech_entry_t``."""

    _fields_ = [("host", Slice), ("config_list", Slice)]

class ClientConfig(Structure):
    """How a client is configured: ``soyokaze_client_config_t``."""

    _fields_ = [
        ("versions", POINTER(c_int32)),
        ("version_count", c_size_t),
        ("limits", POINTER(ClientLimits)),
        ("secure", c_bool),
        ("cookies", c_bool),
        ("hsts", c_bool),
        ("roots", POINTER(Slice)),
        ("root_count", c_size_t),
        ("tls", POINTER(TlsConfig)),
        ("ech", POINTER(EchEntry)),
        ("ech_count", c_size_t),
    ]

class HstsPolicy(Structure):
    """One Strict-Transport-Security policy: ``soyokaze_hsts_policy_t``."""

    _fields_ = [("max_age", c_int64), ("include_subdomains", c_bool), ("preload", c_bool)]

class ServerConfig(Structure):
    """How a server is configured: ``soyokaze_server_config_t``."""

    _fields_ = [
        ("versions", POINTER(c_int32)),
        ("version_count", c_size_t),
        ("limits", POINTER(ServerLimits)),
        ("identity", c_void_p),
        ("certificate", Slice),
        ("key", Slice),
        ("tls", POINTER(TlsConfig)),
        ("ech", c_void_p),
        ("hsts", POINTER(HstsPolicy)),
        ("reuseport", c_bool),
    ]

class Field(Structure):
    """One field going into an encoder: ``soyokaze_field_t``."""

    _fields_ = [("name", Slice), ("value", Slice)]

ON_REQUEST = CFUNCTYPE(c_void_p, c_void_p, c_void_p)
ON_WEBSOCKET = CFUNCTYPE(None, c_void_p, c_void_p)

def slice_of(octets):
    """A :class:`Slice` viewing ``octets``, which must stay alive alongside it."""
    if octets is None:
        return Slice(None, 0)
    array = (c_uint8 * len(octets)).from_buffer_copy(octets) if octets else None
    view = Slice(ctypes.cast(array, POINTER(c_uint8)) if array else None, len(octets))
    view.keepalive = array
    return view

def locate():
    """Every path or name the shared library might load from, in order.

    ``SOYOKAZE_LIBRARY`` first, then a copy beside this package, then the
    crate's ``target`` directory, then whatever the system loader knows.
    """
    override = os.environ.get("SOYOKAZE_LIBRARY")
    if override:
        return [override]

    if sys.platform == "darwin":
        name = "libsoyokaze.dylib"
    elif sys.platform in ("win32", "cygwin"):
        name = "soyokaze.dll"
    else:
        name = "libsoyokaze.so"

    package = pathlib.Path(__file__).resolve().parent
    candidates = [package / name]

    for target in (package.parent.parent, package.parent.parent.parent):
        for profile in ("release", "debug"):
            candidates.append(target / "target" / profile / name)

    located = [str(candidate) for candidate in candidates if candidate.is_file()]

    found = ctypes.util.find_library("soyokaze")
    if found:
        located.append(found)

    return located

def load():
    """The shared library, tried candidate by candidate.

    A candidate the loader rejects — a stale artifact, a wrong architecture —
    is skipped rather than fatal, so a good build elsewhere still loads.
    """
    failures = []

    for candidate in locate():
        try:
            return ctypes.CDLL(candidate)
        except OSError as failure:
            failures.append(str(failure))

    raise OSError(
        "the soyokaze shared library was not loaded; build it with `cargo build`"
        " or point SOYOKAZE_LIBRARY at it"
        + ("".join(f"\n  - {failure}" for failure in failures))
    )

library = load()

def declare(name, restype, *argtypes):
    """Declares one exported function's signature and returns it."""
    function = getattr(library, name)
    function.restype = restype
    function.argtypes = list(argtypes)
    return function

# ------------------------------------------------------------------- common
declare("soyokaze_buffer_free", None, Buffer)
declare("soyokaze_version", Slice)
declare("soyokaze_limits_default", Limits)
declare("soyokaze_runtime_new", c_void_p, c_uint32)
declare("soyokaze_runtime_free", None, c_void_p)

# ------------------------------------------------------------------- errors
declare("soyokaze_error_free", None, c_void_p)
declare("soyokaze_error_status", c_int32, c_void_p)
declare("soyokaze_error_message", Slice, c_void_p)
declare("soyokaze_error_stream_id", c_int64, c_void_p)
declare("soyokaze_error_code", c_int64, c_void_p)
declare("soyokaze_status_message", Slice, c_int32)

# ---------------------------------------------------------------------- url
declare("soyokaze_url_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_url_free", None, c_void_p)
declare("soyokaze_url_scheme", Slice, c_void_p)
declare("soyokaze_url_host", Slice, c_void_p)
declare("soyokaze_url_target", Slice, c_void_p)
declare("soyokaze_url_port", c_uint16, c_void_p)
declare("soyokaze_url_secure", c_bool, c_void_p)
declare("soyokaze_url_authority", Buffer, c_void_p)

# ------------------------------------------------------------------ message
declare("soyokaze_message_new", c_void_p, c_int32)
declare("soyokaze_message_request", c_void_p, c_int32, c_char_p, c_size_t, c_int32)
declare("soyokaze_message_response", c_void_p, c_uint16, c_int32)
declare("soyokaze_message_free", None, c_void_p)
declare("soyokaze_message_version", c_int32, c_void_p)
declare("soyokaze_message_method", c_int32, c_void_p)
declare("soyokaze_message_status_code", c_int32, c_void_p)
declare("soyokaze_message_target", Slice, c_void_p)
declare("soyokaze_message_is_request", c_bool, c_void_p)
declare("soyokaze_message_is_response", c_bool, c_void_p)
declare("soyokaze_message_is_informational", c_bool, c_void_p)
declare("soyokaze_message_secure", c_bool, c_void_p)
declare("soyokaze_message_set_secure", c_bool, c_void_p, c_bool)
declare("soyokaze_message_header_count", c_size_t, c_void_p)
declare("soyokaze_message_header_name", Slice, c_void_p, c_size_t)
declare("soyokaze_message_header_value", Slice, c_void_p, c_size_t)
declare("soyokaze_message_header", Slice, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_append_header", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_message_insert_header", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_message_remove_header", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_trailer_count", c_size_t, c_void_p)
declare("soyokaze_message_trailer_name", Slice, c_void_p, c_size_t)
declare("soyokaze_message_trailer_value", Slice, c_void_p, c_size_t)
declare("soyokaze_message_trailer", Slice, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_append_trailer", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_message_insert_trailer", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_message_remove_trailer", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_stream_id", c_int64, c_void_p)
declare("soyokaze_message_set_stream_id", c_bool, c_void_p, c_int64)
declare("soyokaze_message_connection_id", Slice, c_void_p)
declare("soyokaze_message_early_data", c_bool, c_void_p)
declare("soyokaze_message_tls", c_bool, c_void_p)
declare("soyokaze_message_tls_version", c_int32, c_void_p)
declare("soyokaze_message_tls_group", c_int32, c_void_p)
declare("soyokaze_message_tls_cipher", c_int32, c_void_p)
declare("soyokaze_message_quic", c_bool, c_void_p)
declare("soyokaze_message_quic_version", c_int64, c_void_p)
declare("soyokaze_message_set_body_data", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_set_body_text", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_set_body_file", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_message_body_len", c_int64, c_void_p)
declare("soyokaze_message_body", c_int32, c_void_p, c_void_p, POINTER(Buffer), POINTER(c_void_p))

# ---------------------------------------------------------------- responses
declare("soyokaze_response_content", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_text", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_html", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_markdown", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_json", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_file", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_response_redirect", c_void_p, c_char_p, c_size_t, c_int32)
declare("soyokaze_message_set_cookie", c_int32, c_void_p, c_void_p, POINTER(c_void_p))
declare("soyokaze_message_delete_cookie", c_int32, c_void_p, c_void_p, POINTER(c_void_p))

# ------------------------------------------------------------------ cookies
declare("soyokaze_cookie_new", c_void_p)
declare("soyokaze_cookie_parse", c_void_p, c_char_p, c_size_t)
declare("soyokaze_cookie_free", None, c_void_p)
declare("soyokaze_cookie_count", c_size_t, c_void_p)
declare("soyokaze_cookie_name", Slice, c_void_p, c_size_t)
declare("soyokaze_cookie_value", Slice, c_void_p, c_size_t)
declare("soyokaze_cookie_get", Slice, c_void_p, c_char_p, c_size_t)
declare("soyokaze_cookie_append", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_cookie_build", Buffer, c_void_p)
declare("soyokaze_setcookie_new", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_setcookie_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_setcookie_free", None, c_void_p)
declare("soyokaze_setcookie_name", Slice, c_void_p)
declare("soyokaze_setcookie_value", Slice, c_void_p)
declare("soyokaze_setcookie_expires", Slice, c_void_p)
declare("soyokaze_setcookie_max_age", c_bool, c_void_p, POINTER(c_int64))
declare("soyokaze_setcookie_domain", Slice, c_void_p)
declare("soyokaze_setcookie_path", Slice, c_void_p)
declare("soyokaze_setcookie_secure", c_bool, c_void_p)
declare("soyokaze_setcookie_httponly", c_bool, c_void_p)
declare("soyokaze_setcookie_samesite", c_int32, c_void_p)
declare("soyokaze_setcookie_set_value", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_setcookie_set_expires", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_setcookie_set_max_age", c_bool, c_void_p, c_bool, c_int64)
declare("soyokaze_setcookie_set_domain", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_setcookie_set_path", c_bool, c_void_p, c_char_p, c_size_t)
declare("soyokaze_setcookie_set_secure", c_bool, c_void_p, c_bool)
declare("soyokaze_setcookie_set_httponly", c_bool, c_void_p, c_bool)
declare("soyokaze_setcookie_set_samesite", c_bool, c_void_p, c_int32)
declare("soyokaze_setcookie_build", c_int32, c_void_p, POINTER(Buffer), POINTER(c_void_p))
declare("soyokaze_cookiejar_new", c_void_p, POINTER(Limits))
declare("soyokaze_cookiejar_free", None, c_void_p)
declare("soyokaze_cookiejar_learn", c_bool, c_void_p, c_void_p, POINTER(Slice), c_size_t)
declare("soyokaze_cookiejar_cookie", Buffer, c_void_p, c_void_p)
declare("soyokaze_cookiejar_prune", None, c_void_p)

# --------------------------------------------------------------------- hsts
declare("soyokaze_hsts_policy_parse", c_bool, c_char_p, c_size_t, POINTER(HstsPolicy))
declare("soyokaze_hsts_policy_build", Buffer, POINTER(HstsPolicy))
declare("soyokaze_hsts_store_new", c_void_p, POINTER(Limits))
declare("soyokaze_hsts_store_free", None, c_void_p)
declare("soyokaze_hsts_store_learn", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_bool)
declare("soyokaze_hsts_store_secure", c_bool, c_void_p, c_char_p, c_size_t)

# ---------------------------------------------------------------------- tls
declare("soyokaze_tls_config_default", TlsConfig)
declare("soyokaze_identity_new", c_void_p, POINTER(Slice), c_size_t, c_char_p, c_size_t)
declare("soyokaze_identity_from_pkcs12", c_int32, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_identity_free", None, c_void_p)
declare("soyokaze_ech_keys_generate", c_int32, c_char_p, c_size_t, c_uint8, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_ech_keys_new", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
declare("soyokaze_ech_keys_free", None, c_void_p)
declare("soyokaze_ech_keys_config", Slice, c_void_p)
declare("soyokaze_ech_keys_private_key", Slice, c_void_p)
declare("soyokaze_ech_keys_config_list", Buffer, c_void_p)
declare("soyokaze_ech_config_list_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_ech_config_list_free", None, c_void_p)
declare("soyokaze_ech_config_list_count", c_size_t, c_void_p)
declare("soyokaze_ech_config_version", c_uint16, c_void_p, c_size_t)
declare("soyokaze_ech_config_public_name", Slice, c_void_p, c_size_t)
declare("soyokaze_ech_config_maximum_name_length", c_int32, c_void_p, c_size_t)

# ------------------------------------------------------------------- client
declare("soyokaze_client_limits_default", ClientLimits)
declare("soyokaze_client_new", c_void_p, POINTER(ClientConfig))
declare("soyokaze_client_free", None, c_void_p)
declare("soyokaze_client_fetch", c_int32, c_void_p, c_void_p, c_int32, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_get", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_head", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_post", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_put", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_delete", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_open", c_int32, c_void_p, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_connect", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(Port), POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_request", c_int32, c_void_p, c_void_p, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_client_websocket", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_connection_version", c_int32, c_void_p)
declare("soyokaze_connection_role", c_uint32, c_void_p)
declare("soyokaze_connection_id", Buffer, c_void_p)
declare("soyokaze_connection_reusable", c_bool, c_void_p)
declare("soyokaze_connection_send", c_int32, c_void_p, c_void_p, c_void_p, POINTER(c_void_p))
declare("soyokaze_connection_receive", c_int32, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_connection_open_websocket", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_connection_close", None, c_void_p, c_void_p)
declare("soyokaze_connection_free", None, c_void_p)

# ---------------------------------------------------------------- websocket
declare("soyokaze_websocket_free", None, c_void_p)
declare("soyokaze_websocket_role", c_uint32, c_void_p)
declare("soyokaze_websocket_closing", c_bool, c_void_p)
declare("soyokaze_websocket_id", Buffer, c_void_p)
declare("soyokaze_websocket_send", c_int32, c_void_p, c_bool, c_uint8, c_char_p, c_size_t, POINTER(c_void_p))
declare("soyokaze_websocket_receive", c_int32, c_void_p, POINTER(c_bool), POINTER(c_uint8), POINTER(Buffer), POINTER(c_void_p))
declare("soyokaze_websocket_send_message", c_int32, c_void_p, c_uint8, c_char_p, c_size_t, POINTER(c_void_p))
declare("soyokaze_websocket_receive_message", c_int32, c_void_p, POINTER(c_uint8), POINTER(Buffer), POINTER(c_void_p))
declare("soyokaze_websocket_close", c_bool, c_void_p, c_uint16, c_char_p, c_size_t)

# ------------------------------------------------------------------- server
declare("soyokaze_server_limits_default", ServerLimits)
declare("soyokaze_cores", c_uint32)
declare("soyokaze_server_new", c_void_p, POINTER(ServerConfig))
declare("soyokaze_server_free", None, c_void_p)
declare("soyokaze_server_serve", c_int32, c_void_p, c_void_p, ON_REQUEST, ON_WEBSOCKET, c_void_p, POINTER(Port), c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_server_handle_port", c_uint16, c_void_p)
declare("soyokaze_server_handle_address_count", c_size_t, c_void_p)
declare("soyokaze_server_handle_port_at", c_uint16, c_void_p, c_size_t)
declare("soyokaze_server_handle_close", None, c_void_p, c_void_p, c_double)
declare("soyokaze_server_run", c_int32, c_void_p, ON_REQUEST, ON_WEBSOCKET, c_void_p, POINTER(Port), c_size_t, c_uint32, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_cluster_port", c_uint16, c_void_p)
declare("soyokaze_cluster_address_count", c_size_t, c_void_p)
declare("soyokaze_cluster_port_at", c_uint16, c_void_p, c_size_t)
declare("soyokaze_cluster_workers", c_uint32, c_void_p)
declare("soyokaze_cluster_close", None, c_void_p, c_double)
declare("soyokaze_response_with_body", c_void_p, c_uint16, c_int32, c_char_p, c_size_t)

# ---------------------------------------------------------------- finalizer
declare("soyokaze_http_date", Buffer, c_uint64)

# ------------------------------------------------------------------ helpers
declare("soyokaze_base64_encode", Buffer, c_char_p, c_size_t)
declare("soyokaze_base64_decode", c_bool, c_char_p, c_size_t, POINTER(Buffer))
declare("soyokaze_sha1", Buffer, c_char_p, c_size_t)
declare("soyokaze_huffman_encode", Buffer, c_char_p, c_size_t)
declare("soyokaze_huffman_decode", c_bool, c_char_p, c_size_t, POINTER(Buffer))
declare("soyokaze_fields_free", None, c_void_p)
declare("soyokaze_fields_count", c_size_t, c_void_p)
declare("soyokaze_fields_name", Slice, c_void_p, c_size_t)
declare("soyokaze_fields_value", Slice, c_void_p, c_size_t)
declare("soyokaze_hpack_encoder_new", c_void_p)
declare("soyokaze_hpack_encoder_free", None, c_void_p)
declare("soyokaze_hpack_encoder_set_max_capacity", c_bool, c_void_p, c_size_t)
declare("soyokaze_hpack_encoder_set_capacity_limit", c_bool, c_void_p, c_size_t)
declare("soyokaze_hpack_encode", Buffer, c_void_p, POINTER(Field), c_size_t)
declare("soyokaze_hpack_decoder_new", c_void_p)
declare("soyokaze_hpack_decoder_free", None, c_void_p)
declare("soyokaze_hpack_decoder_set_max_decoded_size", c_bool, c_void_p, c_size_t)
declare("soyokaze_hpack_decoder_set_max_capacity", c_bool, c_void_p, c_size_t)
declare("soyokaze_hpack_decode", c_int32, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
declare("soyokaze_qpack_encoder_new", c_void_p)
declare("soyokaze_qpack_encoder_free", None, c_void_p)
declare("soyokaze_qpack_encoder_set_max_capacity", c_bool, c_void_p, c_size_t, POINTER(Buffer))
declare("soyokaze_qpack_encoder_set_capacity_limit", c_bool, c_void_p, c_size_t, POINTER(Buffer))
declare("soyokaze_qpack_encoder_set_max_instruction_size", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_encoder_set_max_outstanding_sections", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_encode", c_bool, c_void_p, c_uint64, POINTER(Field), c_size_t, POINTER(Buffer), POINTER(Buffer))
declare("soyokaze_qpack_encoder_on_decoder_instructions", c_int32, c_void_p, c_char_p, c_size_t, POINTER(c_void_p))
declare("soyokaze_qpack_encoder_cancel", c_bool, c_void_p, c_uint64)
declare("soyokaze_qpack_decoder_new", c_void_p)
declare("soyokaze_qpack_decoder_free", None, c_void_p)
declare("soyokaze_qpack_decoder_set_max_decoded_size", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_decoder_set_max_capacity", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_decoder_set_max_instruction_size", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_decoder_set_max_blocked_streams", c_bool, c_void_p, c_size_t)
declare("soyokaze_qpack_decoder_on_encoder_instructions", c_int32, c_void_p, c_char_p, c_size_t, POINTER(Buffer), POINTER(c_void_p))
declare("soyokaze_qpack_decode", c_int32, c_void_p, c_uint64, c_char_p, c_size_t, POINTER(c_void_p), POINTER(Buffer), POINTER(c_void_p))

def take(buffer):
    """The octets a :class:`Buffer` holds, releasing it as they are read."""
    octets = ctypes.string_at(buffer.data, buffer.len) if buffer.data else b""
    library.soyokaze_buffer_free(buffer)
    return octets

def taken(buffer):
    """As :func:`take`, but ``None`` when the buffer's pointer was null.

    For the calls where an absent value and an empty one differ.
    """
    if not buffer.data:
        return None
    return take(buffer)

def encoded(text):
    """Octets for an argument that may be ``str`` or ``bytes``."""
    if isinstance(text, str):
        return text.encode()
    return bytes(text)

def version():
    """The crate's version, as ``MAJOR.MINOR.PATCH``."""
    return library.soyokaze_version().text()
