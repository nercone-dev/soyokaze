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

from ctypes import CFUNCTYPE, POINTER, Structure, c_bool, c_char_p, c_double, c_int32, c_int64, c_size_t, c_ssize_t, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p

class Slice(Structure):
    """A borrowed view of octets: ``soyokaze_slice_t``.

    A ``data`` of null means the value was absent, which is how a lookup that
    found nothing is told apart from one that found an empty value.
    """

    _fields_ = [("data", POINTER(c_uint8)), ("len", c_size_t)]

    @classmethod
    def of(cls, octets):
        """A slice viewing ``octets``, which must stay alive alongside it."""
        if octets is None:
            return cls(None, 0)
        array = (c_uint8 * len(octets)).from_buffer_copy(octets) if octets else None
        view = cls(ctypes.cast(array, POINTER(c_uint8)) if array else None, len(octets))
        view.keepalive = array
        return view

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

    def take(self):
        """The octets held here, releasing the buffer as they are read."""
        octets = ctypes.string_at(self.data, self.len) if self.data else b""
        library.soyokaze_buffer_free(self)
        return octets

    def taken(self):
        """As :meth:`take`, but ``None`` when the buffer's pointer was null.

        For the calls where an absent value and an empty one differ.
        """
        if not self.data:
            return None
        return self.take()

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
        ("max_requests_per_connection", c_uint64),
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

class TLSConfig(Structure):
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

class ECHEntry(Structure):
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
        ("tls", POINTER(TLSConfig)),
        ("ech", POINTER(ECHEntry)),
        ("ech_count", c_size_t),
    ]

class StoredCookie(Structure):
    """A cookie as a jar holds it: ``soyokaze_stored_cookie_t``."""

    _fields_ = [
        ("name", Slice),
        ("value", Slice),
        ("domain", Slice),
        ("host_only", c_bool),
        ("path", Slice),
        ("secure", c_bool),
        ("expires_in", c_double),
    ]

class Security(Structure):
    """What a connection turned out to be underneath: ``soyokaze_security_t``."""

    _fields_ = [
        ("secure", c_bool),
        ("early_data", c_bool),
        ("tls", c_bool),
        ("tls_version", c_int32),
        ("tls_group", c_int32),
        ("tls_cipher", c_int32),
        ("quic", c_bool),
        ("quic_version", c_int64),
    ]

class WebSocketFrameHead(Structure):
    """The head of a frame: ``soyokaze_websocket_frame_head_t``."""

    _fields_ = [
        ("fin", c_bool),
        ("opcode", c_uint8),
        ("masked", c_bool),
        ("mask", c_uint8 * 4),
        ("start", c_size_t),
        ("length", c_size_t),
    ]

class WebSocketLimits(Structure):
    """What one WebSocket connection may spend: ``soyokaze_websocket_limits_t``."""

    _fields_ = [
        ("max_message_size", c_uint64),
        ("ws_max_fragments", c_uint16),
        ("ws_linger_timeout", c_double),
        ("read_timeout", c_double),
        ("write_timeout", c_double),
        ("read_chunk_size", c_uint64),
        ("idle_capacity", c_uint64),
    ]

class HSTSPolicy(Structure):
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
        ("tls", POINTER(TLSConfig)),
        ("ech", c_void_p),
        ("hsts", POINTER(HSTSPolicy)),
        ("reuseport", c_bool),
    ]

class Field(Structure):
    """One field going into an encoder: ``soyokaze_field_t``."""

    _fields_ = [("name", Slice), ("value", Slice)]

class HuffmanSymbol(Structure):
    """One Huffman code word: ``soyokaze_huffman_symbol_t``."""

    _fields_ = [("code", c_uint32), ("length", c_uint8)]

class HuffmanTransition(Structure):
    """One step of the Huffman decoding automaton: ``soyokaze_huffman_transition_t``."""

    _fields_ = [("next", c_uint16), ("symbol", c_uint8), ("flags", c_uint8)]

class H1Limits(Structure):
    """What one HTTP/1.x connection may spend: ``soyokaze_h1_limits_t``."""

    _fields_ = [
        ("max_message_size", c_uint64),
        ("max_message_body_size", c_uint64),
        ("max_startline_size", c_uint32),
        ("max_headers_size", c_uint64),
        ("max_header_count", c_uint16),
        ("max_chunk_header_size", c_uint32),
        ("inline_body_size", c_uint64),
        ("max_concurrent_streams", c_uint32),
        ("read_chunk_size", c_uint64),
        ("idle_capacity", c_uint64),
        ("read_timeout", c_double),
        ("write_timeout", c_double),
        ("receive_timeout", c_double),
        ("send_timeout", c_double),
    ]

class H2Limits(Structure):
    """What one HTTP/2 connection may spend: ``soyokaze_h2_limits_t``."""

    _fields_ = [
        ("max_message_size", c_uint64),
        ("max_message_body_size", c_uint64),
        ("max_headers_size", c_uint64),
        ("max_header_count", c_uint16),
        ("max_concurrent_streams", c_uint32),
        ("max_connection_buffer_size", c_uint64),
        ("max_premature_resets", c_uint32),
        ("max_idle_frames", c_uint32),
        ("output_high_water", c_uint64),
        ("max_encoder_table_size", c_uint64),
        ("read_chunk_size", c_uint64),
        ("idle_capacity", c_uint64),
        ("read_timeout", c_double),
        ("write_timeout", c_double),
        ("receive_timeout", c_double),
        ("send_timeout", c_double),
    ]

class H3Limits(Structure):
    """What one HTTP/3 connection may spend: ``soyokaze_h3_limits_t``."""

    _fields_ = [
        ("max_message_size", c_uint64),
        ("max_message_body_size", c_uint64),
        ("max_headers_size", c_uint64),
        ("max_header_count", c_uint16),
        ("max_concurrent_streams", c_uint32),
        ("max_connection_buffer_size", c_uint64),
        ("max_premature_resets", c_uint32),
        ("max_requests_per_connection", c_uint64),
        ("max_encoder_table_size", c_uint64),
        ("qpack_block_timeout", c_double),
        ("max_peer_uni_streams", c_uint32),
        ("max_outstanding_sections", c_uint32),
        ("max_blocked_streams", c_uint32),
        ("tunnel_backlog", c_uint32),
        ("command_backlog", c_uint32),
        ("idle_capacity", c_uint64),
        ("receive_timeout", c_double),
        ("send_timeout", c_double),
    ]

class H2FrameHeader(Structure):
    """The head of an HTTP/2 frame: ``soyokaze_h2_frame_header_t``."""

    _fields_ = [("length", c_uint32), ("kind", c_int32), ("flags", c_uint8), ("stream_id", c_uint64)]

class H2Parameter(Structure):
    """One HTTP/2 settings parameter: ``soyokaze_h2_parameter_t``."""

    _fields_ = [("id", c_uint16), ("value", c_uint32)]

class H2Settings(Structure):
    """The HTTP/2 connection parameters: ``soyokaze_h2_settings_t``."""

    _fields_ = [
        ("header_table_size", c_uint32),
        ("enable_push", c_bool),
        ("max_concurrent_streams", c_int64),
        ("initial_window_size", c_uint32),
        ("max_frame_size", c_uint32),
        ("max_header_list_size", c_int64),
        ("enable_connect_protocol", c_bool),
    ]

class H3Parameter(Structure):
    """One HTTP/3 settings parameter: ``soyokaze_h3_parameter_t``."""

    _fields_ = [("id", c_uint64), ("value", c_uint64)]

class H3Settings(Structure):
    """The HTTP/3 connection parameters: ``soyokaze_h3_settings_t``."""

    _fields_ = [
        ("qpack_max_table_capacity", c_uint64),
        ("qpack_blocked_streams", c_uint64),
        ("max_field_section_size", c_int64),
        ("enable_connect_protocol", c_bool),
    ]

ON_REQUEST = CFUNCTYPE(c_void_p, c_void_p, c_void_p)
ON_WEBSOCKET = CFUNCTYPE(None, c_void_p, c_void_p)

class Library:
    """The shared library the bindings call through, and how it is reached."""

    @classmethod
    def locate(cls):
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

    @classmethod
    def load(cls):
        """The shared library, tried candidate by candidate.

        A candidate the loader rejects — a stale artifact, a wrong
        architecture — is skipped rather than fatal, so a good build elsewhere
        still loads.
        """
        failures = []

        for candidate in cls.locate():
            try:
                return ctypes.CDLL(candidate)
            except OSError as failure:
                failures.append(str(failure))

        listed = "".join(f"\n  - {failure}" for failure in failures)
        raise OSError(f"the soyokaze shared library was not loaded; build it with `cargo build` or point SOYOKAZE_LIBRARY at it{listed}")

    @classmethod
    def declare(cls, name, restype, *argtypes):
        """Declares one exported function's signature and returns it."""
        function = getattr(library, name)
        function.restype = restype
        function.argtypes = list(argtypes)
        return function

    @classmethod
    def encoded(cls, text):
        """Octets for an argument that may be ``str`` or ``bytes``."""
        if isinstance(text, str):
            return text.encode()
        return bytes(text)

    @classmethod
    def version(cls):
        """The crate's version, as ``MAJOR.MINOR.PATCH``."""
        return library.soyokaze_version().text()

library = Library.load()


# ------------------------------------------------------------------- common
Library.declare("soyokaze_buffer_free", None, Buffer)
Library.declare("soyokaze_version", Slice)
Library.declare("soyokaze_limits_default", Limits)
Library.declare("soyokaze_runtime_new", c_void_p, c_uint32)
Library.declare("soyokaze_runtime_free", None, c_void_p)

# ------------------------------------------------------------------- errors
Library.declare("soyokaze_error_free", None, c_void_p)
Library.declare("soyokaze_error_status", c_int32, c_void_p)
Library.declare("soyokaze_error_message", Slice, c_void_p)
Library.declare("soyokaze_error_stream_id", c_int64, c_void_p)
Library.declare("soyokaze_error_code", c_int64, c_void_p)
Library.declare("soyokaze_status_message", Slice, c_int32)
Library.declare("soyokaze_error_reason", Slice, c_void_p)
Library.declare("soyokaze_error_new", c_void_p, c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_error_stream", c_void_p, c_uint64, c_uint64, c_char_p, c_size_t)
Library.declare("soyokaze_error_tls", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_error_quic", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_error_on_stream", c_void_p, c_void_p, c_uint64, c_uint64)

# --------------------------------------------------------------- vocabulary
Library.declare("soyokaze_port_transport", c_int32, POINTER(Port))
Library.declare("soyokaze_port_carries", c_bool, POINTER(Port), c_int32)
Library.declare("soyokaze_port_offers", c_size_t, POINTER(Port), POINTER(c_int32), c_size_t, POINTER(c_int32))
Library.declare("soyokaze_version_alpn", Slice, c_int32)
Library.declare("soyokaze_version_from_alpn", c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_version_major", c_uint8, c_int32)
Library.declare("soyokaze_version_transport", c_int32, c_int32)
Library.declare("soyokaze_version_name", Slice, c_int32)
Library.declare("soyokaze_version_parse", c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_alpn_wire", Buffer, POINTER(c_int32), c_size_t)
Library.declare("soyokaze_alpn_select", Slice, POINTER(c_int32), c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_alpn_negotiated", c_int32, c_char_p, c_size_t, POINTER(c_int32), c_size_t, POINTER(c_int32), POINTER(c_void_p))
Library.declare("soyokaze_method_name", Slice, c_int32)
Library.declare("soyokaze_method_parse", c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_method_safe", c_bool, c_int32)
Library.declare("soyokaze_method_idempotent", c_bool, c_int32)
Library.declare("soyokaze_role_is_client", c_bool, c_int32)
Library.declare("soyokaze_role_is_server", c_bool, c_int32)
Library.declare("soyokaze_header_case_from_version", c_int32, c_int32)
Library.declare("soyokaze_header_case_apply", Buffer, c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_header_case_apply_in_place", c_bool, c_int32, POINTER(c_uint8), c_size_t)

# ------------------------------------------------------------------ headers
Library.declare("soyokaze_headers_well_known", c_uint32, c_char_p, c_size_t)
Library.declare("soyokaze_headers_bit", c_uint32, c_bool, c_uint32)
Library.declare("soyokaze_headers_named", c_bool, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_headers_new", c_void_p)
Library.declare("soyokaze_headers_with_capacity", c_void_p, c_size_t)
Library.declare("soyokaze_headers_free", None, c_void_p)
Library.declare("soyokaze_headers_len", c_size_t, c_void_p)
Library.declare("soyokaze_headers_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_headers_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_headers_value", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_headers_contains", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_headers_absent", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_headers_get", Slice, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_headers_get_all_count", c_size_t, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_headers_get_all", Slice, c_void_p, c_char_p, c_size_t, c_size_t)
Library.declare("soyokaze_headers_append", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_headers_append_lowercase", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_headers_insert", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_headers_remove", c_bool, c_void_p, c_char_p, c_size_t)

# ---------------------------------------------------------------------- url
Library.declare("soyokaze_url_default_port", c_uint16, c_char_p, c_size_t)
Library.declare("soyokaze_url_authority_of", Buffer, c_char_p, c_size_t, c_char_p, c_size_t, c_uint16)
Library.declare("soyokaze_url_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_url_free", None, c_void_p)
Library.declare("soyokaze_url_scheme", Slice, c_void_p)
Library.declare("soyokaze_url_host", Slice, c_void_p)
Library.declare("soyokaze_url_target", Slice, c_void_p)
Library.declare("soyokaze_url_port", c_uint16, c_void_p)
Library.declare("soyokaze_url_secure", c_bool, c_void_p)
Library.declare("soyokaze_url_authority", Buffer, c_void_p)

# ------------------------------------------------------------------ message
Library.declare("soyokaze_message_new", c_void_p, c_int32)
Library.declare("soyokaze_message_request", c_void_p, c_int32, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_message_response", c_void_p, c_uint16, c_int32)
Library.declare("soyokaze_message_free", None, c_void_p)
Library.declare("soyokaze_message_version", c_int32, c_void_p)
Library.declare("soyokaze_message_method", c_int32, c_void_p)
Library.declare("soyokaze_message_status_code", c_int32, c_void_p)
Library.declare("soyokaze_message_target", Slice, c_void_p)
Library.declare("soyokaze_message_is_request", c_bool, c_void_p)
Library.declare("soyokaze_message_is_response", c_bool, c_void_p)
Library.declare("soyokaze_message_is_informational", c_bool, c_void_p)
Library.declare("soyokaze_message_secure", c_bool, c_void_p)
Library.declare("soyokaze_message_set_secure", c_bool, c_void_p, c_bool)
Library.declare("soyokaze_message_header_count", c_size_t, c_void_p)
Library.declare("soyokaze_message_header_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_message_header_value", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_message_header", Slice, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_append_header", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_message_insert_header", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_message_remove_header", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_trailer_count", c_size_t, c_void_p)
Library.declare("soyokaze_message_trailer_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_message_trailer_value", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_message_trailer", Slice, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_append_trailer", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_message_insert_trailer", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_message_remove_trailer", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_set_version", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_message_set_method", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_message_set_target", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_set_status_code", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_message_tunneling", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_message_headers", c_void_p, c_void_p)
Library.declare("soyokaze_message_trailers", c_void_p, c_void_p)
Library.declare("soyokaze_message_stream_id", c_int64, c_void_p)
Library.declare("soyokaze_message_set_stream_id", c_bool, c_void_p, c_int64)
Library.declare("soyokaze_message_connection_id", Slice, c_void_p)
Library.declare("soyokaze_message_set_connection_id", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_early_data", c_bool, c_void_p)
Library.declare("soyokaze_message_tls", c_bool, c_void_p)
Library.declare("soyokaze_message_tls_version", c_int32, c_void_p)
Library.declare("soyokaze_message_tls_group", c_int32, c_void_p)
Library.declare("soyokaze_message_tls_cipher", c_int32, c_void_p)
Library.declare("soyokaze_message_quic", c_bool, c_void_p)
Library.declare("soyokaze_message_quic_version", c_int64, c_void_p)
Library.declare("soyokaze_message_set_body_data", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_set_body_text", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_set_body_file", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_message_clear_body", c_bool, c_void_p)
Library.declare("soyokaze_message_body_kind", c_int32, c_void_p)
Library.declare("soyokaze_message_body_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_message_body_inline", Slice, c_void_p)
Library.declare("soyokaze_message_body_path", Slice, c_void_p)
Library.declare("soyokaze_message_body_len", c_int64, c_void_p)
Library.declare("soyokaze_message_body", c_int32, c_void_p, c_void_p, POINTER(Buffer), POINTER(c_void_p))

# ---------------------------------------------------------------- responses
Library.declare("soyokaze_response_with_body", c_void_p, c_uint16, c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_response_content", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_text", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_html", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_markdown", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_json", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_file", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_response_redirect", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_message_set_cookie", c_int32, c_void_p, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_message_delete_cookie", c_int32, c_void_p, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_status_reason", Slice, c_uint16)
Library.declare("soyokaze_content_type", Slice, c_char_p, c_size_t)
Library.declare("soyokaze_response_upgrade_required", c_void_p, c_void_p, c_int32, c_char_p, c_size_t)

# ------------------------------------------------------------------ cookies
Library.declare("soyokaze_cookie_new", c_void_p)
Library.declare("soyokaze_cookie_parse", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_cookie_free", None, c_void_p)
Library.declare("soyokaze_cookie_count", c_size_t, c_void_p)
Library.declare("soyokaze_cookie_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_cookie_value", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_cookie_get", Slice, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_cookie_append", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_cookie_build", Buffer, c_void_p)
Library.declare("soyokaze_setcookie_new", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_setcookie_free", None, c_void_p)
Library.declare("soyokaze_setcookie_name", Slice, c_void_p)
Library.declare("soyokaze_setcookie_value", Slice, c_void_p)
Library.declare("soyokaze_setcookie_expires", Slice, c_void_p)
Library.declare("soyokaze_setcookie_max_age", c_bool, c_void_p, POINTER(c_int64))
Library.declare("soyokaze_setcookie_domain", Slice, c_void_p)
Library.declare("soyokaze_setcookie_path", Slice, c_void_p)
Library.declare("soyokaze_setcookie_secure", c_bool, c_void_p)
Library.declare("soyokaze_setcookie_httponly", c_bool, c_void_p)
Library.declare("soyokaze_setcookie_samesite", c_int32, c_void_p)
Library.declare("soyokaze_setcookie_set_value", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_set_expires", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_set_max_age", c_bool, c_void_p, c_bool, c_int64)
Library.declare("soyokaze_setcookie_set_domain", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_set_path", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_set_secure", c_bool, c_void_p, c_bool)
Library.declare("soyokaze_setcookie_set_httponly", c_bool, c_void_p, c_bool)
Library.declare("soyokaze_setcookie_set_samesite", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_setcookie_build", c_int32, c_void_p, POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_cookiejar_new", c_void_p, POINTER(Limits))
Library.declare("soyokaze_cookiejar_free", None, c_void_p)
Library.declare("soyokaze_cookiejar_learn", c_bool, c_void_p, c_void_p, POINTER(Slice), c_size_t)
Library.declare("soyokaze_cookiejar_cookie", Buffer, c_void_p, c_void_p)
Library.declare("soyokaze_cookiejar_prune", None, c_void_p)
Library.declare("soyokaze_cookie_default_max_cookies", c_uint32)
Library.declare("soyokaze_cookie_default_max_cookies_per_domain", c_uint16)
Library.declare("soyokaze_cookie_is_separator", c_bool, c_uint8)
Library.declare("soyokaze_samesite_name", Slice, c_int32)
Library.declare("soyokaze_samesite_parse", c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_setcookie_age", c_bool, c_char_p, c_size_t, POINTER(c_int64))
Library.declare("soyokaze_cookie_path_matches", c_bool, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_cookie_default_path", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_cookiejar_count", c_size_t, c_void_p)
Library.declare("soyokaze_cookiejar_max_cookies", c_uint32, c_void_p)
Library.declare("soyokaze_cookiejar_max_cookies_per_domain", c_uint16, c_void_p)
Library.declare("soyokaze_cookiejar_entry", c_bool, c_void_p, c_size_t, POINTER(StoredCookie), POINTER(Buffer))

# --------------------------------------------------------------------- hsts
Library.declare("soyokaze_hsts_policy_parse", c_bool, c_char_p, c_size_t, POINTER(HSTSPolicy))
Library.declare("soyokaze_hsts_policy_build", Buffer, POINTER(HSTSPolicy))
Library.declare("soyokaze_hsts_store_new", c_void_p, POINTER(Limits))
Library.declare("soyokaze_hsts_store_free", None, c_void_p)
Library.declare("soyokaze_hsts_store_learn", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_bool)
Library.declare("soyokaze_hsts_store_secure", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_hsts_store_prune", None, c_void_p)
Library.declare("soyokaze_hsts_default_max_entries", c_uint32)
Library.declare("soyokaze_hsts_policy_new", HSTSPolicy, c_int64)
Library.declare("soyokaze_hsts_normalize", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_hsts_store_len", c_size_t, c_void_p)
Library.declare("soyokaze_hsts_store_max_entries", c_uint32, c_void_p)

# ---------------------------------------------------------------------- tls
Library.declare("soyokaze_tls_config_default", TLSConfig)
Library.declare("soyokaze_identity_new", c_void_p, POINTER(Slice), c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_identity_from_pkcs12", c_int32, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_identity_free", None, c_void_p)
Library.declare("soyokaze_ech_keys_generate", c_int32, c_char_p, c_size_t, c_uint8, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_ech_keys_new", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_ech_keys_free", None, c_void_p)
Library.declare("soyokaze_ech_keys_config", Slice, c_void_p)
Library.declare("soyokaze_ech_keys_private_key", Slice, c_void_p)
Library.declare("soyokaze_ech_keys_config_list", Buffer, c_void_p)
Library.declare("soyokaze_ech_config_list_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_ech_config_list_free", None, c_void_p)
Library.declare("soyokaze_ech_config_list_count", c_size_t, c_void_p)
Library.declare("soyokaze_ech_config_version", c_uint16, c_void_p, c_size_t)
Library.declare("soyokaze_ech_config_public_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_ech_config_maximum_name_length", c_int32, c_void_p, c_size_t)
Library.declare("soyokaze_tls_version_1_3", c_uint16)
Library.declare("soyokaze_format_sequence", c_uint8)
Library.declare("soyokaze_format_of", c_int32, c_char_p, c_size_t)
Library.declare("soyokaze_format_certificate_count", c_ssize_t, c_char_p, c_size_t)
Library.declare("soyokaze_format_certificate", Buffer, c_char_p, c_size_t, c_size_t)
Library.declare("soyokaze_format_private_key", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_security_default", Security)
Library.declare("soyokaze_security_quic", Security, c_int64)
Library.declare("soyokaze_security_apply", c_bool, POINTER(Security), c_void_p)
Library.declare("soyokaze_message_security", Security, c_void_p)
Library.declare("soyokaze_ech_config_supported_version", c_uint16)
Library.declare("soyokaze_ech_kem_x25519_hkdf_sha256", c_uint16)
Library.declare("soyokaze_ech_kdf_hkdf_sha256", c_uint16)
Library.declare("soyokaze_ech_aead_aes_128_gcm", c_uint16)
Library.declare("soyokaze_ech_maximum_name_length", c_uint8)
Library.declare("soyokaze_ech_keys_encode", Buffer, c_char_p, c_size_t, c_uint8, c_char_p, c_size_t)
Library.declare("soyokaze_identity_certificate_count", c_ssize_t, c_void_p)
Library.declare("soyokaze_identity_certificate", Buffer, c_void_p, c_size_t)
Library.declare("soyokaze_identity_private_key", Buffer, c_void_p)

# ------------------------------------------------------------------- client
Library.declare("soyokaze_versions_count", c_size_t)
Library.declare("soyokaze_versions_at", c_int32, c_size_t)
Library.declare("soyokaze_versions", POINTER(c_int32))
Library.declare("soyokaze_gate_new", c_void_p, c_uint32, c_uint32, POINTER(Rate), c_size_t, c_size_t)
Library.declare("soyokaze_gate_free", None, c_void_p)
Library.declare("soyokaze_gate_count", c_uint32, c_void_p)
Library.declare("soyokaze_gate_max_connections", c_uint32, c_void_p)
Library.declare("soyokaze_gate_max_connections_per_ip", c_uint32, c_void_p)
Library.declare("soyokaze_gate_max_connection_history", c_size_t, c_void_p)
Library.declare("soyokaze_gate_rate_count", c_size_t, c_void_p)
Library.declare("soyokaze_gate_rate", Rate, c_void_p, c_size_t)
Library.declare("soyokaze_gate_window", c_double, c_void_p)
Library.declare("soyokaze_gate_count_for", c_uint32, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_gate_admit", c_void_p, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_gate_sweep", None, c_void_p)
Library.declare("soyokaze_permit_free", None, c_void_p)
Library.declare("soyokaze_permit_address", Buffer, c_void_p)
Library.declare("soyokaze_permit_gate", c_void_p, c_void_p)

Library.declare("soyokaze_client_limits_default", ClientLimits)
Library.declare("soyokaze_client_id", Buffer, c_void_p, c_char_p, c_size_t, POINTER(Port))
Library.declare("soyokaze_client_authority", Buffer, c_void_p, c_char_p, c_size_t, POINTER(Port))
Library.declare("soyokaze_client_ech", Slice, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_client_prior_version", c_int32, c_void_p, POINTER(c_int32), POINTER(c_void_p))
Library.declare("soyokaze_client_only_quic", c_bool, c_void_p)
Library.declare("soyokaze_client_version_count", c_size_t, c_void_p)
Library.declare("soyokaze_client_version_at", c_int32, c_void_p, c_size_t)
Library.declare("soyokaze_client_jar", c_void_p, c_void_p)
Library.declare("soyokaze_client_store", c_void_p, c_void_p)
Library.declare("soyokaze_client_apply_hsts", c_bool, c_void_p, c_void_p)
Library.declare("soyokaze_client_request_finalizer", c_void_p, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_client_new", c_void_p, POINTER(ClientConfig))
Library.declare("soyokaze_client_free", None, c_void_p)
Library.declare("soyokaze_client_fetch", c_int32, c_void_p, c_void_p, c_int32, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_get", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_head", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_post", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_put", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_delete", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_open", c_int32, c_void_p, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_connect", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(Port), POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_request", c_int32, c_void_p, c_void_p, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_client_websocket", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_connection_version", c_int32, c_void_p)
Library.declare("soyokaze_connection_role", c_uint32, c_void_p)
Library.declare("soyokaze_connection_id", Buffer, c_void_p)
Library.declare("soyokaze_connection_reusable", c_bool, c_void_p)
Library.declare("soyokaze_connection_send", c_int32, c_void_p, c_void_p, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_connection_receive", c_int32, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_connection_open_websocket", c_int32, c_void_p, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_connection_close", None, c_void_p, c_void_p)
Library.declare("soyokaze_connection_free", None, c_void_p)

# ---------------------------------------------------------------- websocket
Library.declare("soyokaze_websocket_free", None, c_void_p)
Library.declare("soyokaze_websocket_role", c_uint32, c_void_p)
Library.declare("soyokaze_websocket_closing", c_bool, c_void_p)
Library.declare("soyokaze_websocket_id", Buffer, c_void_p)
Library.declare("soyokaze_websocket_send", c_int32, c_void_p, c_bool, c_uint8, c_char_p, c_size_t, POINTER(c_void_p))
Library.declare("soyokaze_websocket_receive", c_int32, c_void_p, POINTER(c_bool), POINTER(c_uint8), POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_websocket_send_message", c_int32, c_void_p, c_uint8, c_char_p, c_size_t, POINTER(c_void_p))
Library.declare("soyokaze_websocket_receive_message", c_int32, c_void_p, POINTER(c_uint8), POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_websocket_close", c_bool, c_void_p, c_uint16, c_char_p, c_size_t)
Library.declare("soyokaze_websocket_guid", Slice)
Library.declare("soyokaze_websocket_version", Slice)
Library.declare("soyokaze_websocket_protocol", Slice)
Library.declare("soyokaze_websocket_maximum_control_payload", c_size_t)
Library.declare("soyokaze_websocket_opcode_known", c_bool, c_uint8)
Library.declare("soyokaze_websocket_opcode_control", c_bool, c_uint8)
Library.declare("soyokaze_websocket_close_code_known", c_bool, c_uint16)
Library.declare("soyokaze_websocket_close_code_permitted", c_bool, c_uint16)
Library.declare("soyokaze_websocket_random", c_bool, POINTER(c_uint8), c_size_t)
Library.declare("soyokaze_websocket_masking_key", Buffer)
Library.declare("soyokaze_websocket_apply_mask", c_bool, c_char_p, POINTER(c_uint8), c_size_t)
Library.declare("soyokaze_websocket_frame_head", c_int32, c_char_p, c_size_t, POINTER(WebSocketFrameHead), POINTER(c_void_p))
Library.declare("soyokaze_websocket_frame_encode", Buffer, c_bool, c_uint8, c_char_p, c_char_p, c_size_t)
Library.declare("soyokaze_websocket_frame_decode", c_int32, c_char_p, c_size_t, POINTER(WebSocketFrameHead), POINTER(Buffer), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_websocket_accept_key", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_websocket_nonce", Buffer)
Library.declare("soyokaze_websocket_upgrade_request", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_websocket_upgrade_response", c_void_p, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_websocket_verify_upgrade_request", c_int32, c_void_p, POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_websocket_verify_upgrade_response", c_int32, c_void_p, c_char_p, c_size_t, POINTER(c_void_p))
Library.declare("soyokaze_websocket_connect_request", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_websocket_connect_response", c_void_p, c_int32)
Library.declare("soyokaze_websocket_verify_connect_request", c_int32, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_websocket_verify_connect_response", c_int32, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_websocket_requested", c_bool, c_void_p)
Library.declare("soyokaze_websocket_verify", c_int32, c_void_p, POINTER(c_void_p))
Library.declare("soyokaze_websocket_refusal", c_void_p, c_void_p, c_int32)
Library.declare("soyokaze_websocket_token_present", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_websocket_limits_default", WebSocketLimits)
Library.declare("soyokaze_websocket_limits_of", WebSocketLimits, POINTER(Limits))
Library.declare("soyokaze_websocket_limits", WebSocketLimits, c_void_p)

# ------------------------------------------------------------------- server
Library.declare("soyokaze_server_limits_default", ServerLimits)
Library.declare("soyokaze_cores", c_uint32)
Library.declare("soyokaze_server_new", c_void_p, POINTER(ServerConfig))
Library.declare("soyokaze_server_free", None, c_void_p)
Library.declare("soyokaze_server_serve", c_int32, c_void_p, c_void_p, ON_REQUEST, ON_WEBSOCKET, c_void_p, POINTER(Port), c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_server_handle_port", c_uint16, c_void_p)
Library.declare("soyokaze_server_handle_address_count", c_size_t, c_void_p)
Library.declare("soyokaze_server_handle_port_at", c_uint16, c_void_p, c_size_t)
Library.declare("soyokaze_server_handle_close", None, c_void_p, c_void_p, c_double)
Library.declare("soyokaze_server_run", c_int32, c_void_p, ON_REQUEST, ON_WEBSOCKET, c_void_p, POINTER(Port), c_size_t, c_uint32, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_cluster_port", c_uint16, c_void_p)
Library.declare("soyokaze_cluster_address_count", c_size_t, c_void_p)
Library.declare("soyokaze_cluster_port_at", c_uint16, c_void_p, c_size_t)
Library.declare("soyokaze_cluster_workers", c_uint32, c_void_p)
Library.declare("soyokaze_cluster_close", None, c_void_p, c_double)
Library.declare("soyokaze_cluster_address_at", Buffer, c_void_p, c_size_t)
Library.declare("soyokaze_server_handle_address_at", Buffer, c_void_p, c_size_t)
Library.declare("soyokaze_server_version_count", c_size_t, c_void_p)
Library.declare("soyokaze_server_version_at", c_int32, c_void_p, c_size_t)
Library.declare("soyokaze_server_reuseport", c_bool, c_void_p)
Library.declare("soyokaze_server_limits_gate", c_void_p, POINTER(ServerLimits))
Library.declare("soyokaze_server_open", c_int32, c_void_p, POINTER(Port), POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_raw_socket_free", None, c_void_p)
Library.declare("soyokaze_raw_socket_address", Buffer, c_void_p)
Library.declare("soyokaze_raw_socket_port", c_uint16, c_void_p)
Library.declare("soyokaze_raw_socket_share", c_int32, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_raw_socket_descriptor", c_int32, c_void_p)

# ---------------------------------------------------------------- finalizer
Library.declare("soyokaze_http_date", Buffer, c_uint64)
Library.declare("soyokaze_date_length", c_size_t)
Library.declare("soyokaze_day_name", Slice, c_size_t)
Library.declare("soyokaze_month_name", Slice, c_size_t)
Library.declare("soyokaze_civil_from_days", None, c_int64, POINTER(c_int64), POINTER(c_uint32), POINTER(c_uint32))
Library.declare("soyokaze_date_cache_new", c_void_p)
Library.declare("soyokaze_date_cache_free", None, c_void_p)
Library.declare("soyokaze_date_cache_now", Buffer, c_void_p)
Library.declare("soyokaze_response_finalizer_new", c_void_p, POINTER(HSTSPolicy))
Library.declare("soyokaze_response_finalizer_free", None, c_void_p)
Library.declare("soyokaze_response_finalizer_finalize", c_bool, c_void_p, c_int32, c_bool, c_void_p)
Library.declare("soyokaze_request_finalizer_new", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_request_finalizer_free", None, c_void_p)
Library.declare("soyokaze_request_finalizer_authority", Slice, c_void_p)
Library.declare("soyokaze_request_finalizer_finalize", c_bool, c_void_p, c_int32, c_void_p)
Library.declare("soyokaze_message_finalize_response", c_bool, c_void_p, c_void_p, POINTER(HSTSPolicy))
Library.declare("soyokaze_message_finalize_request", c_bool, c_void_p, c_char_p, c_size_t)

# ----------------------------------------------------------------- protocol
Library.declare("soyokaze_read_buffer_default_chunk_size", c_size_t)
Library.declare("soyokaze_read_buffer_chunk_ramp", c_size_t)
Library.declare("soyokaze_read_buffer_oversized", c_bool, c_size_t, c_size_t, c_size_t)
Library.declare("soyokaze_read_buffer_new", c_void_p)
Library.declare("soyokaze_read_buffer_with_chunk_size", c_void_p, c_size_t)
Library.declare("soyokaze_read_buffer_free", None, c_void_p)
Library.declare("soyokaze_read_buffer_chunk_size", c_size_t, c_void_p)
Library.declare("soyokaze_read_buffer_set_chunk_size", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_read_buffer_len", c_size_t, c_void_p)
Library.declare("soyokaze_read_buffer_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_read_buffer_eof", c_bool, c_void_p)
Library.declare("soyokaze_read_buffer_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_read_buffer_bytes", Slice, c_void_p)
Library.declare("soyokaze_read_buffer_extend", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_read_buffer_consume", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_read_buffer_take", Buffer, c_void_p, c_size_t)
Library.declare("soyokaze_read_buffer_reclaim", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_pseudo_request_count", c_size_t)
Library.declare("soyokaze_pseudo_request_name", Slice, c_size_t)
Library.declare("soyokaze_pseudo_response_count", c_size_t)
Library.declare("soyokaze_pseudo_response_name", Slice, c_size_t)
Library.declare("soyokaze_connection_specific_count", c_size_t)
Library.declare("soyokaze_connection_specific_name", Slice, c_size_t)
Library.declare("soyokaze_connection_specific", c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_pseudo_status", Buffer, c_uint16)
Library.declare("soyokaze_fields_of_message", c_int32, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_fields_to_message", c_int32, c_void_p, c_int32, POINTER(c_void_p), POINTER(c_void_p))

Library.declare("soyokaze_varint_maximum", c_uint64)
Library.declare("soyokaze_varint_max_size", c_size_t)
Library.declare("soyokaze_varint_len", c_size_t, c_uint64)
Library.declare("soyokaze_varint_encode", Buffer, c_uint64)
Library.declare("soyokaze_varint_decode", c_bool, c_char_p, c_size_t, POINTER(c_uint64), POINTER(c_size_t))
Library.declare("soyokaze_varint_only", c_int32, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_uint64), POINTER(c_void_p))
Library.declare("soyokaze_quic_stream_step", c_uint64)
Library.declare("soyokaze_quic_stream_is_bidi", c_bool, c_uint64)
Library.declare("soyokaze_quic_stream_is_uni", c_bool, c_uint64)
Library.declare("soyokaze_quic_stream_client_initiated", c_bool, c_uint64)
Library.declare("soyokaze_quic_stream_first_bidi", c_uint64, c_int32)
Library.declare("soyokaze_quic_stream_first_uni", c_uint64, c_int32)
Library.declare("soyokaze_quic_handshake_negotiated", c_int32, c_char_p, c_size_t, POINTER(c_int32), c_size_t, POINTER(c_int32), POINTER(c_void_p))
Library.declare("soyokaze_quic_handshake_security", Security, c_uint32)

Library.declare("soyokaze_h1_limits_default", H1Limits)
Library.declare("soyokaze_h1_limits_of", H1Limits, POINTER(Limits))
Library.declare("soyokaze_h1_token", c_uint8)
Library.declare("soyokaze_h1_field", c_uint8)
Library.declare("soyokaze_h1_octet_table", Slice)
Library.declare("soyokaze_h1_is_control", c_bool, c_uint8)
Library.declare("soyokaze_h1_is_token", c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_h1_keep_alive", c_bool, c_void_p, c_int32)
Library.declare("soyokaze_h1_start_line_encode", Buffer, c_void_p)
Library.declare("soyokaze_h1_start_line_parse", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_h1_start_line_error_status", c_uint16, c_char_p, c_size_t)
Library.declare("soyokaze_h1_version_parse", c_int32, c_char_p, c_size_t, POINTER(c_int32), POINTER(c_void_p))
Library.declare("soyokaze_h1_field_encode", Buffer, c_char_p, c_size_t, c_char_p, c_size_t, c_int32)
Library.declare("soyokaze_h1_field_encode_all", Buffer, c_void_p, c_int32)
Library.declare("soyokaze_h1_field_size", c_uint64, c_void_p)
Library.declare("soyokaze_h1_field_parse", c_int32, c_char_p, c_size_t, POINTER(Buffer), POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_h1_field_parse_block", c_int32, c_char_p, c_size_t, c_size_t, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_h1_field_block_end", c_bool, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t))
Library.declare("soyokaze_h1_chunk_encode", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_h1_chunk_parse_size", c_int32, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_h1_chunk_decode", c_int32, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_size_t), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_h1_body_length", c_int32, c_void_p, c_int32, POINTER(c_int32), POINTER(c_uint64), POINTER(c_void_p))
Library.declare("soyokaze_h1_content_length", c_int32, c_char_p, c_size_t, POINTER(c_uint64), POINTER(c_void_p))
Library.declare("soyokaze_h1_decimal", Buffer, c_uint64)
Library.declare("soyokaze_h1_hexadecimal", Buffer, c_uint64)

Library.declare("soyokaze_h2_limits_default", H2Limits)
Library.declare("soyokaze_h2_limits_of", H2Limits, POINTER(Limits))
Library.declare("soyokaze_h2_preface", Slice)
Library.declare("soyokaze_h2_flag_end_stream", c_uint8)
Library.declare("soyokaze_h2_flag_ack", c_uint8)
Library.declare("soyokaze_h2_flag_end_headers", c_uint8)
Library.declare("soyokaze_h2_flag_padded", c_uint8)
Library.declare("soyokaze_h2_flag_priority", c_uint8)
Library.declare("soyokaze_h2_frame_type_known", c_bool, c_uint8)
Library.declare("soyokaze_h2_frame_type_streamed", c_int32, c_int32)
Library.declare("soyokaze_h2_header_size", c_size_t)
Library.declare("soyokaze_h2_header_encode", Buffer, H2FrameHeader)
Library.declare("soyokaze_h2_header_decode", c_bool, c_char_p, c_size_t, POINTER(H2FrameHeader), POINTER(c_uint32))
Library.declare("soyokaze_h2_frame_data", c_void_p, c_uint64, c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_h2_frame_headers", c_void_p, c_uint64, c_bool, c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_h2_frame_priority", c_void_p, c_uint64, c_uint64, c_bool, c_uint8)
Library.declare("soyokaze_h2_frame_rst_stream", c_void_p, c_uint64, c_uint32)
Library.declare("soyokaze_h2_frame_settings", c_void_p, c_bool, POINTER(H2Parameter), c_size_t)
Library.declare("soyokaze_h2_frame_push_promise", c_void_p, c_uint64, c_uint64, c_char_p, c_size_t)
Library.declare("soyokaze_h2_frame_ping", c_void_p, c_bool, c_char_p)
Library.declare("soyokaze_h2_frame_goaway", c_void_p, c_uint64, c_uint32, c_char_p, c_size_t)
Library.declare("soyokaze_h2_frame_window_update", c_void_p, c_uint64, c_uint32)
Library.declare("soyokaze_h2_frame_continuation", c_void_p, c_uint64, c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_h2_frame_free", None, c_void_p)
Library.declare("soyokaze_h2_frame_kind", c_int32, c_void_p)
Library.declare("soyokaze_h2_frame_stream_id", c_uint64, c_void_p)
Library.declare("soyokaze_h2_frame_flags", c_uint8, c_void_p)
Library.declare("soyokaze_h2_frame_bytes", Slice, c_void_p)
Library.declare("soyokaze_h2_frame_error_code", c_int64, c_void_p)
Library.declare("soyokaze_h2_frame_other_stream_id", c_int64, c_void_p)
Library.declare("soyokaze_h2_frame_increment", c_int64, c_void_p)
Library.declare("soyokaze_h2_frame_weight", c_int32, c_void_p)
Library.declare("soyokaze_h2_frame_exclusive", c_bool, c_void_p)
Library.declare("soyokaze_h2_frame_parameter_count", c_size_t, c_void_p)
Library.declare("soyokaze_h2_frame_parameter", H2Parameter, c_void_p, c_size_t)
Library.declare("soyokaze_h2_frame_encode", Buffer, c_void_p)
Library.declare("soyokaze_h2_frame_payload", Buffer, c_void_p)
Library.declare("soyokaze_h2_frame_decode", c_int32, c_char_p, c_size_t, c_uint32, POINTER(c_void_p), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_h2_settings_default", H2Settings)
Library.declare("soyokaze_h2_settings_peer", H2Settings)
Library.declare("soyokaze_h2_settings_parameter_count", c_size_t, POINTER(H2Settings))
Library.declare("soyokaze_h2_settings_parameter", H2Parameter, POINTER(H2Settings), c_size_t)
Library.declare("soyokaze_h2_settings_apply", c_int32, POINTER(H2Settings), c_uint16, c_uint32, POINTER(c_int64), POINTER(c_void_p))
Library.declare("soyokaze_h2_setting_header_table_size", c_uint16)
Library.declare("soyokaze_h2_setting_enable_push", c_uint16)
Library.declare("soyokaze_h2_setting_max_concurrent_streams", c_uint16)
Library.declare("soyokaze_h2_setting_initial_window_size", c_uint16)
Library.declare("soyokaze_h2_setting_max_frame_size", c_uint16)
Library.declare("soyokaze_h2_setting_max_header_list_size", c_uint16)
Library.declare("soyokaze_h2_setting_enable_connect_protocol", c_uint16)
Library.declare("soyokaze_h2_default_initial_window_size", c_uint32)
Library.declare("soyokaze_h2_default_max_frame_size", c_uint32)
Library.declare("soyokaze_h2_maximum_frame_size", c_uint32)
Library.declare("soyokaze_h2_maximum_window_size", c_uint32)
Library.declare("soyokaze_h2_error_code_name", Slice, c_uint32)

Library.declare("soyokaze_h3_limits_default", H3Limits)
Library.declare("soyokaze_h3_limits_of", H3Limits, POINTER(Limits))
Library.declare("soyokaze_h3_stream_kind_code", c_int64, c_int32)
Library.declare("soyokaze_h3_stream_kind_from_code", c_int32, c_uint64)
Library.declare("soyokaze_h3_frame_type_known", c_bool, c_uint64)
Library.declare("soyokaze_h3_reserved_frame_count", c_size_t)
Library.declare("soyokaze_h3_reserved_frame", c_int64, c_size_t)
Library.declare("soyokaze_h3_frame_data", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_h3_frame_headers", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_h3_frame_cancel_push", c_void_p, c_uint64)
Library.declare("soyokaze_h3_frame_settings", c_void_p, POINTER(H3Parameter), c_size_t)
Library.declare("soyokaze_h3_frame_push_promise", c_void_p, c_uint64, c_char_p, c_size_t)
Library.declare("soyokaze_h3_frame_goaway", c_void_p, c_uint64)
Library.declare("soyokaze_h3_frame_max_push_id", c_void_p, c_uint64)
Library.declare("soyokaze_h3_frame_free", None, c_void_p)
Library.declare("soyokaze_h3_frame_kind", c_int32, c_void_p)
Library.declare("soyokaze_h3_frame_bytes", Slice, c_void_p)
Library.declare("soyokaze_h3_frame_id", c_int64, c_void_p)
Library.declare("soyokaze_h3_frame_parameter_count", c_size_t, c_void_p)
Library.declare("soyokaze_h3_frame_parameter", H3Parameter, c_void_p, c_size_t)
Library.declare("soyokaze_h3_frame_payload_len", c_size_t, c_void_p)
Library.declare("soyokaze_h3_frame_encode", Buffer, c_void_p)
Library.declare("soyokaze_h3_frame_payload", Buffer, c_void_p)
Library.declare("soyokaze_h3_frame_decode", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_h3_settings_default", H3Settings)
Library.declare("soyokaze_h3_settings_peer", H3Settings)
Library.declare("soyokaze_h3_settings_parameter_count", c_size_t, POINTER(H3Settings))
Library.declare("soyokaze_h3_settings_parameter", H3Parameter, POINTER(H3Settings), c_size_t)
Library.declare("soyokaze_h3_settings_apply", c_int32, POINTER(H3Settings), c_uint64, c_uint64, POINTER(c_void_p))
Library.declare("soyokaze_h3_setting_qpack_max_table_capacity", c_uint64)
Library.declare("soyokaze_h3_setting_max_field_section_size", c_uint64)
Library.declare("soyokaze_h3_setting_qpack_blocked_streams", c_uint64)
Library.declare("soyokaze_h3_setting_enable_connect_protocol", c_uint64)
Library.declare("soyokaze_h3_reserved_setting_count", c_size_t)
Library.declare("soyokaze_h3_reserved_setting", c_int64, c_size_t)
Library.declare("soyokaze_h3_error_code_name", Slice, c_uint64)

# ------------------------------------------------------------------ helpers
Library.declare("soyokaze_text_inline", c_size_t)
Library.declare("soyokaze_text_new", c_void_p)
Library.declare("soyokaze_text_from_utf8", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_from_utf8_lossy", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_from_ascii", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_from_ascii_lowercase", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_copy_inline", c_bool, c_char_p, c_size_t, POINTER(c_uint8))
Library.declare("soyokaze_text_from_verified_ascii", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_from_verified_ascii_lowercase", c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_text_free", None, c_void_p)
Library.declare("soyokaze_text_bytes", Slice, c_void_p)
Library.declare("soyokaze_text_len", c_size_t, c_void_p)
Library.declare("soyokaze_text_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_text_is_inline", c_bool, c_void_p)
Library.declare("soyokaze_text_make_ascii_lowercase", c_bool, c_void_p)
Library.declare("soyokaze_text_into_bytes", Buffer, c_void_p)
Library.declare("soyokaze_text_equals", c_bool, c_void_p, c_void_p)
Library.declare("soyokaze_text_compare", c_int32, c_void_p, c_void_p)

Library.declare("soyokaze_scan_lanes", c_size_t)
Library.declare("soyokaze_scan_low", c_uint64)
Library.declare("soyokaze_scan_high", c_uint64)
Library.declare("soyokaze_scan_holds_zero", c_uint64, c_uint64)
Library.declare("soyokaze_scan_holds_less", c_uint64, c_uint64, c_uint64)
Library.declare("soyokaze_scan_marks_zero", c_uint64, c_uint64)
Library.declare("soyokaze_scan_word_at", c_uint64, c_char_p, c_size_t, c_size_t)
Library.declare("soyokaze_scan_find", c_ssize_t, c_char_p, c_size_t, c_uint8)
Library.declare("soyokaze_scan_copy", c_bool, POINTER(c_uint8), c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_scan_value_control", c_uint8)
Library.declare("soyokaze_scan_value_obs_text", c_uint8)
Library.declare("soyokaze_scan_classify_field_value", c_uint8, c_char_p, c_size_t)
Library.declare("soyokaze_scan_is_field_value", c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_scan_all_in_class", c_bool, c_char_p, c_size_t, c_char_p, c_uint8)

Library.declare("soyokaze_timeout_armed", c_bool, c_double)
Library.declare("soyokaze_timeout_nanos", c_int64, c_double)
Library.declare("soyokaze_elapsed_message", Buffer, c_double)
Library.declare("soyokaze_elapsed_status", c_int32)

Library.declare("soyokaze_base64_error_message", Slice, c_int32)
Library.declare("soyokaze_base64_alphabet", Slice)
Library.declare("soyokaze_base64_pad", c_uint8)
Library.declare("soyokaze_base64_invalid", c_uint8)
Library.declare("soyokaze_base64_values", Slice)
Library.declare("soyokaze_base64_symbol", c_uint8, c_uint8)
Library.declare("soyokaze_base64_value", c_int32, c_uint8)
Library.declare("soyokaze_base64_encoded_len", c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_base64_sextets", c_bool, c_char_p, c_size_t, POINTER(c_uint32), POINTER(c_int32), POINTER(c_uint64))
Library.declare("soyokaze_base64_encode", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_base64_decode", c_bool, c_char_p, c_size_t, POINTER(Buffer), POINTER(c_int32), POINTER(c_uint64))

Library.declare("soyokaze_sha1_block_size", c_size_t)
Library.declare("soyokaze_sha1_digest_size", c_size_t)
Library.declare("soyokaze_sha1_initial_state", POINTER(c_uint32))
Library.declare("soyokaze_sha1_constants", POINTER(c_uint32))
Library.declare("soyokaze_sha1", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_sha1_new", c_void_p)
Library.declare("soyokaze_sha1_free", None, c_void_p)
Library.declare("soyokaze_sha1_update", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_sha1_compress", c_bool, c_void_p, c_char_p, c_size_t)
Library.declare("soyokaze_sha1_finish", c_bool, c_void_p, POINTER(Buffer))

Library.declare("soyokaze_huffman_error_message", Slice, c_int32)
Library.declare("soyokaze_huffman_eos", c_uint16)
Library.declare("soyokaze_huffman_table_len", c_size_t)
Library.declare("soyokaze_huffman_symbol", HuffmanSymbol, c_size_t)
Library.declare("soyokaze_huffman_length", c_uint8, c_size_t)
Library.declare("soyokaze_huffman_nibble", c_size_t)
Library.declare("soyokaze_huffman_emit", c_uint8)
Library.declare("soyokaze_huffman_fail", c_uint8)
Library.declare("soyokaze_huffman_ended", c_uint8)
Library.declare("soyokaze_huffman_states", c_size_t)
Library.declare("soyokaze_huffman_nodes", c_size_t)
Library.declare("soyokaze_huffman_transition", HuffmanTransition, c_size_t, c_uint8)
Library.declare("soyokaze_huffman_accepting", c_bool, c_size_t)
Library.declare("soyokaze_huffman_step", c_int32, c_size_t, c_bool, POINTER(c_uint32))
Library.declare("soyokaze_huffman_encoded_len", c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_huffman_encode", Buffer, c_char_p, c_size_t)
Library.declare("soyokaze_huffman_decode", c_bool, c_char_p, c_size_t, POINTER(Buffer), POINTER(c_int32))
Library.declare("soyokaze_huffman_decode_ascii", c_bool, c_char_p, c_size_t, POINTER(Buffer), POINTER(c_bool), POINTER(c_int32))

Library.declare("soyokaze_fields_error_message", Slice, c_int32)
Library.declare("soyokaze_field_overhead", c_size_t)
Library.declare("soyokaze_field_sensitive_count", c_size_t)
Library.declare("soyokaze_field_sensitive_name", Slice, c_size_t)
Library.declare("soyokaze_field_size", c_size_t, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_field_is_sensitive", c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_fields_new", c_void_p)
Library.declare("soyokaze_fields_append", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_fields_free", None, c_void_p)
Library.declare("soyokaze_fields_count", c_size_t, c_void_p)
Library.declare("soyokaze_fields_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_fields_value", Slice, c_void_p, c_size_t)

Library.declare("soyokaze_integer_limit", c_uint64, c_uint8)
Library.declare("soyokaze_integer_encode", Buffer, c_uint64, c_uint8, c_uint8)
Library.declare("soyokaze_integer_decode", c_bool, c_char_p, c_size_t, c_uint8, POINTER(c_uint64), POINTER(c_size_t), POINTER(c_int32))
Library.declare("soyokaze_string_prefers_huffman", c_bool, c_char_p, c_size_t)
Library.declare("soyokaze_string_encode", Buffer, c_char_p, c_size_t, c_uint8, c_uint8, c_bool)
Library.declare("soyokaze_string_encode_shorter", Buffer, c_char_p, c_size_t, c_uint8, c_uint8)
Library.declare("soyokaze_string_decode", c_bool, c_char_p, c_size_t, c_uint8, POINTER(Buffer), POINTER(c_size_t), POINTER(c_int32))
Library.declare("soyokaze_static_index_lookup", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_int64), POINTER(c_int64))

Library.declare("soyokaze_hpack_default_capacity", c_size_t)
Library.declare("soyokaze_hpack_default_capacity_limit", c_size_t)
Library.declare("soyokaze_hpack_default_max_decoded_size", c_size_t)
Library.declare("soyokaze_hpack_static_count", c_size_t)
Library.declare("soyokaze_hpack_static_base", c_size_t)
Library.declare("soyokaze_hpack_static_name", Slice, c_size_t)
Library.declare("soyokaze_hpack_static_value", Slice, c_size_t)
Library.declare("soyokaze_hpack_static_index", c_void_p)
Library.declare("soyokaze_hpack_static_find", c_bool, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_bool))
Library.declare("soyokaze_hpack_table_size", c_size_t, c_void_p)
Library.declare("soyokaze_hpack_table_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_hpack_table_len", c_size_t, c_void_p)
Library.declare("soyokaze_hpack_table_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_hpack_table_name", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_table_value", Slice, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_table_find", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_bool))
Library.declare("soyokaze_hpack_encoder_new", c_void_p)
Library.declare("soyokaze_hpack_encoder_free", None, c_void_p)
Library.declare("soyokaze_hpack_encoder_set_max_capacity", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_encoder_set_capacity_limit", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_encoder_capacity_limit", c_size_t, c_void_p)
Library.declare("soyokaze_hpack_encoder_max_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_hpack_encoder_table", c_void_p, c_void_p)
Library.declare("soyokaze_hpack_encoder_reference", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_bool))
Library.declare("soyokaze_hpack_encode", Buffer, c_void_p, POINTER(Field), c_size_t)
Library.declare("soyokaze_hpack_encode_field", Buffer, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_hpack_decoder_new", c_void_p)
Library.declare("soyokaze_hpack_decoder_free", None, c_void_p)
Library.declare("soyokaze_hpack_decoder_set_max_decoded_size", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_decoder_set_max_capacity", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_hpack_decoder_table", c_void_p, c_void_p)
Library.declare("soyokaze_hpack_decoder_resolve", c_bool, c_void_p, c_uint64, POINTER(Slice), POINTER(Slice))
Library.declare("soyokaze_hpack_decode", c_int32, c_void_p, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_void_p))

Library.declare("soyokaze_qpack_default_capacity", c_size_t)
Library.declare("soyokaze_qpack_default_capacity_limit", c_size_t)
Library.declare("soyokaze_qpack_default_max_outstanding_sections", c_size_t)
Library.declare("soyokaze_qpack_default_max_instruction_size", c_size_t)
Library.declare("soyokaze_qpack_default_idle_capacity", c_size_t)
Library.declare("soyokaze_qpack_default_max_capacity", c_size_t)
Library.declare("soyokaze_qpack_default_max_decoded_size", c_size_t)
Library.declare("soyokaze_qpack_default_max_blocked_streams", c_size_t)
Library.declare("soyokaze_qpack_static_count", c_size_t)
Library.declare("soyokaze_qpack_static_base", c_size_t)
Library.declare("soyokaze_qpack_static_name", Slice, c_size_t)
Library.declare("soyokaze_qpack_static_value", Slice, c_size_t)
Library.declare("soyokaze_qpack_static_index", c_void_p)
Library.declare("soyokaze_qpack_static_find", c_bool, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_uint64), POINTER(c_bool))
Library.declare("soyokaze_qpack_table_size", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_table_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_table_len", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_table_is_empty", c_bool, c_void_p)
Library.declare("soyokaze_qpack_table_inserted_count", c_uint64, c_void_p)
Library.declare("soyokaze_qpack_table_name", Slice, c_void_p, c_uint64)
Library.declare("soyokaze_qpack_table_value", Slice, c_void_p, c_uint64)
Library.declare("soyokaze_qpack_table_fits", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_qpack_table_relative", c_int64, c_void_p, c_uint64)
Library.declare("soyokaze_qpack_table_indexed", c_int64, c_void_p, c_uint64, c_uint64)
Library.declare("soyokaze_qpack_table_post_base", c_int64, c_void_p, c_uint64, c_uint64)
Library.declare("soyokaze_qpack_table_find", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_uint64), POINTER(c_bool))
Library.declare("soyokaze_qpack_table_probe", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_uint64, POINTER(c_uint64), POINTER(c_bool), POINTER(c_bool))
Library.declare("soyokaze_qpack_prefix_max_entries", c_uint64, c_size_t)
Library.declare("soyokaze_qpack_prefix_relative", c_uint64, c_uint64, c_uint64)
Library.declare("soyokaze_qpack_prefix_encode_insert_count", c_uint64, c_uint64, c_size_t)
Library.declare("soyokaze_qpack_prefix_decode_insert_count", c_bool, c_uint64, c_uint64, c_size_t, POINTER(c_uint64))
Library.declare("soyokaze_qpack_encoder_instruction_set_capacity", c_void_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_instruction_insert_with_name_reference", c_void_p, c_bool, c_uint64, c_char_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_instruction_insert_with_literal_name", c_void_p, c_char_p, c_size_t, c_char_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_instruction_duplicate", c_void_p, c_uint64)
Library.declare("soyokaze_qpack_encoder_instruction_free", None, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_kind", c_int32, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_from_static", c_bool, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_index", c_uint64, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_name", Slice, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_value", Slice, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_encode", Buffer, c_void_p)
Library.declare("soyokaze_qpack_encoder_instruction_decode", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_qpack_decoder_instruction_section_acknowledgment", c_void_p, c_uint64)
Library.declare("soyokaze_qpack_decoder_instruction_stream_cancellation", c_void_p, c_uint64)
Library.declare("soyokaze_qpack_decoder_instruction_insert_count_increment", c_void_p, c_uint64)
Library.declare("soyokaze_qpack_decoder_instruction_free", None, c_void_p)
Library.declare("soyokaze_qpack_decoder_instruction_kind", c_int32, c_void_p)
Library.declare("soyokaze_qpack_decoder_instruction_stream_id", c_uint64, c_void_p)
Library.declare("soyokaze_qpack_decoder_instruction_increment", c_uint64, c_void_p)
Library.declare("soyokaze_qpack_decoder_instruction_encode", Buffer, c_void_p)
Library.declare("soyokaze_qpack_decoder_instruction_decode", c_int32, c_char_p, c_size_t, POINTER(c_void_p), POINTER(c_size_t), POINTER(c_void_p))
Library.declare("soyokaze_qpack_encoder_new", c_void_p)
Library.declare("soyokaze_qpack_encoder_free", None, c_void_p)
Library.declare("soyokaze_qpack_encoder_set_max_capacity", c_bool, c_void_p, c_size_t, POINTER(Buffer))
Library.declare("soyokaze_qpack_encoder_set_capacity_limit", c_bool, c_void_p, c_size_t, POINTER(Buffer))
Library.declare("soyokaze_qpack_encoder_set_max_outstanding_sections", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_set_max_instruction_size", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_set_idle_capacity", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_encoder_capacity_limit", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_encoder_max_capacity", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_encoder_outstanding", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_encoder_known_received_count", c_uint64, c_void_p)
Library.declare("soyokaze_qpack_encoder_table", c_void_p, c_void_p)
Library.declare("soyokaze_qpack_encoder_reference", c_bool, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_bool), POINTER(c_uint64), POINTER(c_bool))
Library.declare("soyokaze_qpack_encoder_queue", c_bool, c_void_p, POINTER(c_void_p), c_size_t)
Library.declare("soyokaze_qpack_encoder_stream", Slice, c_void_p)
Library.declare("soyokaze_qpack_encoder_take_stream", Buffer, c_void_p)
Library.declare("soyokaze_qpack_encoder_reclaim_stream", c_bool, c_void_p, Buffer)
Library.declare("soyokaze_qpack_encode", c_bool, c_void_p, c_uint64, POINTER(Field), c_size_t, POINTER(Buffer), POINTER(Buffer))
Library.declare("soyokaze_qpack_encoder_on_decoder_instructions", c_int32, c_void_p, c_char_p, c_size_t, POINTER(c_void_p))
Library.declare("soyokaze_qpack_encoder_on_decoder_instruction", c_bool, c_void_p, c_void_p)
Library.declare("soyokaze_qpack_encoder_cancel", c_bool, c_void_p, c_uint64)
Library.declare("soyokaze_qpack_decoder_new", c_void_p)
Library.declare("soyokaze_qpack_decoder_free", None, c_void_p)
Library.declare("soyokaze_qpack_decoder_set_max_decoded_size", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_decoder_set_max_capacity", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_decoder_set_max_instruction_size", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_decoder_set_max_blocked_streams", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_decoder_set_idle_capacity", c_bool, c_void_p, c_size_t)
Library.declare("soyokaze_qpack_decoder_blocked", c_size_t, c_void_p)
Library.declare("soyokaze_qpack_decoder_unblocked", Buffer, c_void_p)
Library.declare("soyokaze_qpack_decoder_cancel", c_bool, c_void_p, c_uint64)
Library.declare("soyokaze_qpack_decoder_table", c_void_p, c_void_p)
Library.declare("soyokaze_qpack_decoder_resolve", c_bool, c_void_p, c_bool, c_uint64, c_uint64, POINTER(Buffer), POINTER(Buffer))
Library.declare("soyokaze_qpack_decoder_resolve_name", Buffer, c_void_p, c_bool, c_uint64, c_uint64)
Library.declare("soyokaze_qpack_decoder_queue", c_bool, c_void_p, POINTER(c_void_p), c_size_t)
Library.declare("soyokaze_qpack_decoder_stream", Slice, c_void_p)
Library.declare("soyokaze_qpack_decoder_take_stream", Buffer, c_void_p)
Library.declare("soyokaze_qpack_decoder_reclaim_stream", c_bool, c_void_p, Buffer)
Library.declare("soyokaze_qpack_decoder_on_encoder_instructions", c_int32, c_void_p, c_char_p, c_size_t, POINTER(Buffer), POINTER(c_void_p))
Library.declare("soyokaze_qpack_decoder_on_encoder_instruction", c_int32, c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p))
Library.declare("soyokaze_qpack_decode", c_int32, c_void_p, c_uint64, c_char_p, c_size_t, POINTER(c_void_p), POINTER(Buffer), POINTER(c_void_p))
