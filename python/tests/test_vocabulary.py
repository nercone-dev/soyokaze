"""The vocabulary every version shares, verified against the RFCs that set it."""

import pytest

import soyokaze
from soyokaze import ALPN, BodyKind, Compression, HeaderCase, Headers, Method, Port, Role, TransportKind, URL, Version
from soyokaze.helpers import fields, scan, sync, text

def test_versions_carry_their_rfc_alpn_identifiers():
    assert Version.V1_1.alpn() == "http/1.1"
    assert Version.V2_0.alpn() == "h2"
    assert Version.V3_0.alpn() == "h3"

    assert Version.from_alpn(b"h2") == Version.V2_0
    assert Version.from_alpn(b"h3") == Version.V3_0
    assert Version.from_alpn(b"spdy/3") is None

    assert Version.V1_0.major() == 1 and Version.V1_1.major() == 1
    assert Version.V2_0.major() == 2 and Version.V3_0.major() == 3

def test_a_version_runs_over_the_transport_its_alpn_implies():
    assert Version.V1_1.transport() == TransportKind.STREAM
    assert Version.V2_0.transport() == TransportKind.STREAM
    assert Version.V3_0.transport() == TransportKind.QUIC

def test_a_version_round_trips_through_its_written_form():
    for version in Version:
        assert Version.parse(version.as_str()) == version

    assert Version.parse("HTTP/9") is None

def test_a_port_carries_exactly_the_versions_its_transport_carries():
    assert Port.TCP(80).transport() == TransportKind.STREAM
    assert Port.QUIC(443).transport() == TransportKind.QUIC
    assert Port.UDS("/tmp/s").transport() == TransportKind.STREAM

    assert Port.TCP(80).carries(Version.V2_0)
    assert not Port.TCP(80).carries(Version.V3_0)
    assert Port.QUIC(443).carries(Version.V3_0)
    assert not Port.QUIC(443).carries(Version.V2_0)

    offered = Port.TCP(80).offers([Version.V3_0, Version.V2_0, Version.V1_1])
    assert offered == [Version.V2_0, Version.V1_1], "the order the caller gave must be kept"

def test_alpn_is_written_as_length_prefixed_identifiers():
    assert ALPN.wire([Version.V2_0]) == b"\x02h2"
    assert ALPN.wire([Version.V3_0, Version.V2_0]) == b"\x02h3\x02h2"
    assert ALPN.wire([Version.V1_1]) == b"\x08http/1.1"

def test_alpn_selection_prefers_this_ends_order_not_the_clients():
    offered = [Version.V3_0, Version.V2_0]
    assert ALPN.select(offered, ALPN.wire([Version.V2_0, Version.V3_0])) == b"h3"
    assert ALPN.select([Version.V1_1], ALPN.wire([Version.V2_0])) is None

def test_a_handshake_that_agreed_on_nothing_settles_on_http_1_1_only_if_offered():
    assert ALPN.negotiated(None, [Version.V1_1, Version.V2_0]) == Version.V1_1

    with pytest.raises(soyokaze.VersionError):
        ALPN.negotiated(None, [Version.V2_0])

    with pytest.raises(soyokaze.VersionError):
        ALPN.negotiated(b"spdy/3", [Version.V2_0])

def test_methods_match_rfc_9110_on_safety_and_idempotence():
    safe = {Method.GET, Method.HEAD, Method.OPTIONS, Method.TRACE}
    idempotent = safe | {Method.PUT, Method.DELETE}

    for method in Method:
        assert method.safe() == (method in safe)
        assert method.idempotent() == (method in idempotent)
        assert Method.parse(method.as_str()) == method

    assert Method.parse("BREW") is None

def test_roles_split_into_the_side_that_asks_and_the_side_that_answers():
    assert Role.USER_AGENT.is_client() and Role.PROXY.is_client()
    assert Role.ORIGIN.is_server() and Role.GATEWAY.is_server()
    assert not Role.TUNNEL.is_client() and not Role.TUNNEL.is_server()

def test_header_case_follows_the_version_that_will_write_it():
    assert HeaderCase.from_version(Version.V1_0) == HeaderCase.TITLE
    assert HeaderCase.from_version(Version.V1_1) == HeaderCase.TITLE
    assert HeaderCase.from_version(Version.V2_0) == HeaderCase.LOWER
    assert HeaderCase.from_version(Version.V3_0) == HeaderCase.LOWER

    assert HeaderCase.TITLE.apply("content-length") == "Content-Length"
    assert HeaderCase.TITLE.apply("CONTENT-LENGTH") == "Content-Length"
    assert HeaderCase.LOWER.apply("Content-Length") == "content-length"
    assert HeaderCase.TITLE.apply("te") == "Te"

def test_a_url_defaults_its_port_from_its_scheme():
    assert URL.default_port("http") == 80
    assert URL.default_port("https") == 443
    assert URL.default_port("ws") == 80
    assert URL.default_port("wss") == 443

def test_an_authority_omits_the_port_only_when_it_is_the_default():
    assert URL.authority_of("https", "example.com", 443) == "example.com"
    assert URL.authority_of("https", "example.com", 8443) == "example.com:8443"
    assert URL.authority_of("http", "example.com", 80) == "example.com"
    assert URL.authority_of("http", "example.com", 443) == "example.com:443"

def test_a_field_section_keeps_order_and_never_folds_repeats():
    headers = Headers()
    headers.append("Set-Cookie", "a=1")
    headers.append("set-cookie", "b=2")

    assert len(headers) == 2, "repeats must never be folded together"
    assert headers.get_all("set-cookie") == ["a=1", "b=2"]
    assert headers.get("SET-COOKIE") == "a=1", "lookup is case-insensitive"
    assert list(headers) == [("set-cookie", "a=1"), ("set-cookie", "b=2")]

    headers.insert("set-cookie", "c=3")
    assert list(headers) == [("set-cookie", "c=3")], "inserting must drop what was there"

    assert headers.contains("set-cookie") and not headers.absent("set-cookie")
    assert headers.remove("set-cookie") and headers.is_empty()
    assert not headers.remove("set-cookie")

def test_a_well_known_name_has_a_presence_bit_and_an_unknown_one_does_not():
    assert Headers.well_known("cookie") != 0
    assert Headers.well_known("content-length") != 0
    assert Headers.well_known("x-custom") == 0
    assert Headers.well_known("Cookie") == 0, "the bit is only defined for a lowercase name"

    assert Headers.named("content-length", "Content-Length")
    assert not Headers.named("content-length", "content-type")

def test_a_messages_section_is_borrowed_from_it_and_writes_through():
    message = soyokaze.Message.response(200)
    message.headers.append("x-a", "1")

    assert message.header("x-a") == "1", "the borrowed section must be the message's own"
    assert list(message.trailers) == []

def test_a_body_reports_which_of_the_three_kinds_it_is():
    message = soyokaze.Message.response(200)
    assert message.body_kind() == BodyKind.NONE and message.body_is_empty()

    message.set_body(b"abc")
    assert message.body_kind() == BodyKind.DATA
    assert message.body_inline() == b"abc" and message.body_len() == 3

    message.set_body("abc")
    assert message.body_kind() == BodyKind.TEXT and message.body_inline() == b"abc"

    message.clear_body()
    assert message.body_kind() == BodyKind.NONE and message.body_len() is None

def test_a_message_is_rewritten_through_its_own_setters():
    message = soyokaze.Message.request(Method.GET, "/a")
    message.method = Method.POST
    message.target = "/b"
    message.version = Version.V2_0
    message.connection_id = b"cid"

    assert (message.method, message.target, message.version) == (Method.POST, "/b", Version.V2_0)
    assert message.connection_id == b"cid"

    message.connection_id = None
    assert message.connection_id is None

def test_a_prefixed_integer_matches_rfc_7541_appendix_c():
    assert fields.Integer.encode(10, 5) == bytes([0b000_01010])
    assert fields.Integer.encode(1337, 5) == bytes([0b000_11111, 0b1001_1010, 0b0000_1010])
    assert fields.Integer.decode(fields.Integer.encode(1337, 5), 5) == (3, 1337)
    assert fields.Integer.limit(5) == 31

    with pytest.raises(soyokaze.ProtocolError):
        fields.Integer.decode(b"\x1f", 5)

def test_a_string_literal_round_trips_under_either_coding():
    for huffman in (False, True):
        encoded = fields.StringLiteral.encode(b"custom-key", 7, huffman=huffman)
        assert fields.StringLiteral.decode(encoded, 7)[1] == b"custom-key"

    assert fields.StringLiteral.prefers_huffman(b"www.example.com")

def test_a_field_costs_its_octets_plus_the_rfc_7541_overhead():
    assert fields.HeaderField.OVERHEAD == 32
    assert fields.HeaderField("ab", "cde").size() == 2 + 3 + 32

    assert fields.HeaderField("cookie", "x").sensitive()
    assert fields.HeaderField("authorization", "x").sensitive()
    assert not fields.HeaderField("accept", "x").sensitive()

def test_a_timeout_of_zero_or_less_arms_no_deadline():
    assert not sync.Timeout.armed(0.0)
    assert not sync.Timeout.armed(-1.0)
    assert not sync.Timeout.armed(float("nan"))
    assert not sync.Timeout.armed(float("inf"))
    assert sync.Timeout.armed(0.5)

    assert sync.Timeout.duration(0.0) is None
    assert sync.Timeout.duration(1.5) == pytest.approx(1.5)

def test_scanning_finds_an_octet_and_classifies_a_field_value():
    assert scan.find(b"abcdef", ord("d")) == 3
    assert scan.find(b"abcdef", ord("z")) is None
    assert scan.copy(b"abcdef") == b"abcdef"

    assert scan.is_field_value(b"plain text")
    assert not scan.is_field_value(b"with\nnewline")
    assert scan.classify_field_value(b"\x01") & scan.VALUE_CONTROL
    assert scan.classify_field_value(b"\x80") & scan.VALUE_OBS_TEXT

def test_text_stays_inline_until_it_outgrows_the_inline_capacity():
    short = text.Text.from_str("a" * text.INLINE)
    long = text.Text.from_str("a" * (text.INLINE + 1))

    assert short.is_inline() and not long.is_inline()
    assert short.as_str() == "a" * text.INLINE
    assert len(long) == text.INLINE + 1

    lowered = text.Text.from_ascii_lowercase(b"Content-Length")
    assert lowered.as_str() == "content-length"
    assert text.Text.from_str("abc") == "abc"

def test_content_codings_round_trip_through_their_tokens():
    # RFC 9110 §8.4.1 registers these tokens; the enum must spell them exactly.
    assert Compression.ZSTD.as_str() == "zstd"
    assert Compression.BROTLI.as_str() == "br"
    assert Compression.GZIP.as_str() == "gzip"
    assert Compression.DEFLATE.as_str() == "deflate"

    for coding in Compression.codings():
        assert Compression.parse(coding.as_str()) is coding
        assert str(coding) == coding.as_str()

    # The token is read whatever case it was written in, and x-gzip is gzip.
    assert Compression.parse("GZIP") is Compression.GZIP
    assert Compression.parse("X-Gzip") is Compression.GZIP
    assert Compression.parse("Br") is Compression.BROTLI

def test_auto_names_no_coding_of_its_own():
    assert Compression.AUTO.as_str() == ""
    assert Compression.AUTO not in Compression.codings()

    for token in ("compress", "identity", "auto", "", "nonsense"):
        assert Compression.parse(token) is None, f"{token!r} must not name a coding"

    with pytest.raises(soyokaze.ProtocolError):
        Compression.AUTO.encode(b"hello")

def test_the_advertised_field_lists_every_coding_the_library_decodes():
    advertised = tuple(Compression.parse(token) for token in Compression.accepted_field().split(","))
    assert advertised == Compression.codings()

def test_accept_encoding_selection_follows_rfc_9110_quality_rules():
    def accepted(value):
        headers = Headers()
        headers.append("accept-encoding", value)
        return Compression.accepted(headers)

    # Quality settles what is acceptable to the peer; which of the acceptable
    # ones to send is this end's own preference order.
    assert accepted("gzip;q=1.0, zstd;q=0.1") is Compression.ZSTD
    assert accepted("deflate, gzip") is Compression.GZIP

    # A coding at q=0 is refused, and * stands for what the field does not name.
    assert accepted("zstd;q=0, br;q=0, gzip") is Compression.GZIP
    assert accepted("*") is Compression.ZSTD
    assert accepted("*, zstd;q=0") is Compression.BROTLI
    assert accepted("*;q=0") is None

    # An absent field permits nothing rather than everything.
    assert Compression.accepted(Headers()) is None
    assert accepted("identity") is None

    assert Compression.quality("gzip") == 1.0
    assert Compression.quality("gzip;q=0") == 0.0

def test_content_encoding_names_a_coding_only_when_it_names_one():
    def applied(*values):
        headers = Headers()
        for value in values:
            headers.append("content-encoding", value)
        return headers

    assert Compression.applied(applied("gzip")) is Compression.GZIP
    assert Compression.applied(applied("gzip, br")) is None
    assert Compression.applied(applied("gzip", "br")) is None
    assert Compression.applied(applied("compress")) is None
    assert Compression.applied(Headers()) is None

    # A body is coded whether or not the library can decode it; identity codes
    # nothing at all.
    assert Compression.encoded(applied("compress"))
    assert Compression.encoded(applied("gzip"))
    assert not Compression.encoded(applied("identity"))
    assert not Compression.encoded(Headers())

def test_every_coding_round_trips_and_stops_at_its_ceiling():
    body = b"a" * 4096

    for coding in Compression.codings():
        encoded = coding.encode(body)
        assert len(encoded) < len(body), f"{coding} did not shrink a compressible body"
        assert coding.decode(encoded, 1 << 20) == body

        # The ceiling admits a body of exactly its size and nothing past it.
        assert coding.decode(encoded, 4096) == body
        with pytest.raises(soyokaze.LimitError):
            coding.decode(encoded, 4095)

        with pytest.raises(soyokaze.ProtocolError):
            coding.decode(b"not a compressed stream at all", 1 << 20)
