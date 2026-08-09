"""Each version's wire format, verified against the RFC that defines it."""

import pytest

import soyokaze
from soyokaze import Method, Version
from soyokaze.protocol import common, h1, h2, h3, quic

def test_a_varint_uses_the_shortest_of_the_four_rfc_9000_forms():
    assert quic.Varint.len(0) == 1 and quic.Varint.len(63) == 1
    assert quic.Varint.len(64) == 2 and quic.Varint.len(16383) == 2
    assert quic.Varint.len(16384) == 4
    assert quic.Varint.len(1 << 30) == 8

    assert quic.Varint.encode(37) == bytes([0x25])
    assert quic.Varint.encode(15293) == bytes([0x7B, 0xBD])
    assert quic.Varint.encode(494878333) == bytes([0x9D, 0x7F, 0x3E, 0x7D])

    for value in (0, 1, 63, 64, 16383, 16384, 494878333, quic.Varint.MAXIMUM):
        assert quic.Varint.decode(quic.Varint.encode(value)) == (quic.Varint.len(value), value)

def test_quic_numbers_its_streams_two_bits_at_a_time():
    assert quic.QUICStreamID.STEP == 4

    assert quic.QUICStreamID.is_bidi(0) and quic.QUICStreamID.client_initiated(0)
    assert quic.QUICStreamID.is_bidi(1) and not quic.QUICStreamID.client_initiated(1)
    assert quic.QUICStreamID.is_uni(2) and quic.QUICStreamID.client_initiated(2)
    assert quic.QUICStreamID.is_uni(3) and not quic.QUICStreamID.client_initiated(3)

    assert quic.QUICStreamID.first_bidi(soyokaze.Role.USER_AGENT) == 0
    assert quic.QUICStreamID.first_bidi(soyokaze.Role.ORIGIN) == 1
    assert quic.QUICStreamID.first_uni(soyokaze.Role.USER_AGENT) == 2
    assert quic.QUICStreamID.first_uni(soyokaze.Role.ORIGIN) == 3

def test_a_quic_handshake_has_no_version_to_fall_back_to():
    assert quic.Handshake(b"h3", 1).negotiated([Version.V3_0]) == Version.V3_0

    with pytest.raises(soyokaze.VersionError):
        quic.Handshake(b"", 1).negotiated([Version.V3_0])

def test_a_quic_connection_reports_tls_1_3_without_a_cipher_suite():
    security = quic.Handshake(b"h3", 1).security()

    assert security.quic and security.tls and security.secure
    assert security.tls_version == soyokaze.TLSVersion.V1_3
    assert security.tls_cipher is None and security.tls_group is None

def test_pseudo_fields_lead_a_section_and_connection_fields_never_travel():
    assert common.Fields.PSEUDO_REQUEST[:4] == (":method", ":scheme", ":authority", ":path")
    assert common.Fields.PSEUDO_RESPONSE == (":status",)

    for name in ("connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"):
        assert common.Fields.connection_specific(name)

    assert not common.Fields.connection_specific("content-length")
    assert common.Fields.status(200) == "200" and common.Fields.status(404) == "404"

def test_a_message_round_trips_through_the_field_section_it_travels_as():
    request = soyokaze.Message.request(Method.GET, "/a", Version.V2_0)
    request.headers.append("host", "example.com")
    request.headers.append("connection", "keep-alive")

    with pytest.raises(soyokaze.ProtocolError):
        common.Fields.of(request), "a connection-specific field must never travel above HTTP/1.x"

    request.headers.remove("connection")
    section = common.Fields.of(request)
    names = [name for name, value in section]

    assert names[:4] == [":method", ":scheme", ":authority", ":path"]
    assert ("host", "example.com") not in section, "the authority travels as a pseudo-field"

    back = common.Fields.message(section, Version.V2_0)
    assert back.method == Method.GET and back.target == "/a"

def test_a_read_buffer_hands_back_what_was_put_into_it():
    buffer = common.Buffer()
    buffer.extend(b"hello world")

    assert len(buffer) == 11 and not buffer.is_empty()
    assert buffer.take(5) == b"hello"
    assert buffer.as_slice() == b" world"

    buffer.consume(1)
    assert buffer.as_slice() == b"world"

def test_an_http_1_start_line_round_trips():
    request = soyokaze.Message.request(Method.GET, "/a")
    assert h1.StartLine.encode(request) == "GET /a HTTP/1.1"

    parsed = h1.StartLine.parse("GET /a HTTP/1.1")
    assert parsed.method == Method.GET and parsed.target == "/a"
    assert parsed.version == Version.V1_1

    response = h1.StartLine.parse("HTTP/1.1 204 No Content")
    assert response.status_code == 204

def test_a_malformed_start_line_earns_the_status_its_fault_calls_for():
    assert h1.StartLine.error_status("BAD~METHOD / HTTP/1.1") == 501, "an unknown method"
    assert h1.StartLine.error_status("GET / HTTP/9.9") == 505, "a version this end will not speak"
    assert h1.StartLine.error_status("GET  HTTP/1.1") == 400, "an empty target"
    assert h1.StartLine.error_status("nonsense") == 400

def test_an_http_1_field_is_written_and_read_back():
    assert h1.Field.encode("content-length", "5") == "Content-Length: 5\r\n"
    assert h1.Field.encode("content-length", "5", soyokaze.HeaderCase.LOWER) == "content-length: 5\r\n"
    assert h1.Field.parse("Host: example.com") == ("host", "example.com")

    headers = h1.Field.parse_block(b"Host: a\r\nX-B: c\r\n", 8)
    assert list(headers) == [("host", "a"), ("x-b", "c")]

    with pytest.raises(soyokaze.LimitError):
        h1.Field.parse_block(b"Host: a\r\nX-B: c\r\n", 1)

def test_a_field_block_ends_at_the_empty_line():
    searched, fields_end, section_end = h1.Field.block_end(b"Host: a\r\n")
    assert (fields_end, section_end) == (None, None), "an unfinished section must ask for more octets"

    block = b"Host: a\r\n\r\nbody"
    searched, fields_end, section_end = h1.Field.block_end(block, searched)

    assert block[:fields_end] == b"Host: a\r\n"
    assert block[section_end:] == b"body", "the section ends past its blank line"

    assert h1.Field.block_end(b"\r\nbody")[1:] == (0, 2), "a section may hold no fields at all"

def test_a_chunk_carries_its_size_in_hexadecimal():
    assert h1.Chunk.encode(b"abc") == b"3\r\nabc\r\n"
    assert h1.Chunk.encode(b"") == b"0\r\n\r\n"

    assert h1.Chunk.parse_size(b"3\r\nabc\r\n") == (3, 3)
    assert h1.Chunk.parse_size(b"3") is None, "an unfinished header must ask for more octets"

    read, start, end = h1.Chunk.decode(b"3\r\nabc\r\n")
    assert (read, start, end) == (8, 3, 6)

def test_a_body_is_framed_by_what_the_message_says_about_it():
    request = soyokaze.Message.request(Method.POST, "/a")
    assert h1.BodyLength.of(request).kind == h1.BodyKind.NONE

    request.headers.insert("content-length", "5")
    framing = h1.BodyLength.of(request)
    assert framing.kind == h1.BodyKind.FIXED and framing.length == 5

    request.headers.remove("content-length")
    request.headers.insert("transfer-encoding", "chunked")
    assert h1.BodyLength.of(request).kind == h1.BodyKind.CHUNKED

    request.headers.insert("content-length", "5")
    with pytest.raises(soyokaze.ProtocolError):
        h1.BodyLength.of(request)

def test_a_response_to_head_never_has_a_body_however_it_is_labelled():
    response = soyokaze.Message.response(200)
    response.headers.insert("content-length", "10")

    assert h1.BodyLength.of(response, Method.HEAD).kind == h1.BodyKind.NONE
    assert h1.BodyLength.of(response, Method.GET).kind == h1.BodyKind.FIXED

def test_http_1_persistence_flips_between_1_0_and_1_1():
    assert h1.Persistence.keep_alive(None, Version.V1_1)
    assert not h1.Persistence.keep_alive(None, Version.V1_0)

    headers = soyokaze.Headers()
    headers.append("connection", "close")
    assert not h1.Persistence.keep_alive(headers, Version.V1_1)

    headers = soyokaze.Headers()
    headers.append("connection", "keep-alive")
    assert h1.Persistence.keep_alive(headers, Version.V1_0)

def test_the_http_2_preface_is_the_one_rfc_9113_sets():
    assert h2.PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def test_an_http_2_frame_header_is_nine_octets():
    assert h2.FrameHeader.SIZE == 9

    header = h2.FrameHeader(3, h2.FrameType.HEADERS, h2.Flag.END_STREAM, 1)
    encoded = header.encode()

    assert len(encoded) == 9
    assert encoded == bytes.fromhex("000003010100000001")

    length, back = h2.FrameHeader.decode(encoded)
    assert length == 3
    assert (back.kind, back.flags, back.stream_id) == (h2.FrameType.HEADERS, h2.Flag.END_STREAM, 1)

def test_every_http_2_frame_round_trips_through_the_wire():
    frames = [
        h2.Frame.Data(1, b"abc", end_stream=True),
        h2.Frame.Headers(1, b"\x82", end_stream=False),
        h2.Frame.Priority(3, dependency=1, exclusive=True, weight=16),
        h2.Frame.RstStream(1, h2.Code.CANCEL),
        h2.Frame.Settings([(h2.Settings.MAX_FRAME_SIZE, 16384)]),
        h2.Frame.Ping(b"12345678"),
        h2.Frame.GoAway(7, h2.Code.NO_ERROR, b"bye"),
        h2.Frame.WindowUpdate(0, 1024),
        h2.Frame.Continuation(1, b"\x82"),
    ]

    for frame in frames:
        read, back = h2.Frame.parse(frame.encode())
        assert back is not None, f"{frame} must decode from what it encoded"
        assert read == len(frame.encode())
        assert back.kind() == frame.kind()
        assert back.stream_id() == frame.stream_id()
        assert back.flags() == frame.flags()

def test_an_http_2_frame_carries_the_fields_its_kind_defines():
    _, data = h2.Frame.parse(h2.Frame.Data(1, b"abc", end_stream=True).encode())
    assert data.bytes() == b"abc" and data.flags() & h2.Flag.END_STREAM

    _, reset = h2.Frame.parse(h2.Frame.RstStream(1, h2.Code.REFUSED_STREAM).encode())
    assert reset.error_code() == h2.Code.REFUSED_STREAM

    _, credit = h2.Frame.parse(h2.Frame.WindowUpdate(0, 1024).encode())
    assert credit.increment() == 1024

    _, away = h2.Frame.parse(h2.Frame.GoAway(7, h2.Code.NO_ERROR, b"bye").encode())
    assert away.other_stream_id() == 7 and away.bytes() == b"bye"

    _, settings = h2.Frame.parse(h2.Frame.Settings([(h2.Settings.MAX_FRAME_SIZE, 16384)]).encode())
    assert settings.parameters() == [(h2.Settings.MAX_FRAME_SIZE, 16384)]

def test_an_incomplete_http_2_frame_asks_for_more_octets():
    encoded = h2.Frame.Data(1, b"abcdef").encode()
    read, frame = h2.Frame.parse(encoded[:5])

    assert frame is None and read == 0

def test_http_2_frames_belong_on_a_stream_or_on_the_connection():
    for kind in (h2.FrameType.DATA, h2.FrameType.HEADERS, h2.FrameType.RST_STREAM, h2.FrameType.CONTINUATION):
        assert kind.streamed() is True

    for kind in (h2.FrameType.SETTINGS, h2.FrameType.PING, h2.FrameType.GOAWAY):
        assert kind.streamed() is False

    assert h2.FrameType.WINDOW_UPDATE.streamed() is None

def test_http_2_settings_carry_the_rfc_9113_identifiers_and_defaults():
    assert (h2.Settings.HEADER_TABLE_SIZE, h2.Settings.ENABLE_PUSH) == (0x1, 0x2)
    assert (h2.Settings.MAX_CONCURRENT_STREAMS, h2.Settings.INITIAL_WINDOW_SIZE) == (0x3, 0x4)
    assert (h2.Settings.MAX_FRAME_SIZE, h2.Settings.MAX_HEADER_LIST_SIZE) == (0x5, 0x6)
    assert h2.Settings.ENABLE_CONNECT_PROTOCOL == 0x8

    assert h2.Settings.DEFAULT_INITIAL_WINDOW_SIZE == 65535
    assert h2.Settings.DEFAULT_MAX_FRAME_SIZE == 16384
    assert h2.Settings.MAXIMUM_FRAME_SIZE == 16777215
    assert h2.Settings.MAXIMUM_WINDOW_SIZE == 0x7FFFFFFF

    peer = h2.Settings.peer()
    assert peer.initial_window_size == h2.Settings.DEFAULT_INITIAL_WINDOW_SIZE
    assert peer.max_frame_size == h2.Settings.DEFAULT_MAX_FRAME_SIZE

def test_only_the_window_setting_moves_an_open_streams_window():
    settings = h2.Settings.peer()

    assert settings.apply(h2.Settings.INITIAL_WINDOW_SIZE, 1000) == 1000 - 65535
    assert settings.initial_window_size == 1000
    assert settings.apply(h2.Settings.MAX_FRAME_SIZE, 32768) == 0
    assert settings.apply(0xFF, 1) == 0, "an unknown parameter is accepted and ignored"

    with pytest.raises(soyokaze.ProtocolError):
        settings.apply(h2.Settings.MAX_FRAME_SIZE, 1)

def test_an_http_3_unidirectional_stream_announces_which_kind_it_is():
    assert h3.StreamKind.CONTROL.code() == 0x00
    assert h3.StreamKind.PUSH.code() == 0x01
    assert h3.StreamKind.QPACK_ENCODER.code() == 0x02
    assert h3.StreamKind.QPACK_DECODER.code() == 0x03
    assert h3.StreamKind.REQUEST.code() is None, "a request stream announces nothing"

    assert h3.StreamKind.from_code(0x00) == h3.StreamKind.CONTROL
    assert h3.StreamKind.from_code(0x99) is None

def test_every_http_3_frame_round_trips_through_the_wire():
    frames = [
        h3.Frame.Data(b"abc"),
        h3.Frame.Headers(b"\x00\x00\xd1"),
        h3.Frame.CancelPush(3),
        h3.Frame.Settings([(h3.Settings.QPACK_MAX_TABLE_CAPACITY, 4096)]),
        h3.Frame.PushPromise(3, b"\x00"),
        h3.Frame.GoAway(7),
        h3.Frame.MaxPushID(9),
    ]

    for frame in frames:
        encoded = frame.encode()
        read, back = h3.Frame.parse(encoded)

        assert back is not None, f"{frame} must decode from what it encoded"
        assert read == len(encoded) and back.kind() == frame.kind()

def test_an_http_3_frame_carries_the_fields_its_kind_defines():
    _, data = h3.Frame.parse(h3.Frame.Data(b"abc").encode())
    assert data.bytes() == b"abc" and data.payload_len() == 3

    _, away = h3.Frame.parse(h3.Frame.GoAway(7).encode())
    assert away.id() == 7

    _, settings = h3.Frame.parse(h3.Frame.Settings([(h3.Settings.QPACK_BLOCKED_STREAMS, 16)]).encode())
    assert settings.parameters() == [(h3.Settings.QPACK_BLOCKED_STREAMS, 16)]

def test_http_3_reserves_the_codes_that_would_mean_an_http_2_peer():
    assert set(h3.FrameType.RESERVED) == {0x02, 0x06, 0x08, 0x09}
    assert set(h3.Settings.RESERVED) == {0x00, 0x02, 0x03, 0x04, 0x05}

    settings = h3.Settings()
    for reserved in h3.Settings.RESERVED:
        with pytest.raises(soyokaze.ProtocolError):
            settings.apply(reserved, 1)

def test_http_3_settings_carry_the_rfc_9114_identifiers():
    assert h3.Settings.QPACK_MAX_TABLE_CAPACITY == 0x01
    assert h3.Settings.MAX_FIELD_SECTION_SIZE == 0x06
    assert h3.Settings.QPACK_BLOCKED_STREAMS == 0x07
    assert h3.Settings.ENABLE_CONNECT_PROTOCOL == 0x08

    settings = h3.Settings()
    settings.apply(h3.Settings.MAX_FIELD_SECTION_SIZE, 8192)
    assert settings.max_field_section_size == 8192
    settings.apply(0xFF, 1)

def test_error_codes_read_back_under_the_names_their_rfcs_give_them():
    assert h2.Code.ENHANCE_YOUR_CALM.name_of() == "ENHANCE_YOUR_CALM"
    assert h2.Code.HTTP_1_1_REQUIRED.name_of() == "HTTP_1_1_REQUIRED"
    assert h3.Code.EXCESSIVE_LOAD.name_of() == "H3_EXCESSIVE_LOAD"
    assert h3.Code.QPACK_DECOMPRESSION_FAILED.name_of() == "QPACK_DECOMPRESSION_FAILED"

def test_each_versions_limits_are_narrowed_from_the_one_set_of_limits():
    limits = soyokaze.Limits(max_header_count=32, max_message_size=1024)

    assert h1.H1Limits.of(limits).max_header_count == 32
    assert h2.H2Limits.of(limits).max_header_count == 32
    assert h3.H3Limits.of(limits).max_header_count == 32

    assert h1.H1Limits.of(limits).max_message_size == 1024
    assert h2.H2Limits.of(limits).max_message_size == 1024
    assert h3.H3Limits.of(limits).max_message_size == 1024
