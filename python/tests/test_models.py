"""The vocabulary types, verified against what HTTP itself says of them."""

import pathlib

import pytest

import soyokaze
from soyokaze import Compression, Message, Method, URL, Version

def test_a_url_is_taken_apart_into_the_pieces_a_request_needs():
    url = URL("https://example.test:8443/a/b?q=1")

    assert url.scheme == "https"
    assert url.host == "example.test"
    assert url.target == "/a/b?q=1"
    assert url.port == 8443
    assert url.secure()
    assert url.authority() == "example.test:8443"

def test_a_url_defaults_its_port_and_target_from_the_scheme():
    assert URL("http://example.test").port == 80
    assert URL("https://example.test").port == 443
    assert URL("wss://example.test").port == 443
    assert URL("http://example.test").target == "/"

def test_a_url_that_will_not_parse_raises_a_protocol_error():
    with pytest.raises(soyokaze.ProtocolError):
        URL("not a url")

def test_a_request_and_a_response_each_carry_only_what_belongs_to_them():
    request = Message.request(Method.GET, "/index.html", Version.V1_1)
    assert request.is_request() and not request.is_response()
    assert request.method == Method.GET
    assert request.status_code is None
    assert request.target == "/index.html"

    response = Message.response(404, Version.V2_0)
    assert response.is_response() and not response.is_request()
    assert response.status_code == 404
    assert response.method is None
    assert response.target is None
    assert response.version == Version.V2_0

def test_appending_keeps_every_field_and_inserting_keeps_one():
    response = Message.response(200)
    response.append_header("Set-Cookie", "a=1")
    response.append_header("set-cookie", "b=2")
    assert len(response.headers) == 2, "appending must never fold fields together"
    assert response.header("SET-COOKIE") == "a=1", "names are matched without regard to case"

    response.insert_header("set-cookie", "c=3")
    assert response.headers == [("set-cookie", "c=3")], "inserting must drop what was there"

    assert response.remove_header("set-cookie")
    assert not response.remove_header("set-cookie"), "removing twice finds nothing"

def test_an_absent_field_is_told_apart_from_an_empty_one():
    response = Message.response(200)
    response.append_header("x-empty", "")

    assert response.header("x-empty") == ""
    assert response.header("x-missing") is None

def test_trailers_mirror_headers():
    message = Message.response(200)
    message.append_trailer("checksum", "abc")
    message.append_trailer("checksum", "def")
    assert message.trailers == [("checksum", "abc"), ("checksum", "def")]
    assert message.trailer("Checksum") == "abc"

    message.insert_trailer("checksum", "ghi")
    assert message.trailers == [("checksum", "ghi")]
    assert message.remove_trailer("checksum")
    assert message.trailers == []

async def test_a_body_reads_back_whichever_way_it_was_set(tmp_path):
    message = Message.response(200)
    assert message.body_len() is None
    assert await message.body() == b""

    message.set_body(b"octets")
    assert message.body_len() == 6
    assert await message.body() == b"octets"

    message.set_body("text")
    assert await message.body() == b"text"

    path = tmp_path / "payload"
    path.write_bytes(b"from a file")
    message.set_body(pathlib.Path(path))
    assert message.body_len() is None, "a file body has no length until it is read"
    assert await message.body() == b"from a file", "a file body is read on a worker thread, not on the loop"

    message.set_body(pathlib.Path(tmp_path / "missing"))
    with pytest.raises(soyokaze.IOError):
        await message.body()

def test_stream_and_connection_facts_default_to_absent():
    message = Message.response(200)
    assert message.stream_id is None
    assert message.connection_id is None
    assert not message.early_data
    assert not message.tls and message.tls_version is None
    assert not message.quic and message.quic_version is None

    message.stream_id = 7
    assert message.stream_id == 7
    message.stream_id = None
    assert message.stream_id is None

    message.secure = True
    assert message.secure

def test_the_response_constructors_set_their_content_type():
    assert Message.text("hi").header("content-type") == "text/plain"
    assert Message.html("<p>").header("content-type") == "text/html"
    assert Message.markdown("# t").header("content-type") == "text/markdown"
    assert Message.json("{}").header("content-type") == "application/json"
    assert Message.file("a.css").header("content-type") == "text/css"
    assert Message.content("application/x-thing", b"x").header("content-type") == "application/x-thing"

    redirect = Message.redirect("/elsewhere")
    assert redirect.status_code == 307
    assert redirect.header("location") == "/elsewhere"

def test_a_consumed_message_refuses_further_use():
    message = Message.response(200)
    message.take()
    with pytest.raises(soyokaze.InvalidError):
        message.take()

def test_http_date_renders_the_imf_fixdate():
    assert soyokaze.DateCache.http_date(784111777) == "Sun, 06 Nov 1994 08:49:37 GMT"
    assert len(soyokaze.DateCache.http_date(0)) == 29

def test_every_role_carries_the_number_the_c_abi_gives_it():
    assert (soyokaze.Role.USER_AGENT, soyokaze.Role.ORIGIN) == (0, 1)
    assert (soyokaze.Role.PROXY, soyokaze.Role.GATEWAY, soyokaze.Role.TUNNEL) == (2, 3, 4)

    assert soyokaze.Role.USER_AGENT.is_client() and soyokaze.Role.PROXY.is_client()
    assert soyokaze.Role.ORIGIN.is_server() and soyokaze.Role.GATEWAY.is_server()

    assert not soyokaze.Role.TUNNEL.is_client(), "a tunnel originates nothing"
    assert not soyokaze.Role.TUNNEL.is_server(), "a tunnel answers nothing either"

def test_a_message_that_crossed_nothing_reports_no_transport_underneath():
    message = Message.response(200)

    assert message.tls is False
    assert message.tls_version is None
    assert message.tls_group is None
    assert message.tls_cipher is None
    assert message.quic is False
    assert message.quic_version is None
    assert message.early_data is False

def test_a_failure_that_names_no_stream_leaves_its_stream_fields_unset():
    with pytest.raises(soyokaze.ProtocolError) as raised:
        URL("not a url")

    assert raised.value.status == soyokaze.Status.PROTOCOL
    assert raised.value.stream_id is None, "a failure that took the whole connection names no stream"
    assert raised.value.code is None, "and carries no code to reset one with"

def test_a_message_the_caller_built_has_crossed_nothing():
    message = Message.request(Method.GET, "/")

    assert message.client is None, "a message you built has no access source"
    assert message.compression is None, "a message you built is coded in nothing"
    assert not message.compressed()
    assert message.accepted() is None

def test_a_message_reports_the_coding_its_body_will_go_out_in():
    message = Message.response(200)

    message.compression = Compression.BROTLI
    assert message.compression is Compression.BROTLI

    message.compression = None
    assert message.compression is None

    # Judged from Content-Encoding alone: RFC 9110 §8.4 gives nothing else the
    # job of saying a representation is coded.
    message.append_header("content-encoding", "gzip")
    assert message.compressed()

    message.append_header("accept-encoding", "br, gzip")
    assert message.accepted() is Compression.BROTLI

def test_a_body_round_trips_through_a_coding():
    body = b"a" * 4096

    for coding in Compression.codings():
        message = Message.response(200)
        message.set_body(body)
        message.compression = coding
        message.compress()

        assert message.compressed()
        assert message.header("content-encoding") == coding.as_str()
        assert message.body_len() < len(body), f"{coding} did not shrink a compressible body"

        message.decompress(1 << 20)

        assert not message.compressed()
        assert message.header("content-encoding") is None
        assert message.compression is coding, "the message must say what came off the body"
        assert message.body_inline() == body

def test_an_automatic_coding_needs_something_to_settle_against():
    message = Message.response(200)
    message.set_body(b"a" * 4096)
    message.compression = Compression.AUTO

    message.compress()
    assert not message.compressed(), "a client has nothing to settle Auto against"
    assert message.compression is None

    message.compression = Compression.AUTO
    message.compress(Compression.ZSTD)

    assert message.compression is Compression.ZSTD
    # RFC 9110 §12.5.5: a response that varies on Accept-Encoding must say so.
    assert message.header("vary") == "Accept-Encoding"

def test_a_body_past_the_decoded_ceiling_is_refused():
    message = Message.response(200)
    message.set_body(Compression.GZIP.encode(bytes(1024 * 1024)))
    message.append_header("content-encoding", "gzip")

    with pytest.raises(soyokaze.LimitError):
        message.decompress(1024)

def test_a_coding_the_library_does_not_implement_leaves_the_body_alone():
    for value in ("compress", "gzip, br"):
        message = Message.response(200)
        message.set_body(b"opaque octets")
        message.append_header("content-encoding", value)

        message.decompress(1 << 20)

        assert message.compressed(), f"{value!r} must leave the body reported as coded"
        assert message.compression is None
        assert message.body_inline() == b"opaque octets"

async def test_a_file_body_is_read_before_it_is_coded(tmp_path):
    path = tmp_path / "body.txt"
    path.write_bytes(b"a" * 4096)

    message = Message.response(200)
    message.set_body(path)
    message.compression = Compression.GZIP

    with pytest.raises(soyokaze.ProtocolError):
        message.compress()

    await message.materialize()
    message.compress()

    assert message.compressed()
    assert message.body_len() < 4096
