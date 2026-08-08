"""The vocabulary types, verified against what HTTP itself says of them."""

import pathlib

import pytest

import soyokaze
from soyokaze import Message, Method, URL, Version

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
    assert len(response.headers()) == 2, "appending must never fold fields together"
    assert response.header("SET-COOKIE") == "a=1", "names are matched without regard to case"

    response.insert_header("set-cookie", "c=3")
    assert response.headers() == [("set-cookie", "c=3")], "inserting must drop what was there"

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
    assert message.trailers() == [("checksum", "abc"), ("checksum", "def")]
    assert message.trailer("Checksum") == "abc"

    message.insert_trailer("checksum", "ghi")
    assert message.trailers() == [("checksum", "ghi")]
    assert message.remove_trailer("checksum")
    assert message.trailers() == []

def test_a_body_reads_back_whichever_way_it_was_set(tmp_path):
    message = Message.response(200)
    assert message.body_len() is None
    assert message.body() == b""

    message.set_body(b"octets")
    assert message.body_len() == 6
    assert message.body() == b"octets"

    message.set_body("text")
    assert message.body() == b"text"

    path = tmp_path / "payload"
    path.write_bytes(b"from a file")
    message.set_body(pathlib.Path(path))
    assert message.body_len() is None, "a file body has no length until it is read"
    assert message.body() == b"from a file"

    message.set_body(pathlib.Path(tmp_path / "missing"))
    with pytest.raises(soyokaze.IOError):
        message.body()

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
