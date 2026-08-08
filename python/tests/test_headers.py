"""Cookies, verified against RFC 6265 rather than against the implementation."""

import pytest

import soyokaze
from soyokaze import Cookie, CookieJar, Message, SameSite, SetCookie, URL

def test_a_cookie_field_parses_into_its_pairs():
    cookie = Cookie.parse('a=1; b="quoted"; malformed; =unnamed; a=repeated')

    assert cookie.pairs() == [("a", "1"), ("b", "quoted")], "quotes unwrap, junk is skipped, the first repeat wins"
    assert cookie.get("a") == "1"
    assert cookie.get("missing") is None

def test_a_cookie_field_builds_back_out():
    cookie = Cookie()
    cookie.append("a", "1")
    cookie.append("b", "2")
    assert cookie.build() == "a=1; b=2"

def test_a_setcookie_parses_every_attribute():
    cookie = SetCookie.parse("sid=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT; Max-Age=3600; Domain=.example.test; Path=/a; Secure; HttpOnly; SameSite=Lax")

    assert cookie.name == "sid"
    assert cookie.value == "abc"
    assert cookie.expires == "Sun, 06 Nov 1994 08:49:37 GMT"
    assert cookie.max_age == 3600
    assert cookie.domain == ".example.test"
    assert cookie.path == "/a"
    assert cookie.secure and cookie.httponly
    assert cookie.samesite == SameSite.LAX

def test_a_setcookie_without_a_pair_is_refused():
    with pytest.raises(soyokaze.ProtocolError):
        SetCookie.parse("no pair here")

def test_a_setcookie_builds_what_was_set():
    cookie = SetCookie("sid", "abc")
    cookie.max_age = 60
    cookie.path = "/"
    cookie.secure = True
    cookie.samesite = SameSite.STRICT

    assert cookie.build() == "sid=abc; Max-Age=60; Path=/; Secure; SameSite=Strict"

    cookie.max_age = None
    cookie.path = None
    cookie.secure = False
    cookie.samesite = None
    assert cookie.build() == "sid=abc"

def test_a_setcookie_value_that_could_break_out_is_refused():
    cookie = SetCookie("sid", "a;b")
    with pytest.raises(soyokaze.ProtocolError):
        cookie.build()

def test_a_jar_returns_matching_cookies_and_forgets_deleted_ones():
    jar = CookieJar()
    url = URL("https://example.test/a/b")

    jar.learn(url, ["sid=abc; Path=/a", "other=1; Domain=elsewhere.test"])
    assert jar.cookie(url) == "sid=abc", "a cookie for another domain must not be sent"
    assert jar.cookie(URL("https://example.test/c")) is None, "the path must match"

    jar.learn(url, ["sid=abc; Path=/a; Max-Age=0"])
    assert jar.cookie(url) is None, "a Max-Age of zero deletes"

def test_a_secure_cookie_stays_off_plaintext():
    jar = CookieJar()
    secure = URL("https://example.test/")
    jar.learn(secure, ["sid=abc; Secure"])

    assert jar.cookie(secure) == "sid=abc"
    assert jar.cookie(URL("http://example.test/")) is None

def test_set_cookie_goes_onto_a_response_and_delete_zeroes_it():
    response = Message.response(200)
    response.set_cookie(SetCookie("sid", "abc"))
    assert response.header("set-cookie") == "sid=abc"

    response.delete_cookie(SetCookie("sid", "abc"))
    values = [value for name, value in response.headers() if name == "set-cookie"]
    assert values == ["sid=abc", "sid=; Max-Age=0"]
