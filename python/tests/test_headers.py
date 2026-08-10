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
    values = [value for name, value in response.headers if name == "set-cookie"]
    assert values == ["sid=abc", "sid=; Max-Age=0"]

# ---------------------------------------------------------------- conformance

def test_a_borrowed_section_keeps_the_message_it_points_into_alive():
    """A view of a message's fields must not outlive the handle it borrows.

    The view holds no memory of its own — it points into the message — so a
    message collected while a view of it is still held would leave that view
    reading freed memory.
    """
    import gc

    def borrowed():
        message = soyokaze.Message.request(soyokaze.Method.GET, "/", soyokaze.Version.V1_1)
        message.append_header("x-marker", "A" * 40)
        return message.headers

    view = borrowed()
    gc.collect()

    # Churn the allocator, so a view that had been left dangling would read
    # something else back.
    keep = []
    for _ in range(200):
        other = soyokaze.Headers()
        for index in range(8):
            other.append(f"y-{index}", "Z" * 40)
        keep.append(other)

    assert view.len() == 1
    assert view.get("x-marker") == "A" * 40

def test_a_borrowed_trailer_section_keeps_its_message_too():
    import gc

    def borrowed():
        message = soyokaze.Message.response(200, soyokaze.Version.V1_1)
        message.append_trailer("x-trailer", "kept")
        return message.trailers

    view = borrowed()
    gc.collect()

    assert view.get("x-trailer") == "kept"

def test_a_section_a_message_owns_is_not_freed_twice():
    """A borrowed view frees nothing; only the message does."""
    message = soyokaze.Message.request(soyokaze.Method.GET, "/", soyokaze.Version.V1_1)

    for _ in range(64):
        view = message.headers
        assert view.len() == 0
        del view

    message.append_header("x-still-here", "1")
    assert message.header("x-still-here") == "1"

def test_a_cookie_may_only_be_scoped_to_a_domain_the_response_came_from():
    """RFC 6265 5.3: a Domain the request host does not domain-match is ignored."""
    jar = CookieJar()

    jar.learn(URL("https://evil.test/"), [
        "a=1; Domain=victim.test",
        "b=1; Domain=test",
        "c=1; Domain=evil.test.attacker.test",
    ])

    assert jar.cookie(URL("https://victim.test/")) is None
    assert jar.cookie(URL("https://other.test/")) is None
    assert jar.cookie(URL("https://evil.test/")) is None

def test_a_cookie_scoped_to_the_host_or_a_parent_of_it_is_kept():
    jar = CookieJar()
    jar.learn(URL("https://shop.example.test/"), ["a=1; Domain=example.test", "b=2", "c=3; Domain=shop.example.test"])

    sent = jar.cookie(URL("https://shop.example.test/"))
    assert "a=1" in sent and "b=2" in sent and "c=3" in sent

    parent = jar.cookie(URL("https://example.test/"))
    assert "a=1" in parent
    assert "b=2" not in parent and "c=3" not in parent

def test_a_jar_that_may_hold_nothing_holds_nothing():
    limits = soyokaze.Limits(max_cookies=0)
    jar = CookieJar(limits=limits)

    jar.learn(URL("https://example.test/"), ["a=1", "b=2"])

    assert jar.cookie(URL("https://example.test/")) is None

def test_a_client_jar_outlives_nothing_it_points_into():
    """The jar a client keeps is borrowed; holding it must hold the client."""
    import gc

    def borrowed():
        client = soyokaze.Client()
        return client.jar

    jar = borrowed()
    gc.collect()

    jar.learn(URL("https://example.test/"), ["a=1"])
    assert jar.cookie(URL("https://example.test/")) == "a=1"

def test_a_client_store_outlives_nothing_it_points_into():
    import gc

    def borrowed():
        client = soyokaze.Client()
        return client.store

    store = borrowed()
    gc.collect()

    store.learn("example.test", "max-age=31536000", secure=True)
    assert store.secure("example.test")
