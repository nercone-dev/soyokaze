"""The codecs, verified against their RFCs' own test vectors."""

import pytest

import soyokaze
from soyokaze import hsts
from soyokaze.helpers import base64, hpack, huffman, qpack, sha1

def test_base64_round_trips_and_matches_rfc_4648():
    assert base64.encode(b"") == ""
    assert base64.encode(b"f") == "Zg=="
    assert base64.encode(b"fo") == "Zm8="
    assert base64.encode(b"foo") == "Zm9v"
    assert base64.decode("Zm9vYmFy") == b"foobar"

    with pytest.raises(soyokaze.InvalidError):
        base64.decode("not base64!")

def test_sha1_matches_rfc_3174():
    assert sha1.sha1(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert sha1.sha1(b"").hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

def test_huffman_matches_rfc_7541_appendix_c():
    assert huffman.encode(b"www.example.com").hex() == "f1e3c2e5f23a6ba0ab90f4ff"
    assert huffman.decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")) == b"www.example.com"

    with pytest.raises(soyokaze.ProtocolError):
        huffman.decode(bytes.fromhex("ff" * 5))

def test_hpack_round_trips_a_section_through_its_dynamic_tables():
    encoder = hpack.Encoder()
    decoder = hpack.Decoder()

    fields = [(":method", "GET"), (":path", "/"), ("x-custom", "value")]

    for _ in range(2):
        block = encoder.encode(fields)
        assert decoder.decode(block) == fields, "the second block leans on the dynamic table and must still decode"

def test_hpack_refuses_a_block_that_references_nothing():
    decoder = hpack.Decoder()
    with pytest.raises(soyokaze.ProtocolError):
        decoder.decode(bytes([0xFF, 0xFF, 0xFF]))

def test_qpack_round_trips_without_a_dynamic_table():
    encoder = qpack.Encoder()
    decoder = qpack.Decoder()

    fields = [(":method", "GET"), ("x-custom", "value")]
    block, instructions = encoder.encode(0, fields)
    assert instructions == b"", "with no capacity, nothing rides the encoder stream"

    decoded, answer = decoder.decode(0, block)
    assert decoded == fields

def test_qpack_round_trips_through_the_dynamic_table():
    encoder = qpack.Encoder()
    decoder = qpack.Decoder()

    decoder.set_max_capacity(4096)

    setup = encoder.set_max_capacity(4096)
    assert setup != b"", "announcing capacity rides the encoder stream"
    assert decoder.on_encoder_instructions(setup) == b""

    fields = [("x-custom", "value"), ("x-other", "thing")]

    block, instructions = encoder.encode(0, fields)
    assert instructions != b"", "fresh fields are inserted into the dynamic table"

    increment = decoder.on_encoder_instructions(instructions)
    assert increment != b"", "insertions are answered with an Insert Count Increment"
    encoder.on_decoder_instructions(increment)

    decoded, answer = decoder.decode(0, block)
    assert decoded == fields

    later, instructions = encoder.encode(4, fields)
    assert instructions == b"", "acknowledged fields need no new insertions"
    assert len(later) < len(block), "the second block leans on the dynamic table"

    decoded, answer = decoder.decode(4, later)
    assert decoded == fields
    assert answer != b"", "a section leaning on the table is acknowledged"
    encoder.on_decoder_instructions(answer)

def test_hsts_policy_parses_and_builds():
    policy = hsts.HstsPolicy.parse("max-age=31536000; includeSubDomains")
    assert policy.max_age == 31536000
    assert policy.include_subdomains and not policy.preload

    assert hsts.HstsPolicy(60, preload=True).build() == "max-age=60; preload"

    with pytest.raises(soyokaze.ProtocolError):
        hsts.HstsPolicy.parse("includeSubDomains"), "max-age is mandatory"

    with pytest.raises(soyokaze.ProtocolError):
        hsts.HstsPolicy.parse("max-age=1; max-age=2"), "a repeated directive cannot be trusted"

def test_hsts_store_remembers_and_withdraws():
    store = hsts.HstsStore()

    store.learn("example.test", "max-age=60; includeSubDomains", secure=True)
    assert store.secure("example.test")
    assert store.secure("sub.example.test"), "includeSubDomains covers children"
    assert not store.secure("other.test")

    store.learn("plain.test", "max-age=60", secure=False)
    assert not store.secure("plain.test"), "a policy over plaintext could be injected and is ignored"

    store.learn("example.test", "max-age=0", secure=True)
    assert not store.secure("example.test"), "max-age=0 withdraws"

    store.learn("kept.test", "max-age=60", secure=True)
    store.prune()
    assert store.secure("kept.test"), "an unexpired entry survives a prune"
