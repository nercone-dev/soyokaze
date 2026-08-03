"""Identities and Encrypted Client Hello."""

import pytest

import soyokaze
from soyokaze import EchConfigList, EchKeys, Identity

def test_ech_keys_publish_a_parsable_config_list():
    keys = EchKeys.generate("public.example", config_id=7)

    assert len(keys.private_key) == 32, "an X25519 private key is 32 octets"
    published = keys.config_list()

    parsed = EchConfigList.parse(published)
    assert len(parsed.configs) == 1
    assert parsed.configs[0].public_name == "public.example"
    assert parsed.configs[0].version == 0xFE0D
    assert parsed.configs[0].maximum_name_length == 64

def test_ech_keys_rebuild_from_their_parts():
    keys = EchKeys.generate("public.example")
    rebuilt = EchKeys(keys.config, keys.private_key)

    assert rebuilt.config_list() == keys.config_list()

def test_a_config_list_that_will_not_parse_is_refused():
    with pytest.raises(soyokaze.TlsError):
        EchConfigList.parse(b"\x00")

    with pytest.raises(soyokaze.TlsError):
        EchConfigList.parse(b"\x00\x04\x00\x00\x00\x00"), "an unsupported version alone is no list"

def test_an_identity_holds_its_blobs_without_parsing_them():
    Identity([b"not a certificate"], b"not a key"), "malformed blobs surface when a server is built"

def test_a_pkcs12_archive_that_will_not_parse_is_refused():
    with pytest.raises(soyokaze.TlsError):
        Identity.from_pkcs12(b"not an archive", "")
