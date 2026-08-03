"""Identities, context details and Encrypted Client Hello."""

import ctypes

import pytest

import soyokaze
from soyokaze import EchConfigList, EchKeys, Identity, TlsConfig

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

def test_a_tls_config_defaults_to_changing_nothing():
    struct = TlsConfig().build()

    assert not struct.ciphers.data, "an absent list keeps the profile's ciphers"
    assert not struct.groups.data
    assert not struct.signature_algorithms.data
    assert not struct.prefer_server_ciphers
    assert struct.session_tickets, "tickets are on unless turned off"
    assert not struct.early_data
    assert not struct.certificate_compression

def test_a_tls_config_carries_its_lists_and_flags():
    config = TlsConfig(
        ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305",
        groups="X25519:P-256",
        signature_algorithms="ecdsa_secp384r1_sha384",
        prefer_server_ciphers=True,
        session_tickets=False,
        early_data=True,
        certificate_compression=True,
    )

    struct = config.build()

    assert ctypes.string_at(struct.groups.data, struct.groups.len) == b"X25519:P-256"
    assert ctypes.string_at(struct.signature_algorithms.data, struct.signature_algorithms.len) == b"ecdsa_secp384r1_sha384"
    assert struct.prefer_server_ciphers
    assert not struct.session_tickets
    assert struct.early_data
    assert struct.certificate_compression

def test_a_client_and_a_server_take_a_tls_config():
    from soyokaze import Client, ClientConfig, Server, ServerConfig

    client = Client(ClientConfig(tls=TlsConfig(groups="X25519")))
    assert client.handle, "a client must accept TLS details the way it accepts roots"

    server = Server(ServerConfig(tls=TlsConfig(session_tickets=False, certificate_compression=True)))
    assert server.handle, "a server must accept TLS details the way it accepts an identity"
