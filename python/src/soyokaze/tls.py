"""TLS identities and Encrypted Client Hello.

:class:`Identity` is what a server serves, :class:`EchKeys` is what it offers
ECH with, and :class:`EchConfigList` is what a client reads back out of what
a server published — the same three parts as the crate's ``tls`` module.
"""

import ctypes

from . import ffi
from .errors import InvalidError, error_out, raise_for
from .ffi import library


class Identity:
    """A certificate chain and the private key that goes with it.

    Each chain entry and the key are DER or PEM, so the chain may arrive as
    one PEM bundle, as one certificate per entry, or as a mixture of the two.
    Nothing is parsed here; a malformed chain or key surfaces when a server
    is built from it.
    """

    def __init__(self, certificates=None, key=None, handle=None):
        if handle is None:
            blobs = [ffi.encoded(certificate) for certificate in certificates]
            slices = [ffi.slice_of(blob) for blob in blobs]
            array = (ffi.Slice * len(slices))(*slices)
            encoded = ffi.encoded(key)
            handle = library.soyokaze_identity_new(array, len(slices), encoded, len(encoded))
            if not handle:
                raise InvalidError("the chain or key was refused")
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_identity_free(self.handle)
            self.handle = None

    @classmethod
    def from_pkcs12(cls, data, passphrase=""):
        """An identity from a PKCS#12 archive, as ``.p12`` and ``.pfx`` files carry."""
        handle = ctypes.c_void_p()
        error = error_out()
        data = ffi.encoded(data)
        passphrase = ffi.encoded(passphrase)
        raise_for(library.soyokaze_identity_from_pkcs12(data, len(data), passphrase, len(passphrase), ctypes.byref(handle), ctypes.byref(error)), error)
        return cls(handle=handle)


class EchKeys:
    """A server's ECH key pair, and the config that publishes its public half."""

    def __init__(self, config=None, private_key=None, handle=None):
        """Keys rebuilt from a stored config and private key, or a wrapper."""
        if handle is None:
            config, private_key = ffi.encoded(config), ffi.encoded(private_key)
            handle = library.soyokaze_ech_keys_new(config, len(config), private_key, len(private_key))
            if not handle:
                raise InvalidError("the config or key was refused")
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_ech_keys_free(self.handle)
            self.handle = None

    @classmethod
    def generate(cls, public_name, config_id=0):
        """Generates a fresh X25519 key pair and the config that publishes it.

        ``public_name`` is what a watcher sees instead of the real server
        name, and must be a name the server can present a certificate for.
        """
        handle = ctypes.c_void_p()
        error = error_out()
        encoded = ffi.encoded(public_name)
        raise_for(library.soyokaze_ech_keys_generate(encoded, len(encoded), config_id, ctypes.byref(handle), ctypes.byref(error)), error)
        return cls(handle=handle)

    @property
    def config(self):
        """The raw ECHConfig."""
        return library.soyokaze_ech_keys_config(self.handle).bytes()

    @property
    def private_key(self):
        """The raw X25519 private key. Handle with care: this is the secret half."""
        return library.soyokaze_ech_keys_private_key(self.handle).bytes()

    def config_list(self):
        """The config wrapped as a one-entry ``ECHConfigList``, ready to publish.

        This is what goes in a client configuration's ECH mapping.
        """
        return ffi.take(library.soyokaze_ech_keys_config_list(self.handle))


class EchConfig:
    """One ECH configuration, as far as a client needs to read it."""

    def __init__(self, version, public_name, maximum_name_length):
        self.version = version
        self.public_name = public_name
        self.maximum_name_length = maximum_name_length

    def __repr__(self):
        return f"EchConfig({self.public_name!r})"


class EchConfigList:
    """A list of ECH configurations, as published for a host."""

    def __init__(self, configs):
        self.configs = configs

    @classmethod
    def parse(cls, data):
        """Parses a published ``ECHConfigList``.

        Configurations of other versions are skipped rather than rejected.
        """
        handle = ctypes.c_void_p()
        error = error_out()
        data = ffi.encoded(data)
        raise_for(library.soyokaze_ech_config_list_parse(data, len(data), ctypes.byref(handle), ctypes.byref(error)), error)

        configs = [
            EchConfig(
                library.soyokaze_ech_config_version(handle, index),
                library.soyokaze_ech_config_public_name(handle, index).text(),
                library.soyokaze_ech_config_maximum_name_length(handle, index),
            )
            for index in range(library.soyokaze_ech_config_list_count(handle))
        ]

        library.soyokaze_ech_config_list_free(handle)
        return cls(configs)
