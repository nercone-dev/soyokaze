"""TLS identities, context details and Encrypted Client Hello.

:class:`Identity` is what a server serves, :class:`TLSConfig` is how either
side's context is tuned, :class:`ECHKeys` is what a server offers ECH with,
and :class:`ECHConfigList` is what a client reads back out of what a server
published — the same parts as the crate's ``tls`` module.
"""

import ctypes
import enum

from . import ffi
from .errors import Error, InvalidError, TLSError
from .ffi import library

TLS_VERSION_1_3 = library.soyokaze_tls_version_1_3()
"""The one TLS version this library speaks, as its wire code."""

class TLSVersion(int):
    """A TLS version, as its wire code."""

    V1_3 = None
    """The one version this library offers or accepts."""

class TLSCipher(int):
    """A TLS cipher suite, as its wire code."""

class TLSGroup(int):
    """A TLS named group, as its wire code."""

TLSVersion.V1_3 = TLSVersion(TLS_VERSION_1_3)

class Format(enum.IntEnum):
    """Which encoding a certificate or key blob is in.

    One DER blob holds exactly one object, while one PEM blob holds as many as
    were concatenated into it — which is how a chain, or a chain and its key,
    is usually shipped in a single file.
    """

    DER = 0
    PEM = 1

    @classmethod
    def of(cls, raw):
        """The format a blob is in, recognised from its contents.

        The first octet that is not whitespace decides it: DER starts with
        :data:`SEQUENCE`, and anything else is read as PEM.
        """
        raw = ffi.Library.encoded(raw)
        return cls(library.soyokaze_format_of(raw, len(raw)))

    @classmethod
    def certificates(cls, raw):
        """Every certificate in one blob, as DER, in the order they appear.

        Sections that are not certificates are skipped, so a file holding a
        chain and its key parses to the chain alone.
        """
        raw = ffi.Library.encoded(raw)
        count = library.soyokaze_format_certificate_count(raw, len(raw))
        if count < 0:
            raise TLSError("the blob holds no certificate that will parse")
        return [library.soyokaze_format_certificate(raw, len(raw), index).take() for index in range(count)]

    @classmethod
    def certificate_list(cls, blobs):
        """Every certificate across several blobs, in the order they were given."""
        return [certificate for blob in blobs for certificate in cls.certificates(blob)]

    @classmethod
    def private_key(cls, raw):
        """The private key in a blob, as DER."""
        raw = ffi.Library.encoded(raw)
        key = library.soyokaze_format_private_key(raw, len(raw)).taken()
        if key is None:
            raise TLSError("the blob holds no private key that will parse")
        return key

Format.SEQUENCE = library.soyokaze_format_sequence()

class Security:
    """What a connection turned out to be underneath.

    Stamped on every message a connection receives, so these read as absent on
    one the caller built. A QUIC connection reports TLS 1.3, which is what it
    carries, but not the cipher suite or group: the QUIC stack does not hand
    its session out.
    """

    def __init__(self, secure=False, early_data=False, tls=False, tls_version=None, tls_group=None, tls_cipher=None, quic=False, quic_version=None):
        self.secure = secure
        self.early_data = early_data
        self.tls = tls
        self.tls_version = tls_version
        self.tls_group = tls_group
        self.tls_cipher = tls_cipher
        self.quic = quic
        self.quic_version = quic_version

    @classmethod
    def taken(cls, struct):
        """The :class:`Security` a ``soyokaze_security_t`` stands for."""
        return cls(
            struct.secure,
            struct.early_data,
            struct.tls,
            None if struct.tls_version < 0 else TLSVersion(struct.tls_version),
            None if struct.tls_group < 0 else TLSGroup(struct.tls_group),
            None if struct.tls_cipher < 0 else TLSCipher(struct.tls_cipher),
            struct.quic,
            None if struct.quic_version < 0 else struct.quic_version,
        )

    @classmethod
    def default(cls):
        """What a plain connection reports: nothing negotiated at all."""
        return cls.taken(library.soyokaze_security_default())

    @classmethod
    def quic_of(cls, quic_version=None):
        """What a QUIC connection reports."""
        return cls.taken(library.soyokaze_security_quic(-1 if quic_version is None else quic_version))

    @classmethod
    def of(cls, message):
        """What a message's connection turned out to be underneath."""
        return cls.taken(library.soyokaze_message_security(message.handle))

    def build(self):
        """The ``soyokaze_security_t`` this stands for."""
        return ffi.Security(
            self.secure,
            self.early_data,
            self.tls,
            -1 if self.tls_version is None else int(self.tls_version),
            -1 if self.tls_group is None else int(self.tls_group),
            -1 if self.tls_cipher is None else int(self.tls_cipher),
            self.quic,
            -1 if self.quic_version is None else int(self.quic_version),
        )

    def apply(self, message):
        """Stamps what the transport turned out to be onto a message."""
        struct = self.build()
        library.soyokaze_security_apply(ctypes.byref(struct), message.handle)

    def __repr__(self):
        return f"Security(secure={self.secure}, tls={self.tls}, quic={self.quic})"

class TLSConfig:
    """The TLS details a context is built with, beyond its identity and roots.

    Every field has a working default, so ``TLSConfig()`` changes nothing
    about how a context would otherwise behave. Each string is an OpenSSL
    list, entries separated by ``:`` and most preferred first; ``None`` keeps
    that field's default. BoringSSL keeps its built-in order for the TLS 1.3
    suites, so ``ciphers`` restricts and orders TLS 1.2.
    """

    def __init__(self, ciphers=None, groups=None, signature_algorithms=None, prefer_server_ciphers=False, session_tickets=True, early_data=False, certificate_compression=False):
        self.ciphers = ciphers
        self.groups = groups
        self.signature_algorithms = signature_algorithms
        self.prefer_server_ciphers = prefer_server_ciphers
        self.session_tickets = session_tickets
        self.early_data = early_data
        self.certificate_compression = certificate_compression

    def build(self):
        """The ``soyokaze_tls_config_t`` this stands for.

        The struct keeps everything it points at alive on itself.
        """
        struct = library.soyokaze_tls_config_default()
        keepalive = []

        for name in ("ciphers", "groups", "signature_algorithms"):
            value = getattr(self, name)
            if value is not None:
                view = ffi.Slice.of(ffi.Library.encoded(value))
                keepalive.append(view)
                setattr(struct, name, view)

        struct.prefer_server_ciphers = self.prefer_server_ciphers
        struct.session_tickets = self.session_tickets
        struct.early_data = self.early_data
        struct.certificate_compression = self.certificate_compression

        struct.keepalive = keepalive
        return struct

class Identity:
    """A certificate chain and the private key that goes with it.

    Each chain entry and the key are DER or PEM, so the chain may arrive as
    one PEM bundle, as one certificate per entry, or as a mixture of the two.
    Nothing is parsed here; a malformed chain or key surfaces when a server
    is built from it.
    """

    def __init__(self, certificates=None, key=None, handle=None):
        if handle is None:
            blobs = [ffi.Library.encoded(certificate) for certificate in certificates]
            slices = [ffi.Slice.of(blob) for blob in blobs]
            array = (ffi.Slice * len(slices))(*slices)
            encoded = ffi.Library.encoded(key)
            handle = library.soyokaze_identity_new(array, len(slices), encoded, len(encoded))
            if not handle:
                raise InvalidError("the chain or key was refused")
        self.handle = handle

    def __del__(self):
        if getattr(self, "handle", None):
            library.soyokaze_identity_free(self.handle)
            self.handle = None

    def chain(self):
        """The certificate chain, as DER, in the order it was given."""
        count = library.soyokaze_identity_certificate_count(self.handle)
        if count < 0:
            raise TLSError("the chain holds no certificate that will parse")
        return [library.soyokaze_identity_certificate(self.handle, index).take() for index in range(count)]

    def private_key(self):
        """The private key, as DER."""
        key = library.soyokaze_identity_private_key(self.handle).taken()
        if key is None:
            raise TLSError("the identity holds no private key that will parse")
        return key

    @classmethod
    def from_pkcs12(cls, data, passphrase=""):
        """An identity from a PKCS#12 archive, as ``.p12`` and ``.pfx`` files carry."""
        handle = ctypes.c_void_p()
        error = Error.out()
        data = ffi.Library.encoded(data)
        passphrase = ffi.Library.encoded(passphrase)
        Error.raise_for(library.soyokaze_identity_from_pkcs12(data, len(data), passphrase, len(passphrase), ctypes.byref(handle), ctypes.byref(error)), error)
        return cls(handle=handle)

class ECHKeys:
    """A server's ECH key pair, and the config that publishes its public half."""

    KEM_X25519_HKDF_SHA256 = library.soyokaze_ech_kem_x25519_hkdf_sha256()
    """The one key encapsulation mechanism this library generates keys for."""

    KDF_HKDF_SHA256 = library.soyokaze_ech_kdf_hkdf_sha256()
    """The one key derivation function this library offers."""

    AEAD_AES_128_GCM = library.soyokaze_ech_aead_aes_128_gcm()
    """The one AEAD this library offers."""

    MAXIMUM_NAME_LENGTH = library.soyokaze_ech_maximum_name_length()
    """How long a name a generated configuration says it can cover."""

    @classmethod
    def encode(cls, public_name, config_id, public_key):
        """The ECHConfig a public name, config identifier and public key spell out."""
        public_name, public_key = ffi.Library.encoded(public_name), ffi.Library.encoded(public_key)
        return library.soyokaze_ech_keys_encode(public_name, len(public_name), config_id, public_key, len(public_key)).take()

    def __init__(self, config=None, private_key=None, handle=None):
        """Keys rebuilt from a stored config and private key, or a wrapper."""
        if handle is None:
            config, private_key = ffi.Library.encoded(config), ffi.Library.encoded(private_key)
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
        error = Error.out()
        encoded = ffi.Library.encoded(public_name)
        Error.raise_for(library.soyokaze_ech_keys_generate(encoded, len(encoded), config_id, ctypes.byref(handle), ctypes.byref(error)), error)
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
        return library.soyokaze_ech_keys_config_list(self.handle).take()

class ECHConfig:
    """One ECH configuration, as far as a client needs to read it."""

    VERSION = library.soyokaze_ech_config_supported_version()
    """The version a configuration must carry to be understood."""

    def __init__(self, version, public_name, maximum_name_length):
        self.version = version
        self.public_name = public_name
        self.maximum_name_length = maximum_name_length

    def __repr__(self):
        return f"ECHConfig({self.public_name!r})"

class ECHConfigList:
    """A list of ECH configurations, as published for a host."""

    def __init__(self, configs):
        self.configs = configs

    @classmethod
    def entry(cls, handle, index):
        """The version, public name and padded name length of one entry."""
        version = library.soyokaze_ech_config_version(handle, index)
        public_name = library.soyokaze_ech_config_public_name(handle, index).text()
        maximum_name_length = library.soyokaze_ech_config_maximum_name_length(handle, index)
        return version, public_name, maximum_name_length

    @classmethod
    def parse(cls, data):
        """Parses a published ``ECHConfigList``.

        Configurations of other versions are skipped rather than rejected.
        """
        handle = ctypes.c_void_p()
        error = Error.out()
        data = ffi.Library.encoded(data)
        Error.raise_for(library.soyokaze_ech_config_list_parse(data, len(data), ctypes.byref(handle), ctypes.byref(error)), error)

        count = library.soyokaze_ech_config_list_count(handle)
        configs = [ECHConfig(*cls.entry(handle, index)) for index in range(count)]

        library.soyokaze_ech_config_list_free(handle)
        return cls(configs)
