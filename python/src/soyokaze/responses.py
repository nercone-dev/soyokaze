"""The response constructors a handler reaches for most.

Each one builds a :class:`Message <models.Message>` with its ``Content-Type``
already set, so a handler can answer in a line, mirroring the crate's
``responses`` module. :class:`ResponseMixin` is folded into
:class:`Message <models.Message>` itself rather than used on its own.
"""

import ctypes

from . import ffi
from .errors import Error, InvalidError
from .ffi import library

class Status:
    """The reason phrases a status code is conventionally sent with."""

    @classmethod
    def reason(cls, status_code):
        """The reason phrase for a status code.

        A code outside the ranges the library knows reads as the phrase for the
        class it falls in.
        """
        return library.soyokaze_status_reason(status_code).text()

class ResponseMixin:
    """The response constructors and cookie methods that extend :class:`Message <models.Message>`.

    The version defaults to ``None``, which each constructor resolves through
    :meth:`Message.version_code <models.Message.version_code>`, so this module
    stands alone rather than reaching back into :mod:`models`.
    """

    @classmethod
    def content_type(cls, path):
        """The media type a path's extension names.

        An extension the library does not know reads as
        ``application/octet-stream``.
        """
        path = ffi.Library.encoded(path)
        return library.soyokaze_content_type(path, len(path)).text()

    @classmethod
    def upgrade_required(cls, request, version=None, protocol="HTTP/2.0"):
        """The ``426 Upgrade Required`` for a request in a version this end will not speak.

        ``request`` is read, not consumed.
        """
        encoded = ffi.Library.encoded(protocol)
        handle = library.soyokaze_response_upgrade_required(request.handle, cls.version_code(version), encoded, len(encoded))
        if not handle:
            raise InvalidError("the protocol was refused")
        return cls(handle=handle)

    def finalize_response(self, date=None, hsts=None):
        """Stamps the fields a response is expected to carry onto this message.

        The ``Date`` field comes from ``date``, or from the shared cache when
        none is given; ``hsts`` stamps a ``Strict-Transport-Security``.
        """
        policy = None if hsts is None else ffi.HSTSPolicy(hsts.max_age, hsts.include_subdomains, hsts.preload)
        library.soyokaze_message_finalize_response(
            self.handle,
            None if date is None else date.handle,
            None if policy is None else ctypes.byref(policy),
        )

    def finalize_request(self, authority):
        """Fills in the authority a request is expected to carry.

        Writes ``Host`` for HTTP/1.x and ``:authority`` above it, and leaves
        whichever is already there alone.
        """
        encoded = ffi.Library.encoded(authority)
        library.soyokaze_message_finalize_request(self.handle, encoded, len(encoded))

    @classmethod
    def content(cls, content_type, body, version=None):
        """A ``200 OK`` carrying ``body`` under the given media type."""
        kind = ffi.Library.encoded(content_type)
        data = ffi.Library.encoded(body)
        handle = library.soyokaze_response_content(kind, len(kind), data, len(data), cls.version_code(version))
        if not handle:
            raise InvalidError("the content type was refused")
        return cls(handle=handle)

    @classmethod
    def text(cls, content, version=None):
        """A ``200 OK`` of ``text/plain``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_text(encoded, len(encoded), cls.version_code(version)))

    @classmethod
    def html(cls, content, version=None):
        """A ``200 OK`` of ``text/html``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_html(encoded, len(encoded), cls.version_code(version)))

    @classmethod
    def markdown(cls, content, version=None):
        """A ``200 OK`` of ``text/markdown``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_markdown(encoded, len(encoded), cls.version_code(version)))

    @classmethod
    def json(cls, content, version=None):
        """A ``200 OK`` of ``application/json``, sent as given."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_json(encoded, len(encoded), cls.version_code(version)))

    @classmethod
    def file(cls, path, version=None):
        """A ``200 OK`` serving a file, typed by its extension."""
        encoded = ffi.Library.encoded(str(path))
        return cls(handle=library.soyokaze_response_file(encoded, len(encoded), cls.version_code(version)))

    @classmethod
    def redirect(cls, target, version=None):
        """A ``307 Temporary Redirect`` to ``target``, which preserves the method."""
        encoded = ffi.Library.encoded(target)
        return cls(handle=library.soyokaze_response_redirect(encoded, len(encoded), cls.version_code(version)))

    def set_cookie(self, cookie):
        """Adds a ``Set-Cookie`` field, keeping any already on the message."""
        error = Error.out()
        Error.raise_for(library.soyokaze_message_set_cookie(self.handle, cookie.handle, ctypes.byref(error)), error)

    def delete_cookie(self, cookie):
        """Adds a ``Set-Cookie`` field that deletes the cookie."""
        error = Error.out()
        Error.raise_for(library.soyokaze_message_delete_cookie(self.handle, cookie.handle, ctypes.byref(error)), error)
