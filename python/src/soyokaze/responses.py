"""The response constructors a handler reaches for most.

Each one builds a :class:`Message <models.Message>` with its ``Content-Type``
already set, so a handler can answer in a line, mirroring the crate's
``responses`` module. :class:`ResponseMixin` is folded into
:class:`Message <models.Message>` itself rather than used on its own.
"""

import ctypes

from . import ffi
from .errors import InvalidError, error_out, raise_for
from .ffi import library
from .models import Version

class ResponseMixin:
    """The response constructors and cookie methods that extend :class:`Message <models.Message>`."""

    @classmethod
    def content(cls, content_type, body, version=Version.V1_1):
        """A ``200 OK`` carrying ``body`` under the given media type."""
        kind = ffi.encoded(content_type)
        data = ffi.encoded(body)
        handle = library.soyokaze_response_content(kind, len(kind), data, len(data), int(version))
        if not handle:
            raise InvalidError("the content type was refused")
        return cls(handle=handle)

    @classmethod
    def text(cls, content, version=Version.V1_1):
        """A ``200 OK`` of ``text/plain``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_text(encoded, len(encoded), int(version)))

    @classmethod
    def html(cls, content, version=Version.V1_1):
        """A ``200 OK`` of ``text/html``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_html(encoded, len(encoded), int(version)))

    @classmethod
    def markdown(cls, content, version=Version.V1_1):
        """A ``200 OK`` of ``text/markdown``."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_markdown(encoded, len(encoded), int(version)))

    @classmethod
    def json(cls, content, version=Version.V1_1):
        """A ``200 OK`` of ``application/json``, sent as given."""
        encoded = content.encode()
        return cls(handle=library.soyokaze_response_json(encoded, len(encoded), int(version)))

    @classmethod
    def file(cls, path, version=Version.V1_1):
        """A ``200 OK`` serving a file, typed by its extension."""
        encoded = ffi.encoded(str(path))
        return cls(handle=library.soyokaze_response_file(encoded, len(encoded), int(version)))

    @classmethod
    def redirect(cls, target, version=Version.V1_1):
        """A ``307 Temporary Redirect`` to ``target``, which preserves the method."""
        encoded = ffi.encoded(target)
        return cls(handle=library.soyokaze_response_redirect(encoded, len(encoded), int(version)))

    def set_cookie(self, cookie):
        """Adds a ``Set-Cookie`` field, keeping any already on the message."""
        error = error_out()
        raise_for(library.soyokaze_message_set_cookie(self.handle, cookie.handle, ctypes.byref(error)), error)

    def delete_cookie(self, cookie):
        """Adds a ``Set-Cookie`` field that deletes the cookie."""
        error = error_out()
        raise_for(library.soyokaze_message_delete_cookie(self.handle, cookie.handle, ctypes.byref(error)), error)
