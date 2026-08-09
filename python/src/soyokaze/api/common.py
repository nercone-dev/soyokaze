"""What the two entry points configure in common.

The one thing the crate's ``api::common`` holds: the versions a client offers
and a server accepts when nothing narrows them, newest first.
"""

from ..ffi import library
from ..models import Version

VERSIONS = tuple(
    Version(library.soyokaze_versions_at(index))
    for index in range(library.soyokaze_versions_count())
)
"""The versions offered when nothing narrows them, newest first."""
