"""What the client and the server configure in common.

:data:`VERSIONS` is the version list both configurations offer by default.
:class:`Limits` lives with the rest of the shared vocabulary in
:mod:`soyokaze.models`, mirroring the crate.
"""

from ..models import Version

VERSIONS = [Version.V3_0, Version.V2_0, Version.V1_1]
