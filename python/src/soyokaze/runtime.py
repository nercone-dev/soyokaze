"""The runtime the blocking calls in the bindings drive.

The crate's own surface is async; every call that has to wait runs on a
:class:`Runtime`. One default runtime serves the whole process unless a call
is handed another, so most code never touches this module.
"""

from .errors import RuntimeError
from .ffi import library


class Runtime:
    """A multi-threaded runtime.

    Work a call leaves running — a server's accept loops, most of all —
    keeps running on it after the call returns, so a runtime must outlive
    whatever it was used to start.
    """

    def __init__(self, workers=0):
        """Builds a runtime with ``workers`` threads, or one per core when zero."""
        self.handle = library.soyokaze_runtime_new(workers)
        if not self.handle:
            raise RuntimeError("the runtime could not be built")

    def close(self):
        """Releases the runtime, waiting for the work still on it to finish."""
        if self.handle:
            library.soyokaze_runtime_free(self.handle)
            self.handle = None

    def __del__(self):
        self.close()


shared = None


def default_runtime():
    """The runtime used when a call is not handed one, built on first use."""
    global shared
    if shared is None:
        shared = Runtime()
    return shared
