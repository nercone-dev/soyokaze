"""The two runtimes an awaited call crosses.

The crate's own surface is async, and it reaches Python through a C ABI that
is not: every symbol that waits waits on the calling thread. The bindings are
async all the same, and this module is where the two sides meet.

A :class:`Runtime` is the crate's half — the tokio runtime the library drives
its own work on, the accept loops most of all. Asyncio's event loop is the
caller's half. :func:`offload` joins them: it makes the blocking call on one
of :class:`Threads`, and hands the event loop back until it returns, so
nothing else awaiting is held up. That is sound because ctypes releases the
GIL for the length of a foreign call, so a thread waiting on the library
holds nothing Python needs.

:func:`resolved` is the same seam the other way round, for a handler the
library calls rather than a call the caller makes: the library hands a
request to a callback on one of its own threads, and a handler written as a
coroutine has to be run on the caller's event loop and waited for there.

One default runtime and one default pool serve the whole process unless a
call is handed another, so most code never touches this module.

Cancelling the task that awaits a call does not cancel the call: the worker
thread runs on until the library returns, and only the waiting stops. Close
the connection to make a call that is waiting give up.
"""

import asyncio
import concurrent.futures
import inspect
import threading

from .errors import RuntimeError
from .ffi import library

GUARD = threading.Lock()
"""Guards building the shared runtime and the shared pool.

Either is built on first use, and first use can be two threads at once — a
caller awaiting from more than one event loop, most of all. Without this, both
would be built and one thrown away: a whole tokio runtime, or a thread pool,
started and then left to a garbage collector.
"""

class Runtime:
    """A multi-threaded runtime, the crate's half of an awaited call.

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

    @classmethod
    def default(cls):
        """The runtime used when a call is not handed one, built on first use."""
        if cls.shared is None:
            with GUARD:
                if cls.shared is None:
                    cls.shared = cls()
        return cls.shared

class Threads:
    """The worker threads the blocking library calls are made on.

    A call that waits holds a thread for as long as it waits — a WebSocket
    with nothing to read holds one until a frame arrives — so the ceiling is
    on how many calls may be in flight at once, not on how much work the
    machine will do. Threads are created as they are needed and reused, so a
    caller that awaits one call at a time only ever has one.

    The interpreter joins these threads on the way out, so a call still
    waiting keeps the process alive until it gives up. The timeouts in
    :class:`Limits` are what bound that, and a caller that has turned one off
    — a zero waits forever — should close what it opened, or call
    :meth:`close` with ``wait=False``, rather than leave the exit to them.

    :class:`Limits`: soyokaze.models.Limits
    """

    WORKERS = 1024
    """How many calls may be waiting at once before further ones queue."""

    shared = None

    @classmethod
    def default(cls):
        """The pool used when a call is not handed one, built on first use."""
        if cls.shared is None:
            with GUARD:
                if cls.shared is None:
                    cls.shared = concurrent.futures.ThreadPoolExecutor(max_workers=cls.WORKERS, thread_name_prefix="soyokaze")
        return cls.shared

    @classmethod
    def configure(cls, workers):
        """Builds the shared pool with ``workers`` threads instead of :data:`WORKERS`.

        Call this before the first awaited call; a pool that is already
        serving calls is left alone, since the calls on it are still waiting.
        """
        with GUARD:
            if cls.shared is not None:
                raise RuntimeError("the shared pool is already in use")
            cls.shared = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="soyokaze")
            return cls.shared

    @classmethod
    def close(cls, wait=True):
        """Releases the shared pool, waiting for the calls on it by default."""
        with GUARD:
            pool, cls.shared = cls.shared, None

        if pool is not None:
            pool.shutdown(wait=wait)

async def offload(call, *arguments):
    """Awaits a blocking library call, made on a worker thread.

    The event loop is handed back for as long as the call waits, so the rest
    of the program runs while a request is in flight. Whatever the call
    raises is raised here, and whatever it returns is returned here.
    """
    return await asyncio.get_running_loop().run_in_executor(Threads.default(), call, *arguments)

def resolved(value, loop):
    """What a handler produced, waiting for it on ``loop`` when it is awaitable.

    The mirror of :func:`offload`, for the calls the library makes rather than
    the ones it takes. A handler runs on one of the library's own threads,
    which is not where a coroutine may be awaited, so a coroutine is handed
    to the caller's event loop and this thread waits for the answer. A plain
    callable's return value is passed straight back and never reaches the
    loop at all.
    """
    if not inspect.isawaitable(value):
        return value

    async def awaited():
        return await value

    return asyncio.run_coroutine_threadsafe(awaited(), loop).result()
