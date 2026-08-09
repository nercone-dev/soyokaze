"""Running a server across several worker threads.

:class:`Cluster` is what :meth:`Server.run <soyokaze.api.server.Server.run>`
hands back: the worker threads and the ports they bound.
:meth:`Cluster.cores` is the worker count to reach for when there is no
better number.
"""

from ..ffi import library
from ..runtime import offload

class Cluster:
    """A server running across several threads, as :meth:`Server.run` returns it.

    Usable as an async context manager, which closes it on the way out.

    :meth:`Server.run`: soyokaze.api.server.Server.run
    """

    def __init__(self, handle, callbacks):
        self.handle = handle
        self.callbacks = callbacks

    async def __aenter__(self):
        return self

    async def __aexit__(self, kind, value, traceback):
        await self.close()
        return False

    @classmethod
    def cores(cls):
        """How many threads the machine can run at once, or 1 if that cannot be found."""
        return library.soyokaze_cores()

    @property
    def port(self):
        """The port the first listener actually bound."""
        return library.soyokaze_cluster_port(self.handle)

    def ports(self):
        """The port of every bound address."""
        count = library.soyokaze_cluster_address_count(self.handle)
        return [library.soyokaze_cluster_port_at(self.handle, index) for index in range(count)]

    def address(self):
        """The address the first listener bound, or ``None``."""
        addresses = self.addresses()
        return addresses[0] if addresses else None

    def addresses(self):
        """Every address the cluster bound, as text."""
        count = library.soyokaze_cluster_address_count(self.handle)
        return [library.soyokaze_cluster_address_at(self.handle, index).take().decode() for index in range(count)]

    def workers(self):
        """How many worker threads are running."""
        return library.soyokaze_cluster_workers(self.handle)

    async def close(self, timeout=None):
        """Stops every worker and waits for the threads to finish.

        The wait is made on a worker thread, so the event loop keeps running
        and a coroutine handler still in flight can finish.
        """
        if self.handle:
            handle, self.handle = self.handle, None
            await offload(library.soyokaze_cluster_close, handle, -1.0 if timeout is None else timeout)
