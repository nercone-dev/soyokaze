"""Running a server across several worker threads.

:class:`Cluster` is what :meth:`Server.run <soyokaze.api.server.Server.run>`
hands back: the worker threads and the ports they bound.
:meth:`Cluster.cores` is the worker count to reach for when there is no
better number.
"""

from ..ffi import library

class Cluster:
    """A server running across several threads, as :meth:`Server.run` returns it.

    :meth:`Server.run`: soyokaze.api.server.Server.run
    """

    def __init__(self, handle, callbacks):
        self.handle = handle
        self.callbacks = callbacks

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

    def close(self, timeout=None):
        """Stops every worker and waits for the threads to finish. This blocks."""
        if self.handle:
            library.soyokaze_cluster_close(self.handle, -1.0 if timeout is None else timeout)
            self.handle = None
