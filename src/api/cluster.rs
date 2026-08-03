//! Running a server across several worker threads.
//!
//! [`Cluster`] is what [`Server::run`] hands back: the worker threads, their
//! shutdown switch, and the addresses they bound. [`cores`] is the worker
//! count to reach for when there is no better number.
//!
//! [`Server::run`]: crate::api::server::Server::run

/// How many threads the machine can run at once, or 1 if that cannot be found.
///
/// Useful as the worker count for [`Server::run`].
///
/// [`Server::run`]: crate::api::server::Server::run
pub fn cores() -> usize {
    std::thread::available_parallelism().map(|count| count.get()).unwrap_or(1)
}

/// A server running across several threads, as [`Server::run`]
/// returns it.
///
/// Dropping this leaves the workers running; call [`Cluster::close`] to wind
/// them down.
///
/// [`Server::run`]: crate::api::server::Server::run
pub struct Cluster {
    shutdown: tokio::sync::watch::Sender<Option<f64>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    addresses: Vec<std::net::SocketAddr>,
}

impl Cluster {
    /// A cluster over already-started workers.
    pub fn new(shutdown: tokio::sync::watch::Sender<Option<f64>>, threads: Vec<std::thread::JoinHandle<()>>, addresses: Vec<std::net::SocketAddr>) -> Self {
        Self { shutdown, threads, addresses }
    }

    /// The first bound address, if any port has one.
    pub fn address(&self) -> Option<std::net::SocketAddr> {
        self.addresses.first().copied()
    }

    /// Every bound address.
    pub fn addresses(&self) -> &[std::net::SocketAddr] {
        &self.addresses
    }

    /// How many worker threads are running.
    pub fn workers(&self) -> usize {
        self.threads.len()
    }

    /// Stops every worker and waits for the threads to finish.
    ///
    /// `timeout` is passed to each worker's [`ServerHandle::close`], bounding
    /// how long it waits for its connections. This blocks, so do not call it
    /// from inside an async context.
    ///
    /// [`ServerHandle::close`]: crate::api::server::ServerHandle::close
    pub fn close(self, timeout: Option<f64>) {
        let _ = self.shutdown.send(timeout);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}
