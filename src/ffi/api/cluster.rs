//! Running a server across worker threads, from C.
//!
//! [`crate::api::cluster`] runs one server on a thread per core, each with a
//! runtime of its own, and hands back a [`Cluster`] to close them all with.
//! The cluster itself is built by `soyokaze_server_run`; what is here is what
//! can be read off one, and the core count a caller sizes its own pools by.
//!
//! [`Cluster`]: crate::api::cluster::Cluster

pub use crate::api::cluster::Cluster;

/// How many cores the machine reports, which is how many workers a cluster
/// takes when it is not told otherwise.
///
/// Never zero: a machine that reports nothing is treated as having one.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_cores() -> u32 {
    Cluster::cores() as u32
}

/// How many worker threads the cluster is running.
///
/// # Safety
///
/// `cluster` must either be null or be a handle that has not been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_workers(cluster: *const Cluster) -> u32 {
    unsafe { cluster.as_ref() }.map_or(0, |cluster| cluster.workers() as u32)
}

/// How many addresses the cluster is listening on.
///
/// # Safety
///
/// As [`soyokaze_cluster_workers`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_address_count(cluster: *const Cluster) -> usize {
    unsafe { cluster.as_ref() }.map_or(0, |cluster| cluster.addresses().len())
}

/// The port of the first address, or zero when there is none.
///
/// What a caller that bound port zero reads back to learn which port the
/// operating system picked.
///
/// # Safety
///
/// As [`soyokaze_cluster_workers`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_port(cluster: *const Cluster) -> u16 {
    unsafe { cluster.as_ref() }.and_then(|cluster| cluster.address()).map_or(0, |address| address.port())
}

/// The port of the address at `index`, or zero past the end.
///
/// # Safety
///
/// As [`soyokaze_cluster_workers`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_port_at(cluster: *const Cluster, index: usize) -> u16 {
    unsafe { cluster.as_ref() }.and_then(|cluster| cluster.addresses().get(index)).map_or(0, |address| address.port())
}

/// The address at `index` as text, owned by the caller.
///
/// An empty buffer with a null pointer means there is no address there.
///
/// # Safety
///
/// As [`soyokaze_cluster_workers`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_address_at(cluster: *const Cluster, index: usize) -> crate::ffi::Buffer {
    match unsafe { cluster.as_ref() }.and_then(|cluster| cluster.addresses().get(index)) {
        Some(address) => crate::ffi::Buffer::new(address.to_string().into_bytes()),
        None => crate::ffi::Buffer::EMPTY,
    }
}

/// Closes every worker and waits for them to finish.
///
/// Consumes `cluster`, which must not be used again. A negative `timeout`
/// waits as long as it takes; zero closes at once, without letting connections
/// finish.
///
/// # Safety
///
/// `cluster` must come from `soyokaze_server_run` and not have been closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn soyokaze_cluster_close(cluster: *mut Cluster, timeout: f64) {
    if cluster.is_null() {
        return;
    }

    unsafe { Box::from_raw(cluster) }.close((timeout >= 0.0).then_some(timeout));
}
