//! What the two entry points configure in common, from C.
//!
//! The one thing [`crate::api::common`] holds: the versions a client offers
//! and a server accepts when nothing narrows them, newest first.

use crate::models::Version;

/// How many versions are offered when nothing narrows them.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_versions_count() -> usize {
    crate::api::common::VERSIONS.len()
}

/// The version at `index` in that list, newest first.
///
/// An index past the end reads as `-1`.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_versions_at(index: usize) -> i32 {
    match crate::api::common::VERSIONS.get(index) {
        Some(&version) => version as i32,
        None => -1,
    }
}

/// The whole list, borrowed from the library and valid for its lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn soyokaze_versions() -> *const Version {
    crate::api::common::VERSIONS.as_ptr()
}
