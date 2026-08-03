//! What the client and the server configure in common.
//!
//! [`VERSIONS`] is the version list both configurations offer by default.
//! What one connection may spend is bounded by [`Limits`], which lives with
//! the rest of the shared vocabulary in [`crate::models`]; [`ClientLimits`]
//! and [`ServerLimits`] extend it with what only one side needs.
//!
//! [`Limits`]: crate::models::Limits
//! [`ClientLimits`]: crate::api::client::ClientLimits
//! [`ServerLimits`]: crate::api::server::ServerLimits

use crate::models::Version;

/// The versions a configuration offers by default, in the order they are
/// preferred.
///
/// A server offers all of them and lets negotiation choose; a client prefers
/// them in this order.
pub const VERSIONS: &[Version] = &[Version::V3_0, Version::V2_0, Version::V1_1];
