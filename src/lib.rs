pub mod error;
pub mod fiat_shamir;
pub mod generators;
pub mod hash;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

/// ARC ciphersuite context string for P-256.
///
/// Reference: <https://ietf-wg-privacypass.github.io/draft-arc/draft-ietf-privacypass-arc-crypto.html#name-arcp-256>
pub const CONTEXT_STRING: &[u8] = b"ARCV1-P256";
