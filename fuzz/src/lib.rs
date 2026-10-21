//! Shared fixtures: the fuzz targets and the seed generator use the same
//! anchor key and clock, so seeds are valid inputs that reach deep paths.

use cleimesh_aat::{Jwk, SigningKey};

/// Fixed "now" for policies and seeds.
pub const NOW: i64 = 1_800_000_000;
/// Audience every seed's proof of possession names.
pub const AUDIENCE: &str = "fuzz-node";

/// Trust anchor of the AAT target and signer of the receipt seeds.
pub fn anchor_key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

pub fn anchor_jwk() -> Jwk {
    Jwk::from_key(&anchor_key().verifying_key())
}

/// The call every AAT seed authorizes.
pub fn call() -> (&'static str, serde_json::Value) {
    ("echo", serde_json::json!({"message": "oi"}))
}
