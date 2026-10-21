//! Attenuating Agent Tokens, JWT/JWS profile of
//! draft-niyikiza-oauth-attenuating-agent-tokens-01 (S4).
//!
//! A root token grants tools to a holder key; each holder may derive a
//! narrower token for the next agent, offline, and the last holder proves
//! possession on every call. [`verify`] runs the draft's section 7 algorithm
//! against the chain, the call and its proof of possession.
//!
//! Only Ed25519 (`EdDSA`) is accepted, the one algorithm the draft requires.

mod constraint;
mod jws;
mod token;
mod verify;

pub use constraint::{Constraint, MAX_CONSTRAINT_DEPTH};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use jws::Jwk;
pub use token::{derive, derive_with, inspect, issue_root, issue_root_with, pop, Claims, Cnf, Presentation, Tools, AAT_TYPE};
pub use verify::{verify, Policy, ReplayGuard, Verified};

/// Largest accepted token, in bytes (draft recommends 64 KiB).
pub const MAX_TOKEN_SIZE: usize = 64 * 1024;
/// Largest accepted chain, in bytes (draft recommends 256 KiB).
pub const MAX_STACK_SIZE: usize = 256 * 1024;
/// Deepest delegation accepted, root excluded.
pub const MAX_DELEGATION_DEPTH: u32 = 16;
/// How far in the future a token's `iat` may be, in seconds.
pub const MAX_IAT_SKEW: i64 = 30;
/// Longest token lifetime, in seconds (draft's upper bound: 90 days).
pub const MAX_TOKEN_LIFETIME: i64 = 90 * 24 * 3600;
/// Accepted distance between a proof of possession's `iat` and now, in seconds.
pub const POP_IAT_TOLERANCE: i64 = 30;

/// Why a token was refused or could not be built. Every failure denies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn deny(reason: impl Into<String>) -> Error {
    Error(reason.into())
}
