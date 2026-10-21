//! Signed log heads (C2): what the receipt draft cannot
//! show by itself, lines cut from the end of a log.
//!
//! After every append the log rewrites `<log>.head`: how many lines it has
//! and the SHA-256 of the last one, signed by the same key. A log shorter
//! than its head, or whose line at the head's position differs, was cut or
//! edited. Someone with disk access can still swap in an older head along
//! with the cut log; a head kept elsewhere (`cleimesh audit head`) catches
//! that too.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{decode_hex, encode_hex, err, sha256_hex, Result};

/// Prefix of the signed bytes, so a head signature can never pass for a
/// receipt's (whose canonical bytes start with `{"step_id"`) or a token's.
const DOMAIN: &[u8] = b"cleimesh/receipt-head/v1\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub lines: u64,
    /// SHA-256 of the last line, as in `prev_hash`; empty for an empty log.
    pub last_sha256: String,
    pub ts_ms: u64,
    pub public_key: String,
    pub signature: String,
}

/// Where the head of the log at `log` lives.
pub fn head_path(log: &Path) -> PathBuf {
    let mut name = log.as_os_str().to_owned();
    name.push(".head");
    PathBuf::from(name)
}

fn signed_bytes(lines: u64, last_sha256: &str, ts_ms: u64) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(format!("{}\n{}\n{}", lines, last_sha256, ts_ms).as_bytes());
    bytes
}

impl Head {
    pub fn sign(key: &SigningKey, lines: u64, last_sha256: &str, ts_ms: u64) -> Head {
        Head {
            lines,
            last_sha256: last_sha256.to_string(),
            ts_ms,
            public_key: encode_hex(key.verifying_key().as_bytes()),
            signature: encode_hex(&key.sign(&signed_bytes(lines, last_sha256, ts_ms)).to_bytes()),
        }
    }

    /// Checks the signature and that `anchor` made it.
    pub fn verify(&self, anchor: &VerifyingKey) -> Result<()> {
        let key: [u8; 32] = decode_hex(&self.public_key, 32).ok_or_else(|| err("head public_key is not 64 lowercase hex characters"))?.try_into().unwrap();
        if key != *anchor.as_bytes() {
            return Err(err("head signed by another key"));
        }
        let sig: [u8; 64] = decode_hex(&self.signature, 64).ok_or_else(|| err("head signature is not 128 lowercase hex characters"))?.try_into().unwrap();
        anchor.verify(&signed_bytes(self.lines, &self.last_sha256, self.ts_ms), &Signature::from_bytes(&sig)).map_err(|_| err("head signature does not verify"))
    }

    pub fn read(path: &Path) -> Result<Head> {
        let text = std::fs::read_to_string(path).map_err(|e| err(format!("cannot read {}: {}", path.display(), e)))?;
        serde_json::from_str(&text).map_err(|e| err(format!("invalid head {}: {}", path.display(), e)))
    }

    /// Replaces the head file atomically. Not synced: a head lost in a
    /// crash leaves an older head, which `check_head` accepts as "behind".
    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        let tmp = head_path(&path.with_extension("tmp"));
        std::fs::write(&tmp, serde_json::to_vec(self).expect("head serializes")).map_err(|e| err(format!("cannot write {}: {}", tmp.display(), e)))?;
        std::fs::rename(&tmp, path).map_err(|e| err(format!("cannot write {}: {}", path.display(), e)))
    }
}

/// How a log relates to a head that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadStatus {
    /// The log ends exactly where the head says.
    Matches,
    /// The log has these lines after the head (e.g. written just before a
    /// crash, or since the head was saved elsewhere); `verify_log` checks
    /// that they chain on.
    Behind(u64),
}

/// Whether `log` still holds everything `head` (already verified) covers.
pub fn check_head(log: &[u8], head: &Head) -> Result<HeadStatus> {
    let body = log.strip_suffix(b"\n").unwrap_or(log);
    let lines: Vec<&[u8]> = if log.is_empty() { Vec::new() } else { body.split(|b| *b == b'\n').collect() };
    let have = lines.len() as u64;
    if have < head.lines {
        return Err(err(format!("log truncated: the head covers {} lines, the log has {}", head.lines, have)));
    }
    if head.lines > 0 && sha256_hex(lines[head.lines as usize - 1]) != head.last_sha256 {
        return Err(err(format!("line {} differs from the one the head covers (log edited or replaced)", head.lines)));
    }
    Ok(if have == head.lines { HeadStatus::Matches } else { HeadStatus::Behind(have - head.lines) })
}
