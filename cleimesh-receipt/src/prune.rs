//! Retention (C3): removing receipts older than a date,
//! with a receipt of the removal itself.
//!
//! The pruned log starts a new chain. Its first line is a receipt that says
//! how many lines were removed, up to when, and binds the old log's head
//! (line count and last-line hash), so a head saved elsewhere before the
//! pruning still proves what the log held. The receipts kept are signed
//! again in the new chain with the same content; only `prev_hash` and the
//! signature change.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;
use std::path::Path;

use crate::{err, head_path, sha256_hex, sign, verify_log, Entry, Head, Receipt, Result};

/// `action_id` of the receipt that opens a pruned log.
pub const PRUNE_ACTION_ID: &str = "cleimesh.log_pruned";

#[derive(Debug, Clone, PartialEq)]
pub struct PruneSummary {
    pub removed: usize,
    pub kept: usize,
    /// The receipt of the pruning, as written (absent on a dry run or when
    /// nothing was old enough).
    pub receipt: Option<Receipt>,
}

/// Removes the receipts of `log_path` dated before `cutoff_ms` (the oldest
/// run of them, in log order). Refuses a log that fails verification, and
/// a log that changes while it works (run it with the node stopped).
/// `dry_run` only counts.
pub fn prune(log_path: &Path, key: &SigningKey, anchor: &VerifyingKey, cutoff_ms: u64, now_ms: u64, dry_run: bool) -> Result<PruneSummary> {
    let bytes = std::fs::read(log_path).map_err(|e| err(format!("cannot read {}: {}", log_path.display(), e)))?;
    let report = verify_log(&bytes, anchor);
    if !report.ok() {
        let first = &report.failures[0];
        return Err(err(format!("refusing to prune a log that fails verification (line {}: {})", first.line, first.reason)));
    }
    let text = String::from_utf8(bytes.clone()).map_err(|_| err("log is not UTF-8"))?;
    let lines: Vec<&str> = text.lines().collect();
    let receipts = lines.iter().map(|l| Receipt::parse(l)).collect::<Result<Vec<_>>>()?;
    let removed = receipts.iter().take_while(|r| r.ts_ms < cutoff_ms).count();
    if dry_run || removed == 0 {
        return Ok(PruneSummary { removed, kept: lines.len() - removed, receipt: None });
    }

    let opening = sign(
        key,
        Entry {
            step_id: format!("prune-{}", now_ms),
            action_id: PRUNE_ACTION_ID.to_string(),
            params: json!({
                "removed_lines": removed,
                "removed_before_ms": cutoff_ms,
                "removed_last_sha256": sha256_hex(lines[removed - 1].as_bytes()),
                "previous_lines": lines.len(),
                "previous_last_sha256": sha256_hex(lines[lines.len() - 1].as_bytes()),
                "kept_lines": lines.len() - removed,
            }),
            success: true,
            ts_ms: now_ms,
            actor: None,
        },
        None,
    )?;
    let mut out = Vec::new();
    let mut prev = None;
    let mut last_ts = now_ms;
    for receipt in std::iter::once(opening.clone()).chain(receipts.into_iter().skip(removed).map(|r| {
        // Kept receipts: same content, chained anew below.
        Receipt { prev_hash: None, signature: String::new(), ..r }
    })) {
        let entry = Entry { step_id: receipt.step_id, action_id: receipt.action_id, params: receipt.params, success: receipt.success, ts_ms: receipt.ts_ms, actor: receipt.actor };
        last_ts = entry.ts_ms;
        let signed = sign(key, entry, prev.clone())?;
        let line = signed.to_line()?;
        prev = Some(sha256_hex(line.as_bytes()));
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }

    // Write beside, check nothing was appended meanwhile, then swap in.
    let tmp = log_path.with_extension("pruning");
    std::fs::write(&tmp, &out).and_then(|_| std::fs::File::open(&tmp)?.sync_all()).map_err(|e| err(format!("cannot write {}: {}", tmp.display(), e)))?;
    if std::fs::read(log_path).map_err(|e| err(format!("cannot read {}: {}", log_path.display(), e)))? != bytes {
        let _ = std::fs::remove_file(&tmp);
        return Err(err("the log changed while pruning (is the node running?); nothing was removed"));
    }
    std::fs::rename(&tmp, log_path).map_err(|e| err(format!("cannot replace {}: {}", log_path.display(), e)))?;
    let kept = lines.len() - removed;
    Head::sign(key, kept as u64 + 1, prev.as_deref().unwrap_or(""), last_ts).write(&head_path(log_path))?;
    Ok(PruneSummary { removed, kept, receipt: Some(opening) })
}
