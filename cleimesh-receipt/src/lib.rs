//! Signed, hash-chained action receipts, per
//! draft-sahu-agent-action-receipts-00 (C2).
//!
//! Each receipt is one JSON line signed with Ed25519 over a canonical byte
//! sequence (section 4), and carries the SHA-256 of the previous line
//! (section 6), so changing, removing or reordering an interior line
//! breaks the log. [`verify_log`] runs the draft's section 7 checks offline
//! against the expected signer.
//!
//! What a receipt cannot show: lines cut from the end of a log, since
//! nothing after them points back (the draft's "head assertions" open
//! issue). The signed head in [`head`] covers that.

mod head;
mod prune;
pub use head::{check_head, head_path, Head, HeadStatus};
pub use prune::{prune, PruneSummary, PRUNE_ACTION_ID};

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Why a receipt could not be built, read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn err(reason: impl Into<String>) -> Error {
    Error(reason.into())
}

/// Optional attribution, self-asserted by the signer (draft section 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub agent: Option<String>,
    pub user: Option<String>,
}

/// One receipt. `public_key` and `signature` are lowercase hex.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub step_id: String,
    pub action_id: String,
    pub params: Value,
    pub success: bool,
    pub ts_ms: u64,
    pub actor: Option<Actor>,
    pub prev_hash: Option<String>,
    pub public_key: String,
    pub signature: String,
}

/// What the producer decides; the log adds the chain link and signature.
#[derive(Debug, Clone)]
pub struct Entry {
    pub step_id: String,
    pub action_id: String,
    pub params: Value,
    pub success: bool,
    pub ts_ms: u64,
    pub actor: Option<Actor>,
}

impl Receipt {
    /// The signed bytes (section 4): fixed outer order, `params` sorted by
    /// code point at every depth, absent members left out entirely.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        let mut out = String::from("{\"step_id\":");
        write_string(&mut out, &self.step_id);
        out.push_str(",\"action_id\":");
        write_string(&mut out, &self.action_id);
        out.push_str(",\"params\":");
        write_value(&mut out, &self.params)?;
        out.push_str(if self.success { ",\"success\":true" } else { ",\"success\":false" });
        out.push_str(&format!(",\"ts_ms\":{}", self.ts_ms));
        if let Some(actor) = &self.actor {
            out.push_str(",\"actor\":{");
            let members = [("agent", &actor.agent), ("user", &actor.user)];
            let present = members.iter().filter_map(|(k, v)| v.as_ref().map(|v| (k, v)));
            for (i, (name, value)) in present.enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(&mut out, name);
                out.push(':');
                write_string(&mut out, value);
            }
            out.push('}');
        }
        if let Some(prev) = &self.prev_hash {
            out.push_str(",\"prev_hash\":");
            write_string(&mut out, prev);
        }
        out.push('}');
        Ok(out.into_bytes())
    }

    /// The line as written to the log: the signed members, then the key
    /// and signature.
    pub fn to_line(&self) -> Result<String> {
        let mut line = String::from_utf8(self.canonical()?).expect("canonical bytes are UTF-8");
        line.pop();
        line.push_str(",\"public_key\":");
        write_string(&mut line, &self.public_key);
        line.push_str(",\"signature\":");
        write_string(&mut line, &self.signature);
        line.push('}');
        Ok(line)
    }

    /// Steps 1 and 2: parses a line, refusing duplicate member names (a
    /// parser keeping either copy would read the line differently from
    /// another) and wrong types. Unknown members are ignored.
    pub fn parse(line: &str) -> Result<Self> {
        reject_duplicate_keys(line)?;
        let value: Value = serde_json::from_str(line).map_err(|e| err(format!("not JSON: {}", e)))?;
        let obj = value.as_object().ok_or_else(|| err("not a JSON object"))?;
        let string = |name: &str| -> Result<String> {
            obj.get(name).and_then(Value::as_str).map(str::to_string).ok_or_else(|| err(format!("{} missing or not a string", name)))
        };
        let optional_string = |v: Option<&Value>, name: &str| -> Result<Option<String>> {
            match v {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(err(format!("{} is not a string", name))),
            }
        };
        let actor = match obj.get("actor") {
            None => None,
            Some(Value::Object(actor)) => Some(Actor {
                agent: optional_string(actor.get("agent"), "actor.agent")?,
                user: optional_string(actor.get("user"), "actor.user")?,
            }),
            Some(_) => return Err(err("actor is not an object")),
        };
        Ok(Receipt {
            step_id: string("step_id")?,
            action_id: string("action_id")?,
            params: obj.get("params").cloned().ok_or_else(|| err("params missing"))?,
            success: obj.get("success").and_then(Value::as_bool).ok_or_else(|| err("success missing or not a boolean"))?,
            ts_ms: obj.get("ts_ms").and_then(Value::as_u64).ok_or_else(|| err("ts_ms missing or not a non-negative integer"))?,
            actor,
            prev_hash: optional_string(obj.get("prev_hash"), "prev_hash")?,
            public_key: string("public_key")?,
            signature: string("signature")?,
        })
    }

    /// Step 4: the signature over the canonical bytes, under `public_key`.
    pub fn verify_signature(&self) -> Result<VerifyingKey> {
        let key: [u8; 32] = decode_hex(&self.public_key, 32).ok_or_else(|| err("public_key is not 64 lowercase hex characters"))?.try_into().unwrap();
        let sig: [u8; 64] = decode_hex(&self.signature, 64).ok_or_else(|| err("signature is not 128 lowercase hex characters"))?.try_into().unwrap();
        let key = VerifyingKey::from_bytes(&key).map_err(|_| err("public_key is not an Ed25519 key"))?;
        key.verify(&self.canonical()?, &Signature::from_bytes(&sig)).map_err(|_| err("signature does not verify"))?;
        Ok(key)
    }
}

/// Signs `entry` as the receipt following `prev_hash`.
pub fn sign(key: &SigningKey, entry: Entry, prev_hash: Option<String>) -> Result<Receipt> {
    let mut receipt = Receipt {
        step_id: entry.step_id,
        action_id: entry.action_id,
        params: entry.params,
        success: entry.success,
        ts_ms: entry.ts_ms,
        actor: entry.actor,
        prev_hash,
        public_key: encode_hex(key.verifying_key().as_bytes()),
        signature: String::new(),
    };
    receipt.signature = encode_hex(&key.sign(&receipt.canonical()?).to_bytes());
    Ok(receipt)
}

/// SHA-256 of `bytes`, lowercase hex: the chain link of section 6, also
/// handy for digests of content a receipt must commit to.
pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

/// A JSON value in the canonical form of section 4 (objects sorted by code
/// point at every depth, no whitespace), for digests of structured content.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// Where a log's lines go. A receipt counts as written once `sync`
/// returns.
pub trait ReceiptSink: Send {
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()>;
    fn sync(&mut self) -> std::io::Result<()>;
}

impl ReceiptSink for File {
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        self.write_all(line)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }
}

/// An append-only receipt log, one line per receipt.
pub struct ReceiptLog {
    sink: Box<dyn ReceiptSink>,
    key: SigningKey,
    prev_hash: Option<String>,
    /// Lines in the log, and where its signed head goes (file logs only).
    lines: u64,
    head: Option<PathBuf>,
    /// Set by a failed write, which may have left part of a line behind:
    /// the log takes nothing more until it is checked and reopened.
    damaged: bool,
}

impl ReceiptLog {
    /// Opens or creates the log at `path`; new receipts chain onto its last
    /// line. Refuses a log that doesn't end with a newline, which a crash
    /// mid-write would leave: chaining onto half a line hides it.
    pub fn open(path: &Path, key: SigningKey) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| err(format!("cannot create {}: {}", dir.display(), e)))?;
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(err(format!("cannot read {}: {}", path.display(), e))),
        };
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(err(format!("{} ends in a partial line; run `cleimesh audit verify` and repair it before appending", path.display())));
        }
        let prev_hash = bytes[..bytes.len().saturating_sub(1)].rsplit(|b| *b == b'\n').next().filter(|l| !l.is_empty()).map(sha256_hex);
        let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| err(format!("cannot open {}: {}", path.display(), e)))?;
        // One writer per log: a second one would chain onto a stale last
        // line and break the log. The lock goes with the file handle.
        file.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => err(format!("{} is in use by another process (a node or `mcp serve` already writes it)", path.display())),
            std::fs::TryLockError::Error(e) => err(format!("cannot lock {}: {}", path.display(), e)),
        })?;
        let mut log = Self::with_sink(Box::new(file), key, prev_hash);
        log.lines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
        log.head = Some(head_path(path));
        Ok(log)
    }

    /// A log writing to `sink`, chaining onto the line whose hash is
    /// `prev_hash` (`None` for a new log).
    pub fn with_sink(sink: Box<dyn ReceiptSink>, key: SigningKey, prev_hash: Option<String>) -> Self {
        ReceiptLog { sink, key, prev_hash, lines: 0, head: None, damaged: false }
    }

    /// Signs `entry`, appends it and syncs it to disk. After a failed
    /// write, every append fails.
    pub fn append(&mut self, entry: Entry) -> Result<Receipt> {
        if self.damaged {
            return Err(err("receipt log damaged by an earlier failed write; run `cleimesh audit verify` and restart"));
        }
        let receipt = sign(&self.key, entry, self.prev_hash.clone())?;
        let line = receipt.to_line()?;
        if let Err(e) = self.sink.write_line(format!("{}\n", line).as_bytes()).and_then(|_| self.sink.sync()) {
            self.damaged = true;
            return Err(err(format!("cannot write receipt: {}", e)));
        }
        self.prev_hash = Some(sha256_hex(line.as_bytes()));
        self.lines += 1;
        if let Some(path) = &self.head {
            // The receipt is on disk already; a head that fails to update
            // only lags, which `check_head` reports as "behind".
            let _ = Head::sign(&self.key, self.lines, self.prev_hash.as_deref().unwrap_or(""), receipt.ts_ms).write(path);
        }
        Ok(receipt)
    }
}

/// A failed check, at a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub line: usize,
    pub reason: String,
}

/// Outcome of [`verify_log`]: the log is valid only if `failures` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub lines: usize,
    pub failures: Vec<Failure>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Runs section 7 over every line of `log`, signed by `anchor`. Every
/// failure is reported at its line; none is skipped.
pub fn verify_log(log: &[u8], anchor: &VerifyingKey) -> Report {
    let mut failures = Vec::new();
    let body = log.strip_suffix(b"\n").unwrap_or(log);
    if !log.is_empty() && !log.ends_with(b"\n") {
        failures.push(Failure { line: body.split(|b| *b == b'\n').count(), reason: "last line has no newline (partial write?)".into() });
    }
    let lines: Vec<&[u8]> = if log.is_empty() { Vec::new() } else { body.split(|b| *b == b'\n').collect() };
    // After an unparseable line, prev_hash values stop being meaningful
    // (step 1), but each line's own signature can still be checked.
    let mut chain_known = true;
    for (i, raw) in lines.iter().enumerate() {
        let n = i + 1;
        let mut fail = |reason: String| failures.push(Failure { line: n, reason });
        let receipt = match std::str::from_utf8(raw).map_err(|_| err("not UTF-8")).and_then(Receipt::parse) {
            Ok(r) => r,
            Err(e) => {
                fail(e.0);
                chain_known = false;
                continue;
            }
        };
        match receipt.verify_signature() {
            Ok(key) if key != *anchor => fail("signed by another key".into()),
            Ok(_) => {}
            Err(e) => fail(e.0),
        }
        let expected = if i == 0 { None } else { Some(sha256_hex(lines[i - 1])) };
        match (&receipt.prev_hash, &expected) {
            (Some(_), None) => fail("first line has prev_hash".into()),
            (None, Some(_)) => fail("prev_hash missing".into()),
            (Some(got), Some(want)) if chain_known && got != want => fail("prev_hash does not match the previous line (line changed, removed or reordered)".into()),
            _ => {}
        }
        chain_known = true;
    }
    Report { lines: lines.len(), failures }
}

/// Reads the lines of a log file for display, newest last.
pub fn read_lines(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).map_err(|e| err(format!("cannot open {}: {}", path.display(), e)))?;
    BufReader::new(file).lines().collect::<std::io::Result<_>>().map_err(|e| err(format!("cannot read {}: {}", path.display(), e)))
}

fn write_string(out: &mut String, s: &str) {
    // serde_json escapes only what RFC 8259 requires, with the short forms
    // and lowercase \u00xx: the shortest form section 4 asks for.
    out.push_str(&serde_json::to_string(s).expect("strings serialize"));
}

fn write_value(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                // Shortest round-trip, never an exponent. The draft says to
                // avoid non-integers (4.1); this only reads foreign ones.
                let f = n.as_f64().ok_or_else(|| err("unrepresentable number"))?;
                out.push_str(&f.to_string());
            }
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map)?,
    }
    Ok(())
}

fn write_object(out: &mut String, map: &Map<String, Value>) -> Result<()> {
    // Rust strings compare by UTF-8 bytes, which orders like code points.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    out.push('{');
    for (i, key) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, &map[key])?;
    }
    out.push('}');
    Ok(())
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Exactly `len` bytes of lowercase hex, or `None`.
pub(crate) fn decode_hex(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() != len * 2 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..len).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// Walks the JSON and fails on the first object with a repeated key.
fn reject_duplicate_keys(line: &str) -> Result<()> {
    struct Checked;
    struct V;
    impl<'de> Deserialize<'de> for Checked {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(V)
        }
    }
    impl<'de> Visitor<'de> for V {
        type Value = Checked;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, _: bool) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_str<E>(self, _: &str) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_unit<E>(self) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Checked, A::Error> {
            while seq.next_element::<Checked>()?.is_some() {}
            Ok(Checked)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Checked, A::Error> {
            let mut seen = HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(de::Error::custom(format!("duplicate member {:?}", key)));
                }
                map.next_value::<Checked>()?;
            }
            Ok(Checked)
        }
    }
    serde_json::from_str::<Checked>(line).map(|_| ()).map_err(|e| err(format!("invalid JSON: {}", e)))
}
