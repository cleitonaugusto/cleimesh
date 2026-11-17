//! A transparency log over the receipt chain (idea: "verifiable provenance that
//! survives the agent disappearing"). The signed, hash-chained receipts already
//! prove no interior line changed; this layer adds an RFC 6962-style Merkle tree
//! so a third party can verify that **one** receipt is in the log, under a
//! **signed tree head**, without holding the whole log and without trusting the
//! producer. This is what traceability regimes (and multi-agent handoffs) ask
//! for: proof that is independent of the agent and its middleware.
//!
//! The hashing matches RFC 6962 (Certificate Transparency / Sigstore Rekor):
//! a leaf is `SHA-256(0x00 || entry)` and an interior node is
//! `SHA-256(0x01 || left || right)`, with the same domain separation, so the
//! structure is interoperable with existing transparency-log tooling.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{err, Result};

type Hash = [u8; 32];

/// RFC 6962 leaf hash: `SHA-256(0x00 || leaf)`.
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || left || right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash over `leaves` (already leaf-hashed).
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest(b"").into(), // MTH of the empty tree
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 audit path proving `leaves[m]` is in the tree of `leaves`.
pub fn inclusion_proof(leaves: &[Hash], m: usize) -> Result<Vec<Hash>> {
    if m >= leaves.len() {
        return Err(err("leaf index out of range"));
    }
    Ok(path(leaves, m))
}

fn path(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = path(&leaves[..k], m);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = path(&leaves[k..], m - k);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Verify that `leaf` (a leaf hash) is at index `m` in a tree of `tree_size`
/// leaves whose Merkle root is `root`, given the audit `proof`. Independent of
/// the log itself: a verifier needs only this receipt, the proof and the head.
pub fn verify_inclusion(leaf: &Hash, m: usize, tree_size: usize, proof: &[Hash], root: &Hash) -> bool {
    if m >= tree_size {
        return false;
    }
    let mut fna = m;
    let mut sna = tree_size - 1;
    let mut r = *leaf;
    for sibling in proof {
        if fna == sna || fna & 1 == 1 {
            r = node_hash(sibling, &r);
            while fna != 0 && fna & 1 == 0 {
                fna >>= 1;
                sna >>= 1;
            }
        } else {
            r = node_hash(&r, sibling);
        }
        fna >>= 1;
        sna >>= 1;
    }
    sna == 0 && r == *root
}

/// A signed tree head: a commitment to the whole log at a point in time.
/// `root` and fields below are lowercase hex; `signature` is Ed25519 over the
/// canonical bytes of (tree_size, root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: usize,
    pub root: String,
    pub public_key: String,
    pub signature: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Result<Hash> {
    if s.len() != 64 {
        return Err(err("hash is not 64 lowercase hex characters"));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| err("hash is not hex"))?;
    }
    Ok(out)
}

/// Bytes an STH signs: `"cleimesh-sth"` || tree_size (8 bytes, big-endian) || root.
fn sth_bytes(tree_size: usize, root: &Hash) -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + 8 + 32);
    b.extend_from_slice(b"cleimesh-sth");
    b.extend_from_slice(&(tree_size as u64).to_be_bytes());
    b.extend_from_slice(root);
    b
}

impl SignedTreeHead {
    /// Build and sign a tree head over `leaves` with `key`.
    pub fn sign(key: &SigningKey, leaves: &[Hash]) -> Self {
        let root = merkle_root(leaves);
        let sig = key.sign(&sth_bytes(leaves.len(), &root));
        SignedTreeHead {
            tree_size: leaves.len(),
            root: hex(&root),
            public_key: hex(key.verifying_key().as_bytes()),
            signature: hex(&sig.to_bytes()),
        }
    }

    /// The root as bytes.
    pub fn root_hash(&self) -> Result<Hash> {
        unhex32(&self.root)
    }

    /// Verify the head's signature under `anchor` (the trusted node key).
    pub fn verify(&self, anchor: &VerifyingKey) -> Result<()> {
        let got = unhex32(&self.public_key)?;
        if &got != anchor.as_bytes() {
            return Err(err("tree head signed by an unexpected key"));
        }
        let root = self.root_hash()?;
        let sig: [u8; 64] = {
            if self.signature.len() != 128 {
                return Err(err("signature is not 128 lowercase hex characters"));
            }
            let mut s = [0u8; 64];
            for (i, o) in s.iter_mut().enumerate() {
                *o = u8::from_str_radix(&self.signature[2 * i..2 * i + 2], 16).map_err(|_| err("signature is not hex"))?;
            }
            s
        };
        anchor
            .verify(&sth_bytes(self.tree_size, &root), &Signature::from_bytes(&sig))
            .map_err(|_| err("tree head signature does not verify"))
    }
}

/// A self-contained inclusion proof: everything a third party needs to check
/// that `receipt` is in the log, and nothing else (not the other receipts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionBundle {
    pub sth: SignedTreeHead,
    pub index: usize,
    pub tree_size: usize,
    /// The receipt's exact log line.
    pub receipt: String,
    /// Audit path hashes, lowercase hex.
    pub proof: Vec<String>,
}

/// Build an inclusion bundle for the receipt at `index` of `log`, signing a
/// tree head with `key`.
pub fn prove(log: &[u8], key: &SigningKey, index: usize) -> Result<InclusionBundle> {
    let lines: Vec<&[u8]> = log.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
    if index >= lines.len() {
        return Err(err("receipt index out of range"));
    }
    let leaves = leaves_from_log(log);
    let proof = inclusion_proof(&leaves, index)?;
    Ok(InclusionBundle {
        sth: SignedTreeHead::sign(key, &leaves),
        index,
        tree_size: leaves.len(),
        receipt: String::from_utf8_lossy(lines[index]).into_owned(),
        proof: proof.iter().map(|h| hex(h)).collect(),
    })
}

impl InclusionBundle {
    /// Verify the head under `anchor` (the trusted node key) and that the
    /// receipt is included. Needs only this bundle and the anchor.
    pub fn verify(&self, anchor: &VerifyingKey) -> Result<()> {
        self.sth.verify(anchor)?;
        if self.tree_size != self.sth.tree_size {
            return Err(err("bundle tree_size disagrees with the signed head"));
        }
        let proof: Result<Vec<Hash>> = self.proof.iter().map(|s| unhex32(s)).collect();
        let proof = proof?;
        let leaf = leaf_hash(self.receipt.as_bytes());
        if verify_inclusion(&leaf, self.index, self.tree_size, &proof, &self.sth.root_hash()?) {
            Ok(())
        } else {
            Err(err("receipt is not in the log under this head"))
        }
    }
}

// ----- consistency: the log only ever appended (RFC 6962) -----

fn inner_proof_size(index: usize, size: usize) -> usize {
    let x = (index ^ (size - 1)) as u64;
    (64 - x.leading_zeros()) as usize
}

fn decomp_incl_proof(index: usize, size: usize) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    let border = ((index >> inner) as u64).count_ones() as usize;
    (inner, border)
}

fn chain_inner(seed: Hash, proof: &[Hash], index: usize) -> Hash {
    let mut acc = seed;
    for (i, p) in proof.iter().enumerate() {
        acc = if (index >> i) & 1 == 0 { node_hash(&acc, p) } else { node_hash(p, &acc) };
    }
    acc
}

fn chain_inner_right(seed: Hash, proof: &[Hash], index: usize) -> Hash {
    let mut acc = seed;
    for (i, p) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            acc = node_hash(p, &acc);
        }
    }
    acc
}

fn chain_border_right(seed: Hash, proof: &[Hash]) -> Hash {
    let mut acc = seed;
    for p in proof {
        acc = node_hash(p, &acc);
    }
    acc
}

fn subproof(m: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete { Vec::new() } else { vec![merkle_root(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// RFC 6962 consistency proof that the tree of `leaves` (size n) is an append of
/// the tree of its first `m` leaves: proves nothing was changed or removed, only
/// added. Requires `0 < m <= n`.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Result<Vec<Hash>> {
    let n = leaves.len();
    if m == 0 || m > n {
        return Err(err("consistency requires 0 < m <= n"));
    }
    if m == n {
        return Ok(Vec::new());
    }
    Ok(subproof(m, leaves, true))
}

/// Verify a consistency proof: that a log of `m` leaves with root `old_root`
/// grew into one of `n` leaves with root `new_root` by appending only.
pub fn verify_consistency(m: usize, n: usize, proof: &[Hash], old_root: &Hash, new_root: &Hash) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && old_root == new_root;
    }
    if m == 0 {
        return proof.is_empty();
    }
    let (inner_full, border) = decomp_incl_proof(m - 1, n);
    let shift = (m as u64).trailing_zeros() as usize;
    let inner = match inner_full.checked_sub(shift) {
        Some(v) => v,
        None => return false,
    };
    let (seed, start) = if m == (1usize << shift) {
        (*old_root, 0usize)
    } else {
        if proof.is_empty() {
            return false;
        }
        (proof[0], 1usize)
    };
    if proof.len() != start + inner + border {
        return false;
    }
    let proof = &proof[start..];
    let mask = (m - 1) >> shift;
    let hash1 = chain_border_right(chain_inner_right(seed, &proof[..inner], mask), &proof[inner..]);
    if &hash1 != old_root {
        return false;
    }
    let hash2 = chain_border_right(chain_inner(seed, &proof[..inner], mask), &proof[inner..]);
    &hash2 == new_root
}

/// Leaf-hash every non-empty line of a receipt log, in order.
pub fn leaves_from_log(log: &[u8]) -> Vec<Hash> {
    log.split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(leaf_hash)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(format!("receipt-{i}").as_bytes())).collect()
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), l[0]);
    }

    #[test]
    fn matches_rfc6962_reference_hashing() {
        // External reference constants, independent of this crate:
        // the empty tree is SHA-256(""), and the leaf of "" is SHA-256(0x00).
        assert_eq!(hex(&merkle_root(&[])), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&leaf_hash(b"")), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");

        // A from-scratch RFC 6962 Merkle Tree Hash, not using this module's
        // functions, must agree on a mixed-size tree.
        fn ref_leaf(d: &[u8]) -> Hash {
            let mut h = Sha256::new();
            h.update([0u8]);
            h.update(d);
            h.finalize().into()
        }
        fn ref_node(l: &Hash, r: &Hash) -> Hash {
            let mut h = Sha256::new();
            h.update([1u8]);
            h.update(l);
            h.update(r);
            h.finalize().into()
        }
        fn ref_mth(d: &[&[u8]]) -> Hash {
            match d.len() {
                0 => Sha256::digest(b"").into(),
                1 => ref_leaf(d[0]),
                n => {
                    let mut k = 1;
                    while k << 1 < n {
                        k <<= 1;
                    }
                    ref_node(&ref_mth(&d[..k]), &ref_mth(&d[k..]))
                }
            }
        }
        let data: Vec<&[u8]> = vec![b"a", b"bb", b"ccc", b"dddd", b"eeeee", b"ffffff", b"ggggggg"];
        let ours = merkle_root(&data.iter().map(|d| leaf_hash(d)).collect::<Vec<_>>());
        assert_eq!(ours, ref_mth(&data));
    }

    #[test]
    fn every_leaf_proves_inclusion_at_every_size() {
        for n in 1..=33 {
            let l = leaves(n);
            let root = merkle_root(&l);
            for m in 0..n {
                let proof = inclusion_proof(&l, m).unwrap();
                assert!(verify_inclusion(&l[m], m, n, &proof, &root), "n={n} m={m}");
            }
        }
    }

    #[test]
    fn a_tampered_leaf_or_wrong_index_fails() {
        let l = leaves(8);
        let root = merkle_root(&l);
        let proof = inclusion_proof(&l, 3).unwrap();
        assert!(verify_inclusion(&l[3], 3, 8, &proof, &root));
        // Wrong leaf.
        assert!(!verify_inclusion(&leaf_hash(b"forged"), 3, 8, &proof, &root));
        // Wrong index.
        assert!(!verify_inclusion(&l[3], 4, 8, &proof, &root));
        // Wrong root (one bit).
        let mut bad = root;
        bad[0] ^= 1;
        assert!(!verify_inclusion(&l[3], 3, 8, &proof, &bad));
    }

    #[test]
    fn signed_tree_head_verifies_and_rejects_a_foreign_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let l = leaves(5);
        let sth = SignedTreeHead::sign(&key, &l);
        assert_eq!(sth.tree_size, 5);
        assert_eq!(sth.root_hash().unwrap(), merkle_root(&l));
        assert!(sth.verify(&key.verifying_key()).is_ok());
        assert!(sth.verify(&other.verifying_key()).is_err());
    }

    #[test]
    fn a_forged_head_root_breaks_the_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut sth = SignedTreeHead::sign(&key, &leaves(4));
        // Flip the claimed root.
        let mut r = sth.root_hash().unwrap();
        r[0] ^= 1;
        sth.root = hex(&r);
        assert!(sth.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn consistency_holds_for_every_append_at_every_size() {
        for n in 1..=24 {
            let l = leaves(n);
            let new_root = merkle_root(&l);
            for m in 1..=n {
                let old_root = merkle_root(&l[..m]);
                let proof = consistency_proof(&l, m).unwrap();
                assert!(verify_consistency(m, n, &proof, &old_root, &new_root), "n={n} m={m}");
            }
        }
    }

    #[test]
    fn consistency_rejects_a_log_that_was_not_an_append() {
        let l = leaves(10);
        let old_root = merkle_root(&l[..6]);
        let new_root = merkle_root(&l);
        let proof = consistency_proof(&l, 6).unwrap();
        assert!(verify_consistency(6, 10, &proof, &old_root, &new_root));
        // A rewritten history (different leaf 2) yields a different old root.
        let mut rewritten = l.clone();
        rewritten[2] = leaf_hash(b"rewritten");
        let forged_old = merkle_root(&rewritten[..6]);
        assert!(!verify_consistency(6, 10, &proof, &forged_old, &new_root));
        // A tampered new root (one bit) is rejected.
        let mut bad_new = new_root;
        bad_new[0] ^= 1;
        assert!(!verify_consistency(6, 10, &proof, &old_root, &bad_new));
    }

    #[test]
    fn leaves_from_a_log_skip_blank_lines() {
        let log = b"line-a\nline-b\n\nline-c\n";
        let got = leaves_from_log(log);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], leaf_hash(b"line-a"));
        assert_eq!(got[2], leaf_hash(b"line-c"));
    }
}
