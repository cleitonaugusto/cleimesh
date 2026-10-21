# Threat model

What CleiMesh protects, against whom, how, and where it stops. Each
protection names the test that checks it; each limit is stated plainly. If
you find a way around a protection listed here, please report it privately
(see [SECURITY.md](../SECURITY.md)).

Last reviewed: 2026-10-13, alpha. Only the latest commit is supported.

## What is being protected

- **The host:** files, secrets (SSH keys, credentials), network reach and
  CPU/memory of the machine running the node.
- **The scope of a delegation:** a subagent must never get more than the
  token it was handed, and that token never more than its parent's.
- **The record:** the receipt log must show every decision and result, and
  any edit, removal or reordering must be detectable.
- **The data subjects** named in calls: receipts must not expose who they
  are, or what a call read or produced.

## Who we defend against

| Adversary | Can | Wants |
|---|---|---|
| An agent steered by prompt injection | call any tool its token lists, with any arguments | read or send what it shouldn't |
| A subagent | hold a derived token, derive further | widen its own scope |
| A malicious or buggy tool (WASM module) | run code inside the sandbox | escape it: other files, network, the node |
| A remote peer | connect to a node's P2P port | run tools, crash the node |
| Someone editing the log later | write access to the log file, not the node key | hide or alter what happened |
| An agent that can run shell commands | everything its OS user can do | read the node key, edit the log, clear its own taint |
| A dishonest node operator | the node key | sign a false result |
| An auditor or anyone reading receipts | the log and the node's public key | learn who a call was about, or its content |

## What it protects, and how

**Nothing is allowed by default.** A tool in the sandbox sees no file, no
network, no environment, and runs under time, instruction and memory limits.
Tests: `cleimesh-wasm-sandbox/tests/builtin_tools.rs`
(`file_read_is_denied_without_permission`, `paths_outside_allowed_dir_are_blocked`,
`infinite_loop_times_out`).

**The token is the sandbox.** Directories, network and limits come from the
signed token, per tool, and every delegation link must narrow its parent;
the node checks every link again at call time (a narrower parent's path
must contain the child's, component by component; symlinks can't step out).
Tests: `cleimesh-p2p/tests/grants.rs`, the property test
`cleimesh-p2p/tests/grant_properties.rs` (20,000 random chains), and
`cleimesh-aat/tests/properties.rs` for argument constraints.

**Tokens can't be forged, widened, reused or stolen.** AAT chains (IETF
draft, JWS/Ed25519) are verified against the node's own key only;
attenuation is checked link by link; each call carries a proof of
possession bound to the tool, its arguments and the node (audience), seen
once. Tests: `cleimesh-aat/tests/` (including the draft's vectors) and
fuzzing of the verifier (`fuzz/`, `aat_verify`).

**No receipt, no run.** The decision receipt is written and synced before
the tool runs; if it can't be written, the call is refused. Receipts are
Ed25519-signed and hash-chained (`draft-sahu-agent-action-receipts-00`); a
signed head records the line count, so cutting the end of the log is
detected against a head kept elsewhere. Tests:
`cleimesh-receipt/tests/` (draft vectors, `head_and_prune.rs`), the property
test that any byte change is caught, and fuzzing (`receipt_log`).

**One writer per log.** A second process on the same log is refused instead
of breaking the chain (`a_second_writer_on_the_same_log_is_refused`).

**Don't trust a result, replay it.** Every run sees a frozen clock and
seeded randomness recorded in its decision receipt, so anyone with the
input, the module and the node's public key can re-run the call and compare
the output hash (`cleimesh audit replay`). A node that signs a false result
is caught. Tests: `cleimesh-p2p/tests/replay.rs`, including a log recorded
on one machine and replayed by CI on another
(`a_log_recorded_on_another_machine_replays_here`).

**Injected instructions can't drive tools that act on the world.** Tools
marked `taints` (they bring in outside content) taint every holder in the
calling chain once they return; tools marked `clean_only` are refused while
any holder in the chain is tainted. Delegating to a fresh subagent or
switching tokens doesn't launder it; the taint survives restarts (rebuilt
from decision receipts, so a missing result receipt doesn't lose it); only
a recorded human decision clears it. The node taints before it sends the
content back, so no clean-only call can follow the content untainted.
Tests: `cleimesh-p2p/tests/taint.rs`, including the property test
`any_forest_and_any_order_follow_the_rule` (random delegation forests, any
order of reads, writes, clearings and restarts), `taint_blocks_clean_only_tools_through_the_cli`
(over the network), `one_server_with_several_tokens_keeps_one_view_of_taint`.

**An agent with a shell can't reach the node.** Run as its own OS user,
the node keeps the key, the receipt log and the taint state where the
agent's user can't read or write them; `cleimesh mcp serve --node` only
forwards calls to it and never opens any of them. While the node runs it
holds the log locked, so a clearing can't be written beside it. Setup:
[separate-user.md](separate-user.md). Test:
`mcp_serve_forwards_to_a_node_and_holds_nothing_of_it`. `mcp serve`
without `--node` runs the node in-process, as the agent's user, and warns
that this protection is off.

**A peer can't exhaust a node.** The P2P codec refuses a frame whose
length prefix is over the limit (1 MiB request, 8 MiB response) before
allocating for it; a peer may have at most 4 calls running at once (more are
refused with a reason, before authorization) and 2 connections; every
request has a timeout; an output over the response limit comes back as an
error. Tests: `an_oversized_length_is_refused_before_allocating`
(`cleimesh-p2p/src/behaviour.rs`), `one_peer_cannot_run_more_than_its_share_at_once`
and `an_output_over_the_limit_comes_back_as_an_error` (`cleimesh-p2p/tests/e2e.rs`).

**Receipts don't expose people or content.** Inputs and outputs are kept as
SHA-256 digests; the data subject as an HMAC under a key derived from the
node key; directories a call touched as per-component HMACs below the
granted directory, file names never. Tests: `cleimesh-p2p/tests/report.rs`,
`the_result_receipt_names_directories_only_by_pseudonym`.

## What it does not protect against

- **The wrong action that is allowed.** If the token allows sending mail,
  an agent can send the wrong mail. CleiMesh limits reach and proves what
  happened; it doesn't judge intent. Human approval for risky actions is
  planned, not built.
- **Tools outside the sandbox.** Native tools, other MCP servers and
  anything the agent runs without CleiMesh are not isolated or recorded.
  A native MCP server behind `cleimesh mcp wrap` gets the token's tool and
  argument checks, taint and receipts, but runs unconfined: it reaches
  whatever its OS user can, and its receipts say `"confined": false`. A
  token granting such a tool directories or network is refused, since
  those grants could not be enforced. The wrapper also keeps the node key
  in its own process, so run it as a user the agent is not.
- **Content that reaches the agent another way.** Taint means "the node
  returned output of a `taints` tool to this chain". The prompt itself, or
  another tool outside the node, doesn't taint anything.
- **Mislabelled tools.** Taint is only as good as the `taints` and
  `clean_only` labels the token issuer chose.
- **Taint across nodes.** Each node keeps its own view. The same token used
  on two nodes, or on two `mcp serve` processes with different logs, is
  tainted separately.
- **Coarse taint.** After reading one mail, the agent loses every clean-only
  tool until a human clears it. That is the price of being deterministic.
- **A dishonest node, for calls that can't replay.** Calls that read
  directories or use the network don't replay yet; for them, a receipt only
  proves what the node key signed.
- **Rolling back the log and its head together.** Someone with disk access
  can restore an older log with its matching head. Keep a head elsewhere
  (`cleimesh audit head`) and check with `audit verify --head`. An external
  witness is planned (M8).
- **Secrets generated in the sandbox.** Randomness there is seeded and the
  seed is in the receipt, so a tool must not create keys or tokens inside
  it.
- **Side channels and wasmtime bugs.** Isolation rests on wasmtime. Timing
  side channels between tools on one host, and a sandbox escape through a
  wasmtime or OS bug, are out of scope; keep wasmtime current.
- **A stolen node key.** Whoever holds it can issue root tokens and sign
  receipts. Keep `identity.key` private (it is created with mode 0600).

## Trust assumptions

- wasmtime and wasmtime-wasi enforce what they are configured to enforce.
- The OS, filesystem and clock of the node's host are not hostile.
- The node key is secret; the human issuing root tokens means what they
  grant.
- An agent that can run commands doesn't run as the node's OS user, can't
  become it without the human, and can't replace the node's binary
  ([separate-user.md](separate-user.md)).
- Directory observation (C5) is lexical and relies on wasmtime-wasi's
  preview1 ABI functions, which it documents as internal; a test fails if an
  upgrade hides them.

## Known gaps before 1.0

| Gap | Effect | Task |
|---|---|---|
| No revocation for AAT tokens; expiry only (90 days max) | a leaked token works until it expires; use short lifetimes | S10, PC8 |
| The proof-of-possession replay guard lives in memory | right after a restart, a captured proof could be replayed within its 30 s window | S10 |
| Native implementations of the built-in tools still exist in `tools.rs` (unused by the node) | someone embedding the library could run a tool outside the sandbox by mistake | S14 |
| No central redaction of secrets in logs and errors | a secret printed by a tool could reach a log | S15 |
| WASI preview2 has no per-call grants | refused rather than run with the wrong grants | R6 |
| No independent security review yet | | S13 |

## Reporting

See [SECURITY.md](../SECURITY.md). Do not open a public issue.
