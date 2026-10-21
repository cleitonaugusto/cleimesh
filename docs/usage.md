# Using CleiMesh

Command recipes beyond the quick start in the [README](../README.md).

## Delegate

```sh
# The agent narrows its token for a subagent: offline, no server involved
cleimesh token derive chain.json <subagent-peer-id> --tool file_read --read ~/code/my-project/docs -o sub.json

# Widening is refused, by the CLI and again by the node
cleimesh token derive sub.json <anyone> --tool file_read --read ~/.ssh
# Error: Cannot derive token: tool file_read: read access to /home/you/.ssh not granted by the parent
```

## Replay a call

```sh
# Anyone with the log, the node's public key and the call's input
cleimesh audit replay <step-id> --args input.json
# REPRODUCED 01a1…f80d: same outcome and output (sha256 84a7…)
```

Calls that use no directories and no network are replayable; their receipt says so, and says why when not.

## Shrink a token to what the agent used

```sh
# The sandbox records which directories each call touched (by keyed pseudonym, never file names);
# audit suggest compares that with the token and proposes the narrowest grants (--lang pt for Portuguese, --format json)
cleimesh audit suggest --token chain.json -o grants.json
#   echo: 0 call(s), 0 file(s) read, 0 written
#     never called in the period: drop it from the token
#   file_read: 10 call(s), 10 file(s) read, 0 written
#     read: /home/you/code/my-project -> /home/you/code/my-project/docs

# Nothing changes until you derive; a grants file wider than the parent is refused
cleimesh token derive chain.json <agent-peer-id> --tool file_read --grants grants.json -o narrower.json
```

## Audit and retention

```sh
cleimesh invoke <node> <tool> '<args>' --token chain.json --subject customer-42 --purpose support
cleimesh audit report --subject customer-42          # what was done with this person's data (Markdown, --lang pt, or --format json)
cleimesh audit report --agent <agent-peer-id>        # an agent's record of operations (LGPD art. 37, GDPR art. 30)
cleimesh audit head > head.json                      # keep a signed head elsewhere; audit verify --head proves nothing was cut since
cleimesh audit prune --before 2026-01-01 --dry-run   # retention, leaving a receipt of the removal
```

Token flags: sandbox `--read DIR`, `--write DIR`, `--network`, `--max-instructions N`, `--max-memory BYTES`, `--timeout-ms MS`, scoped with `--sandbox-for TOOL`; flow `--taints`, `--clean-only`; argument constraints `--tools '{"echo":{"message":{"constraint_type":"exact","value":"hi"}}}'`.

## Check the setup

```sh
cleimesh doctor
# ok    node key     /home/you/.config/cleimesh/identity.key (12D3KooW…)
# ok    receipts     42 receipts in /home/you/.local/share/cleimesh/receipts/receipts.jsonl verify
# ok    sandbox      runs a builtin tool and refuses a file it was not granted
# warn  OpenClaw     uses CleiMesh, but its own exec, process tool(s) are still on and bypass it; add them to "tools": {"deny": [...]} in ~/.openclaw/openclaw.json
```

Keys (present, `0600`), the receipt log (verifies, has a signed head), the sandbox, and each agent with CleiMesh registered (Claude Code, OpenClaw; Hermes Agent only registration): an agent that keeps its own file or shell tools can do what the token refuses, without a receipt. Claude Code is read in every scope (user, local and the project's `.mcp.json`). When your agents call a node run as another user (`--node`), the node's keys and log are not yours to have: check them with `sudo -u cleimesh cleimesh doctor`. Changes nothing; exits non-zero only on a failure.

## Writing a tool (ABI v1)

A `wasm32-wasip1` module exporting `memory`, `cleimesh_alloc(len) -> ptr`, `cleimesh_execute(ptr, len) -> u64` (returns `(out_ptr << 32) | out_len` pointing at `{"ok": ...}` or `{"error": "..."}`) and optionally `cleimesh_dealloc(ptr, len)`. See [`wasm-tools/builtins`](../wasm-tools/builtins/src/lib.rs). The ABI will move to the Component Model (WIT) before 1.0.
