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

When the node runs as another user (`setup`, [separate-user.md](separate-user.md)), the receipts and the node key are that user's and the token is yours (`0600`): pipe it in with `--token -`.

```sh
(cd / && sudo -u cleimesh -H cleimesh audit suggest --token - -o /tmp/grants.json) < ~/.config/cleimesh/openclaw/write.json
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

## Set up an agent

```sh
cleimesh setup openclaw --read ~/code/proj --untrusted ~/mail/inbox --write ~/mail/out --dry-run
cleimesh setup hermes --untrusted ~/mail/inbox --write ~/mail/out
```

On Linux, for OpenClaw and Hermes Agent, `setup` does what [separate-user.md](separate-user.md) describes by hand:

- as root (`sudo`): installs the binary in `/usr/local/bin`, creates the `cleimesh` user and runs the node as a systemd service on `127.0.0.1:7400` (`--node-user`, `--port`);
- as you: lets `cleimesh` reach the granted directories with ACLs (only entries you own, so files the node wrote don't stop a second run), and has the node issue the agent's tokens into `~/.config/cleimesh/<agent>/` (mode `0600`): `read.json`, `untrusted.json` (reading taints), `write.json` (clean only);
- registers `cleimesh mcp serve --node ...` as the agent's MCP server and turns off the agent's own tools: OpenClaw's `tools.deny` (read, write, edit, apply_patch, exec, process, ls); Hermes' `terminal`, `file`, `browser`, `code_execution` and `computer_use` toolsets.

It prints every command with the user it runs as, and asks before running them (`-y` skips the question). Run it again to renew the tokens: the taint state stays on the node, so a tainted agent stays tainted. `--read` and `--untrusted` together are refused for now.

Hermes needs its MCP support (`hermes setup`, or `uv sync --extra mcp` in its checkout). Without it, `hermes mcp add` cannot start the server and saves it disabled; `setup` then stops before turning Hermes' own tools off, so the agent is not left with no tools, and `doctor` fails on the disabled entry.

### Using with airlock

[airlock](https://github.com/otsoa-dubief/airlock) is a Hermes plugin that checks each tool call inside Hermes and asks the owner before risky ones. The two cover different layers, so they can run together: airlock watches Hermes' terminal and browser; CleiMesh does the file work in its sandbox, as another OS user, with a signed receipt for every call.

```sh
hermes plugins install airlock --enable
cleimesh setup hermes --untrusted ~/mail/inbox --write ~/mail/out --with-airlock
```

With `--with-airlock`, `setup` keeps Hermes' `terminal` and `browser` on and turns off only `file`, `code_execution` and `computer_use`. It also lets airlock admit CleiMesh's tools: when `~/.hermes/airlock.yaml` does not exist it writes one with `tools.admitted_mcp_servers: [cleimesh]`; an existing policy is never rewritten, and `setup` stops if it does not admit `cleimesh` (add it there and run again). It refuses to run if airlock is not enabled in Hermes, and with any agent other than Hermes.

Run that way, reading the poisoned mail through CleiMesh taints both: the next CleiMesh write is refused by the node with a receipt, and a `curl -d @mail.txt` through the terminal is held by airlock for the owner's approval. `doctor` accepts the terminal and browser only while airlock is enabled and admits CleiMesh:

```sh
cleimesh doctor
# ok    Hermes Agent uses CleiMesh for files; its own terminal, browser stay on, guarded by airlock
```

What each one does not do:

- The terminal can still touch files directly, outside the folders the token grants, and those calls leave no CleiMesh receipt. airlock judges them by what the command looks like and by the session's taint; CleiMesh's guarantees cover only the calls that go through it.
- airlock does not look inside MCP arguments: to airlock a CleiMesh write to `~/.ssh` is a normal call; CleiMesh's sandbox is what refuses it.
- CleiMesh has no per-call human approval yet; airlock has it.

If you need CleiMesh's guarantees for everything the agent does, leave `--with-airlock` out: Hermes' own tools are then all off.

## Check the setup

```sh
cleimesh doctor
# ok    node key     /home/you/.config/cleimesh/identity.key (12D3KooW…)
# ok    receipts     42 receipts in /home/you/.local/share/cleimesh/receipts/receipts.jsonl verify
# ok    sandbox      runs a builtin tool and refuses a file it was not granted
# FAIL  OpenClaw     uses CleiMesh, but its own exec, process tool(s) are still on and bypass it; add them to "tools": {"deny": [...]} in ~/.openclaw/openclaw.json
```

Keys (present, `0600`), the receipt log (verifies, has a signed head), the sandbox, and each agent with CleiMesh registered (Claude Code, OpenClaw, Hermes Agent): an agent that keeps its own file or shell tools can do what the token refuses, without a receipt, so that fails the run (an update or a config change that turns them back on stops a script or CI running `doctor`; Hermes' terminal and browser under `--with-airlock` are the exception). Each node the agents call with `--node` is dialed: it fails if nothing answers or if what answers is another node (it restarted with a new key, so every call would fail); the dial sends no call, so it leaves no receipt there. Claude Code is read in every scope (user, local and the project's `.mcp.json`). When your agents call a node run as another user (`--node`), the node's keys and log are not yours to have: check them with `sudo -u cleimesh cleimesh doctor`. Changes nothing; exits non-zero only on a failure.

## Writing a tool (ABI v1)

A `wasm32-wasip1` module exporting `memory`, `cleimesh_alloc(len) -> ptr`, `cleimesh_execute(ptr, len) -> u64` (returns `(out_ptr << 32) | out_len` pointing at `{"ok": ...}` or `{"error": "..."}`) and optionally `cleimesh_dealloc(ptr, len)`. See [`wasm-tools/builtins`](../wasm-tools/builtins/src/lib.rs). The ABI will move to the Component Model (WIT) before 1.0.
