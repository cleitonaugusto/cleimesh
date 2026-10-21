# CleiMesh in an NVIDIA OpenShell sandbox

An OpenShell workload, laid out like OpenShell's own examples: the agent runs
inside an OpenShell sandbox, the CleiMesh node runs outside it, and the
sandbox policy lets the agent reach exactly one thing, the node's port.
OpenShell contains the agent process; CleiMesh decides each tool call against
a signed token, runs it in its WebAssembly sandbox and signs a receipt.

| File          | What it is                                                              |
| ------------- | ----------------------------------------------------------------------- |
| `Dockerfile`  | The agent's image: the `cleimesh` client from a release, checked by sha256, as a non-root user |
| `policy.yaml` | A complete sandbox policy whose only network rule is the node's port, for the `cleimesh` binary |
| `demo.sh`     | The whole walkthrough below, without an LLM, in a fresh `/tmp` folder   |

Needs a running OpenShell gateway, Docker, and `cleimesh` on the host. The
step-by-step guide, with OpenClaw as the agent, is [docs/openshell.md](../../docs/openshell.md).

## Run it

```sh
examples/openshell/demo.sh
```

What it does:

1. Starts the node on the host (`cleimesh start --listen /ip4/0.0.0.0/tcp/7400`).
2. Builds the image and creates the sandbox with `--policy policy.yaml`.
3. Creates the agent's key **inside** the sandbox, issues its tokens **outside**
   with the node key, and uploads only the tokens: read `inbox/` (marked
   `--taints`, it brings in outside content) and write `out/` (marked
   `--clean-only`, it acts on the world).
4. From inside the sandbox, through `cleimesh invoke` to
   `/dns4/host.openshell.internal/tcp/7400/p2p/<NODE_ID>`:
   - writing a draft is allowed;
   - reading the mail, which carries a hidden instruction, is allowed, and
     the node marks the agent tainted;
   - the write the instruction asks for is **refused by the node**, on a
     signed receipt.
5. A connection to another port of the host is **refused by OpenShell**
   (an OCSF `NET:OPEN DENIED` event in `openshell logs`).
6. The node key is not in the sandbox.
7. `cleimesh audit verify` checks the receipts and `cleimesh audit export`
   writes them as OCSF API Activity events, next to the network events
   OpenShell already writes in OCSF. An allowed call leaves two receipts
   (the decision before it runs, the result after); a refused one leaves
   one, so the run above writes five.

Tested with OpenShell 0.1.5 (Docker compute driver) and CleiMesh v0.1.0
(`CLEIMESH_VERSION=v0.1.0 examples/openshell/demo.sh`).

## With your agent

Add the agent to the `Dockerfile`, add the rule it needs for its model
provider to `policy.yaml`, and point it at `cleimesh mcp serve --node` as its
MCP server; [docs/openshell.md](../../docs/openshell.md) shows it for OpenClaw.
Turn off the agent's own file and shell tools, or OpenShell's policy is the
only thing between them and the sandbox's files: CleiMesh only contains the
calls that go through it.
