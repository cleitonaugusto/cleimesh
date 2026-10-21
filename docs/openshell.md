# CleiMesh with NVIDIA OpenShell

OpenShell runs an agent inside a sandbox: its files, processes and network
connections follow a policy. CleiMesh decides and records each tool call the
agent makes. Together, the agent's body and its hands are both contained:

- the agent runs **inside** an OpenShell sandbox;
- the CleiMesh node runs **outside** it, holding its key, receipt log and
  taint state where the agent cannot reach them;
- the sandbox policy lets the agent reach exactly one thing besides its
  model: the node's port.

Tested with OpenShell 0.1.4 and OpenClaw 2026.10.3, with both a command-line
agent and OpenClaw inside the sandbox. What was checked is at the end.

## 1. The node, outside the sandbox

On the host that runs the OpenShell gateway, as a user the agent is not:

```sh
cleimesh start --listen /ip4/0.0.0.0/tcp/7400
```

It prints its address, ending in `/p2p/<NODE_ID>`. Inside a sandbox the host
is reached as `host.openshell.internal`.

## 2. The sandbox

An image with your agent; for OpenClaw:

```dockerfile
FROM node:24-bookworm-slim
RUN npm install -g openclaw@latest
```

```sh
docker build -t my-agent .
openshell sandbox create --name agent --from my-agent -- sleep infinity
openshell sandbox upload agent "$(command -v cleimesh)" /sandbox/
```

The sandbox runs as an unprivileged user with `HOME=/sandbox`, so the agent's
key is created there:

```sh
openshell sandbox exec agent -- /sandbox/cleimesh id --client
```

## 3. The agent's tokens

The node issues them, outside the sandbox, for the id printed above, and you
upload only the tokens. The node key never enters the sandbox.

```sh
cleimesh token issue <AGENT_ID> --tool file_read --read /data/inbox --taints -o read.json
cleimesh token issue <AGENT_ID> --tool file_write --write /data/out --clean-only -o write.json
openshell sandbox upload agent read.json /sandbox/
openshell sandbox upload agent write.json /sandbox/
```

The folders are on the node's host: tools run in the node's WebAssembly
sandbox, not in the agent's.

## 4. One way out

Allow the `cleimesh` binary in the sandbox to reach the node's port, and
nothing else:

```sh
openshell policy update agent --rule-name cleimesh --binary /sandbox/cleimesh \
  --add-endpoint host.openshell.internal:7400::tcp --wait
```

Add the rule your agent needs for its model provider the same way.

## 5. The agent's MCP server

Inside the sandbox, point the agent at `cleimesh mcp serve --node`, which
forwards each call to the node and holds nothing of it:

```sh
openclaw mcp add cleimesh --command /sandbox/cleimesh --arg mcp --arg serve \
  --arg --node --arg /dns4/host.openshell.internal/tcp/7400/p2p/<NODE_ID> \
  --arg --token --arg /sandbox/read.json --arg --token --arg /sandbox/write.json
```

OpenClaw inside OpenShell: `/var/tmp` is not writable there, and OpenClaw's
SQLite store needs a temporary directory. Run the agent with
`TMPDIR=/sandbox/tmp SQLITE_TMPDIR=/sandbox/tmp` (create the folder first).

## 6. The record

Receipts stay with the node. `cleimesh audit verify` checks them, and
`cleimesh audit export` writes them as OCSF API Activity events, next to the
network events OpenShell already writes in OCSF:

```sh
cleimesh audit verify
cleimesh audit export -o cleimesh-ocsf.jsonl
```

## What was checked

- Allowed calls go through; a read outside the granted folder is refused by
  CleiMesh.
- An OpenClaw turn inside the sandbox writes a draft, reads a mail carrying an
  injection, and its next write is refused by the node because the agent read
  untrusted content; the refusal is a signed receipt.
- The node key does not exist in the sandbox.
- A connection from the sandbox to another port of the host is denied by
  OpenShell (an OCSF `NET:OPEN DENIED` event).
- The receipts verify, and the OCSF export carries two allowed calls and one
  blocked.

The agent turns were driven by a scripted model rather than an LLM, so the
same calls happen on every run; [`tests/agents`](../tests/agents) runs that
script against OpenClaw and Hermes.
