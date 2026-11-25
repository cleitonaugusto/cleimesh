# Evaluation kit

A reproducible check of the properties an evaluator usually asks about, against the released `cleimesh` and real MCP servers, with no model and no account. Each check prints `PASS` or `FAIL`.

```sh
docker build -t cleimesh-eval examples/evaluation && docker run --rm cleimesh-eval
```

It takes about two minutes, one of them waiting out a timeout on purpose. The servers are synthetic and APC-style (`stub_apc.py`: tickets, which are outside content, and payments, which are actions; `stub_notify.py`: a second server that acts), and `agent.py` is a scripted agent that does what an injected one would. Swap the stubs for your own servers to run the same checks on your workflow.

| # | Property | What runs | Expected |
|---|---|---|---|
| 1 | Authorization bound to the exact tool definition, arguments, destination and context | The agent reads a ticket carrying an injection, then pays the destination the token fixes, then the injected one. The server is then updated with a new description for `read_ticket`. | ACC-1 paid; ACC-EVIL refused. The decision receipt carries the approved definition's digest (equal to its pin), the argument digest, and the receipt that tainted the agent. The changed tool is withheld. |
| 2 | Enforcement across servers | Read through `apc`, then act through `notify` | The action runs before the read and is refused after it. |
| 3 | Redirects, expiry | `cleimesh demo redirect`; a token issued for 3 s, used after 5 s | The redirect is refused on the connection, and the attacker's server sees 0 connections. The expired token is refused. |
| 4 | Receipts link authorization, invocation and outcome | A call, then `cleimesh audit verify`, then one changed byte | Verifies against the node key alone. The result receipt points to its decision receipt. A change fails verification. |
| 5 | Timeouts with an unknown outcome | A call that takes 75 s, then a settlement | It is cut at 60 s and the agent is told the outcome is unknown. The result receipt records `outcome: unknown`, not a failure. A person later checks the world out of band and settles it once (`cleimesh audit settle`), in a receipt linked to that result; the chain still verifies. |

## Limits, stated plainly

- **Destination.** For a native MCP server, CleiMesh constrains the arguments that name a destination (property 1). The server's own network is not sandboxed. Checking the connection itself (every redirect hop re-checked, the socket pinned to the address that was checked) applies to tools that run in CleiMesh's WASM sandbox (property 3).
- **Timeouts.** CleiMesh stops waiting and records that the outcome is unknown; it doesn't guess. Settling is a person's (or a script's) out-of-band check, recorded as its own receipt. Making the operation safe to retry is up to the server (an idempotency key it honours).
- **Replay and delegation** are not runtime checks in this kit; the repository's tests cover them. Each proof of possession is accepted once (`cleimesh-aat/tests/chain.rs`, `replayed_proof_is_refused_once_seen`). A fresh subagent derived from a tainted agent is refused (`cleimesh-p2p/tests/taint.rs`, including a property test over random delegation forests). To run them: `cargo test -p cleimesh-aat -p cleimesh-p2p`.
- **The labels are the deployer's.** The checks pass `--taints`, `--clean-only` and `--when-tainted` explicitly. Without them, `mcp add` takes labels from the hints each server declares.

## Where it sits

The wrapper sits between the MCP client and the servers, over stdio or served over HTTP (`cleimesh mcp wrap --listen ADDR --listen-token-env VAR`), which is how an HTTP MCP client such as an n8n MCP client node reaches it. Remote servers are reached with their bearer token from the environment (`mcp add --url ... --bearer-env VAR`), so OAuth stays where it is. A policy engine (OPA, Cedar) stays the decision point: its decision becomes the token CleiMesh enforces at execution.
