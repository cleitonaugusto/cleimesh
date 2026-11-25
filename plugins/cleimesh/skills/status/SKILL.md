---
description: Show what CleiMesh recorded: whether the agent is tainted and by which receipt, and whether the signed receipt log verifies. Use when the user asks why a tool call was refused, whether the agent is tainted, or to check the audit trail.
---

# CleiMesh status

- Who is tainted, and by which receipt: `cleimesh taint list`
- Does the receipt log verify: `cleimesh audit verify`
- Which servers are behind the token: read `~/.config/cleimesh/mcp/servers.json` (names, commands or URLs, never tokens)

Explain a refusal from its message: "received untrusted content" means a tool marked `--taints` returned content to this agent, so tools marked `--clean-only` are refused until a person clears it with `cleimesh taint clear <holder> --reason "..."`. Clearing taint is the user's decision; don't run it on your own.
