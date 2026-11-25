---
description: Put an MCP server behind a CleiMesh token, so what the agent reads can't decide what it does. Use when the user wants to add, protect or wrap an MCP server with CleiMesh, or asks how to limit what an agent can do with a server's tools.
---

# Add an MCP server behind CleiMesh

The plugin runs one MCP server, `cleimesh`, that serves every server added here behind signed tokens: one receipt log, one view of taint across them.

1. Check the binary: `cleimesh --version` (0.2.5 or later). If it is missing, show the user the install command and run it only once they say yes:
   `curl -fsSL https://github.com/cleitonaugusto/cleimesh/releases/latest/download/install.sh | sh`
2. Ask which server to add, if they haven't said: the command that starts it (for example `uvx mcp-server-fetch`), or the URL of a remote server.
3. Run `mcp add` with `--print`, so it only updates the server list (the plugin's `cleimesh` server is what Claude Code runs):
   - local: `cleimesh mcp add <name> --print -- <command and arguments>`
   - remote: `cleimesh mcp add <name> --print --url <https URL> --bearer-env <VAR>` (the token stays in that environment variable; only its name is saved)
   Without `--taints`/`--clean-only`, labels come from the hints the server declares; if the command stops to ask what a tool does, ask the user and pass their answer on.
4. Show the user what `mcp add` printed: each granted tool, its label, and what it tells the model. Point out any tool left unlabelled and ask whether it brings outside content in (`--taints`) or acts (`--clean-only`).
5. Tell them to reconnect the `cleimesh` server in `/mcp` so it picks up the new server.

Never pass `--allow-private`, widen a grant, or clear taint on your own: those are the user's decisions.
