# `cleimesh mcp add` with two real MCP servers

The official [`mcp-server-fetch`](https://pypi.org/project/mcp-server-fetch/) and
[`@modelcontextprotocol/server-filesystem`](https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem),
each added with one command, behind one `cleimesh-mcp` entry:

```sh
cleimesh mcp add fetch --taints fetch -- python -m mcp_server_fetch
cleimesh mcp add fs --clean-only write_file --clean-only edit_file --clean-only move_file -- mcp-server-filesystem /data
```

A scripted agent (no model; it does what an injected one would) writes a draft, fetches a page carrying a
hidden instruction, reads a secret, and tries to write it where the instruction says. The fetch taints the
agent, so the write is refused on the other server, and every step is on a signed receipt
([transcript](transcript.txt)):

```
1. write_file notes.txt (clean)    -> ok
2. fetch the release-notes page    -> ok
3. read_text_file secrets.txt      -> ok
4. write_file leak.txt (injected)  -> REFUSED | ... received untrusted content ...
```

The page is served inside the container and the secret is fake; nothing leaves it. To run it, put a Linux
`cleimesh` binary next to the Dockerfile:

```sh
cp "$(command -v cleimesh)" examples/mcp-add/
docker build -t cleimesh-mcp-add examples/mcp-add && docker run --rm cleimesh-mcp-add
```

The `Received exception from stream ... validation errors` lines in the transcript come from
`mcp-server-fetch` itself: on its first fetch it installs its npm helpers and npm's output lands on the
server's stdout, which is the MCP channel. The wrapper answers that non-JSON line with a JSON-RPC error, the
server logs it, and the fetch goes through.

Reading the secret is allowed here (step 3): taint stops the *action* that would leak it, not the read.
The wrapped servers are not sandboxed; see the main README.
