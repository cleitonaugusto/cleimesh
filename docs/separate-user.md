# Running the node as its own user

An agent that can run shell commands (Claude Code, Codex, Cursor's agent)
runs them as your OS user. If the node runs as that same user, the agent can
read the node key, edit the receipt log and run `cleimesh taint clear` on
itself. File permissions don't help: `identity.key` is mode 0600, but it is
*your* file. Whoever holds the node key can issue root tokens, so every
other protection falls with it.

The fix is the OS's own boundary: the node runs as a separate user that owns
the key, the log and the taint state, and the agent only reaches it through
`cleimesh mcp serve --node`, which forwards calls and holds nothing of the
node. Test: `mcp_serve_forwards_to_a_node_and_holds_nothing_of_it`
(`cleimesh-cli/tests/mcp.rs`).

`mcp serve` without `--node` keeps the node in-process and prints a warning.
Use it only for MCP clients that can't run commands (Claude Desktop without
shell tools, for example) or for trying things out.

## Setup (Linux)

1. **Install the binary where the agent can't replace it.** A node running
   `~/.cargo/bin/cleimesh` runs whatever your user puts there.

   ```sh
   sudo install -m 755 -o root -g root target/release/cleimesh /usr/local/bin/cleimesh
   ```

2. **Create the node's user.**

   ```sh
   sudo useradd --system --create-home --home-dir /var/lib/cleimesh --shell /usr/sbin/nologin cleimesh
   ```

3. **Start the node** as that user, listening on localhost only. As a
   systemd service, `/etc/systemd/system/cleimesh.service`:

   ```ini
   [Unit]
   Description=CleiMesh node
   After=network.target

   [Service]
   User=cleimesh
   ExecStart=/usr/local/bin/cleimesh start --listen /ip4/127.0.0.1/tcp/7400
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```

   ```sh
   sudo systemctl enable --now cleimesh
   sudo journalctl -u cleimesh | grep -o "/ip4/127.0.0.1/tcp/7400/p2p/.*"   # the node's address
   ```

4. **Let the node reach the directories you will grant**, and nothing else.
   The sandbox can only open what both the token and the OS allow the
   `cleimesh` user. `x` on your home lets it pass through, not list it:

   ```sh
   setfacl -m u:cleimesh:x ~
   setfacl -R -m u:cleimesh:rX ~/proj        # directories granted with --read
   setfacl -R -m u:cleimesh:rwX ~/proj/out   # directories granted with --write
   ```

   Files the tools write belong to `cleimesh` (mode 644): you can read them,
   and copy them to edit.

5. **Issue the agent's token as the node's user** (you, not the agent:
   `sudo` asks for your password). `sudo -u cleimesh` uses
   `/var/lib/cleimesh` as home, so the node key is the service's:

   ```sh
   AGENT=$(cleimesh id --client)          # the agent's key, in your home
   cd /                                   # a directory the cleimesh user can enter
   sudo -u cleimesh cleimesh token issue "$AGENT" --tool file_read --read ~/proj \
     --output /var/lib/cleimesh/agent.json
   sudo cat /var/lib/cleimesh/agent.json > ~/agent-token.json
   ```

   The token is not secret on its own: using it takes the agent's key and a
   fresh proof of possession for each call.

6. **Point the MCP client at the node:**

   ```sh
   claude mcp add cleimesh -- cleimesh mcp serve \
     --node /ip4/127.0.0.1/tcp/7400/p2p/<NODE_ID> --token ~/agent-token.json
   ```

## Clearing a taint

The running node holds its receipt log locked, so nothing can be written
beside it, not even by the `cleimesh` user. Stop it, clear, start it:

```sh
sudo systemctl stop cleimesh
cd /
sudo -u cleimesh cleimesh taint list
sudo -u cleimesh cleimesh taint clear <HOLDER> --reason "mail reviewed"
sudo systemctl start cleimesh
```

## What this still assumes

- The agent's user can't become `cleimesh` or root without you: no
  passwordless `sudo` for it, and you don't approve a `sudo` the agent asks
  for without reading it.
- The agent can't edit the service file or the binary (both owned by root).
- Anyone on the machine can connect to port 7400, but a call still needs a
  token rooted in the node key and the holder's key for each proof.

## Validated

On Ubuntu 22.04 (sudo 1.9.9, systemd), 2026-10-13, following these steps:
the agent's user could not read the node key, list the receipts or clear its
taint; the mail scenario ran end to end through `mcp serve --node` (write
allowed, mail read, write refused, cleared by the node's user with the node
stopped, write allowed again); `audit verify` passed on the node's log.
