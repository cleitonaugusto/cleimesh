#!/usr/bin/env bash
# Put Gmail (taylorwilsdon/google_workspace_mcp) behind CleiMesh taint:
# an agent that READ an email cannot SEND or DRAFT one until a human clears it.
# This is the control for the 2026 "one crafted email takes over the agent"
# attacks (Salt Labs' Manus, Barracuda's inbox-assistant phishing): the
# injection may win at the model, but the outgoing action is refused.
#
# YOU run this — it needs YOUR Google OAuth. CleiMesh never sees your Google
# password or token: workspace-mcp holds the OAuth and talks to Google;
# CleiMesh sits in front of it and gates each tool call, with receipts.
#
# Prerequisites
#   - cleimesh on PATH (or: CLEIMESH=/path/to/cleimesh ./wrap-google-workspace.sh)
#   - uv installed, for `uvx workspace-mcp`
#   - A Google Cloud OAuth client; export GOOGLE_OAUTH_CLIENT_ID and
#     GOOGLE_OAUTH_CLIENT_SECRET before running.
#
# IMPORTANT, verify in your environment (not tested here, no Google creds):
#   workspace-mcp's docs say OAuth wants the HTTP transport, while
#   `cleimesh mcp wrap` spawns a stdio child. If Gmail serves over stdio once
#   you are authenticated (e.g. after a one-time `start_google_auth`), this
#   works as written. If your setup needs HTTP-only OAuth, authenticate
#   workspace-mcp once on its own first, then wrap it. This script performs no
#   Google login itself.

set -euo pipefail

CLEIMESH="${CLEIMESH:-cleimesh}"
command -v "$CLEIMESH" >/dev/null || { echo "cleimesh not found; set CLEIMESH=path/to/cleimesh" >&2; exit 1; }
command -v uvx >/dev/null || { echo "uv (uvx) not found; install it to run workspace-mcp" >&2; exit 1; }

DIR="${CLEIMESH_GMAIL_DIR:-$HOME/.config/cleimesh-gmail}"
mkdir -p "$DIR"
cd "$DIR"

# The agent (holder) key and its PeerId; node.key signs the tokens.
PEER="$("$CLEIMESH" id --client --identity agent.key)"

# Reading/searching mail brings in outside content -> these taint the holder.
"$CLEIMESH" token issue "$PEER" \
  --tool search_gmail_messages \
  --tool get_gmail_message_content \
  --tool get_gmail_messages_content_batch \
  --tool get_gmail_thread_content \
  --tool get_gmail_threads_content_batch \
  --tool get_gmail_attachment_content \
  --taints --identity node.key -o gmail-read.json

# Sending/drafting act on the world -> clean-only, refused while tainted,
# so instructions injected via a read message cannot drive them.
"$CLEIMESH" token issue "$PEER" \
  --tool send_gmail_message \
  --tool draft_gmail_message \
  --clean-only --identity node.key -o gmail-act.json

echo "Tokens in $DIR. Register this command with your MCP client (Claude Code, Cursor):"
echo "  $CLEIMESH mcp wrap --token $DIR/gmail-read.json --token $DIR/gmail-act.json \\"
echo "    --holder $DIR/agent.key --identity $DIR/node.key --receipts $DIR/receipts.jsonl \\"
echo "    -- uvx workspace-mcp --tools gmail"
echo
echo "After the agent reads a message, a send/draft is refused until you run:"
echo "  $CLEIMESH taint clear $PEER --reason \"reviewed\" --receipts $DIR/receipts.jsonl --identity $DIR/node.key"
echo
echo "Starting the wrap now (Ctrl-C to stop)..."
exec "$CLEIMESH" mcp wrap \
  --token gmail-read.json --token gmail-act.json \
  --holder agent.key --identity node.key --receipts receipts.jsonl \
  -- uvx workspace-mcp --tools gmail
