#!/usr/bin/env bash
# Drives real OpenClaw and Hermes agent turns through `cleimesh mcp serve`
# with a scripted model (no API key, no LLM), in throwaway containers.
# Installs each agent's latest release from its official channel, so a new
# release that breaks the integration shows up here.
#
#   tests/agents/run.sh target/debug/cleimesh [openclaw|hermes]...
set -euo pipefail
# Debian trixie: its glibc is new enough for a binary built on a current Ubuntu runner.
here=$(cd "$(dirname "$0")" && pwd)
bin=$(realpath "${1:?usage: run.sh CLEIMESH_BINARY [AGENT]...}"); shift
agents=("$@")
[ $# -eq 0 ] && agents=(openclaw hermes)
status=0
for agent in "${agents[@]}"; do
  case $agent in
    openclaw) image=node:24-trixie-slim
              install='npm install -g openclaw@latest > /tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; }' ;;
    hermes)   image=node:24-trixie-slim
              install='apt-get update -qq >/dev/null && apt-get install -y -qq curl git ca-certificates xz-utils >/dev/null
                       curl -fsSL https://hermes-agent.nousresearch.com/install.sh -o /tmp/install.sh
                       bash /tmp/install.sh < /dev/null > /tmp/install.log 2>&1 || { tail -20 /tmp/install.log; exit 1; }' ;;
    *) echo "unknown agent $agent" >&2; exit 2 ;;
  esac
  echo "== $agent"
  docker run --rm -v "$bin":/cleimesh/bin/cleimesh:ro -v "$here":/cleimesh/tests:ro "$image" \
    bash -c "$install && bash /cleimesh/tests/in-container.sh $agent" || status=1
done
exit $status
