# The agent's image for an OpenShell sandbox: the CleiMesh client only.
# Add your agent (OpenClaw, Hermes, your own) on top; it reaches its tools
# through `cleimesh mcp serve --node`, and the node runs outside the sandbox.

FROM debian:bookworm-slim

ARG CLEIMESH_VERSION=v0.1.1
ARG CLEIMESH_BIN=cleimesh-x86_64-unknown-linux-musl

# curl only downloads and checks the release binary, then is removed.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && cd /tmp \
    && curl -fsSLO "https://github.com/cleitonaugusto/cleimesh/releases/download/${CLEIMESH_VERSION}/${CLEIMESH_BIN}" \
    && curl -fsSLO "https://github.com/cleitonaugusto/cleimesh/releases/download/${CLEIMESH_VERSION}/${CLEIMESH_BIN}.sha256" \
    && sha256sum -c "${CLEIMESH_BIN}.sha256" \
    && install -m 0755 "${CLEIMESH_BIN}" /usr/local/bin/cleimesh \
    && rm -f "${CLEIMESH_BIN}" "${CLEIMESH_BIN}.sha256" \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1500 agent \
    && useradd --uid 1500 --gid agent --create-home --home-dir /sandbox agent

WORKDIR /sandbox
USER agent

# OpenShell replaces CMD with its supervisor; commands run through
# `openshell sandbox exec`.
CMD ["sleep", "infinity"]
