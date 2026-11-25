FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv mcp
ENV PATH=/root/.local/bin:$PATH
RUN curl -fsSL https://github.com/cleitonaugusto/cleimesh/releases/latest/download/install.sh | sh \
 && uv tool install mcp-email-server
