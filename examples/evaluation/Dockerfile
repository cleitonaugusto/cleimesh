FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates jq \
 && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir "mcp>=1.9,<2"
ENV PATH=/root/.local/bin:$PATH
RUN curl -fsSL https://github.com/cleitonaugusto/cleimesh/releases/latest/download/install.sh | sh
COPY . /kit
WORKDIR /kit
CMD ["bash", "/kit/run.sh"]
