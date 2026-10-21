# OpenClaw and CleiMesh for the real-model demo video.
FROM node:24-trixie-slim
RUN npm install -g openclaw@latest >/tmp/npm.log 2>&1 && openclaw --version
COPY cleimesh /usr/local/bin/cleimesh
