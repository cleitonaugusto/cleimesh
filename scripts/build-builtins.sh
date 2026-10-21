#!/usr/bin/env bash
# Rebuilds wasm-tools/builtins.wasm from wasm-tools/builtins (Rust -> wasm32-wasip1).
# The resulting .wasm is committed so a fresh clone builds without the wasm target.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
cargo build --release --target wasm32-wasip1 \
  --manifest-path "$root/wasm-tools/builtins/Cargo.toml" \
  --target-dir "$root/target/builtins"
cp "$root/target/builtins/wasm32-wasip1/release/cleimesh_builtins.wasm" "$root/wasm-tools/builtins.wasm"
ls -l "$root/wasm-tools/builtins.wasm"
