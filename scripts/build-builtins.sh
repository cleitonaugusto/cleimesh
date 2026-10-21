#!/usr/bin/env bash
# Rebuilds wasm-tools/builtins.wasm from wasm-tools/builtins (Rust -> wasm32-wasip1).
# The resulting .wasm is committed so a fresh clone builds without the wasm target.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
# Panic messages embed source paths; map the machine-specific prefixes (the
# toolchain, the cargo registry, this checkout) to fixed ones, so the
# committed module names no local user or directory and builds the same
# bytes on any machine with the same toolchain.
sysroot="$(rustc --print sysroot)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$sysroot=/rustc --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$root=/cleimesh"
cargo build --release --target wasm32-wasip1 \
  --manifest-path "$root/wasm-tools/builtins/Cargo.toml" \
  --target-dir "$root/target/builtins"
cp "$root/target/builtins/wasm32-wasip1/release/cleimesh_builtins.wasm" "$root/wasm-tools/builtins.wasm"
ls -l "$root/wasm-tools/builtins.wasm"
