#!/usr/bin/env bash
# Fuzz the parsers that take outside input (S17).
# Needs nightly and cargo-fuzz (`cargo install cargo-fuzz`).
#
#   scripts/fuzz.sh            # seeds, then 180 s per target
#   SECONDS_PER_TARGET=3600 scripts/fuzz.sh
#
# A crash lands in fuzz/artifacts/<target>/; replay it with
# `cargo +nightly fuzz run <target> <file>`.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
cargo +nightly run --bin seeds
for target in aat_verify receipt_log; do
  cargo +nightly fuzz run "$target" -- -max_total_time="${SECONDS_PER_TARGET:-180}" -rss_limit_mb=2048
done
