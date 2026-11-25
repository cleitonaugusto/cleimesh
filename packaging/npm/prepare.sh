#!/bin/bash
# Sets this package's version and checksums from a published release.
# Usage: packaging/npm/prepare.sh v0.2.5
set -euo pipefail
cd "$(dirname "$0")"
TAG="$1"; VERSION="${TAG#v}"
BASE="https://github.com/cleitonaugusto/cleimesh/releases/download/$TAG"
SUMS="{}"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc.exe; do
  s=$(curl -fsSL "$BASE/cleimesh-$t.sha256" | awk '{print $1}')
  SUMS=$(echo "$SUMS" | python3 -c "import json,sys; d=json.load(sys.stdin); d['cleimesh-$t']='$s'; print(json.dumps(d))")
done
python3 - "$VERSION" "$SUMS" <<'PY'
import json, sys
p = json.load(open("package.json"))
p["version"] = sys.argv[1]
p["cleimesh"]["sha256"] = json.loads(sys.argv[2])
json.dump(p, open("package.json", "w"), indent=2)
open("package.json", "a").write("\n")
PY
echo "package.json set to $VERSION"
