#!/bin/sh
# Installs the `cleimesh` binary from GitHub Releases, after checking its
# SHA-256. No root, no daemon, no container: one file in ~/.local/bin.
#
#   curl -fsSL https://github.com/cleitonaugusto/cleimesh/releases/latest/download/install.sh | sh
#
# CLEIMESH_VERSION=v0.1.0      a given release instead of the latest
# CLEIMESH_INSTALL_DIR=DIR     where to put it (default ~/.local/bin)
# CLEIMESH_DOWNLOAD_BASE=URL   another source (a mirror, or file:// for tests)
set -eu

REPO="cleitonaugusto/cleimesh"
DIR="${CLEIMESH_INSTALL_DIR:-$HOME/.local/bin}"
if [ -n "${CLEIMESH_DOWNLOAD_BASE:-}" ]; then
  BASE="$CLEIMESH_DOWNLOAD_BASE"
elif [ -n "${CLEIMESH_VERSION:-}" ]; then
  BASE="https://github.com/$REPO/releases/download/$CLEIMESH_VERSION"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;   # static: any distribution
  Darwin) os=apple-darwin ;;
  *) echo "cleimesh: unsupported system $(uname -s); see the releases page for Windows" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) echo "cleimesh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
NAME="cleimesh-$arch-$os"

if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $NAME from $BASE"
curl -fsSL "$BASE/$NAME" -o "$TMP/$NAME"
curl -fsSL "$BASE/$NAME.sha256" -o "$TMP/$NAME.sha256"
expected="$(cut -d' ' -f1 "$TMP/$NAME.sha256")"
actual="$(cd "$TMP" && $SHA "$NAME" | cut -d' ' -f1)"
if [ "$expected" != "$actual" ]; then
  echo "cleimesh: checksum mismatch, refusing to install (expected $expected, got $actual)" >&2
  exit 1
fi

mkdir -p "$DIR"
chmod +x "$TMP/$NAME"
mv "$TMP/$NAME" "$DIR/cleimesh"
echo "Installed $DIR/cleimesh ($("$DIR/cleimesh" --version 2>/dev/null || echo "checksum $actual"))"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "Add $DIR to your PATH: export PATH=\"$DIR:\$PATH\"" ;;
esac
echo "Next: cleimesh token issue \$(cleimesh id --client) --tool file_read --read <your project> -o chain.json"
echo "      claude mcp add cleimesh -- cleimesh mcp serve --token chain.json"
