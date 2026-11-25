#!/bin/bash
# Writes the Homebrew formula for a release from its published .sha256 files.
# Usage: scripts/brew-formula.sh v0.2.5 > Formula/cleimesh.rb
set -euo pipefail
TAG="$1"; VERSION="${TAG#v}"
REPO=cleitonaugusto/cleimesh
BASE="https://github.com/$REPO/releases/download/$TAG"
sha() { curl -fsSL "$BASE/cleimesh-$1.sha256" | awk '{print $1}'; }
MAC_ARM=$(sha aarch64-apple-darwin); MAC_X86=$(sha x86_64-apple-darwin)
LIN_ARM=$(sha aarch64-unknown-linux-musl); LIN_X86=$(sha x86_64-unknown-linux-musl)
cat <<RUBY
class Cleimesh < Formula
  desc "What your agent reads can't decide what it does: MCP servers behind signed tokens"
  homepage "https://github.com/$REPO"
  version "$VERSION"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "$BASE/cleimesh-aarch64-apple-darwin"
      sha256 "$MAC_ARM"
    end
    on_intel do
      url "$BASE/cleimesh-x86_64-apple-darwin"
      sha256 "$MAC_X86"
    end
  end

  on_linux do
    on_arm do
      url "$BASE/cleimesh-aarch64-unknown-linux-musl"
      sha256 "$LIN_ARM"
    end
    on_intel do
      url "$BASE/cleimesh-x86_64-unknown-linux-musl"
      sha256 "$LIN_X86"
    end
  end

  def install
    bin.install Dir["cleimesh-*"].first => "cleimesh"
  end

  test do
    assert_match "cleimesh #{version}", shell_output("#{bin}/cleimesh --version")
  end
end
RUBY
