#!/usr/bin/env bash
# Cross-compile layzmd release binaries into dist/.
# Usage: scripts/build-release.sh [version]   (defaults to `git describe`)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"
mkdir -p dist

targets="windows/amd64 linux/amd64 darwin/amd64 darwin/arm64"
for t in $targets; do
  GOOS="${t%/*}"; GOARCH="${t#*/}"
  ext=""; [ "$GOOS" = "windows" ] && ext=".exe"
  out="dist/layzmd_${VERSION}_${GOOS}_${GOARCH}${ext}"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
done
echo "done:"; ls -1 dist/
