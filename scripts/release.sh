#!/usr/bin/env bash
# release.sh — build a release binary and produce a signed CHECKSUMS.txt
#
# Usage: ./scripts/release.sh [--no-sign]
#
# Prerequisites:
#   - Rust toolchain (stable)
#   - GPG key (optional; skip signing with --no-sign)
#
# Output:
#   target/release/arkos       — the release binary
#   CHECKSUMS.txt              — SHA-256 hash + metadata
#   CHECKSUMS.txt.asc          — GPG detached signature (unless --no-sign)

set -euo pipefail

SIGN=true
if [[ "${1:-}" == "--no-sign" ]]; then
    SIGN=false
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building Arkos release binary..."
cargo build --release --locked

BINARY="target/release/arkos"
if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: binary not found at $BINARY" >&2
    exit 1
fi

COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION=$(cargo metadata --no-deps --format-version 1 | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")

echo "==> Computing checksums..."
CHECKSUM=$(sha256sum "$BINARY" 2>/dev/null || shasum -a 256 "$BINARY")

CHECKSUMS_FILE="CHECKSUMS.txt"
cat >"$CHECKSUMS_FILE" <<EOF
# Arkos Release Checksums
# Version : $VERSION
# Commit  : $COMMIT
# Branch  : $BRANCH
# Built   : $BUILD_DATE
#
# Verify with: sha256sum --check CHECKSUMS.txt
#          or: shasum -a 256 --check CHECKSUMS.txt

$CHECKSUM
EOF

echo "==> Written: $CHECKSUMS_FILE"
cat "$CHECKSUMS_FILE"

if [[ "$SIGN" == "true" ]]; then
    echo "==> Signing with GPG..."
    if ! command -v gpg &>/dev/null; then
        echo "WARNING: gpg not found — skipping signature. Re-run with --no-sign to suppress this warning."
    else
        gpg --armor --detach-sign --output "${CHECKSUMS_FILE}.asc" "$CHECKSUMS_FILE"
        echo "==> Signature written: ${CHECKSUMS_FILE}.asc"
        echo "==> Verify with: gpg --verify ${CHECKSUMS_FILE}.asc $CHECKSUMS_FILE"
    fi
fi

echo ""
echo "✅ Release build complete:"
echo "   Binary  : $BINARY"
echo "   Version : $VERSION"
echo "   Commit  : $COMMIT"
echo "   SHA-256 : $(echo "$CHECKSUM" | awk '{print $1}')"
