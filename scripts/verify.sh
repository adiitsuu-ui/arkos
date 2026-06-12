#!/usr/bin/env bash
# verify.sh — verify the integrity and authenticity of a release binary
#
# Usage: ./scripts/verify.sh [CHECKSUMS_FILE]
#
# If CHECKSUMS_FILE is not provided, uses CHECKSUMS.txt in the project root.
# If CHECKSUMS.txt.asc is present alongside the checksums file, also verifies
# the GPG signature.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CHECKSUMS="${1:-CHECKSUMS.txt}"

if [[ ! -f "$CHECKSUMS" ]]; then
    echo "ERROR: checksums file not found: $CHECKSUMS" >&2
    echo "Run ./scripts/release.sh first to generate it." >&2
    exit 1
fi

echo "==> Verifying checksums in $CHECKSUMS..."
if command -v sha256sum &>/dev/null; then
    sha256sum --check "$CHECKSUMS" --ignore-missing
else
    shasum -a 256 --check "$CHECKSUMS" --ignore-missing
fi

echo "✅ Checksum verification passed"

SIG="${CHECKSUMS}.asc"
if [[ -f "$SIG" ]]; then
    echo ""
    echo "==> Verifying GPG signature $SIG..."
    if ! command -v gpg &>/dev/null; then
        echo "WARNING: gpg not found — cannot verify signature" >&2
    else
        gpg --verify "$SIG" "$CHECKSUMS"
        echo "✅ GPG signature verified"
    fi
else
    echo "NOTE: No GPG signature file found at $SIG — skipping signature check."
fi
