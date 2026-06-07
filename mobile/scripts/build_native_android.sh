#!/usr/bin/env bash
# build_native_android.sh
# Cross-compiles the Arkos mobile native library for all Android ABIs.
# Outputs .so files into the correct jniLibs directory for Gradle.
#
# Prerequisites:
#   - Rust toolchain (rustup)
#   - cargo-ndk: `cargo install cargo-ndk`
#   - Android NDK installed (set NDK_HOME or ANDROID_NDK_HOME)
#
# Usage:
#   cd mobile && ./scripts/build_native_android.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="$SCRIPT_DIR/../native"
OUT_DIR="$SCRIPT_DIR/../android/app/src/main/jniLibs"
PROFILE="${1:-debug}"
CARGO_FLAGS=""
[ "$PROFILE" = "--release" ] && { PROFILE="release"; CARGO_FLAGS="--release"; }

TARGETS=(
    "aarch64-linux-android"    # arm64-v8a  (primary modern target)
    "armv7-linux-androideabi"  # armeabi-v7a
    "x86_64-linux-android"     # x86_64     (emulator)
)

ABI_MAP=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "x86_64-linux-android:x86_64"
)

echo "==> Installing Rust targets..."
for TARGET in "${TARGETS[@]}"; do
    rustup target add "$TARGET"
done

echo "==> Building native library ($PROFILE)..."
pushd "$NATIVE_DIR" > /dev/null
cargo ndk \
    --target aarch64-linux-android \
    --target armv7-linux-androideabi \
    --target x86_64-linux-android \
    --android-platform 26 \
    $CARGO_FLAGS \
    -- build
popd > /dev/null

echo "==> Copying .so files to jniLibs..."
for PAIR in "${ABI_MAP[@]}"; do
    TARGET="${PAIR%%:*}"
    ABI="${PAIR##*:}"
    SRC="$NATIVE_DIR/target/$TARGET/$PROFILE/libarkos_mobile.so"
    DST="$OUT_DIR/$ABI/libarkos_mobile.so"
    mkdir -p "$OUT_DIR/$ABI"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$DST"
        echo "  ✓ $ABI  ($DST)"
    else
        echo "  ✗ $ABI — not found: $SRC" >&2
    fi
done

echo "==> Done. Run 'flutter build apk' or 'flutter build appbundle' from mobile/."
