#!/usr/bin/env bash
# build_native_ios.sh
# Cross-compiles the Arkos mobile native library for iOS (device + simulator)
# and packages them into a fat XCFramework that Xcode links statically.
#
# Prerequisites:
#   - Rust toolchain with iOS targets (see below)
#   - Xcode command-line tools: `xcode-select --install`
#
# Usage:
#   cd mobile && ./scripts/build_native_ios.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="$SCRIPT_DIR/../native"
IOS_DIR="$SCRIPT_DIR/../ios"
PROFILE="${1:-debug}"
CARGO_FLAGS=""
[ "$PROFILE" = "--release" ] && { PROFILE="release"; CARGO_FLAGS="--release"; }

DEVICE_TARGET="aarch64-apple-ios"
SIM_ARM_TARGET="aarch64-apple-ios-sim"   # Apple Silicon simulator
SIM_X86_TARGET="x86_64-apple-ios"        # Intel simulator

echo "==> Installing Rust iOS targets..."
rustup target add "$DEVICE_TARGET" "$SIM_ARM_TARGET" "$SIM_X86_TARGET"

echo "==> Building for iOS device ($DEVICE_TARGET)..."
pushd "$NATIVE_DIR" > /dev/null
cargo build --target "$DEVICE_TARGET" $CARGO_FLAGS

echo "==> Building for iOS simulator arm64 ($SIM_ARM_TARGET)..."
cargo build --target "$SIM_ARM_TARGET" $CARGO_FLAGS

echo "==> Building for iOS simulator x86_64 ($SIM_X86_TARGET)..."
cargo build --target "$SIM_X86_TARGET" $CARGO_FLAGS
popd > /dev/null

# Create a fat simulator slice (arm64 + x86_64) with lipo.
SIM_FAT_DIR="$NATIVE_DIR/target/ios-sim-fat/$PROFILE"
mkdir -p "$SIM_FAT_DIR"
lipo -create \
    "$NATIVE_DIR/target/$SIM_ARM_TARGET/$PROFILE/libarkos_mobile.a" \
    "$NATIVE_DIR/target/$SIM_X86_TARGET/$PROFILE/libarkos_mobile.a" \
    -output "$SIM_FAT_DIR/libarkos_mobile.a"
echo "==> Fat simulator slice: $SIM_FAT_DIR/libarkos_mobile.a"

# Package into XCFramework (device slice + simulator fat slice).
XCFRAMEWORK_PATH="$IOS_DIR/Frameworks/ArkosNative.xcframework"
rm -rf "$XCFRAMEWORK_PATH"
xcodebuild -create-xcframework \
    -library "$NATIVE_DIR/target/$DEVICE_TARGET/$PROFILE/libarkos_mobile.a" \
    -library "$SIM_FAT_DIR/libarkos_mobile.a" \
    -output "$XCFRAMEWORK_PATH"

echo "==> XCFramework: $XCFRAMEWORK_PATH"

# Generate the C header (needed by Flutter FFI and Swift interop).
HEADER_SRC="$NATIVE_DIR/src/arkos_mobile.h"
HEADER_DST="$IOS_DIR/Runner/ArkosNative.h"
if [ -f "$HEADER_SRC" ]; then
    cp "$HEADER_SRC" "$HEADER_DST"
    echo "==> Header copied: $HEADER_DST"
else
    echo "  ⚠ No header found at $HEADER_SRC — generate with cbindgen if needed"
fi

echo "==> Done. Open ios/Runner.xcworkspace in Xcode, add ArkosNative.xcframework"
echo "    to 'Frameworks, Libraries, and Embedded Content' (Embed: Do Not Embed)."
