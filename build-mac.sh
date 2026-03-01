#!/usr/bin/env bash
# Build a macOS .app bundle for lancer-semgrep.
#
# Per plan §"GUI → Build output → macOS: build/lancer-semgrep
# (bundled into lancer-semgrep.app via cargo-bundle in the build-mac.sh
# companion)".
#
# Requires:
#   - cargo (rustup.rs)
#   - cargo-bundle: `cargo install cargo-bundle`
#   - C compiler discoverable on PATH

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BIN="lancer-semgrep"
echo "==> Building release binary..."
cargo build --release --bin "$BIN"

mkdir -p build
cp "target/release/$BIN" "build/$BIN"
echo "==> Binary at build/$BIN"

if command -v cargo-bundle >/dev/null 2>&1; then
    echo "==> Bundling .app via cargo-bundle..."
    cargo bundle --release --bin "$BIN" || {
        echo "(cargo-bundle failed; the bare binary at build/$BIN is still usable.)"
    }
else
    echo "==> cargo-bundle not installed; install with: cargo install cargo-bundle"
    echo "    The bare binary at build/$BIN is still usable."
fi
