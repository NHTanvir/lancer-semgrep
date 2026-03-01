#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-semgrep"
INSTALL=0
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        *) ;;
    esac
done

echo "================================================"
echo "  lancer-semgrep Build"
echo "================================================"
echo ""
echo "  Repo    : $REPO"
echo "  Output  : $BUILD/$BIN"
echo "  Install : $([ $INSTALL -eq 1 ] && echo yes || echo no)"
echo ""

echo "[1/2] Building release binary..."
cargo build --release --bin lancer-semgrep

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"

if [ $INSTALL -eq 1 ]; then
    # Per plan §"GUI → Build output → Linux: also installable as a .desktop
    # entry via build-linux.sh --install".
    INSTALL_BIN="${HOME}/.local/bin"
    DESKTOP_DIR="${HOME}/.local/share/applications"
    mkdir -p "$INSTALL_BIN" "$DESKTOP_DIR"

    cp "$BUILD/$BIN" "$INSTALL_BIN/$BIN"
    chmod +x "$INSTALL_BIN/$BIN"

    DESKTOP_FILE="$DESKTOP_DIR/lancer-semgrep.desktop"
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Lancer Semgrep
Comment=Rust clone of semgrep (Lancer toolkit)
Exec=$INSTALL_BIN/$BIN
Terminal=false
Categories=Development;Security;
EOF

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$DESKTOP_DIR" || true
    fi
    echo ""
    echo "  Installed binary  -> $INSTALL_BIN/$BIN"
    echo "  Installed entry   -> $DESKTOP_FILE"
fi

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"
