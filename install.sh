#!/usr/bin/env sh
# ZeroTrace One-Line Installer (Linux & macOS)
# Usage: curl -fsSL https://zerotrace.eu/install.sh | sh
set -eu

REPO="chuanjin/zerotrace"
INSTALL_DIR="${ZEROTRACE_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="zerotrace"

info() { printf "\033[1;34m==>\033[0m %s\n" "$1"; }
success() { printf "\033[1;32m  ✓\033[0m %s\n" "$1"; }
err() { printf "\033[1;31m  ✗ Error:\033[0m %s\n" "$1" >&2; exit 1; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux|darwin) ;;
  *) err "Unsupported OS: $OS (ZeroTrace supports Linux and macOS)" ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $ARCH" ;;
esac

mkdir -p "$INSTALL_DIR"

info "Installing ZeroTrace ($OS/$ARCH) to $INSTALL_DIR/$BINARY_NAME..."

# 1. If running inside a local git checkout with Go available, build from source
if [ -f "./agent/cmd/zerotrace/main.go" ] && command -v go >/dev/null 2>&1; then
  info "Local source detected — building reproducible binary with Go..."
  (cd ./agent && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/$BINARY_NAME" ./cmd/zerotrace)
  chmod +x "$INSTALL_DIR/$BINARY_NAME"
  success "Built and installed $INSTALL_DIR/$BINARY_NAME"
else
  # 2. Download prebuilt release binary from GitHub Releases
  RELEASE_URL="https://github.com/${REPO}/releases/latest/download/zerotrace-${OS}-${ARCH}"
  info "Downloading prebuilt binary from $RELEASE_URL..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RELEASE_URL" -o "$INSTALL_DIR/$BINARY_NAME"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$INSTALL_DIR/$BINARY_NAME" "$RELEASE_URL"
  else
    err "Neither curl nor wget found."
  fi
  chmod +x "$INSTALL_DIR/$BINARY_NAME"
  success "Downloaded $INSTALL_DIR/$BINARY_NAME"
fi

# Verify installation and run initial setup if not yet initialized
"$INSTALL_DIR/$BINARY_NAME" version
echo ""
info "Initializing local configuration & background service..."
"$INSTALL_DIR/$BINARY_NAME" init
"$INSTALL_DIR/$BINARY_NAME" daemon install || true
"$INSTALL_DIR/$BINARY_NAME" hook install || true

echo ""
success "ZeroTrace is running in the background (:9000)!"
info "Open a new shell or run 'source ~/.zshrc' to start using Claude Code / OpenAI with zero-leak proxy."

