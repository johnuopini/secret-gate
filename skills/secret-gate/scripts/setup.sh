#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${HOME}/.config/secret-gate"
CONFIG_FILE="${CONFIG_DIR}/config.json"
BIN_DIR="${CONFIG_DIR}/bin"
BIN_PATH="${BIN_DIR}/secret-gate"

usage() {
  echo "Usage: setup.sh [--server <url>]"
  echo ""
  echo "Sets up the secret-gate client."
  echo "Downloads the secret-gate binary and saves the server URL."
  echo ""
  echo "Options:"
  echo "  --server <url>  The secret-gate server URL"
  echo ""
  echo "If --server is not provided, reads from:"
  echo "  1. \$SECRET_GATE_URL environment variable"
  echo "  2. \$OP_APPROVAL_PROXY_URL environment variable (legacy)"
  echo "  3. ${CONFIG_FILE}"
  echo "  4. Interactive prompt"
}

get_server_url() {
  local server_url=""

  # Check command line arg
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) server_url="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done

  # Check env var (SECRET_GATE_URL first, fall back to legacy)
  if [[ -z "$server_url" ]]; then
    server_url="${SECRET_GATE_URL:-${OP_APPROVAL_PROXY_URL:-}}"
  fi

  # Check existing config
  if [[ -z "$server_url" && -f "$CONFIG_FILE" ]]; then
    server_url=$(grep -o '"server_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | head -1 | sed 's/.*"server_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  fi

  # Interactive prompt
  if [[ -z "$server_url" ]]; then
    echo "Enter the secret-gate server URL:"
    read -r server_url
  fi

  if [[ -z "$server_url" ]]; then
    echo "Error: server URL is required" >&2
    exit 1
  fi

  # Strip trailing slash
  server_url="${server_url%/}"
  echo "$server_url"
}

detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac
}

main() {
  # Handle --help before subshell so exit works correctly
  for arg in "$@"; do
    case "$arg" in
      --help|-h) usage; exit 0 ;;
    esac
  done

  local server_url
  server_url=$(get_server_url "$@")

  local arch
  arch=$(detect_arch)

  echo "Server: $server_url"
  echo "Architecture: $arch"

  # Create directories
  mkdir -p "$BIN_DIR"
  mkdir -p "$CONFIG_DIR"

  # Save config
  cat > "$CONFIG_FILE" <<CONF
{"server_url": "$server_url"}
CONF
  echo "Config saved to $CONFIG_FILE"

  # Download binary from server
  echo "Downloading secret-gate ($arch)..."
  local http_code
  http_code=$(curl -sL -w "%{http_code}" -o "$BIN_PATH" "$server_url/client/$arch")

  if [[ "$http_code" != "200" ]]; then
    rm -f "$BIN_PATH"
    echo "Server download failed (HTTP $http_code). Trying GitHub Releases..." >&2

    # Fallback: try GitHub Releases
    local github_url="https://github.com/johnuopini/secret-gate/releases/latest/download/secret-gate-${arch}"
    http_code=$(curl -sL -w "%{http_code}" -o "$BIN_PATH" "$github_url")

    if [[ "$http_code" != "200" ]]; then
      rm -f "$BIN_PATH"
      echo "Error: failed to download secret-gate from GitHub (HTTP $http_code)" >&2
      echo "Is the server running at $server_url?" >&2
      exit 1
    fi
  fi

  chmod +x "$BIN_PATH"
  echo "Binary saved to $BIN_PATH"

  # Verify
  echo ""
  echo "Setup complete. Testing connectivity..."
  if curl -sf "$server_url/health" > /dev/null 2>&1; then
    echo "Server is healthy."
  else
    echo "Warning: could not reach server health endpoint." >&2
    echo "The binary is installed but the server may be down." >&2
  fi
}

main "$@"
