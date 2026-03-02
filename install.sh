#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="secret-gate"
GITHUB_REPO="johnuopini/secret-gate"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}/main"

# Parse args
SERVER_URL=""
TOOL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="$2"; shift 2 ;;
    --tool) TOOL="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: install.sh [--server <url>] [--tool <tool>]"
      echo ""
      echo "Installs the secret-gate skill for AI coding tools."
      echo ""
      echo "Options:"
      echo "  --server <url>   The secret-gate server URL"
      echo "  --tool <tool>    Force install for specific tool (claude-code, codex, opencode)"
      echo ""
      echo "Auto-detects installed tools if --tool is not specified."
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Detect if running from local checkout
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_SKILL=""
if [[ -f "$SCRIPT_DIR/skills/${SKILL_NAME}/SKILL.md" ]]; then
  LOCAL_SKILL="$SCRIPT_DIR/skills/${SKILL_NAME}"
fi

install_skill() {
  local target_dir="$1"
  local tool_name="$2"

  echo "Installing ${SKILL_NAME} for ${tool_name}..."
  mkdir -p "${target_dir}/scripts"

  if [[ -n "$LOCAL_SKILL" ]]; then
    cp "$LOCAL_SKILL/SKILL.md" "${target_dir}/SKILL.md"
    cp "$LOCAL_SKILL/scripts/setup.sh" "${target_dir}/scripts/setup.sh"
  else
    curl -sL -o "${target_dir}/SKILL.md" "${GITHUB_RAW}/skills/${SKILL_NAME}/SKILL.md"
    curl -sL -o "${target_dir}/scripts/setup.sh" "${GITHUB_RAW}/skills/${SKILL_NAME}/scripts/setup.sh"
  fi

  chmod +x "${target_dir}/scripts/setup.sh"
  echo "  Installed to ${target_dir}"
}

INSTALLED=0

# Claude Code
if [[ "$TOOL" == "claude-code" || ("$TOOL" == "" && -d "${HOME}/.claude") ]]; then
  install_skill "${HOME}/.claude/skills/${SKILL_NAME}" "Claude Code"
  INSTALLED=1
fi

# Codex / OpenCode / Cline / Roo Code (shared .agents/ path)
if [[ "$TOOL" == "codex" || "$TOOL" == "opencode" || ("$TOOL" == "" && (-d "${HOME}/.agents" || -d "${HOME}/.codex" || -d "${HOME}/.config/opencode")) ]]; then
  install_skill "${HOME}/.agents/skills/${SKILL_NAME}" "Codex/OpenCode"
  INSTALLED=1
fi

# OpenCode native path
if [[ "$TOOL" == "opencode" || ("$TOOL" == "" && -d "${HOME}/.config/opencode") ]]; then
  install_skill "${HOME}/.config/opencode/skills/${SKILL_NAME}" "OpenCode"
  INSTALLED=1
fi

# If nothing detected, install to both common paths
if [[ $INSTALLED -eq 0 ]]; then
  echo "No AI coding tool detected. Installing to default paths..."
  install_skill "${HOME}/.claude/skills/${SKILL_NAME}" "Claude Code"
  install_skill "${HOME}/.agents/skills/${SKILL_NAME}" "Codex/OpenCode"
fi

# Run setup if server URL provided
SETUP_SCRIPT="${HOME}/.claude/skills/${SKILL_NAME}/scripts/setup.sh"
if [[ ! -f "$SETUP_SCRIPT" ]]; then
  SETUP_SCRIPT="${HOME}/.agents/skills/${SKILL_NAME}/scripts/setup.sh"
fi

if [[ -n "$SERVER_URL" && -f "$SETUP_SCRIPT" ]]; then
  echo ""
  echo "Running setup with server: $SERVER_URL"
  "$SETUP_SCRIPT" --server "$SERVER_URL"
elif [[ -n "${SECRET_GATE_URL:-}" && -f "$SETUP_SCRIPT" ]]; then
  echo ""
  echo "Running setup with \$SECRET_GATE_URL: $SECRET_GATE_URL"
  "$SETUP_SCRIPT" --server "$SECRET_GATE_URL"
else
  echo ""
  echo "Skill installed. To complete setup, either:"
  echo "  1. Run: setup.sh --server <your-server-url>"
  echo "  2. Set: export SECRET_GATE_URL=<your-server-url>"
  echo "  3. Your AI tool will prompt you on first use"
fi

echo ""
echo "Done!"
