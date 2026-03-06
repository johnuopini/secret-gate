# Changelog

## v0.2.1 — Cross-Platform & SSH Fixes

### Added

- **macOS client binaries** — Docker image and server now build and serve darwin/amd64 and darwin/arm64 binaries alongside Linux. Download via `/client/{os}/{arch}`.
- **OS detection** in setup.sh and SKILL.md — `uname -s` is used to auto-detect platform when downloading the client binary.
- Legacy `/client/{arch}` path still works (assumes Linux) for backwards compatibility.

### Fixed

- **SSH agent fallback** — `ssh_with_secret` MCP tool now falls back to a temp key file with `ssh -i` when `ssh-add` fails (e.g., locked agents), instead of returning an error. The temp file is cleaned up immediately after use.
- **README "Without Secret Gate" section** — rewritten to explain actual alternatives (local 1Password CLI, service accounts, manual copy-paste) and their security tradeoffs.
- Removed OpenFaaS deployment section from public README (internal-only deployment).

## v0.2.0 — MCP Server

### Added

- **MCP server** (`secret-gate mcp`) — built-in [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio. AI agents can now search, request, and use secrets through structured MCP tool calls instead of shell commands.
- **6 MCP tools**: `search_secrets`, `inspect_fields`, `request_secret`, `exec_with_secret`, `ssh_with_secret`, `daemon_status`
- **`exec_with_secret`** — run any shell command with a secret injected as an environment variable. The secret value never appears in the agent's context.
- **`ssh_with_secret`** — SSH to a host using an approved SSH key. The key is added to ssh-agent automatically.
- **`request_secret`** — trigger Telegram approval and cache the result. Returns approval status only, never the secret value.
- Output truncation (1MB cap) for `exec_with_secret` and `ssh_with_secret` to prevent memory issues with large command output.
- SSH `BatchMode=yes` and `StrictHostKeyChecking=accept-new` for non-interactive SSH via MCP.
- Context cancellation support in the approval polling loop.
- Thread-safe daemon client with `sync.Mutex` for concurrent MCP tool calls.

### Changed

- SKILL.md updated with MCP-first workflow — MCP is now the recommended integration path, with CLI as fallback.
- README rewritten with MCP setup instructions, before/after comparison, and updated architecture.

## v0.1.0 — Initial Release

### Added

- Secret Gate server with 1Password Connect integration and Telegram approval flow.
- Client binary with search, field inspection, and secret request commands.
- Background caching daemon with Unix socket IPC and configurable TTL.
- Automatic SSH key detection and ssh-agent integration with TTL-matched expiry.
- Skill files for Claude Code, Codex, OpenCode, Cline, and Roo Code.
- One-time-use tokens for secret retrieval.
- OpenAPI 3.0 specification at `/openapi.json`.
- Docker Compose, Docker, OpenFaaS, and binary deployment options.
- GitHub Actions CI/CD with multi-platform release builds.
