# Secret Gate

**Human-in-the-loop secret approval for AI coding agents. Retrieve secrets from 1Password with Telegram-based approval.**

![CI](https://github.com/johnuopini/secret-gate/actions/workflows/test.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## How It Works

1. Your AI coding agent detects it needs a credential (API key, SSH key, database password, etc.)
2. The agent searches for the secret in 1Password via the Secret Gate server
3. The agent requests access -- you receive a Telegram notification with **Approve** / **Deny** buttons
4. On approval, the agent retrieves the secret through a one-time-use token
5. SSH keys are automatically added to ssh-agent with TTL-matched expiry; secrets are cached in memory by the local daemon

## Quick Start

```bash
# 1. Clone and start the server
git clone https://github.com/johnuopini/secret-gate.git
cd secret-gate
cp .env.example .env  # Edit with your credentials
docker compose up -d

# 2. Install the AI tool integration
curl -sL https://raw.githubusercontent.com/johnuopini/secret-gate/main/install.sh | bash -s -- --server http://localhost:8080

# 3. That's it -- your AI coding tool will auto-detect the skill
```

## Prerequisites

- **1Password Connect server** -- a running instance that Secret Gate queries for secrets ([setup guide](https://developer.1password.com/docs/connect/get-started/))
- **Telegram bot** -- created via [@BotFather](https://t.me/BotFather) to send approval notifications
- **Docker** (recommended) or Go 1.23+ for building from source

## Server Deployment

### Docker Compose (recommended)

Create a `.env` file with your configuration (see [Server Configuration](#server-configuration)), then:

```bash
docker compose up -d
```

### Docker

```bash
docker run -d \
  -p 8080:8080 \
  -e OP_CONNECT_HOST=https://connect.example.com \
  -e OP_CONNECT_TOKEN=your-token \
  -e TELEGRAM_BOT_TOKEN=your-bot-token \
  -e TELEGRAM_CHAT_ID=your-chat-id \
  -e WEBHOOK_BASE_URL=https://gate.example.com \
  ghcr.io/johnuopini/secret-gate:latest
```

### OpenFaaS

Secret Gate can be deployed as an OpenFaaS function. Secrets are read from `/var/openfaas/secrets/` when available. See the included `secret-gate.yml` for the function definition.

### Binary

```bash
go install github.com/johnuopini/secret-gate/cmd/server@latest
```

Then run the `server` binary with the required environment variables set.

## Server Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OP_CONNECT_HOST` | Yes | -- | 1Password Connect server URL |
| `OP_CONNECT_TOKEN` | Yes | -- | 1Password Connect API token |
| `TELEGRAM_BOT_TOKEN` | Yes | -- | Telegram bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Yes | -- | Telegram chat ID for approval notifications |
| `WEBHOOK_BASE_URL` | Yes | -- | Public URL where this server is accessible |
| `PORT` | No | `8080` | HTTP listen port |
| `REQUEST_TTL` | No | `15m` | How long approval requests remain valid |
| `CLEANUP_INTERVAL` | No | `5m` | Interval for cleaning up expired requests |

## Client Installation

The client binary (`secret-gate`) runs on the machine where your AI coding agent operates. It handles communication with the server and manages a local caching daemon.

### From the server

The server hosts pre-compiled client binaries at `/client/{arch}`:

```bash
curl -sL https://your-server/client/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') -o secret-gate
chmod +x secret-gate
sudo mv secret-gate /usr/local/bin/
```

### From GitHub Releases

Download the latest release from [github.com/johnuopini/secret-gate/releases](https://github.com/johnuopini/secret-gate/releases).

### From source

```bash
go install github.com/johnuopini/secret-gate/cmd/client@latest
```

## AI Tool Integration

Secret Gate ships with skill files that teach AI coding agents how to use it. The `install.sh` script places these skill files in the correct location for each supported tool.

**Supported tools:** Claude Code, OpenAI Codex, OpenCode, Cline, Roo Code.

```bash
# Auto-detect and install for all detected tools
curl -sL https://raw.githubusercontent.com/johnuopini/secret-gate/main/install.sh | bash -s -- \
  --server https://your-server

# Install for a specific tool
curl -sL https://raw.githubusercontent.com/johnuopini/secret-gate/main/install.sh | bash -s -- \
  --server https://your-server --tool claude-code
```

Once installed, the AI agent will automatically discover the skill and use the `secret-gate` client to search for and request secrets as needed.

## Client Configuration

The client reads its configuration from `~/.config/secret-gate/config.json`. Environment variables override file values.

```json
{
  "server_url": "https://your-server",
  "cache_ttl": "1h",
  "daemon_idle_timeout": "5m",
  "ssh_agent_integration": true
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `server_url` | -- | Secret Gate server URL (also set via `SECRET_GATE_URL` env var) |
| `cache_ttl` | `1h` | How long secrets are cached locally by the daemon |
| `daemon_idle_timeout` | `5m` | Daemon exits after this period of inactivity |
| `ssh_agent_integration` | `true` | Automatically add SSH keys to ssh-agent on retrieval |

## Daemon (Caching)

The client includes a background daemon that caches approved secrets in memory, eliminating redundant approval prompts for recently used credentials.

- The daemon starts automatically on the first secret request
- Secrets are cached for the configured `cache_ttl` (default: 1 hour)
- The daemon exits automatically after `daemon_idle_timeout` of inactivity (default: 5 minutes)
- Communication between the client and daemon uses a Unix socket with `0600` permissions

**Daemon commands:**

```bash
# The daemon starts automatically; manual control is also available:
secret-gate --daemon-status    # Check if the daemon is running
secret-gate --daemon-stop      # Stop the daemon
```

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/search` | None | Search for secrets across all vaults (no approval required) |
| `POST` | `/fields` | None | Get field metadata for a secret without exposing values |
| `POST` | `/request` | None | Request access to one or more secrets (triggers Telegram approval) |
| `GET` | `/status/{token}` | Token | Check approval status of a pending request |
| `GET` | `/secret/{token}` | Token | Retrieve the approved secret (one-time use) |
| `GET` | `/client/{arch}` | None | Download the pre-compiled client binary (`amd64` or `arm64`) |
| `GET` | `/health` | None | Health check |
| `GET` | `/openapi.json` | None | Full OpenAPI 3.0 specification |

For detailed request/response schemas, see the OpenAPI spec at `/openapi.json` on a running server.

## Security

- **No secrets on disk.** Secrets are cached only in the daemon's in-process memory. Nothing is written to the filesystem.
- **Unix socket IPC.** The daemon listens on a Unix socket with `0600` permissions, accessible only to the owning user.
- **SSH agent integration.** SSH keys are added to ssh-agent with a TTL that matches the cache expiry, so they are automatically removed.
- **Telegram approval gate.** Every secret access requires explicit human approval through Telegram inline buttons.
- **One-time tokens.** Secret retrieval tokens can only be used once. A second fetch returns an error.
- **Configurable TTL.** All approval requests expire after a configurable duration (default: 15 minutes).

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push to the branch and open a Pull Request

Please include tests for new functionality and ensure existing tests pass (`go test ./...`).

## License

MIT -- see [LICENSE](LICENSE) for details.
