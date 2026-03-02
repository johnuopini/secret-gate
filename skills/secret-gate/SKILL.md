---
name: secret-gate
description: Use when needing SSH keys, API tokens, passwords, or any credentials to complete a task. Use when encountering authentication failures (401/403), missing SSH keys, or when asked to deploy, connect, or interact with systems requiring secrets. Retrieves secrets from 1Password with human approval via Telegram.
---

# 1Password Approval Proxy

Retrieve secrets from 1Password with human-in-the-loop approval via Telegram. When you need a credential to complete a task, use this skill to request it — a human approves on Telegram before the secret is released.

## Setup Check

Before any operation, verify the setup:

1. **Resolve server URL** (first match wins):
   - `$SECRET_GATE_URL` environment variable (also accepts legacy `$OP_APPROVAL_PROXY_URL`)
   - `~/.config/secret-gate/config.json` -> `server_url` field
   - If neither exists: ask the user for the URL, then run the setup script

2. **Resolve secret-gate binary**:
   - Check `~/.config/secret-gate/bin/secret-gate`
   - If missing: run `~/.claude/skills/secret-gate/scripts/setup.sh --server <url>`
   - If the setup script is also missing, download the binary directly:
     ```bash
     mkdir -p ~/.config/secret-gate/bin
     ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
     curl -sL -o ~/.config/secret-gate/bin/secret-gate "<server_url>/client/$ARCH"
     chmod +x ~/.config/secret-gate/bin/secret-gate
     ```

Store the resolved values for the session:
```bash
SG_SERVER="<resolved_url>"
SG_CLIENT="$HOME/.config/secret-gate/bin/secret-gate"
```

## When to Use

Activate this skill when you:
- Need an SSH key to push, pull, or connect to a remote server
- Need an API token, password, or credential for an external service
- Encounter a 401/403 error suggesting missing authentication
- Are asked to deploy, provision, or interact with infrastructure requiring secrets
- See config files or environment variables referencing credentials you don't have
- Need to read a private key, certificate, or token file that doesn't exist locally

## Caching

The secret-gate client includes a background daemon that caches approved secrets in memory. This means:

- **First request** for a secret triggers Telegram approval as usual
- **Subsequent requests** for the same secret return instantly from cache (no re-approval needed)
- Cache TTL defaults to 1 hour (configurable in `~/.config/secret-gate/config.json` via `cache_ttl`)
- The daemon starts automatically on first use and exits when idle
- Use `--no-cache` to bypass the cache for a specific request

## Workflow

### Step 1: Search for the secret

Find the right item name. Use a short, descriptive query:

```bash
$SG_CLIENT --server "$SG_SERVER" --search "<query>" --format json
```

If multiple results are ambiguous, show the user the top matches and ask which one they need.

### Step 2: Inspect fields

Check what fields the item has (no approval needed, no values exposed):

```bash
$SG_CLIENT --server "$SG_SERVER" --secret "<item_name>" --fields --format json
```

Determine which field(s) you need for the task (e.g., `private_key` for SSH, `password` for API tokens).

### Step 3: Request the secret

Submit the approval request. Always include a clear reason:

```bash
$SG_CLIENT --server "$SG_SERVER" --secret "<item_name>" --field "<field_name>" --reason "<what you are doing and why>" --format json
```

This will:
- Check the daemon cache first — if cached, return immediately
- If not cached: send a Telegram notification with Approve/Deny buttons
- Poll for approval (5-second intervals)
- On approval: return the secret, cache it, and add SSH keys to ssh-agent automatically

**While waiting for approval, communicate status to the user:**
- Immediately: "Waiting for Telegram approval for `<item_name>`..."
- Every 30 seconds: "Still waiting for approval... (N minutes elapsed)"
- At 14 minutes: "Approval request expiring soon"
- On denial: "Request was denied. I'll proceed without this secret."
- On timeout: "Request expired. Would you like me to submit a new one?"

### Step 4: Use the secret

Apply the secret to the task at hand. Common patterns:

**SSH key:**
SSH keys are automatically added to ssh-agent when retrieved. Just use SSH directly:
```bash
# The key is already in ssh-agent — no temp file needed
ssh user@host "<command>"
git push origin main
```

If ssh-agent is not available, fall back to a temp file:
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "<private_key_value>" > ~/.ssh/temp_key && chmod 600 ~/.ssh/temp_key
ssh -i ~/.ssh/temp_key user@host "<command>"
rm -f ~/.ssh/temp_key
```

**Environment variable:**
```bash
export API_TOKEN="<value>"
# Run the command that needs it
some-command --token "$API_TOKEN"
```

**Config file:**
```bash
# Write only the needed credential to the config
```

## Security Rules

**You MUST follow these rules. No exceptions.**

1. **Never display secret values** — do not echo, print, log, or include secret values in any output shown to the user
2. **Never persist secrets** — secrets are cached in daemon memory only, never written to disk permanently
3. **Never commit secrets** — check `git diff` before committing to ensure no secrets are staged
4. **Always provide a reason** — the `--reason` flag must describe what you're doing in human-readable terms so the Telegram notification is meaningful
5. **Minimal scope** — request only the specific field(s) you need, not the entire item
6. **Report usage** — after using a secret, tell the user: "Used `<item_name>/<field>` from 1Password for `<purpose>`"
7. **Prefer ssh-agent** — for SSH keys, rely on the automatic ssh-agent integration rather than temp files

## Error Handling

| Error | Action |
|-------|--------|
| Server unreachable | Check URL, ask user if server is running |
| Binary not found | Run setup script or download directly |
| No search results | Try broader query, ask user for exact name |
| Request denied | Inform user, ask how to proceed without the secret |
| Request expired | Ask if user wants to retry |
| Config missing | Run first-time setup flow |
| Daemon won't start | Use `--no-cache` to proceed without caching |

## Quick Reference

```bash
# Search for secrets
$SG_CLIENT --server "$SG_SERVER" --search "ssh" --format json

# Inspect fields (no approval)
$SG_CLIENT --server "$SG_SERVER" --secret "my-key" --fields --format json

# Request a secret (triggers approval, or returns from cache)
$SG_CLIENT --server "$SG_SERVER" --secret "my-key" --field "private_key" --reason "SSH deploy"

# Request with specific vault
$SG_CLIENT --server "$SG_SERVER" --secret "my-key" --vault "Infrastructure" --reason "deploy"

# Bypass cache for a specific request
$SG_CLIENT --server "$SG_SERVER" --secret "my-key" --field "password" --reason "rotate" --no-cache

# Daemon management
$SG_CLIENT daemon status     # Check daemon status and cache entries
$SG_CLIENT daemon flush      # Clear all cached secrets
$SG_CLIENT daemon stop       # Stop the daemon
```
