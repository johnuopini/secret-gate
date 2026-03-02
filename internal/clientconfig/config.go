package clientconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Config holds client-side configuration
type Config struct {
	ServerURL            string        `json:"server_url"`
	CacheTTL             time.Duration `json:"-"`
	CacheTTLRaw          string        `json:"cache_ttl"`
	DaemonIdleTimeout    time.Duration `json:"-"`
	DaemonIdleTimeoutRaw string        `json:"daemon_idle_timeout"`
	SSHAgentIntegration  bool          `json:"ssh_agent_integration"`
}

// Load reads config from ~/.config/secret-gate/config.json
// with env var overrides. Missing values get sensible defaults.
func Load() *Config {
	cfg := &Config{
		CacheTTL:            1 * time.Hour,
		DaemonIdleTimeout:   5 * time.Minute,
		SSHAgentIntegration: true,
	}

	// Try reading config file
	home, _ := os.UserHomeDir()
	if home != "" {
		path := filepath.Join(home, ".config", "secret-gate", "config.json")
		if data, err := os.ReadFile(path); err == nil {
			cfg.parseJSON(data)
		}
	}

	// Env var overrides (SECRET_GATE_URL preferred, OP_APPROVAL_PROXY_URL for backward compat)
	if url := os.Getenv("SECRET_GATE_URL"); url != "" {
		cfg.ServerURL = url
	} else if url := os.Getenv("OP_APPROVAL_PROXY_URL"); url != "" {
		cfg.ServerURL = url
	}

	return cfg
}

func (c *Config) parseJSON(data []byte) {
	// Use a raw struct to handle the boolean default properly
	var raw struct {
		ServerURL           string `json:"server_url"`
		CacheTTL            string `json:"cache_ttl"`
		DaemonIdleTimeout   string `json:"daemon_idle_timeout"`
		SSHAgentIntegration *bool  `json:"ssh_agent_integration"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	if raw.ServerURL != "" {
		c.ServerURL = raw.ServerURL
	}
	if raw.CacheTTL != "" {
		if d, err := time.ParseDuration(raw.CacheTTL); err == nil {
			c.CacheTTL = d
		}
	}
	if raw.DaemonIdleTimeout != "" {
		if d, err := time.ParseDuration(raw.DaemonIdleTimeout); err == nil {
			c.DaemonIdleTimeout = d
		}
	}
	if raw.SSHAgentIntegration != nil {
		c.SSHAgentIntegration = *raw.SSHAgentIntegration
	}
}
