package clientconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Point to a nonexistent dir so no config file is found
	t.Setenv("HOME", t.TempDir())
	cfg := Load()

	if cfg.CacheTTL != 1*time.Hour {
		t.Errorf("CacheTTL = %v, want 1h", cfg.CacheTTL)
	}
	if cfg.DaemonIdleTimeout != 5*time.Minute {
		t.Errorf("DaemonIdleTimeout = %v, want 5m", cfg.DaemonIdleTimeout)
	}
	if !cfg.SSHAgentIntegration {
		t.Error("SSHAgentIntegration should default to true")
	}
	if cfg.ServerURL != "" {
		t.Errorf("ServerURL = %q, want empty", cfg.ServerURL)
	}
}

func TestLoadFromFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".config", "secret-gate")
	os.MkdirAll(configDir, 0755)

	content := `{
		"server_url": "https://proxy.example.com",
		"cache_ttl": "30m",
		"daemon_idle_timeout": "10m",
		"ssh_agent_integration": false
	}`
	os.WriteFile(filepath.Join(configDir, "config.json"), []byte(content), 0644)

	cfg := Load()

	if cfg.ServerURL != "https://proxy.example.com" {
		t.Errorf("ServerURL = %q, want https://proxy.example.com", cfg.ServerURL)
	}
	if cfg.CacheTTL != 30*time.Minute {
		t.Errorf("CacheTTL = %v, want 30m", cfg.CacheTTL)
	}
	if cfg.DaemonIdleTimeout != 10*time.Minute {
		t.Errorf("DaemonIdleTimeout = %v, want 10m", cfg.DaemonIdleTimeout)
	}
	if cfg.SSHAgentIntegration {
		t.Error("SSHAgentIntegration should be false")
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SECRET_GATE_URL", "https://env.example.com")

	cfg := Load()
	if cfg.ServerURL != "https://env.example.com" {
		t.Errorf("ServerURL = %q, want https://env.example.com", cfg.ServerURL)
	}
}
