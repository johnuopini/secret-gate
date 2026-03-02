package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server settings
	Port string

	// 1Password Connect settings
	OPConnectHost  string
	OPConnectToken string

	// Telegram settings
	TelegramBotToken string
	TelegramChatID   int64

	// Request settings
	RequestTTL      time.Duration
	CleanupInterval time.Duration

	// Webhook settings
	WebhookBaseURL string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:             getEnvDefault("PORT", "8080"),
		OPConnectHost:    os.Getenv("OP_CONNECT_HOST"),
		OPConnectToken:   readSecretOrEnv("op_connect_token", "OP_CONNECT_TOKEN"),
		TelegramBotToken: readSecretOrEnv("telegram_bot_token", "TELEGRAM_BOT_TOKEN"),
		WebhookBaseURL:   os.Getenv("WEBHOOK_BASE_URL"),
		RequestTTL:       getDurationDefault("REQUEST_TTL", 15*time.Minute),
		CleanupInterval:  getDurationDefault("CLEANUP_INTERVAL", 5*time.Minute),
	}

	// Parse Telegram chat ID
	chatIDStr := readSecretOrEnv("telegram_chat_id", "TELEGRAM_CHAT_ID")
	if chatIDStr != "" {
		chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
		if err != nil {
			return nil, errors.New("invalid TELEGRAM_CHAT_ID: must be an integer")
		}
		cfg.TelegramChatID = chatID
	}

	return cfg, nil
}

// Validate checks that required configuration is present
func (c *Config) Validate() error {
	if c.OPConnectHost == "" {
		return errors.New("OP_CONNECT_HOST is required")
	}
	if c.OPConnectToken == "" {
		return errors.New("OP_CONNECT_TOKEN is required")
	}
	if c.TelegramBotToken == "" {
		return errors.New("TELEGRAM_BOT_TOKEN is required")
	}
	if c.TelegramChatID == 0 {
		return errors.New("TELEGRAM_CHAT_ID is required")
	}
	return nil
}

// getEnvDefault returns the environment variable value or a default
func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getDurationDefault parses a duration from env or returns the default
func getDurationDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

// readSecretOrEnv tries to read from OpenFaaS secret file first, then env var
func readSecretOrEnv(secretName, envName string) string {
	// OpenFaaS mounts secrets at /var/openfaas/secrets/
	secretPath := "/var/openfaas/secrets/" + secretName
	if data, err := os.ReadFile(secretPath); err == nil {
		return string(data)
	}

	return os.Getenv(envName)
}
