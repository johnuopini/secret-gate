package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func IsSSHPrivateKey(value string) bool {
	if value == "" {
		return false
	}
	return strings.HasPrefix(value, "-----BEGIN") &&
		strings.Contains(value, "PRIVATE KEY-----")
}

func FindSSHKeyField(fields map[string]string) (string, string, bool) {
	for name, value := range fields {
		if IsSSHPrivateKey(value) {
			return name, value, true
		}
	}
	return "", "", false
}

func AddToSSHAgent(keyValue string, ttl time.Duration) error {
	tmpFile, err := os.CreateTemp("", "op-ssh-key-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := os.Chmod(tmpPath, 0600); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := tmpFile.WriteString(keyValue); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing key to temp file: %w", err)
	}
	if !strings.HasSuffix(keyValue, "\n") {
		tmpFile.WriteString("\n")
	}
	tmpFile.Close()

	ttlSeconds := int(ttl.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}

	cmd := exec.Command("ssh-add", "-t", fmt.Sprintf("%d", ttlSeconds), tmpPath)
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-add failed: %w: %s", err, string(output))
	}

	return nil
}
