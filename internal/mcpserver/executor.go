package mcpserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// execCommand runs a shell command with additional environment variables injected.
// It uses "sh -c" to execute the command, inherits the current process environment,
// and adds the provided env vars on top. stdout and stderr are captured separately.
func execCommand(ctx context.Context, command string, envVars map[string]string, workingDir string, timeout time.Duration) (*ExecResult, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	// Inherit current environment
	cmd.Env = os.Environ()

	// Add secret env vars (these override any existing ones with the same name)
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	if workingDir != "" {
		cmd.Dir = workingDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = result.Stderr + "\ncommand timed out after " + timeout.String()
			return result, nil
		} else {
			return nil, fmt.Errorf("failed to run command: %w", err)
		}
	}

	return result, nil
}
