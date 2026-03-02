package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func itoa(i int) string {
	return strconv.Itoa(i)
}

func SocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "secret-gate.sock")
	}
	return filepath.Join(os.TempDir(), "secret-gate-"+itoa(os.Getuid())+".sock")
}

func PIDFilePath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "secret-gate.pid")
	}
	return filepath.Join(os.TempDir(), "secret-gate-"+itoa(os.Getuid())+".pid")
}

func WritePIDFile(path string) error {
	return os.WriteFile(path, []byte(itoa(os.Getpid())), 0600)
}

func ReadPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file content: %w", err)
	}
	return pid, nil
}

func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func EnsureDaemon(selfBinary string, cacheTTLSeconds int) (*Client, error) {
	sockPath := SocketPath()
	client := NewClient(sockPath)

	if client.IsRunning() {
		return client, nil
	}

	pidFile := PIDFilePath()
	if pid, err := ReadPIDFile(pidFile); err == nil {
		if !IsProcessRunning(pid) {
			os.Remove(pidFile)
			os.Remove(sockPath)
		}
	}

	cmd := exec.Command(selfBinary, "daemon", "run",
		"--socket", sockPath,
		"--cache-ttl", itoa(cacheTTLSeconds),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting daemon: %w", err)
	}

	cmd.Process.Release()

	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		if client.IsRunning() {
			return client, nil
		}
	}

	return nil, fmt.Errorf("daemon did not start within 2.5 seconds")
}
