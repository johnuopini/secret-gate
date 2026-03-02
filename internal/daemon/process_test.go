package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := SocketPath()
	expected := filepath.Join(dir, "secret-gate.sock")
	if path != expected {
		t.Errorf("SocketPath() = %q, want %q", path, expected)
	}
}

func TestSocketPathFallback(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := SocketPath()
	uid := os.Getuid()
	expected := filepath.Join(os.TempDir(), "secret-gate-"+itoa(uid)+".sock")
	if path != expected {
		t.Errorf("SocketPath() = %q, want %q", path, expected)
	}
}

func TestPIDFilePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := PIDFilePath()
	expected := filepath.Join(dir, "secret-gate.pid")
	if path != expected {
		t.Errorf("PIDFilePath() = %q, want %q", path, expected)
	}
}

func TestWriteAndReadPIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "test.pid")

	err := WritePIDFile(pidFile)
	if err != nil {
		t.Fatalf("WritePIDFile: %v", err)
	}

	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		t.Fatalf("ReadPIDFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}

	os.Remove(pidFile)

	_, err = ReadPIDFile(pidFile)
	if err == nil {
		t.Error("expected error reading nonexistent PID file")
	}
}
