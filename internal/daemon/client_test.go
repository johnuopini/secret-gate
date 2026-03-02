package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

func TestClientGetFromDaemon(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	err := client.Store("my-secret", "vault1", map[string]string{"pw": "123"}, 3600)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	fields, err := client.Get("my-secret", "vault1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if fields["pw"] != "123" {
		t.Errorf("pw = %q, want 123", fields["pw"])
	}
}

func TestClientCacheMiss(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	_, err := client.Get("nonexistent", "vault1")
	if err == nil {
		t.Error("expected error on cache miss")
	}
}

func TestClientStatus(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	status, err := client.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.SocketPath != sockPath {
		t.Errorf("socket path = %q, want %q", status.SocketPath, sockPath)
	}
}

func TestClientIsRunning(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")

	client := NewClient(sockPath)
	if client.IsRunning() {
		t.Error("should not be running before server starts")
	}

	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	if !client.IsRunning() {
		t.Error("should be running after server starts")
	}
}

func TestClientFlush(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	client.Store("s1", "v1", map[string]string{"a": "1"}, 3600)

	if err := client.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	_, err := client.Get("s1", "v1")
	if err == nil {
		t.Error("expected cache miss after flush")
	}
}
