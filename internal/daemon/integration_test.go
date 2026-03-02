package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestIntegrationCacheHitMiss(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	_, err := client.Get("ssh-key", "infra")
	if err == nil {
		t.Error("expected cache miss on first request")
	}

	fields := map[string]string{
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-data",
		"public_key":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
	}
	err = client.Store("ssh-key", "infra", fields, 3600)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	cached, err := client.Get("ssh-key", "infra")
	if err != nil {
		t.Fatalf("expected cache hit: %v", err)
	}
	if cached["private_key"] != fields["private_key"] {
		t.Error("cached private_key doesn't match")
	}
}

func TestIntegrationDaemonLifecycle(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	if !client.IsRunning() {
		t.Fatal("daemon should be running")
	}

	status, err := client.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.EntryCount != 0 {
		t.Errorf("initial entry count = %d, want 0", status.EntryCount)
	}

	client.Store("s1", "v1", map[string]string{"a": "1"}, 3600)
	client.Store("s2", "v2", map[string]string{"b": "2"}, 3600)

	status, _ = client.Status()
	if status.EntryCount != 2 {
		t.Errorf("entry count = %d, want 2", status.EntryCount)
	}

	client.Flush()
	status, _ = client.Status()
	if status.EntryCount != 0 {
		t.Errorf("entry count after flush = %d, want 0", status.EntryCount)
	}

	client.StopDaemon()
	time.Sleep(200 * time.Millisecond)

	if client.IsRunning() {
		t.Error("daemon should not be running after stop")
	}
}

func TestIntegrationSSHKeyDetection(t *testing.T) {
	fields := map[string]string{
		"username":    "git",
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU...",
		"public_key":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
	}

	fieldName, value, found := FindSSHKeyField(fields)
	if !found {
		t.Fatal("should detect SSH key")
	}
	if fieldName != "private_key" {
		t.Errorf("field name = %q, want private_key", fieldName)
	}
	if value != fields["private_key"] {
		t.Error("value mismatch")
	}
}

func TestIntegrationConcurrentAccess(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)
	for i := 0; i < 10; i++ {
		name := "secret-" + strconv.Itoa(i)
		client.Store(name, "vault", map[string]string{"val": strconv.Itoa(i)}, 3600)
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			c := NewClient(sockPath)
			name := "secret-" + strconv.Itoa(idx)
			fields, err := c.Get(name, "vault")
			if err != nil {
				t.Errorf("concurrent get %d: %v", idx, err)
				done <- false
				return
			}
			if fields["val"] != strconv.Itoa(idx) {
				t.Errorf("concurrent get %d: val = %q, want %q", idx, fields["val"], strconv.Itoa(idx))
				done <- false
				return
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMockProxyFlow(t *testing.T) {
	approved := false
	mockProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/request":
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{
				"token":      "test-token-123",
				"status_url": "http://" + r.Host + "/status/test-token-123",
				"expires_at": time.Now().Add(15 * time.Minute).Format(time.RFC3339),
				"message":    "submitted",
			})
		case "/status/test-token-123":
			if !approved {
				approved = true
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "pending",
					"message": "waiting",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]string{
					"status":     "approved",
					"message":    "approved",
					"secret_url": "http://" + r.Host + "/secret/test-token-123",
				})
			}
		case "/secret/test-token-123":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{
					"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-key",
					"username":    "deploy",
				},
			})
		}
	}))
	defer mockProxy.Close()

	resp, err := http.Get(mockProxy.URL + "/status/test-token-123")
	if err != nil {
		t.Fatalf("mock proxy request: %v", err)
	}
	defer resp.Body.Close()

	var status map[string]string
	json.NewDecoder(resp.Body).Decode(&status)
	if status["status"] != "pending" {
		t.Errorf("first status = %q, want pending", status["status"])
	}

	resp2, err2 := http.Get(mockProxy.URL + "/status/test-token-123")
	if err2 != nil {
		t.Fatalf("mock proxy second request: %v", err2)
	}
	defer resp2.Body.Close()
	json.NewDecoder(resp2.Body).Decode(&status)
	if status["status"] != "approved" {
		t.Errorf("second status = %q, want approved", status["status"])
	}
}
