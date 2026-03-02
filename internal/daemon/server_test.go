package daemon

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func sendRequest(t *testing.T, conn net.Conn, req Request) Response {
	t.Helper()
	data, _ := json.Marshal(req)
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write request: %v", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("unmarshal response: %v (raw: %s)", err, string(buf[:n]))
	}
	return resp
}

func TestServerStoreAndGet(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp := sendRequest(t, conn, Request{
		Command:    CmdStore,
		SecretName: "my-secret",
		Vault:      "vault1",
		Fields:     map[string]string{"password": "abc123"},
		TTLSeconds: 3600,
	})
	if !resp.OK {
		t.Fatalf("store failed: %s", resp.Error)
	}

	conn2, _ := net.Dial("unix", sockPath)
	defer conn2.Close()

	resp = sendRequest(t, conn2, Request{
		Command:    CmdGet,
		SecretName: "my-secret",
		Vault:      "vault1",
	})
	if !resp.OK {
		t.Fatalf("get failed: %s", resp.Error)
	}
	if resp.Fields["password"] != "abc123" {
		t.Errorf("password = %q, want abc123", resp.Fields["password"])
	}
}

func TestServerCacheMiss(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	defer conn.Close()

	resp := sendRequest(t, conn, Request{
		Command:    CmdGet,
		SecretName: "nonexistent",
		Vault:      "vault1",
	})
	if resp.OK {
		t.Error("expected cache miss to return ok=false")
	}
}

func TestServerStatus(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	defer conn.Close()

	resp := sendRequest(t, conn, Request{Command: CmdStatus})
	if !resp.OK {
		t.Fatalf("status failed: %s", resp.Error)
	}
	if resp.Status == nil {
		t.Fatal("status response is nil")
	}
	if resp.Status.SocketPath != sockPath {
		t.Errorf("socket path = %q, want %q", resp.Status.SocketPath, sockPath)
	}
}

func TestServerFlush(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	sendRequest(t, conn, Request{
		Command:    CmdStore,
		SecretName: "s1",
		Vault:      "v1",
		Fields:     map[string]string{"a": "1"},
		TTLSeconds: 3600,
	})
	conn.Close()

	conn2, _ := net.Dial("unix", sockPath)
	resp := sendRequest(t, conn2, Request{Command: CmdFlush})
	conn2.Close()

	if !resp.OK {
		t.Fatalf("flush failed: %s", resp.Error)
	}

	conn3, _ := net.Dial("unix", sockPath)
	defer conn3.Close()

	resp = sendRequest(t, conn3, Request{Command: CmdStatus})
	if resp.Status.EntryCount != 0 {
		t.Errorf("entry count after flush = %d, want 0", resp.Status.EntryCount)
	}
}
