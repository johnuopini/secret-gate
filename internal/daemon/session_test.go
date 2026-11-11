package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

const (
	gateA = "https://gate-a.example"
	gateB = "https://gate-b.example"
)

// startDaemon runs a daemon on a socket of its own and returns it with a
// client connected to it.
func startDaemon(t *testing.T) (*Server, *Client) {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, time.Hour)
	go srv.Run()

	client := NewClient(sockPath)
	deadline := time.Now().Add(2 * time.Second)
	for !client.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(srv.Stop)

	return srv, client
}

func TestSession_NoneHeld_ReturnsNothing(t *testing.T) {
	_, client := startDaemon(t)

	window, err := client.Session(gateA)

	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if window != nil {
		t.Errorf("window = %+v, want none", window)
	}
}

func TestSession_HeldWindow_IsReturnedWithItsExpiry(t *testing.T) {
	_, client := startDaemon(t)
	closes := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	if err := client.SetSession(gateA, "window-token", closes); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	window, err := client.Session(gateA)

	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if window == nil {
		t.Fatal("daemon holds no window")
	}
	if window.Token != "window-token" {
		t.Errorf("token = %q, want window-token", window.Token)
	}
	if !window.ExpiresAt.Equal(closes) {
		t.Errorf("window closes at %v, want %v", window.ExpiresAt, closes)
	}
}

func TestSession_IsNotHandedToAnotherGate(t *testing.T) {
	_, client := startDaemon(t)
	client.SetSession(gateA, "window-token", time.Now().Add(time.Hour))

	window, err := client.Session(gateB)

	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if window != nil {
		t.Errorf("gate B was handed gate A's window: %+v", window)
	}
}

func TestSession_PastItsExpiry_IsNotReturned(t *testing.T) {
	srv, client := startDaemon(t)
	client.SetSession(gateA, "window-token", time.Now().Add(-time.Second))

	window, err := client.Session(gateA)

	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if window != nil {
		t.Errorf("daemon returned a window that has closed: %+v", window)
	}
	if srv.busy() {
		t.Error("daemon stays alive for a window that has closed")
	}
}

func TestSetSession_WithoutAToken_IsRefused(t *testing.T) {
	_, client := startDaemon(t)

	err := client.SetSession(gateA, "", time.Now().Add(time.Hour))

	if err == nil {
		t.Error("daemon accepted a window without a token")
	}
}

func TestClearSession_ForgetsOnlyThatGatesWindow(t *testing.T) {
	_, client := startDaemon(t)
	client.SetSession(gateA, "token-a", time.Now().Add(time.Hour))
	client.SetSession(gateB, "token-b", time.Now().Add(time.Hour))

	if err := client.ClearSession(gateA, "token-a"); err != nil {
		t.Fatalf("ClearSession: %v", err)
	}

	if window, _ := client.Session(gateA); window != nil {
		t.Errorf("gate A's window survived: %+v", window)
	}
	if window, _ := client.Session(gateB); window == nil || window.Token != "token-b" {
		t.Errorf("gate B's window = %+v, want it kept", window)
	}
}

// Two client processes share the daemon: one learns its window is no good
// after the other has already stored the window that replaced it.
func TestClearSession_OfAWindowAlreadyReplaced_KeepsTheNewOne(t *testing.T) {
	_, client := startDaemon(t)
	client.SetSession(gateA, "token-new", time.Now().Add(time.Hour))

	if err := client.ClearSession(gateA, "token-old"); err != nil {
		t.Fatalf("ClearSession: %v", err)
	}

	if window, _ := client.Session(gateA); window == nil || window.Token != "token-new" {
		t.Errorf("window = %+v, want the new one kept", window)
	}
}

func TestFlush_ForgetsTheWindow(t *testing.T) {
	_, client := startDaemon(t)
	client.SetSession(gateA, "window-token", time.Now().Add(time.Hour))

	if err := client.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if window, _ := client.Session(gateA); window != nil {
		t.Errorf("window survived a flush: %+v", window)
	}
}

func TestStatus_ShowsWhenTheWindowClosesButNotItsToken(t *testing.T) {
	_, client := startDaemon(t)
	closes := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	client.SetSession(gateA, "window-token", closes)

	status, err := client.Status()

	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(status.Sessions) != 1 {
		t.Fatalf("status lists %d windows, want 1", len(status.Sessions))
	}
	window := status.Sessions[0]
	if window.Server != gateA || !window.ExpiresAt.Equal(closes) {
		t.Errorf("status shows %+v, want gate A closing at %v", window, closes)
	}
	if window.Token != "" {
		t.Error("status gives away the window token")
	}
}

func TestDaemon_HoldingALiveWindow_IsBusy(t *testing.T) {
	srv, client := startDaemon(t)
	if srv.busy() {
		t.Fatal("an empty daemon reports busy")
	}

	client.SetSession(gateA, "window-token", time.Now().Add(time.Hour))

	if !srv.busy() {
		t.Error("daemon would exit as idle while holding a live window")
	}
}

func TestDaemon_HoldingACachedSecret_IsBusy(t *testing.T) {
	srv, client := startDaemon(t)

	client.Store("db", "HomeLab", map[string]string{"password": "x"}, 3600)

	if !srv.busy() {
		t.Error("daemon would exit as idle while holding a cached secret")
	}
}
