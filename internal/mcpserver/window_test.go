package mcpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/gatetest"
)

// windowItems is the vault the approval window tests ask from.
var windowItems = []gatetest.Item{
	{Title: "deploy-key", Fields: map[string]string{"password": "deploy-value"}},
	{Title: "db-admin", Fields: map[string]string{"password": "db-value"}},
}

// requestSecret asks the gate for secret and fails the test unless the answer
// arrives well before the first poll tick, which is when a client that does
// not look at the status straight away would first see it.
func requestSecret(t *testing.T, pc ProxyClient, secret string) *RequestResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := pc.Request(ctx, secret, gatetest.Vault, "approval window test")
	if err != nil {
		t.Fatalf("requesting %s: %v", secret, err)
	}
	return result
}

// recordRequests runs a gate that refuses every request and returns the bodies
// it was sent.
func recordRequests(t *testing.T) (serverURL string, bodies func() []string) {
	t.Helper()

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, string(body))
		mu.Unlock()
		http.Error(w, `{"error":"refused","message":"this gate releases nothing"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestRequest_WindowApproval_IsKeptInTheDaemon(t *testing.T) {
	gate := gatetest.Start(t, windowItems)
	gate.TapEveryPrompt("session")
	dc := newMockDaemonClient(true)
	pc := NewHTTPProxyClient(gate.URL, dc, 3600)

	result := requestSecret(t, pc, "deploy-key")

	if result.Status != "approved" {
		t.Fatalf("status = %q, want approved", result.Status)
	}
	window, ok := dc.windows[gate.URL]
	if !ok || window.token == "" {
		t.Fatalf("daemon holds no window for the gate: %+v", dc.windows)
	}
	if left := time.Until(window.expiresAt); left < 7*time.Hour+59*time.Minute || left > 8*time.Hour {
		t.Errorf("window runs for another %s, want just under 8h", left)
	}
	if !strings.Contains(result.Message, "approval window") {
		t.Errorf("message does not say a window is open: %q", result.Message)
	}
	if strings.Contains(result.Message, window.token) {
		t.Error("message shows the window token")
	}
}

func TestRequest_UnderAnOpenWindow_NeedsNoSecondTap(t *testing.T) {
	gate := gatetest.Start(t, windowItems)
	gate.TapEveryPrompt("session")
	dc := newMockDaemonClient(true)
	pc := NewHTTPProxyClient(gate.URL, dc, 3600)
	requestSecret(t, pc, "deploy-key")

	result := requestSecret(t, pc, "db-admin")

	if result.Status != "approved" {
		t.Fatalf("status = %q, want approved", result.Status)
	}
	if prompts := gate.Notifier.Prompts(); len(prompts) != 1 {
		t.Errorf("approver was asked %d times, want once", len(prompts))
	}
	releases := gate.Notifier.Releases()
	if len(releases) != 1 || releases[0].SecretName != "db-admin" {
		t.Errorf("releases reported to the approver = %+v, want only db-admin", releases)
	}
	if cached, err := dc.Get("db-admin", gatetest.Vault); err != nil || cached["password"] != "db-value" {
		t.Errorf("db-admin was not cached: %v", err)
	}
}

func TestRequest_WindowApproval_WithTheDaemonDown_StartsItToKeepTheWindow(t *testing.T) {
	gate := gatetest.Start(t, windowItems)
	gate.TapEveryPrompt("session")
	dc := newMockDaemonClient(false)
	pc := NewHTTPProxyClient(gate.URL, dc, 3600)

	requestSecret(t, pc, "deploy-key")

	if dc.windows[gate.URL].token == "" {
		t.Errorf("daemon holds no window for the gate: %+v", dc.windows)
	}
}

func TestRequest_WithAWindowTheGateNoLongerHonours_ForgetsIt(t *testing.T) {
	gate := gatetest.Start(t, windowItems)
	gate.TapEveryPrompt("approve")
	dc := newMockDaemonClient(true)
	dc.SetSession(gate.URL, "window-the-gate-forgot", time.Now().Add(time.Hour))
	pc := NewHTTPProxyClient(gate.URL, dc, 3600)

	result := requestSecret(t, pc, "deploy-key")

	if result.Status != "approved" {
		t.Fatalf("status = %q, want approved", result.Status)
	}
	if prompts := gate.Notifier.Prompts(); len(prompts) != 1 {
		t.Errorf("approver was asked %d times, want once", len(prompts))
	}
	if window, held := dc.windows[gate.URL]; held {
		t.Errorf("daemon still holds %+v", window)
	}
}

func TestRequest_NeverShowsOneGatesWindowToAnother(t *testing.T) {
	serverURL, bodies := recordRequests(t)
	dc := newMockDaemonClient(true)
	dc.SetSession("https://other-gate.example", "other-gates-window", time.Now().Add(time.Hour))
	pc := NewHTTPProxyClient(serverURL, dc, 3600)

	if _, err := pc.Request(context.Background(), "deploy-key", gatetest.Vault, "approval window test"); err == nil {
		t.Fatal("request to a gate that refuses everything succeeded")
	}

	sent := bodies()
	if len(sent) != 1 {
		t.Fatalf("gate saw %d requests, want 1", len(sent))
	}
	if strings.Contains(sent[0], "other-gates-window") || strings.Contains(sent[0], "session_token") {
		t.Errorf("request carries a window token: %s", sent[0])
	}
	if !strings.Contains(sent[0], `"session":true`) {
		t.Errorf("request does not ask for a window: %s", sent[0])
	}
}

func TestRequest_WithoutADaemon_AsksForNoWindow(t *testing.T) {
	serverURL, bodies := recordRequests(t)
	pc := NewHTTPProxyClient(serverURL, nil, 3600)

	if _, err := pc.Request(context.Background(), "deploy-key", gatetest.Vault, "approval window test"); err == nil {
		t.Fatal("request to a gate that refuses everything succeeded")
	}

	sent := bodies()
	if len(sent) != 1 {
		t.Fatalf("gate saw %d requests, want 1", len(sent))
	}
	if strings.Contains(sent[0], "session") {
		t.Errorf("request asks for a window nothing could hold: %s", sent[0])
	}
}
