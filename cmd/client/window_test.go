package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/gatetest"
)

// runAsClient makes this test binary behave as the client itself, which is how
// the tests run the real command line, daemon included.
const runAsClient = "SECRET_GATE_TEST_RUN_AS_CLIENT"

func TestMain(m *testing.M) {
	if os.Getenv(runAsClient) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

var windowItems = []gatetest.Item{
	{Title: "deploy-key", Fields: map[string]string{"password": "deploy-value"}},
	{Title: "db-admin", Fields: map[string]string{"password": "db-value"}},
	{Title: "registry-token", Fields: map[string]string{"password": "registry-value"}},
}

// startGate runs a gate whose windows are short, so that a daemon a killed
// test run leaves behind does not stay up for hours.
func startGate(t *testing.T) *gatetest.Gate {
	t.Helper()
	return gatetest.Start(t, windowItems, func(cfg *config.Config) {
		cfg.SessionTTL = 2 * time.Minute
	})
}

// machine is one machine's client: its own daemon and its own configuration.
type machine struct {
	t   *testing.T
	env []string
}

func newMachine(t *testing.T) *machine {
	t.Helper()

	// The daemon socket lives here, and a socket path has to stay short.
	runtimeDir, err := os.MkdirTemp("", "sg-")
	if err != nil {
		t.Fatalf("creating runtime dir: %v", err)
	}

	m := &machine{t: t, env: []string{
		runAsClient + "=1",
		"XDG_RUNTIME_DIR=" + runtimeDir,
		"HOME=" + t.TempDir(),
		"PATH=" + os.Getenv("PATH"),
	}}
	t.Cleanup(func() {
		m.run("daemon", "stop")
		os.RemoveAll(runtimeDir)
	})
	return m
}

// run runs the client with args and returns what it printed and whether it
// exited cleanly.
func (m *machine) run(args ...string) (stdout, stderr string, err error) {
	m.t.Helper()

	self, err := os.Executable()
	if err != nil {
		m.t.Fatalf("locating the test binary: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := exec.Command(self, args...)
	cmd.Env = m.env
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// fetch asks gate for the password of secret and returns it.
func (m *machine) fetch(gate *gatetest.Gate, secret string, extra ...string) (password, stderr string) {
	m.t.Helper()

	args := append([]string{
		"--server", gate.URL,
		"--secret", secret,
		"--vault", gatetest.Vault,
		"--field", "password",
		"--reason", "approval window test",
		"--poll-interval", "20ms",
		"--timeout", "5s",
	}, extra...)

	stdout, stderr, err := m.run(args...)
	if err != nil {
		m.t.Fatalf("fetching %s: %v\n%s", secret, err, stderr)
	}
	return strings.TrimSpace(stdout), stderr
}

func TestClient_WindowApproval_ReleasesLaterRequestsWithoutATap(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("session")
	devvm := newMachine(t)

	first, firstLog := devvm.fetch(gate, "deploy-key")
	second, _ := devvm.fetch(gate, "db-admin")

	if first != "deploy-value" || second != "db-value" {
		t.Fatalf("passwords = %q and %q, want deploy-value and db-value", first, second)
	}
	if !strings.Contains(firstLog, "Approval window open until") {
		t.Errorf("client did not say a window opened:\n%s", firstLog)
	}
	if n := len(gate.Notifier.Prompts()); n != 1 {
		t.Errorf("approver was asked %d times, want once", n)
	}
	releases := gate.Notifier.Releases()
	if len(releases) != 1 || releases[0].SecretName != "db-admin" {
		t.Errorf("releases reported to the approver = %+v, want only db-admin", releases)
	}
}

func TestClient_DaemonStatus_ListsTheOpenWindow(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("session")
	devvm := newMachine(t)
	devvm.fetch(gate, "deploy-key")

	status, stderr, err := devvm.run("daemon", "status")

	if err != nil {
		t.Fatalf("daemon status: %v\n%s", err, stderr)
	}
	if !strings.Contains(status, "Window:") || !strings.Contains(status, gate.URL) {
		t.Errorf("status does not list the window for %s:\n%s", gate.URL, status)
	}
}

func TestClient_NoCache_AsksForNoWindow(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("approve")
	devvm := newMachine(t)

	devvm.fetch(gate, "deploy-key", "--no-cache")

	prompts := gate.Notifier.Prompts()
	if len(prompts) != 1 {
		t.Fatalf("approver was asked %d times, want once", len(prompts))
	}
	if prompts[0].SessionTTL != 0 {
		t.Errorf("approver was offered a %s window by a client with nothing to hold it", prompts[0].SessionTTL)
	}
}

func TestClient_NoCache_DoesNotUseTheOpenWindow(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("session")
	devvm := newMachine(t)
	devvm.fetch(gate, "deploy-key")
	gate.TapEveryPrompt("approve")

	devvm.fetch(gate, "db-admin", "--no-cache")

	if n := len(gate.Notifier.Prompts()); n != 2 {
		t.Errorf("approver was asked %d times, want once per request", n)
	}
	if releases := gate.Notifier.Releases(); len(releases) != 0 {
		t.Errorf("gate released %+v under the window", releases)
	}
}

func TestClient_WindowEndedByTheApprover_IsForgotten(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("session")
	devvm := newMachine(t)
	devvm.fetch(gate, "deploy-key")
	devvm.fetch(gate, "db-admin")
	// The approver ends the window from the notice of that release.
	gate.Tap("endsession:" + gate.Notifier.Releases()[0].SessionID)
	gate.TapEveryPrompt("approve")

	password, _ := devvm.fetch(gate, "registry-token")

	if password != "registry-value" {
		t.Fatalf("password = %q, want registry-value", password)
	}
	if n := len(gate.Notifier.Prompts()); n != 2 {
		t.Errorf("approver was asked %d times, want again after ending the window", n)
	}
	status, _, _ := devvm.run("daemon", "status")
	if strings.Contains(status, "Window:") {
		t.Errorf("daemon still lists a window:\n%s", status)
	}
}

func TestClient_DaemonFlush_ForgetsTheWindow(t *testing.T) {
	gate := startGate(t)
	gate.TapEveryPrompt("session")
	devvm := newMachine(t)
	devvm.fetch(gate, "deploy-key")

	flushed, stderr, err := devvm.run("daemon", "flush")

	if err != nil {
		t.Fatalf("daemon flush: %v\n%s", err, stderr)
	}
	if !strings.Contains(flushed, "still open on the gate") {
		t.Errorf("flush does not say the window stays open on the gate:\n%s", flushed)
	}
	status, _, _ := devvm.run("daemon", "status")
	if strings.Contains(status, "Window:") {
		t.Errorf("daemon still lists a window:\n%s", status)
	}
}
