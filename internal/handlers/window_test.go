package handlers_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/gatetest"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/models"
)

// askFromWindowClient submits a request the way a client that can hold an
// approval window does: it says so, and presents the window token it holds.
func askFromWindowClient(t *testing.T, gate *gatetest.Gate, machine, secret, windowToken string) (int, handlers.RequestResponse) {
	t.Helper()

	return ask(t, gate, handlers.BatchRequestPayload{
		SecretName:   secret,
		Vault:        gatetest.Vault,
		Machine:      machine,
		Reason:       "test",
		Session:      true,
		SessionToken: windowToken,
	})
}

// openWindow has devvm ask for a secret, taps the window button, and returns
// the window token the client is handed with the secret.
func openWindow(t *testing.T, gate *gatetest.Gate) string {
	t.Helper()

	_, reply := askFromWindowClient(t, gate, "devvm", "llm-proxy", "")
	gate.Tap("session:" + onlyPromptID(t, gate))

	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK || secret.Session == nil {
		t.Fatalf("GET /secret = %d with window %v, want 200 with a window", code, secret.Session)
	}
	return secret.Session.Token
}

func TestRequest_OffersAWindowOnlyToAClientThatCanHoldOne(t *testing.T) {
	cases := map[string]struct {
		payload handlers.BatchRequestPayload
		want    time.Duration
	}{
		"client holds windows":      {handlers.BatchRequestPayload{SecretName: "db", Machine: "devvm", Session: true}, 8 * time.Hour},
		"client does not say so":    {handlers.BatchRequestPayload{SecretName: "db", Machine: "devvm"}, 0},
		"client without a hostname": {handlers.BatchRequestPayload{SecretName: "db", Session: true}, 0},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gate := gatetest.Start(t, vault)

			ask(t, gate, tc.payload)

			prompts := gate.Notifier.Prompts()
			if len(prompts) != 1 {
				t.Fatalf("approver was asked %d times, want 1", len(prompts))
			}
			if prompts[0].SessionTTL != tc.want {
				t.Errorf("window on offer = %v, want %v", prompts[0].SessionTTL, tc.want)
			}
		})
	}
}

func TestRequest_WindowsSwitchedOff_OffersNone(t *testing.T) {
	gate := gatetest.Start(t, vault, func(cfg *config.Config) { cfg.SessionTTL = 0 })

	askFromWindowClient(t, gate, "devvm", "db", "")

	if got := gate.Notifier.Prompts()[0].SessionTTL; got != 0 {
		t.Errorf("window on offer = %v, want none", got)
	}
}

func TestWindowTap_HandsTheClientAWindowToken(t *testing.T) {
	gate := gatetest.Start(t, vault)
	_, reply := askFromWindowClient(t, gate, "devvm", "llm-proxy", "")

	answer := gate.Tap("session:" + onlyPromptID(t, gate))

	if answer != "Approved, window open" {
		t.Errorf("answer = %q, want Approved, window open", answer)
	}
	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK || secret.Secret["password"] != "s3cret" {
		t.Fatalf("GET /secret = %d with password %q, want 200 with the item's password", code, secret.Secret["password"])
	}
	if secret.Session == nil {
		t.Fatal("secret reply carries no window")
	}
	if len(secret.Session.Token) != 64 {
		t.Errorf("window token is %d characters, want 64", len(secret.Session.Token))
	}
	expires, err := time.Parse(time.RFC3339, secret.Session.ExpiresAt)
	if err != nil {
		t.Fatalf("window expiry %q is not RFC 3339: %v", secret.Session.ExpiresAt, err)
	}
	if left := time.Until(expires); left < 7*time.Hour+59*time.Minute || left > 8*time.Hour {
		t.Errorf("window closes in %v, want 8h", left)
	}
	approved := gate.Notifier.Approved()
	if len(approved) != 1 || approved[0].SessionID == "" {
		t.Errorf("approved message does not show the window: %+v", approved)
	}
}

func TestWindowTap_BatchRequest_AlsoHandsOutTheToken(t *testing.T) {
	gate := gatetest.Start(t, vault)
	_, reply := ask(t, gate, handlers.BatchRequestPayload{
		Secrets: []models.SecretRequest{{SecretName: "llm-proxy", Vault: gatetest.Vault, Fields: []string{"password"}}},
		Machine: "devvm",
		Session: true,
	})

	gate.Tap("session:" + onlyPromptID(t, gate))

	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK || secret.Secrets["llm-proxy"]["password"] != "s3cret" {
		t.Fatalf("GET /secret = %d with %v, want 200 with the requested field", code, secret.Secrets)
	}
	if secret.Session == nil || secret.Session.Token == "" {
		t.Error("batch secret reply carries no window token")
	}
}

func TestWindowTap_WhenTheApproverCannotBeShownTheEndButton_ApprovesOnlyThatRequest(t *testing.T) {
	gate := gatetest.Start(t, vault)
	_, reply := askFromWindowClient(t, gate, "devvm", "llm-proxy", "")
	gate.Notifier.FailEdits()

	answer := gate.Tap("session:" + onlyPromptID(t, gate))

	if answer != "Approved this request only. No window: this message could not be updated." {
		t.Errorf("answer = %q, want one saying no window was opened", answer)
	}
	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK || secret.Secret["password"] != "s3cret" {
		t.Fatalf("GET /secret = %d with password %q, want 200 with the item's password", code, secret.Secret["password"])
	}
	if secret.Session != nil {
		t.Error("a window was opened that the approver has no button to end")
	}
}

func TestApproveTap_OnARequestThatOffersAWindow_OpensNone(t *testing.T) {
	gate := gatetest.Start(t, vault)
	_, reply := askFromWindowClient(t, gate, "devvm", "llm-proxy", "")

	gate.Tap("approve:" + onlyPromptID(t, gate))

	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK {
		t.Fatalf("GET /secret = %d, want 200", code)
	}
	if secret.Session != nil {
		t.Error("a plain approval opened a window")
	}
}

func TestWindowTap_OnARequestThatOfferedNone_OpensNothing(t *testing.T) {
	gate := gatetest.Start(t, vault)
	reply := askFor(t, gate, "llm-proxy")

	answer := gate.Tap("session:" + onlyPromptID(t, gate))

	if answer != "Unknown action" {
		t.Errorf("answer = %q, want Unknown action", answer)
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
}

func TestTap_OnAnExpiredRequest_ApprovesNothing(t *testing.T) {
	for _, action := range []string{"approve", "session", "deny"} {
		t.Run(action, func(t *testing.T) {
			gate := gatetest.Start(t, vault, func(cfg *config.Config) { cfg.RequestTTL = time.Millisecond })
			_, reply := askFromWindowClient(t, gate, "devvm", "llm-proxy", "")
			time.Sleep(10 * time.Millisecond)

			answer := gate.Tap(action + ":" + onlyPromptID(t, gate))

			if answer != "Request expired" {
				t.Errorf("answer = %q, want Request expired", answer)
			}
			if got := statusOf(t, gate, reply.Token); got != "expired" {
				t.Errorf("status = %q, want expired", got)
			}
			if n := len(gate.Notifier.Approved()); n != 0 {
				t.Errorf("message rewritten as approved %d times, want 0", n)
			}
		})
	}
}

func TestRequest_UnderAnOpenWindow_IsReleasedWithoutAsking(t *testing.T) {
	gate := gatetest.Start(t, vault)
	windowToken := openWindow(t, gate)

	code, reply := askFromWindowClient(t, gate, "devvm", "db", windowToken)

	if code != http.StatusAccepted {
		t.Fatalf("POST /request = %d, want %d", code, http.StatusAccepted)
	}
	if reply.SessionInvalid {
		t.Error("gate called a live window token invalid")
	}
	if got := statusOf(t, gate, reply.Token); got != "approved" {
		t.Fatalf("status = %q, want approved", got)
	}
	if n := len(gate.Notifier.Prompts()); n != 1 {
		t.Errorf("approver was asked %d times, want only the one that opened the window", n)
	}
	releases := gate.Notifier.Releases()
	if len(releases) != 1 {
		t.Fatalf("approver was told of %d releases, want 1", len(releases))
	}
	if releases[0].SecretName != "db" || releases[0].RequesterMachine != "devvm" || releases[0].SessionID == "" {
		t.Errorf("release notice = %+v, want db from devvm with its window", releases[0])
	}

	secretCode, secret := retrieve(t, gate, reply.Token)
	if secretCode != http.StatusOK || secret.Secret["password"] != "db-pass" {
		t.Fatalf("GET /secret = %d with password %q, want 200 with the item's password", secretCode, secret.Secret["password"])
	}
	if secret.Session != nil {
		t.Error("a release under a window handed out another window token")
	}
}

func TestRequest_WithAWindowTokenThatDoesNotCoverIt_AsksAgain(t *testing.T) {
	cases := map[string]struct {
		machine string
		token   func(live string) string
	}{
		"another machine presents the token": {"laptop", func(live string) string { return live }},
		"token the gate never issued":        {"devvm", func(string) string { return "not-a-window-token" }},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gate := gatetest.Start(t, vault)
			live := openWindow(t, gate)

			code, reply := askFromWindowClient(t, gate, tc.machine, "db", tc.token(live))

			if code != http.StatusAccepted {
				t.Fatalf("POST /request = %d, want %d", code, http.StatusAccepted)
			}
			if !reply.SessionInvalid {
				t.Error("gate did not tell the client its window token is no good")
			}
			if got := statusOf(t, gate, reply.Token); got != "pending" {
				t.Errorf("status = %q, want pending", got)
			}
			if n := len(gate.Notifier.Prompts()); n != 2 {
				t.Errorf("approver was asked %d times, want 2", n)
			}
			if n := len(gate.Notifier.Releases()); n != 0 {
				t.Errorf("approver was told of %d releases, want 0", n)
			}
		})
	}
}

func TestRequest_AfterTheWindowRanOut_AsksAgain(t *testing.T) {
	gate := gatetest.Start(t, vault, func(cfg *config.Config) { cfg.SessionTTL = time.Millisecond })
	windowToken := openWindow(t, gate)
	time.Sleep(10 * time.Millisecond)

	_, reply := askFromWindowClient(t, gate, "devvm", "db", windowToken)

	if !reply.SessionInvalid {
		t.Error("gate did not tell the client its window ran out")
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
}

func TestRequest_UnderAWindow_WhenTheApproverCannotBeTold_IsRefused(t *testing.T) {
	gate := gatetest.Start(t, vault)
	windowToken := openWindow(t, gate)
	gate.Notifier.FailReleases()

	code, reply := askFromWindowClient(t, gate, "devvm", "db", windowToken)

	if code != http.StatusServiceUnavailable {
		t.Errorf("POST /request = %d, want %d", code, http.StatusServiceUnavailable)
	}
	if reply.Token != "" {
		t.Error("gate handed out a request token for a release it could not report")
	}
}

func TestRequest_UnderAWindowEndedWhileTheApproverIsTold_AsksInstead(t *testing.T) {
	gate := gatetest.Start(t, vault)
	windowToken := openWindow(t, gate)
	windowID := gate.Notifier.Approved()[0].SessionID
	gate.Notifier.WhileReleaseIsSent(func() { gate.Tap("endsession:" + windowID) })

	code, reply := askFromWindowClient(t, gate, "devvm", "db", windowToken)

	if code != http.StatusAccepted {
		t.Fatalf("POST /request = %d, want %d", code, http.StatusAccepted)
	}
	if !reply.SessionInvalid {
		t.Error("gate did not tell the client its window was ended")
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
	if n := len(gate.Notifier.Prompts()); n != 2 {
		t.Errorf("approver was asked %d times, want again for the request the ended window no longer covers", n)
	}
}

func TestEndWindowTap_MakesTheNextRequestAskAgain(t *testing.T) {
	gate := gatetest.Start(t, vault)
	windowToken := openWindow(t, gate)
	windowID := gate.Notifier.Approved()[0].SessionID

	answer := gate.Tap("endsession:" + windowID)

	if answer != "Approval window ended" {
		t.Errorf("answer = %q, want Approval window ended", answer)
	}
	ended := gate.Notifier.Ended()
	if len(ended) != 1 || ended[0] != "devvm" {
		t.Errorf("approver was told windows ended for %v, want [devvm]", ended)
	}

	_, reply := askFromWindowClient(t, gate, "devvm", "db", windowToken)
	if !reply.SessionInvalid {
		t.Error("gate still honours the token of an ended window")
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
}

func TestEndWindowTap_OnAWindowAlreadyEnded_SaysSo(t *testing.T) {
	gate := gatetest.Start(t, vault)
	openWindow(t, gate)
	windowID := gate.Notifier.Approved()[0].SessionID
	gate.Tap("endsession:" + windowID)

	answer := gate.Tap("endsession:" + windowID)

	if answer != "Approval window already ended" {
		t.Errorf("answer = %q, want Approval window already ended", answer)
	}
	if n := len(gate.Notifier.Ended()); n != 1 {
		t.Errorf("approver was told of %d endings, want 1", n)
	}
}
