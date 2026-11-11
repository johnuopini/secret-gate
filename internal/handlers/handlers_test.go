package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/gatetest"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/models"
)

var vault = []gatetest.Item{
	{Title: "llm-proxy", Fields: map[string]string{"username": "deploy", "password": "s3cret"}},
	{Title: "db", Fields: map[string]string{"password": "db-pass"}},
}

// secretReply is what GET /secret/{token} answers, in either of its shapes.
type secretReply struct {
	Secret  map[string]string            `json:"secret"`
	Secrets map[string]map[string]string `json:"secrets"`
	Session *handlers.SessionGrant       `json:"session"`
	Error   string                       `json:"error"`
	Message string                       `json:"message"`
}

// ask submits a secret request and returns the HTTP status and the reply.
func ask(t *testing.T, gate *gatetest.Gate, payload handlers.BatchRequestPayload) (int, handlers.RequestResponse) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encoding payload: %v", err)
	}
	resp, err := http.Post(gate.URL+"/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	defer resp.Body.Close()

	var reply handlers.RequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatalf("decoding /request reply: %v", err)
	}
	return resp.StatusCode, reply
}

// askFor submits a request for one whole item and fails the test unless the
// gate accepts it.
func askFor(t *testing.T, gate *gatetest.Gate, secret string) handlers.RequestResponse {
	t.Helper()

	code, reply := ask(t, gate, handlers.BatchRequestPayload{
		SecretName: secret,
		Vault:      gatetest.Vault,
		Machine:    "devvm",
		Reason:     "test",
	})
	if code != http.StatusAccepted {
		t.Fatalf("POST /request = %d, want %d", code, http.StatusAccepted)
	}
	return reply
}

// statusOf returns the status the gate reports for a request token.
func statusOf(t *testing.T, gate *gatetest.Gate, token string) string {
	t.Helper()

	resp, err := http.Get(gate.URL + "/status/" + token)
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer resp.Body.Close()

	var reply handlers.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatalf("decoding /status reply: %v", err)
	}
	return reply.Status
}

// retrieve fetches the secret behind a request token.
func retrieve(t *testing.T, gate *gatetest.Gate, token string) (int, secretReply) {
	t.Helper()

	resp, err := http.Get(gate.URL + "/secret/" + token)
	if err != nil {
		t.Fatalf("GET /secret: %v", err)
	}
	defer resp.Body.Close()

	var reply secretReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatalf("decoding /secret reply: %v", err)
	}
	return resp.StatusCode, reply
}

// onlyPromptID returns the ID of the single request the approver was asked about.
func onlyPromptID(t *testing.T, gate *gatetest.Gate) string {
	t.Helper()

	prompts := gate.Notifier.Prompts()
	if len(prompts) != 1 {
		t.Fatalf("approver was asked %d times, want 1", len(prompts))
	}
	return prompts[0].ID
}

func TestRequest_AsksTheApproverAndWaits(t *testing.T) {
	gate := gatetest.Start(t, vault)

	reply := askFor(t, gate, "llm-proxy")

	prompts := gate.Notifier.Prompts()
	if len(prompts) != 1 {
		t.Fatalf("approver was asked %d times, want 1", len(prompts))
	}
	if prompts[0].SecretName != "llm-proxy" || prompts[0].RequesterMachine != "devvm" {
		t.Errorf("prompt shows %q from %q, want llm-proxy from devvm", prompts[0].SecretName, prompts[0].RequesterMachine)
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
	if code, _ := retrieve(t, gate, reply.Token); code != http.StatusForbidden {
		t.Errorf("GET /secret before approval = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequest_WhenTheApproverCannotBeAsked_IsRefused(t *testing.T) {
	gate := gatetest.Start(t, vault)
	gate.Notifier.FailPrompts()

	code, reply := ask(t, gate, handlers.BatchRequestPayload{
		SecretName: "llm-proxy",
		Vault:      gatetest.Vault,
		Machine:    "devvm",
		Reason:     "test",
	})

	if code != http.StatusServiceUnavailable {
		t.Errorf("POST /request = %d, want %d", code, http.StatusServiceUnavailable)
	}
	if reply.Token != "" {
		t.Error("gate handed out a request token that no one was asked to approve")
	}
}

func TestRequest_WithoutAWebhookBaseURL_AsksNoOne(t *testing.T) {
	gate := gatetest.Start(t, vault, func(cfg *config.Config) { cfg.WebhookBaseURL = "" })

	code, reply := ask(t, gate, handlers.BatchRequestPayload{
		SecretName: "llm-proxy",
		Vault:      gatetest.Vault,
		Machine:    "devvm",
		Reason:     "test",
	})

	if code != http.StatusInternalServerError || !strings.Contains(reply.Message, "WEBHOOK_BASE_URL") {
		t.Errorf("POST /request = %d %q, want 500 naming WEBHOOK_BASE_URL", code, reply.Message)
	}
	if n := len(gate.Notifier.Prompts()); n != 0 {
		t.Errorf("approver was asked %d times about a request the client has no token for, want 0", n)
	}
}

func TestRequest_NamingTheSameSecretTwice_IsRefused(t *testing.T) {
	gate := gatetest.Start(t, vault)

	code, reply := ask(t, gate, handlers.BatchRequestPayload{
		Secrets: []models.SecretRequest{
			{SecretName: "db", Vault: "Private"},
			{SecretName: "db", Vault: "Shared"},
		},
		Machine: "devvm",
		Reason:  "test",
	})

	if code != http.StatusBadRequest {
		t.Errorf("POST /request = %d, want %d", code, http.StatusBadRequest)
	}
	if !strings.Contains(reply.Message, `"db"`) {
		t.Errorf("message = %q, want it to name the secret asked for twice", reply.Message)
	}
	if reply.Token != "" || len(gate.Notifier.Prompts()) != 0 {
		t.Error("the approver was asked about a request whose reply would hold only one of the two")
	}
}

func TestApprove_BatchWhoseNamesFindTheSameItem_ReleasesItOnceWithEveryField(t *testing.T) {
	gate := gatetest.Start(t, vault)
	_, reply := ask(t, gate, handlers.BatchRequestPayload{
		Secrets: []models.SecretRequest{
			{SecretName: "llm-proxy", Fields: []string{"username"}},
			{SecretName: "llm", Fields: []string{"password"}},
		},
		Machine: "devvm",
		Reason:  "test",
	})
	gate.Tap("approve:" + onlyPromptID(t, gate))

	code, secret := retrieve(t, gate, reply.Token)

	if code != http.StatusOK {
		t.Fatalf("GET /secret = %d %q %q, want 200", code, secret.Error, secret.Message)
	}
	got := secret.Secrets["llm-proxy"]
	if len(secret.Secrets) != 1 || got["username"] != "deploy" || got["password"] != "s3cret" {
		t.Errorf("secrets = %v, want llm-proxy with both the username and the password", secret.Secrets)
	}
}

func TestApprove_BatchWhoseNamesFindTwoItemsOfOneTitle_ReleasesNothing(t *testing.T) {
	gate := gatetest.Start(t, []gatetest.Item{
		{Title: "db", Fields: map[string]string{"password": "db-pass"}},
		{Title: "db", Fields: map[string]string{"password": "other-pass"}, Vault: "Other"},
	})
	_, reply := ask(t, gate, handlers.BatchRequestPayload{
		Secrets: []models.SecretRequest{
			{SecretName: "db", Vault: "Other"},
			// Found in HomeLab, which is searched first.
			{SecretName: "DB"},
		},
		Machine: "devvm",
		Reason:  "test",
	})
	gate.Tap("approve:" + onlyPromptID(t, gate))

	code, secret := retrieve(t, gate, reply.Token)

	if code != http.StatusInternalServerError || secret.Error != "secret_fetch_failed" {
		t.Fatalf("GET /secret = %d %q with %v, want 500 secret_fetch_failed", code, secret.Error, secret.Secrets)
	}
	if !strings.Contains(secret.Message, `"Other"`) || !strings.Contains(secret.Message, `"HomeLab"`) {
		t.Errorf("message = %q, want it to name both vaults", secret.Message)
	}
}

func TestApprove_ReleasesTheSecretOnce(t *testing.T) {
	gate := gatetest.Start(t, vault)
	reply := askFor(t, gate, "llm-proxy")

	answer := gate.Tap("approve:" + onlyPromptID(t, gate))

	if answer != "Approved!" {
		t.Errorf("answer = %q, want Approved!", answer)
	}
	if got := statusOf(t, gate, reply.Token); got != "approved" {
		t.Fatalf("status = %q, want approved", got)
	}
	code, secret := retrieve(t, gate, reply.Token)
	if code != http.StatusOK || secret.Secret["password"] != "s3cret" {
		t.Fatalf("GET /secret = %d with password %q, want 200 with the item's password", code, secret.Secret["password"])
	}
	if len(gate.Notifier.Approved()) != 1 {
		t.Errorf("message rewritten as approved %d times, want 1", len(gate.Notifier.Approved()))
	}
	if code, _ := retrieve(t, gate, reply.Token); code != http.StatusNotFound {
		t.Errorf("second GET /secret = %d, want %d", code, http.StatusNotFound)
	}
}

func TestDeny_RefusesTheSecret(t *testing.T) {
	gate := gatetest.Start(t, vault)
	reply := askFor(t, gate, "llm-proxy")

	answer := gate.Tap("deny:" + onlyPromptID(t, gate))

	if answer != "Denied" {
		t.Errorf("answer = %q, want Denied", answer)
	}
	if got := statusOf(t, gate, reply.Token); got != "denied" {
		t.Errorf("status = %q, want denied", got)
	}
	if code, _ := retrieve(t, gate, reply.Token); code != http.StatusForbidden {
		t.Errorf("GET /secret = %d, want %d", code, http.StatusForbidden)
	}
	if len(gate.Notifier.Denied()) != 1 {
		t.Errorf("message rewritten as denied %d times, want 1", len(gate.Notifier.Denied()))
	}
}

func TestTap_OnAnAnsweredRequest_ChangesNothing(t *testing.T) {
	gate := gatetest.Start(t, vault)
	reply := askFor(t, gate, "llm-proxy")
	id := onlyPromptID(t, gate)
	gate.Tap("deny:" + id)

	answer := gate.Tap("approve:" + id)

	if answer != "Request already processed" {
		t.Errorf("answer = %q, want Request already processed", answer)
	}
	if got := statusOf(t, gate, reply.Token); got != "denied" {
		t.Errorf("status = %q, want denied", got)
	}
}

func TestTap_ThatNamesNoRequest_IsAnsweredWithoutEffect(t *testing.T) {
	taps := map[string]string{
		"approve:no-such-request": "Request not found or expired",
		"approve":                 "Invalid callback data",
	}

	for data, want := range taps {
		t.Run(data, func(t *testing.T) {
			gate := gatetest.Start(t, vault)
			reply := askFor(t, gate, "llm-proxy")

			if answer := gate.Tap(data); answer != want {
				t.Errorf("answer = %q, want %q", answer, want)
			}
			if got := statusOf(t, gate, reply.Token); got != "pending" {
				t.Errorf("status = %q, want pending", got)
			}
		})
	}
}

func TestTap_WithAnUnknownAction_LeavesTheRequestPending(t *testing.T) {
	gate := gatetest.Start(t, vault)
	reply := askFor(t, gate, "llm-proxy")

	answer := gate.Tap("release:" + onlyPromptID(t, gate))

	if answer != "Unknown action" {
		t.Errorf("answer = %q, want Unknown action", answer)
	}
	if got := statusOf(t, gate, reply.Token); got != "pending" {
		t.Errorf("status = %q, want pending", got)
	}
}
