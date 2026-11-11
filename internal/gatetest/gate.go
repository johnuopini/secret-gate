// Package gatetest runs the gate for tests: the real handlers in front of a
// fake 1Password Connect, with a notifier that records what the approver would
// have been shown in Telegram.
package gatetest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/session"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/telegram"
)

// Vault is the name of the one vault the fake Connect serves.
const Vault = "HomeLab"

// Approver is the Telegram username every tap comes from.
const Approver = "approver"

// Item is one 1Password item in the fake vault.
type Item struct {
	Title  string
	Fields map[string]string
}

// Gate is a running gate.
type Gate struct {
	URL      string // base URL of the HTTP API
	Notifier *Notifier

	handler *handlers.Handler
}

// Start runs a gate whose vault holds items. Options adjust its configuration.
func Start(t *testing.T, items []Item, options ...func(*config.Config)) *Gate {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		RequestTTL:     15 * time.Minute,
		SessionTTL:     8 * time.Hour,
		WebhookBaseURL: srv.URL,
	}
	for _, option := range options {
		option(cfg)
	}

	notifier := &Notifier{}
	handler := handlers.New(store.New(), session.NewStore(), fakeConnect(t, items), notifier, cfg)
	handler.Register(mux)

	return &Gate{URL: srv.URL, Notifier: notifier, handler: handler}
}

// Tap presses a button the way the approver would, given the button's callback
// data, and returns the answer Telegram would show them.
func (g *Gate) Tap(data string) string {
	callback := &telegram.CallbackQuery{
		ID:   "callback-1",
		From: telegram.User{Username: Approver},
		Data: data,
	}
	// Telegram sends the message a button sits on along with the tap.
	if _, requestID, ok := strings.Cut(data, ":"); ok {
		if messageID := g.Notifier.promptMessage(requestID); messageID != 0 {
			callback.Message = &telegram.Message{MessageID: messageID}
		}
	}
	g.handler.HandleCallback(callback)
	return g.Notifier.lastAnswer()
}

// TapEveryPrompt makes the approver press button ("approve", "deny" or
// "session") on every approval prompt the moment it is shown, for clients that
// block until they have their answer.
func (g *Gate) TapEveryPrompt(button string) {
	g.Notifier.mu.Lock()
	defer g.Notifier.mu.Unlock()
	g.Notifier.onPrompt = func(requestID string) { g.Tap(button + ":" + requestID) }
}

// Notifier stands in for the Telegram chat and records what was sent to it.
type Notifier struct {
	mu           sync.Mutex
	prompts      []models.ApprovalRequest
	releases     []models.ApprovalRequest
	approved     []models.ApprovalRequest
	denied       []models.ApprovalRequest
	ended        []string
	endedBy      []string
	answers      []string
	failReleases bool
	failEdits    bool
	onPrompt     func(requestID string)
	onRelease    func()
}

// FailReleases makes every later release notice fail to send.
func (n *Notifier) FailReleases() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failReleases = true
}

// FailEdits makes every later rewrite of a message fail, as when Telegram
// refuses the edit.
func (n *Notifier) FailEdits() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failEdits = true
}

// WhileReleaseIsSent runs do while the next release notices are on their way
// to the approver, before the gate hears they arrived.
func (n *Notifier) WhileReleaseIsSent(do func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onRelease = do
}

// Releases returns the requests reported as released under an approval window.
func (n *Notifier) Releases() []models.ApprovalRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]models.ApprovalRequest(nil), n.releases...)
}

// Ended returns the machines whose approval windows were reported as ended.
func (n *Notifier) Ended() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.ended...)
}

// EndedBy returns, for each report in Ended, who the approver was told ended
// the windows.
func (n *Notifier) EndedBy() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.endedBy...)
}

// Prompts returns the approval requests the approver was asked about.
func (n *Notifier) Prompts() []models.ApprovalRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]models.ApprovalRequest(nil), n.prompts...)
}

// Approved returns the requests whose message was rewritten as approved.
func (n *Notifier) Approved() []models.ApprovalRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]models.ApprovalRequest(nil), n.approved...)
}

// Denied returns the requests whose message was rewritten as denied.
func (n *Notifier) Denied() []models.ApprovalRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]models.ApprovalRequest(nil), n.denied...)
}

// promptMessage returns the ID of the message that asked about a request, or
// zero when there is none.
func (n *Notifier) promptMessage(requestID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, prompt := range n.prompts {
		if prompt.ID == requestID {
			return i + 1
		}
	}
	return 0
}

func (n *Notifier) lastAnswer() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.answers) == 0 {
		return ""
	}
	return n.answers[len(n.answers)-1]
}

// SendApprovalRequest implements handlers.Notifier.
func (n *Notifier) SendApprovalRequest(req *models.ApprovalRequest, webhookBaseURL string) (int, error) {
	n.mu.Lock()
	n.prompts = append(n.prompts, *req)
	messageID := len(n.prompts)
	onPrompt := n.onPrompt
	n.mu.Unlock()

	// The tap records its own answer, so it runs with the lock released.
	if onPrompt != nil {
		onPrompt(req.ID)
	}
	return messageID, nil
}

// SendSessionRelease implements handlers.Notifier.
func (n *Notifier) SendSessionRelease(req *models.ApprovalRequest) (int, error) {
	n.mu.Lock()
	if n.failReleases {
		n.mu.Unlock()
		return 0, errors.New("telegram is unreachable")
	}
	n.releases = append(n.releases, *req)
	messageID := len(n.releases)
	onRelease := n.onRelease
	n.mu.Unlock()

	// A tap records its own answer, so it runs with the lock released.
	if onRelease != nil {
		onRelease()
	}
	return messageID, nil
}

// SendSessionEnded implements handlers.Notifier.
func (n *Notifier) SendSessionEnded(machine, endedBy string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ended = append(n.ended, machine)
	n.endedBy = append(n.endedBy, endedBy)
	return nil
}

// UpdateMessageApproved implements handlers.Notifier.
func (n *Notifier) UpdateMessageApproved(messageID int, req *models.ApprovalRequest, approver string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failEdits {
		return errors.New("telegram refused the edit")
	}
	n.approved = append(n.approved, *req)
	return nil
}

// UpdateMessageDenied implements handlers.Notifier.
func (n *Notifier) UpdateMessageDenied(messageID int, req *models.ApprovalRequest, denier string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.denied = append(n.denied, *req)
	return nil
}

// AnswerCallbackQuery implements handlers.Notifier.
func (n *Notifier) AnswerCallbackQuery(callbackID, text string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.answers = append(n.answers, text)
	return nil
}

// fakeConnect serves the vault over the routes 1Password Connect answers.
func fakeConnect(t *testing.T, items []Item) *opconnect.Client {
	t.Helper()

	const vaultID = "vault-1"
	full := make(map[string]opconnect.Item, len(items))
	titles := make([]opconnect.Item, 0, len(items))
	for i, item := range items {
		id := fmt.Sprintf("item-%d", i+1)
		var fields []opconnect.Field
		for label, value := range item.Fields {
			fields = append(fields, opconnect.Field{ID: label, Type: "CONCEALED", Label: label, Value: value})
		}
		full[id] = opconnect.Item{ID: id, Title: item.Title, Fields: fields}
		titles = append(titles, opconnect.Item{ID: id, Title: item.Title})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]opconnect.Vault{{ID: vaultID, Name: Vault}})
	})
	mux.HandleFunc("GET /v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(titles)
	})
	mux.HandleFunc("GET /v1/vaults/"+vaultID+"/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		item, ok := full[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(item)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return opconnect.New(srv.URL, "test-token")
}
