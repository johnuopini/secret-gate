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

// Vault is the name of the vault the fake Connect serves items from unless
// they name another.
const Vault = "HomeLab"

// Approver is the Telegram username every tap comes from.
const Approver = "approver"

// Item is one 1Password item in the fake Connect.
type Item struct {
	Title  string
	Fields map[string]string
	Vault  string // empty means Vault
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
		if messageID := g.Notifier.PromptMessage(requestID); messageID != 0 {
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

// WindowReport is one rewrite of an approval window's report, as the approver
// was shown it.
type WindowReport struct {
	MessageID int  // message that shows the report
	New       bool // sent as a new message rather than written over MessageID
	Report    models.WindowReport
}

// firstReportMessage numbers the messages window reports move to, apart from
// the prompts' message IDs.
const firstReportMessage = 1000

// Notifier stands in for the Telegram chat and records what was sent to it.
type Notifier struct {
	mu             sync.Mutex
	prompts        []models.ApprovalRequest
	reports        []WindowReport
	reportMessages int
	deleted        map[int]bool
	approved       []models.ApprovalRequest
	denied         []models.ApprovalRequest
	ended          []string
	endedBy        []string
	endedStillOpen []int
	answers        []string
	failPrompts    bool
	failReleases   bool
	failEdits      bool
	onPrompt       func(requestID string)
	onRelease      func()
}

// FailPrompts makes every later approval prompt fail to send.
func (n *Notifier) FailPrompts() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failPrompts = true
}

// FailReleases makes every later window report fail, both as an edit and as a
// new message.
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

// DeleteMessage deletes a message from the chat, the way the approver can.
// Later edits of it fail.
func (n *Notifier) DeleteMessage(messageID int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.deleted == nil {
		n.deleted = make(map[int]bool)
	}
	n.deleted[messageID] = true
}

// WhileReleaseIsSent runs do while the next reports of a release are on their
// way to the approver, before the gate hears they arrived.
func (n *Notifier) WhileReleaseIsSent(do func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onRelease = do
}

// WindowReports returns every window report the approver was shown, in order.
func (n *Notifier) WindowReports() []WindowReport {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]WindowReport(nil), n.reports...)
}

// Releases returns the requests the approver is shown as released under
// approval windows, oldest first: those the latest report of each window
// lists.
func (n *Notifier) Releases() []models.ApprovalRequest {
	n.mu.Lock()
	defer n.mu.Unlock()

	var windows []string
	latest := make(map[string]models.WindowReport)
	for _, r := range n.reports {
		if _, seen := latest[r.Report.SessionID]; !seen {
			windows = append(windows, r.Report.SessionID)
		}
		latest[r.Report.SessionID] = r.Report
	}
	var releases []models.ApprovalRequest
	for _, window := range windows {
		recent := latest[window].Recent
		for i := len(recent) - 1; i >= 0; i-- {
			releases = append(releases, recent[i])
		}
	}
	return releases
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

// EndedStillOpen returns, for each report in Ended, how many windows of that
// machine the approver was told stay open.
func (n *Notifier) EndedStillOpen() []int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]int(nil), n.endedStillOpen...)
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

// PromptMessage returns the ID of the message that asked about a request, or
// zero when there is none.
func (n *Notifier) PromptMessage(requestID string) int {
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
	if n.failPrompts {
		n.mu.Unlock()
		return 0, errors.New("telegram is unreachable")
	}
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

// UpdateWindowReport implements handlers.Notifier.
func (n *Notifier) UpdateWindowReport(messageID int, r *models.WindowReport) error {
	n.mu.Lock()
	if n.failReleases || n.failEdits || n.deleted[messageID] {
		n.mu.Unlock()
		return errors.New("telegram refused the edit")
	}
	return n.report(messageID, false, r)
}

// SendWindowReport implements handlers.Notifier.
func (n *Notifier) SendWindowReport(r *models.WindowReport) (int, error) {
	n.mu.Lock()
	if n.failReleases {
		n.mu.Unlock()
		return 0, errors.New("telegram is unreachable")
	}
	n.reportMessages++
	messageID := firstReportMessage + n.reportMessages
	return messageID, n.report(messageID, true, r)
}

// report records r as shown on messageID and releases n.mu, which the caller
// holds. A report that lists more releases than the window's last one runs the
// WhileReleaseIsSent hook.
func (n *Notifier) report(messageID int, isNew bool, r *models.WindowReport) error {
	shown := 0
	for _, prev := range n.reports {
		if prev.Report.SessionID == r.SessionID {
			shown = prev.Report.Released
		}
	}
	report := *r
	report.Recent = append([]models.ApprovalRequest(nil), r.Recent...)
	n.reports = append(n.reports, WindowReport{MessageID: messageID, New: isNew, Report: report})
	onRelease := n.onRelease
	n.mu.Unlock()

	// A tap records its own answer, so it runs with the lock released.
	if onRelease != nil && r.Released > shown {
		onRelease()
	}
	return nil
}

// SendSessionEnded implements handlers.Notifier.
func (n *Notifier) SendSessionEnded(machine, endedBy string, stillOpen int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ended = append(n.ended, machine)
	n.endedBy = append(n.endedBy, endedBy)
	n.endedStillOpen = append(n.endedStillOpen, stillOpen)
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

// fakeConnect serves the vaults over the routes 1Password Connect answers.
// Vault is always listed first, the others in the order their first item
// appears.
func fakeConnect(t *testing.T, items []Item) *opconnect.Client {
	t.Helper()

	vaults := []opconnect.Vault{{ID: "vault-1", Name: Vault}}
	vaultIDs := map[string]string{Vault: "vault-1"}
	full := make(map[string]opconnect.Item, len(items))
	titles := make(map[string][]opconnect.Item)
	for i, item := range items {
		vault := item.Vault
		if vault == "" {
			vault = Vault
		}
		vaultID, ok := vaultIDs[vault]
		if !ok {
			vaultID = fmt.Sprintf("vault-%d", len(vaults)+1)
			vaultIDs[vault] = vaultID
			vaults = append(vaults, opconnect.Vault{ID: vaultID, Name: vault})
		}

		id := fmt.Sprintf("item-%d", i+1)
		var fields []opconnect.Field
		for label, value := range item.Fields {
			fields = append(fields, opconnect.Field{ID: label, Type: "CONCEALED", Label: label, Value: value})
		}
		full[vaultID+"/"+id] = opconnect.Item{ID: id, Title: item.Title, Fields: fields}
		titles[vaultID] = append(titles[vaultID], opconnect.Item{ID: id, Title: item.Title})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(vaults)
	})
	mux.HandleFunc("GET /v1/vaults/{vault}/items", func(w http.ResponseWriter, r *http.Request) {
		list := titles[r.PathValue("vault")]
		if list == nil {
			list = []opconnect.Item{}
		}
		json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("GET /v1/vaults/{vault}/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		item, ok := full[r.PathValue("vault")+"/"+r.PathValue("id")]
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
