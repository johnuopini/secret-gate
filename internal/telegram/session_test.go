package telegram

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

// sentCall is one request the client made to the Bot API.
type sentCall struct {
	Method string
	Body   map[string]any
}

// recordingAPI answers every Bot API call with success and keeps what was sent.
func recordingAPI(t *testing.T) (*Client, *[]sentCall) {
	t.Helper()

	var calls []sentCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		calls = append(calls, sentCall{Method: r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], Body: body})
		w.Write([]byte(`{"ok":true,"result":{"message_id":77,"chat":{"id":42}}}`))
	}))
	t.Cleanup(srv.Close)

	c := New(testToken, 42)
	c.baseURL = srv.URL + "/bot" + testToken
	return c, &calls
}

// buttonData returns the callback data of every button on a sent message.
func buttonData(t *testing.T, call sentCall) []string {
	t.Helper()

	markup, ok := call.Body["reply_markup"].(map[string]any)
	if !ok {
		return nil
	}
	var data []string
	for _, row := range markup["inline_keyboard"].([]any) {
		for _, button := range row.([]any) {
			data = append(data, button.(map[string]any)["callback_data"].(string))
		}
	}
	return data
}

func testRequest() *models.ApprovalRequest {
	return &models.ApprovalRequest{
		ID:               "0123456789abcdef0123456789abcdef",
		SecretName:       "db",
		Vault:            "HomeLab",
		RequesterMachine: "devvm",
		RequesterIP:      "10.0.0.7",
		Reason:           "deploy",
		ExpiresAt:        time.Now().Add(15 * time.Minute),
	}
}

func TestSendApprovalRequest_OffersTheWindowOnlyWhenTheRequestAllowsIt(t *testing.T) {
	t.Run("offered", func(t *testing.T) {
		c, calls := recordingAPI(t)
		req := testRequest()
		req.SessionTTL = 8 * time.Hour

		if _, err := c.SendApprovalRequest(req, ""); err != nil {
			t.Fatalf("SendApprovalRequest: %v", err)
		}

		got := buttonData(t, (*calls)[0])
		want := []string{"approve:" + req.ID, "deny:" + req.ID, "session:" + req.ID}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("buttons = %v, want %v", got, want)
		}
		if !strings.Contains((*calls)[0].Body["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[1].([]any)[0].(map[string]any)["text"].(string), "8h") {
			t.Error("the window button does not say how long the window lasts")
		}
	})

	t.Run("not offered", func(t *testing.T) {
		c, calls := recordingAPI(t)
		req := testRequest()

		if _, err := c.SendApprovalRequest(req, ""); err != nil {
			t.Fatalf("SendApprovalRequest: %v", err)
		}

		got := buttonData(t, (*calls)[0])
		want := []string{"approve:" + req.ID, "deny:" + req.ID}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("buttons = %v, want %v", got, want)
		}
	})
}

func TestUpdateMessageApproved_WithAWindow_CarriesTheEndButton(t *testing.T) {
	c, calls := recordingAPI(t)
	req := testRequest()
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	if err := c.UpdateMessageApproved(77, req, "franz"); err != nil {
		t.Fatalf("UpdateMessageApproved: %v", err)
	}

	got := buttonData(t, (*calls)[0])
	if len(got) != 1 || got[0] != "endsession:"+req.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	if !strings.Contains((*calls)[0].Body["text"].(string), "Approval window") {
		t.Error("the approved message does not mention the approval window")
	}
}

func TestUpdateMessageApproved_WithoutAWindow_HasNoButtons(t *testing.T) {
	c, calls := recordingAPI(t)

	if err := c.UpdateMessageApproved(77, testRequest(), "franz"); err != nil {
		t.Fatalf("UpdateMessageApproved: %v", err)
	}

	if got := buttonData(t, (*calls)[0]); len(got) != 0 {
		t.Errorf("buttons = %v, want none", got)
	}
}

// testReport is the report of a window opened by testRequest and approved by
// franz, with released requests released so far and recent the latest of them.
func testReport(released int, recent ...models.ApprovalRequest) *models.WindowReport {
	opened := testRequest()
	opened.SessionID = "fedcba9876543210fedcba9876543210"
	opened.SessionExpiresAt = time.Now().Add(8 * time.Hour)
	return &models.WindowReport{
		SessionID: opened.SessionID,
		Machine:   opened.RequesterMachine,
		ExpiresAt: opened.SessionExpiresAt,
		Opened:    opened,
		Approver:  "franz",
		Released:  released,
		Recent:    recent,
	}
}

// release is a request from the window's machine for secret, sent from ip.
func release(secret, ip, reason string) models.ApprovalRequest {
	req := *testRequest()
	req.SecretName = secret
	req.RequesterIP = ip
	req.Reason = reason
	return req
}

func TestUpdateWindowReport_EditsTheMessageWithTheReleases(t *testing.T) {
	c, calls := recordingAPI(t)
	var recent []models.ApprovalRequest
	for _, secret := range []string{"s1", "s2", "s3", "s4", "s5"} {
		recent = append(recent, release(secret, "10.0.0.7", "reason of "+secret))
	}
	report := testReport(7, recent...)

	if err := c.UpdateWindowReport(77, report); err != nil {
		t.Fatalf("UpdateWindowReport: %v", err)
	}

	call := (*calls)[0]
	if call.Method != "editMessageText" || call.Body["message_id"] != float64(77) {
		t.Errorf("sent %s for message %v, want editMessageText for message 77", call.Method, call.Body["message_id"])
	}
	if got := buttonData(t, call); len(got) != 1 || got[0] != "endsession:"+report.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	text := call.Body["text"].(string)
	for _, want := range []string{"Released under this window:</b> 7", "s1", "s5", "reason of s3"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not show %q:\n%s", want, text)
		}
	}
	if lines := strings.Count(text, "\n• "); lines != 5 {
		t.Errorf("report lists %d releases, want 5:\n%s", lines, text)
	}
}

func TestUpdateMessageApproved_WithAWindow_ShowsTheEmptyReport(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(0)

	c.UpdateMessageApproved(77, report.Opened, "franz")
	c.UpdateWindowReport(77, report)

	approved, empty := (*calls)[0].Body["text"].(string), (*calls)[1].Body["text"].(string)
	if approved != empty {
		t.Errorf("the approved message:\n%s\nis not the report of a window with no releases:\n%s", approved, empty)
	}
	if !strings.Contains(approved, "Released under this window:</b> none yet") {
		t.Errorf("the approved message does not say nothing was released yet:\n%s", approved)
	}
}

func TestSendWindowReport_IsSilentAndCarriesTheEndButton(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(1, release("db", "10.0.0.7", "deploy"))

	msgID, err := c.SendWindowReport(report)
	if err != nil {
		t.Fatalf("SendWindowReport: %v", err)
	}

	call := (*calls)[0]
	if msgID != 77 || call.Method != "sendMessage" {
		t.Errorf("sent %s returning message %d, want sendMessage returning 77", call.Method, msgID)
	}
	if call.Body["disable_notification"] != true {
		t.Error("the moved report is not silent")
	}
	if got := buttonData(t, call); len(got) != 1 || got[0] != "endsession:"+report.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	text := call.Body["text"].(string)
	for _, want := range []string{"db", "devvm", "deploy", "could not be updated"} {
		if !strings.Contains(text, want) {
			t.Errorf("moved report does not show %q:\n%s", want, text)
		}
	}
}

func TestUpdateWindowReport_OfAMovedReport_KeepsSayingWhyItMoved(t *testing.T) {
	c, calls := recordingAPI(t)
	moved := testReport(2, release("db", "10.0.0.7", "deploy"))
	moved.Moved = true

	c.UpdateWindowReport(77, testReport(1, release("db", "10.0.0.7", "deploy")))
	c.UpdateWindowReport(78, moved)

	if text := (*calls)[0].Body["text"].(string); strings.Contains(text, "could not be updated") {
		t.Errorf("the report in the approval message says it moved:\n%s", text)
	}
	if text := (*calls)[1].Body["text"].(string); !strings.Contains(text, "could not be updated") {
		t.Errorf("the moved report no longer says why it moved:\n%s", text)
	}
}

func TestWindowReport_LongReasonAndBigBatch_StayShort(t *testing.T) {
	c, calls := recordingAPI(t)

	batch := release("", "10.0.0.7", strings.Repeat("x", 500))
	for i := range 20 {
		batch.Secrets = append(batch.Secrets, models.SecretRequest{SecretName: fmt.Sprintf("alpha%02d", i)})
	}
	report := testReport(5, batch, batch, batch, batch, batch)
	// An opening batch too big to repeat in full.
	for i := range 60 {
		report.Opened.Secrets = append(report.Opened.Secrets, models.SecretRequest{SecretName: strings.Repeat("n", 50) + fmt.Sprint(i)})
	}

	c.UpdateWindowReport(77, report)

	text := (*calls)[0].Body["text"].(string)
	if strings.Contains(text, strings.Repeat("x", 81)) {
		t.Error("a release shows more than 80 characters of its reason")
	}
	if !strings.Contains(text, "alpha04") || strings.Contains(text, "alpha05") || !strings.Contains(text, "+15 more") {
		t.Errorf("a release of 20 secrets does not show the first 5 and +15 more:\n%s", text)
	}
	// Telegram rejects messages over 4096 characters.
	if len(text) > 4096 {
		t.Errorf("report is %d bytes, Telegram allows 4096 characters", len(text))
	}
}

func TestWindowReport_ShowsAnIPOnlyWhenItDiffers(t *testing.T) {
	c, calls := recordingAPI(t)
	report := testReport(2, release("db", "10.0.0.9", "deploy"), release("db", "10.0.0.7", "deploy"))

	c.UpdateWindowReport(77, report)

	text := (*calls)[0].Body["text"].(string)
	if !strings.Contains(text, "10.0.0.9") {
		t.Errorf("a release from another IP does not show it:\n%s", text)
	}
	if strings.Contains(text, "10.0.0.7") {
		t.Errorf("a release from the window's own IP shows it:\n%s", text)
	}
}

func TestSendSessionEnded_NamesTheMachine(t *testing.T) {
	c, calls := recordingAPI(t)

	if err := c.SendSessionEnded("devvm", "franz", 0); err != nil {
		t.Fatalf("SendSessionEnded: %v", err)
	}

	call := (*calls)[0]
	if call.Method != "sendMessage" || !strings.Contains(call.Body["text"].(string), "devvm") {
		t.Errorf("sent %s %v, want a message naming devvm", call.Method, call.Body["text"])
	}
}

func TestSendSessionEnded_SaysWhetherOtherWindowsStayOpen(t *testing.T) {
	cases := map[int]string{
		0: "The next request from this machine asks for approval again.",
		1: "1 other approval window of this machine stays open. The End button of any of them closes them all.",
		2: "2 other approval windows of this machine stay open. The End button of any of them closes them all.",
	}
	for stillOpen, want := range cases {
		c, calls := recordingAPI(t)

		if err := c.SendSessionEnded("devvm", "the gate", stillOpen); err != nil {
			t.Fatalf("SendSessionEnded: %v", err)
		}

		text := (*calls)[0].Body["text"].(string)
		if !strings.HasSuffix(text, want) {
			t.Errorf("with %d windows still open the message ends:\n%s\nwant it to end with %q", stillOpen, text, want)
		}
	}
}

func TestSendSessionEnded_SaysWhoEndedIt(t *testing.T) {
	for _, by := range []string{"@franz", "the gate: the secret could not be fetched"} {
		c, calls := recordingAPI(t)

		if err := c.SendSessionEnded("devvm", by, 0); err != nil {
			t.Fatalf("SendSessionEnded: %v", err)
		}

		text := (*calls)[0].Body["text"].(string)
		if !strings.Contains(text, "<b>Ended by:</b> "+by+"\n") {
			t.Errorf("message does not say the window was ended by %q:\n%s", by, text)
		}
	}
}

func TestButtonData_FitsTelegramsLimit(t *testing.T) {
	c, calls := recordingAPI(t)
	req := testRequest()
	req.SessionTTL = 8 * time.Hour
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	c.SendApprovalRequest(req, "")
	c.SendWindowReport(testReport(0))

	// Telegram rejects callback_data longer than 64 bytes.
	for _, call := range *calls {
		for _, data := range buttonData(t, call) {
			if len(data) > 64 {
				t.Errorf("callback data %q is %d bytes, limit is 64", data, len(data))
			}
		}
	}
}

func TestWindowLabel(t *testing.T) {
	cases := map[time.Duration]string{
		8 * time.Hour:    "8h",
		30 * time.Minute: "30m",
		90 * time.Minute: "1h30m",
		45 * time.Second: "45s",
	}
	for ttl, want := range cases {
		if got := windowLabel(ttl); got != want {
			t.Errorf("windowLabel(%s) = %q, want %q", ttl, got, want)
		}
	}
}
