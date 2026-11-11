package telegram

import (
	"encoding/json"
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

func TestSendSessionRelease_IsSilentAndCarriesTheEndButton(t *testing.T) {
	c, calls := recordingAPI(t)
	req := testRequest()
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	msgID, err := c.SendSessionRelease(req)
	if err != nil {
		t.Fatalf("SendSessionRelease: %v", err)
	}

	call := (*calls)[0]
	if msgID != 77 || call.Method != "sendMessage" {
		t.Errorf("sent %s returning message %d, want sendMessage returning 77", call.Method, msgID)
	}
	if call.Body["disable_notification"] != true {
		t.Error("the release notice is not silent")
	}
	if got := buttonData(t, call); len(got) != 1 || got[0] != "endsession:"+req.SessionID {
		t.Errorf("buttons = %v, want the end button for the session", got)
	}
	text := call.Body["text"].(string)
	for _, want := range []string{"db", "devvm", "10.0.0.7", "deploy"} {
		if !strings.Contains(text, want) {
			t.Errorf("release notice does not name %q:\n%s", want, text)
		}
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
		if !strings.Contains(text, "*Ended by:* "+by+"\n") {
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
	c.SendSessionRelease(req)

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
