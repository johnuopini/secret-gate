package telegram

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

const testToken = "123456:TEST-bot-token"

// unreachableClient returns a client whose API endpoint refuses connections,
// with the bot token in the URL the same way the real endpoint carries it.
func unreachableClient(t *testing.T) *Client {
	t.Helper()

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	c := New(testToken, 42)
	c.baseURL = srv.URL + "/bot" + testToken
	return c
}

func TestMessages_ShowEveryRequestValueExactlyAsSent(t *testing.T) {
	c, calls := recordingAPI(t)
	// Every value comes from the requester. Each one tries to close the code
	// span or tag it sits in and add markup of its own.
	req := testRequest()
	req.SecretName = "db`</code><b>prod</b>"
	req.Vault = "Home_Lab"
	req.RequesterMachine = "dev_vm`*x*"
	req.RequesterIP = "10.0.0.7`, <i>1.2.3.4</i>"
	req.Reason = "fix [bug](http://x) & <deploy>"
	req.SessionID = "fedcba9876543210fedcba9876543210"
	req.SessionExpiresAt = time.Now().Add(8 * time.Hour)

	c.SendApprovalRequest(req, "")
	c.SendSessionRelease(req)
	c.UpdateMessageApproved(77, req, "fr_anz")
	c.UpdateMessageDenied(77, req, "fr_anz")
	c.SendSessionEnded(req.RequesterMachine, "@fr_anz", 0)

	code := func(s string) string { return "<code>" + html.EscapeString(s) + "</code>" }
	request := []string{code(req.SecretName), code(req.Vault), code(req.RequesterMachine), code(req.RequesterIP), html.EscapeString(req.Reason)}
	answered := []string{code(req.SecretName), code(req.Vault), code(req.RequesterMachine), "@fr_anz"}
	want := [][]string{request, request, answered, answered, {code(req.RequesterMachine), "@fr_anz"}}

	if len(*calls) != len(want) {
		t.Fatalf("sent %d messages, want %d", len(*calls), len(want))
	}
	for i, call := range *calls {
		if call.Body["parse_mode"] != "HTML" {
			t.Errorf("%s #%d parse_mode = %v, want HTML", call.Method, i, call.Body["parse_mode"])
		}
		text := call.Body["text"].(string)
		for _, w := range want[i] {
			if !strings.Contains(text, w) {
				t.Errorf("%s #%d does not show %q:\n%s", call.Method, i, w, text)
			}
		}
	}
}

func TestTransportErrors_DoNotContainBotToken(t *testing.T) {
	req := &models.ApprovalRequest{ID: "req-1", SecretName: "db", Vault: "HomeLab", ExpiresAt: time.Now()}

	calls := map[string]func(c *Client) error{
		"DeleteWebhook":       func(c *Client) error { return c.DeleteWebhook() },
		"GetUpdates":          func(c *Client) error { _, err := c.GetUpdates(0); return err },
		"AnswerCallbackQuery": func(c *Client) error { return c.AnswerCallbackQuery("cb-1", "ok") },
		"SendApprovalRequest": func(c *Client) error { _, err := c.SendApprovalRequest(req, ""); return err },
		"UpdateMessageApproved": func(c *Client) error {
			return c.UpdateMessageApproved(7, req, "approver")
		},
		"SendSessionRelease": func(c *Client) error { _, err := c.SendSessionRelease(req); return err },
		"SendSessionEnded":   func(c *Client) error { return c.SendSessionEnded("devvm", "approver", 0) },
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call(unreachableClient(t))
			if err == nil {
				t.Fatal("expected a transport error, got nil")
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaks the bot token: %v", err)
			}
		})
	}
}
