package telegram

import (
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
		"SendSessionEnded":   func(c *Client) error { return c.SendSessionEnded("devvm", "approver") },
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
