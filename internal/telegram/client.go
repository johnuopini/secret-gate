package telegram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
)

// CallbackHandler is called when a callback query is received from polling
type CallbackHandler func(callback *CallbackQuery)

// Client wraps the Telegram Bot API
type Client struct {
	token        string
	chatID       int64
	httpClient   *http.Client
	baseURL      string
	lastUpdateID int64
}

// Message represents a Telegram message
type Message struct {
	MessageID int   `json:"message_id"`
	Chat      Chat  `json:"chat"`
	Date      int64 `json:"date"`
}

// Chat represents a Telegram chat
type Chat struct {
	ID int64 `json:"id"`
}

// InlineKeyboardButton represents an inline keyboard button
type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// InlineKeyboardMarkup represents an inline keyboard
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// SendMessageRequest represents a request to send a message
type SendMessageRequest struct {
	ChatID      int64                 `json:"chat_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`

	DisableNotification bool `json:"disable_notification,omitempty"`
}

// EditMessageTextRequest represents a request to edit a message
type EditMessageTextRequest struct {
	ChatID      int64                 `json:"chat_id"`
	MessageID   int                   `json:"message_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// APIResponse represents a Telegram API response
type APIResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Description string          `json:"description,omitempty"`
	ErrorCode   int             `json:"error_code,omitempty"`
}

// CallbackQuery represents a callback query from inline button press
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data"`
}

// User represents a Telegram user
type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
}

// Update represents an incoming Telegram update
type Update struct {
	UpdateID      int64          `json:"update_id"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// New creates a new Telegram client
func New(token string, chatID int64) *Client {
	return &Client{
		token:   token,
		chatID:  chatID,
		baseURL: "https://api.telegram.org/bot" + token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendApprovalRequest sends an approval request message with approve/deny buttons
func (c *Client) SendApprovalRequest(req *models.ApprovalRequest, webhookBaseURL string) (int, error) {
	text := fmt.Sprintf(
		"🔐 <b>Secret Access Request</b>\n\n"+
			"%s"+
			"<b>Machine:</b> %s\n"+
			"<b>IP:</b> %s\n"+
			"<b>Reason:</b> %s\n"+
			"<b>Expires:</b> %s\n\n"+
			"<b>Request ID:</b> %s",
		describeSecrets(req),
		code(req.RequesterMachine),
		code(req.RequesterIP),
		html.EscapeString(defaultIfEmpty(req.Reason, "Not provided")),
		req.ExpiresAt.Format("15:04:05 MST"),
		code(req.ID),
	)

	keyboard := &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{
				{Text: "✅ Approve", CallbackData: fmt.Sprintf("approve:%s", req.ID)},
				{Text: "❌ Deny", CallbackData: fmt.Sprintf("deny:%s", req.ID)},
			},
		},
	}

	if req.SessionTTL > 0 {
		label := windowLabel(req.SessionTTL)
		text += fmt.Sprintf(
			"\n\n<b>Approve for %s:</b> later requests from %s are released without asking, each one reported here.",
			label, code(req.RequesterMachine))
		keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, []InlineKeyboardButton{
			{Text: "🕗 Approve for " + label, CallbackData: fmt.Sprintf("session:%s", req.ID)},
		})
	}

	return c.sendMessage(SendMessageRequest{
		ChatID:      c.chatID,
		Text:        text,
		ParseMode:   "HTML",
		ReplyMarkup: keyboard,
	})
}

// SendSessionRelease reports a request that was released under an open
// approval window. It is silent, and carries the button that ends the window.
func (c *Client) SendSessionRelease(req *models.ApprovalRequest) (int, error) {
	text := fmt.Sprintf(
		"🔓 <b>Secret Released (approval window)</b>\n\n"+
			"%s"+
			"<b>Machine:</b> %s\n"+
			"<b>IP:</b> %s\n"+
			"<b>Reason:</b> %s\n"+
			"<b>Window ends:</b> %s\n\n"+
			"<b>Request ID:</b> %s",
		describeSecrets(req),
		code(req.RequesterMachine),
		code(req.RequesterIP),
		html.EscapeString(defaultIfEmpty(req.Reason, "Not provided")),
		req.SessionExpiresAt.Format("15:04:05 MST"),
		code(req.ID),
	)

	return c.sendMessage(SendMessageRequest{
		ChatID:              c.chatID,
		Text:                text,
		ParseMode:           "HTML",
		ReplyMarkup:         endSessionKeyboard(req.SessionID),
		DisableNotification: true,
	})
}

// SendSessionEnded reports that approval windows of a machine were ended.
// endedBy is shown as given: "@name" for a person, or the gate and its reason.
// stillOpen is how many other windows of the machine stay open.
func (c *Client) SendSessionEnded(machine, endedBy string, stillOpen int) error {
	text := fmt.Sprintf(
		"🔒 <b>Approval Window Ended</b>\n\n"+
			"<b>Machine:</b> %s\n"+
			"<b>Ended by:</b> %s\n\n"+
			"%s",
		code(machine),
		html.EscapeString(endedBy),
		stillOpenNote(stillOpen),
	)

	_, err := c.sendMessage(SendMessageRequest{
		ChatID:              c.chatID,
		Text:                text,
		ParseMode:           "HTML",
		DisableNotification: true,
	})
	return err
}

// stillOpenNote tells the approver whether the machine still has open windows.
func stillOpenNote(stillOpen int) string {
	switch stillOpen {
	case 0:
		return "The next request from this machine asks for approval again."
	case 1:
		return "1 other approval window of this machine stays open. The End button of any of them closes them all."
	default:
		return fmt.Sprintf("%d other approval windows of this machine stay open. The End button of any of them closes them all.", stillOpen)
	}
}

// UpdateMessageApproved updates a message to show it was approved
func (c *Client) UpdateMessageApproved(messageID int, req *models.ApprovalRequest, approver string) error {
	text := fmt.Sprintf(
		"✅ <b>Secret Access Approved</b>\n\n"+
			"<b>Secret:</b> %s\n"+
			"<b>Vault:</b> %s\n"+
			"<b>Machine:</b> %s\n"+
			"<b>Approved by:</b> @%s\n"+
			"<b>Request ID:</b> %s",
		code(req.SecretName),
		code(req.Vault),
		code(req.RequesterMachine),
		html.EscapeString(approver),
		code(req.ID),
	)

	if req.SessionID == "" {
		return c.editMessage(messageID, text, nil)
	}

	text += fmt.Sprintf(
		"\n\n<b>Approval window:</b> open until %s. Requests from %s are released without asking, each one reported here.",
		req.SessionExpiresAt.Format("15:04:05 MST"),
		code(req.RequesterMachine))

	return c.editMessage(messageID, text, endSessionKeyboard(req.SessionID))
}

// UpdateMessageDenied updates a message to show it was denied
func (c *Client) UpdateMessageDenied(messageID int, req *models.ApprovalRequest, denier string) error {
	text := fmt.Sprintf(
		"❌ <b>Secret Access Denied</b>\n\n"+
			"<b>Secret:</b> %s\n"+
			"<b>Vault:</b> %s\n"+
			"<b>Machine:</b> %s\n"+
			"<b>Denied by:</b> @%s\n"+
			"<b>Request ID:</b> %s",
		code(req.SecretName),
		code(req.Vault),
		code(req.RequesterMachine),
		html.EscapeString(denier),
		code(req.ID),
	)

	return c.editMessage(messageID, text, nil)
}

// AnswerCallbackQuery answers a callback query (removes loading state from button)
func (c *Client) AnswerCallbackQuery(callbackID, text string) error {
	reqBody := map[string]interface{}{
		"callback_query_id": callbackID,
		"text":              text,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/answerCallbackQuery", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending request: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	return nil
}

// GetUpdates fetches new updates from Telegram using long polling
func (c *Client) GetUpdates(timeout int) ([]Update, error) {
	endpoint := fmt.Sprintf("%s/getUpdates?offset=%d&timeout=%d&allowed_updates=[\"callback_query\"]",
		c.baseURL, c.lastUpdateID+1, timeout)

	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching updates: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	var updates []Update
	if err := json.Unmarshal(apiResp.Result, &updates); err != nil {
		return nil, fmt.Errorf("parsing updates: %w", err)
	}

	// Track the last update ID so we don't process it again
	for _, u := range updates {
		if u.UpdateID > c.lastUpdateID {
			c.lastUpdateID = u.UpdateID
		}
	}

	return updates, nil
}

// DeleteWebhook removes any active webhook so getUpdates polling can work
func (c *Client) DeleteWebhook() error {
	resp, err := c.httpClient.Post(c.baseURL+"/deleteWebhook", "application/json", nil)
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	return nil
}

// PollUpdates starts a long-polling loop that calls handler for each callback query
func (c *Client) PollUpdates(handler CallbackHandler) {
	log := logger.New()

	// Delete any active webhook before starting long polling (retry until success)
	for {
		if err := c.DeleteWebhook(); err != nil {
			log.Error("Failed to delete webhook, retrying in 5s", logger.F("error", err.Error()))
			time.Sleep(5 * time.Second)
			continue
		}
		log.Info("Cleared Telegram webhook, starting long polling")
		break
	}

	// Use a longer timeout for the HTTP client during long polling
	pollingClient := &http.Client{Timeout: 35 * time.Second}
	origClient := c.httpClient

	for {
		c.httpClient = pollingClient
		updates, err := c.GetUpdates(30)
		c.httpClient = origClient

		if err != nil {
			// If webhook was re-enabled externally, delete it again
			if strings.Contains(err.Error(), "webhook is active") {
				log.Info("Webhook detected, deleting before retry")
				c.DeleteWebhook()
			} else {
				log.Error("Error polling Telegram updates", logger.F("error", err.Error()))
			}
			time.Sleep(5 * time.Second)
			continue
		}

		for _, update := range updates {
			if update.CallbackQuery != nil {
				handler(update.CallbackQuery)
			}
		}
	}
}

// sendMessage posts a message to the chat and returns its message ID.
func (c *Client) sendMessage(msgReq SendMessageRequest) (int, error) {
	body, err := json.Marshal(msgReq)
	if err != nil {
		return 0, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("sending message: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return 0, fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return 0, fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	var msg Message
	if err := json.Unmarshal(apiResp.Result, &msg); err != nil {
		return 0, fmt.Errorf("parsing message: %w", err)
	}

	return msg.MessageID, nil
}

// describeSecrets lists what a request asks for, as the first lines of a message.
func describeSecrets(req *models.ApprovalRequest) string {
	if len(req.Secrets) <= 1 {
		return fmt.Sprintf("<b>Secret:</b> %s\n<b>Vault:</b> %s\n",
			code(req.SecretName), code(req.Vault))
	}

	list := fmt.Sprintf("<b>Secrets (%d items):</b>\n", len(req.Secrets))
	for _, s := range req.Secrets {
		vault := s.Vault
		if vault == "" {
			vault = "auto"
		}
		if len(s.Fields) > 0 {
			list += fmt.Sprintf("  • %s (vault: %s, fields: %s)\n",
				code(s.SecretName), html.EscapeString(vault),
				html.EscapeString(strings.Join(s.Fields, ", ")))
		} else {
			list += fmt.Sprintf("  • %s (vault: %s)\n",
				code(s.SecretName), html.EscapeString(vault))
		}
	}
	return list
}

// code shows a value as fixed-width text, exactly as given. The values come
// from the requester, so they are escaped: they must not be able to end the
// tag they sit in and change what the approver reads.
func code(s string) string {
	return "<code>" + html.EscapeString(s) + "</code>"
}

// endSessionKeyboard is the single button that ends an approval window.
func endSessionKeyboard(sessionID string) *InlineKeyboardMarkup {
	return &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{{Text: "🔒 End approval window", CallbackData: "endsession:" + sessionID}},
		},
	}
}

// windowLabel renders a window length the short way: 8h, 30m, 1h30m.
func windowLabel(ttl time.Duration) string {
	label := ttl.Round(time.Second).String()
	if strings.HasSuffix(label, "m0s") {
		label = strings.TrimSuffix(label, "0s")
	}
	if strings.HasSuffix(label, "h0m") {
		label = strings.TrimSuffix(label, "0m")
	}
	return label
}

func (c *Client) editMessage(messageID int, text string, keyboard *InlineKeyboardMarkup) error {
	editReq := EditMessageTextRequest{
		ChatID:      c.chatID,
		MessageID:   messageID,
		Text:        text,
		ParseMode:   "HTML",
		ReplyMarkup: keyboard,
	}

	body, err := json.Marshal(editReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/editMessageText", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending request: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	return nil
}

// withoutURL drops the request URL from an HTTP client error. The URL carries
// the bot token, and these errors end up in the server log.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
