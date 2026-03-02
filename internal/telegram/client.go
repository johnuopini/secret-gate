package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	var secretsList string
	if len(req.Secrets) > 1 {
		secretsList = fmt.Sprintf("*Secrets (%d items):*\n", len(req.Secrets))
		for _, s := range req.Secrets {
			vault := s.Vault
			if vault == "" {
				vault = "auto"
			}
			if len(s.Fields) > 0 {
				secretsList += fmt.Sprintf("  • `%s` (vault: %s, fields: %s)\n",
					escapeMarkdown(s.SecretName), escapeMarkdown(vault),
					escapeMarkdown(strings.Join(s.Fields, ", ")))
			} else {
				secretsList += fmt.Sprintf("  • `%s` (vault: %s)\n",
					escapeMarkdown(s.SecretName), escapeMarkdown(vault))
			}
		}
	} else {
		secretsList = fmt.Sprintf("*Secret:* `%s`\n*Vault:* `%s`\n",
			escapeMarkdown(req.SecretName), escapeMarkdown(req.Vault))
	}

	text := fmt.Sprintf(
		"🔐 *Secret Access Request*\n\n"+
			"%s"+
			"*Machine:* `%s`\n"+
			"*IP:* `%s`\n"+
			"*Reason:* %s\n"+
			"*Expires:* %s\n\n"+
			"*Request ID:* `%s`",
		secretsList,
		escapeMarkdown(req.RequesterMachine),
		req.RequesterIP,
		escapeMarkdown(defaultIfEmpty(req.Reason, "Not provided")),
		req.ExpiresAt.Format("15:04:05 MST"),
		req.ID,
	)

	keyboard := &InlineKeyboardMarkup{
		InlineKeyboard: [][]InlineKeyboardButton{
			{
				{Text: "✅ Approve", CallbackData: fmt.Sprintf("approve:%s", req.ID)},
				{Text: "❌ Deny", CallbackData: fmt.Sprintf("deny:%s", req.ID)},
			},
		},
	}

	msgReq := SendMessageRequest{
		ChatID:      c.chatID,
		Text:        text,
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	}

	body, err := json.Marshal(msgReq)
	if err != nil {
		return 0, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("sending message: %w", err)
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

// UpdateMessageApproved updates a message to show it was approved
func (c *Client) UpdateMessageApproved(messageID int, req *models.ApprovalRequest, approver string) error {
	text := fmt.Sprintf(
		"✅ *Secret Access Approved*\n\n"+
			"*Secret:* `%s`\n"+
			"*Vault:* `%s`\n"+
			"*Machine:* `%s`\n"+
			"*Approved by:* @%s\n"+
			"*Request ID:* `%s`",
		escapeMarkdown(req.SecretName),
		escapeMarkdown(req.Vault),
		escapeMarkdown(req.RequesterMachine),
		escapeMarkdown(approver),
		req.ID,
	)

	return c.editMessage(messageID, text, nil)
}

// UpdateMessageDenied updates a message to show it was denied
func (c *Client) UpdateMessageDenied(messageID int, req *models.ApprovalRequest, denier string) error {
	text := fmt.Sprintf(
		"❌ *Secret Access Denied*\n\n"+
			"*Secret:* `%s`\n"+
			"*Vault:* `%s`\n"+
			"*Machine:* `%s`\n"+
			"*Denied by:* @%s\n"+
			"*Request ID:* `%s`",
		escapeMarkdown(req.SecretName),
		escapeMarkdown(req.Vault),
		escapeMarkdown(req.RequesterMachine),
		escapeMarkdown(denier),
		req.ID,
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
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// GetUpdates fetches new updates from Telegram using long polling
func (c *Client) GetUpdates(timeout int) ([]Update, error) {
	url := fmt.Sprintf("%s/getUpdates?offset=%d&timeout=%d&allowed_updates=[\"callback_query\"]",
		c.baseURL, c.lastUpdateID+1, timeout)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching updates: %w", err)
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
		return fmt.Errorf("deleting webhook: %w", err)
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

func (c *Client) editMessage(messageID int, text string, keyboard *InlineKeyboardMarkup) error {
	editReq := EditMessageTextRequest{
		ChatID:      c.chatID,
		MessageID:   messageID,
		Text:        text,
		ParseMode:   "Markdown",
		ReplyMarkup: keyboard,
	}

	body, err := json.Marshal(editReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/editMessageText", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
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

func escapeMarkdown(s string) string {
	// Simple escape for Markdown special characters
	replacer := map[string]string{
		"_": "\\_",
		"*": "\\*",
		"`": "\\`",
		"[": "\\[",
	}
	for old, new := range replacer {
		s = replaceAll(s, old, new)
	}
	return s
}

func replaceAll(s, old, new string) string {
	result := ""
	for _, c := range s {
		if string(c) == old {
			result += new
		} else {
			result += string(c)
		}
	}
	return result
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
