package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/session"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/telegram"
)

// Notifier is the approver's side of the gate: the chat where requests are
// approved and where the gate reports what it did. *telegram.Client is the
// real one.
type Notifier interface {
	SendApprovalRequest(req *models.ApprovalRequest, webhookBaseURL string) (int, error)
	UpdateMessageApproved(messageID int, req *models.ApprovalRequest, approver string) error
	UpdateMessageDenied(messageID int, req *models.ApprovalRequest, denier string) error
	AnswerCallbackQuery(callbackID, text string) error
	SendSessionRelease(req *models.ApprovalRequest) (int, error)
	SendSessionEnded(machine, endedBy string) error
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	store    *store.Store
	sessions *session.Store
	opClient *opconnect.Client
	notifier Notifier
	config   *config.Config
	log      *logger.Logger
}

// New creates a new Handler
func New(s *store.Store, sessions *session.Store, op *opconnect.Client, notifier Notifier, cfg *config.Config) *Handler {
	return &Handler{
		store:    s,
		sessions: sessions,
		opClient: op,
		notifier: notifier,
		config:   cfg,
		log:      logger.New(),
	}
}

// Register adds the gate's routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/_/health", h.HandleHealth) // OpenFaaS watchdog health check path
	mux.HandleFunc("/request", h.HandleRequest)
	mux.HandleFunc("/search", h.HandleSearch)
	mux.HandleFunc("/fields", h.HandleFields)
	mux.HandleFunc("/status/", h.HandleStatus)
	mux.HandleFunc("/secret/", h.HandleSecret)
	mux.HandleFunc("/client/", h.HandleClientDownload)
	mux.HandleFunc("/openapi.json", h.HandleOpenAPI)
}

// SearchPayload is the JSON body for secret search
type SearchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

// SearchResponse contains search results
type SearchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

// SearchResultItem is a single search result
type SearchResultItem struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// FieldsPayload is the JSON body for fields request
type FieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

// FieldsResponse contains field metadata
type FieldsResponse struct {
	SecretName string                `json:"secret_name"`
	VaultName  string                `json:"vault_name"`
	Fields     []opconnect.FieldInfo `json:"fields"`
}

// BatchRequestPayload is the JSON body for batch secret requests
type BatchRequestPayload struct {
	// Batch mode
	Secrets []models.SecretRequest `json:"secrets,omitempty"`
	// Legacy single-item mode
	SecretName string `json:"secret_name,omitempty"`
	Vault      string `json:"vault,omitempty"`
	// Common fields
	Machine string `json:"machine"`
	Reason  string `json:"reason,omitempty"`
	// Session says the client can hold an approval window, so the approver
	// may be offered one.
	Session bool `json:"session,omitempty"`
	// SessionToken is the token of the approval window the client holds.
	SessionToken string `json:"session_token,omitempty"`
}

// RequestResponse is the response for a new secret request
type RequestResponse struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
	// SessionInvalid tells the client the window token it presented no longer
	// releases anything, so it should forget it.
	SessionInvalid bool `json:"session_invalid,omitempty"`
}

// SessionGrant is the approval window handed to the client with the secret
// whose approval opened it.
type SessionGrant struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"` // RFC 3339
}

// StatusResponse is the response for status checks
type StatusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

// SecretResponse is the response containing the secret
type SecretResponse struct {
	Secret  map[string]string `json:"secret"`
	Session *SessionGrant     `json:"session,omitempty"`
}

// BatchSecretResponse is the response containing multiple secrets
type BatchSecretResponse struct {
	Secrets map[string]map[string]string `json:"secrets"`
	Session *SessionGrant                `json:"session,omitempty"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// HandleRequest handles POST /request
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload BatchRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	// Normalize: convert legacy single-item format to batch
	secrets := payload.Secrets
	if len(secrets) == 0 && payload.SecretName != "" {
		secrets = []models.SecretRequest{
			{SecretName: payload.SecretName, Vault: payload.Vault},
		}
	}

	if len(secrets) == 0 {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name or secrets[] is required")
		return
	}

	// Use the first secret's name for the approval request label
	primaryName := secrets[0].SecretName
	primaryVault := secrets[0].Vault
	if primaryVault == "" {
		primaryVault = "_auto_"
	}

	// Get requester IP
	requesterIP := r.Header.Get("X-Forwarded-For")
	if requesterIP == "" {
		requesterIP = r.RemoteAddr
	}

	// Create the approval request
	req, err := models.NewApprovalRequest(
		primaryName,
		primaryVault,
		payload.Machine,
		requesterIP,
		payload.Reason,
		h.config.RequestTTL,
	)
	if err != nil {
		h.log.Error("Failed to create request", logger.F("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create request")
		return
	}

	// Attach batch secrets to the request
	req.Secrets = secrets

	// A live approval window for this machine releases the request without
	// asking again. Any other token is reported back so the client drops it.
	var sessionInvalid bool
	if payload.SessionToken != "" {
		sess, ok := h.sessions.Lookup(payload.SessionToken)
		if ok && sess.Machine == payload.Machine {
			h.releaseUnderSession(w, req, sess)
			return
		}
		sessionInvalid = true
	}

	// Offer a window only to a client that can hold one and says who it is.
	if payload.Session && payload.Machine != "" && h.config.SessionTTL > 0 {
		req.SessionTTL = h.config.SessionTTL
	}

	// Save to store
	if err := h.store.Save(req); err != nil {
		h.log.Error("Failed to save request", logger.F("error", err.Error(), "request_id", req.ID))
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return
	}

	// Send Telegram notification
	msgID, err := h.notifier.SendApprovalRequest(req, h.config.WebhookBaseURL)
	if err != nil {
		h.log.Error("Failed to send Telegram notification", logger.F("error", err.Error(), "request_id", req.ID))
	} else {
		req.TelegramMsgID = msgID
		h.store.Update(req)
	}

	h.log.Info("Created approval request", logger.F(
		"request_id", req.ID,
		"secrets_count", len(secrets),
		"machine", req.RequesterMachine,
		"requester_ip", req.RequesterIP,
	))

	// Build response
	baseURL := h.config.WebhookBaseURL
	if baseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	resp := RequestResponse{
		Token:          req.Token,
		StatusURL:      baseURL + "/status/" + req.Token,
		ExpiresAt:      req.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		Message:        "Request submitted. Waiting for human approval via Telegram. Poll the status_url to check approval status.",
		SessionInvalid: sessionInvalid,
	}

	h.writeJSON(w, http.StatusAccepted, resp)
}

// releaseUnderSession approves req under an open approval window. The approver
// is told first: a release that cannot be reported does not happen.
func (h *Handler) releaseUnderSession(w http.ResponseWriter, req *models.ApprovalRequest, sess session.Session) {
	baseURL := h.config.WebhookBaseURL
	if baseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	req.Approve()
	req.SessionID = sess.ID
	req.SessionExpiresAt = sess.ExpiresAt

	msgID, err := h.notifier.SendSessionRelease(req)
	if err != nil {
		h.log.Error("Failed to report release under approval window", logger.F("error", err.Error(), "request_id", req.ID))
		h.writeError(w, http.StatusServiceUnavailable, "notify_failed", "Could not notify the approver, so nothing was released. Try again.")
		return
	}
	req.TelegramMsgID = msgID

	if err := h.store.Save(req); err != nil {
		h.log.Error("Failed to save request", logger.F("error", err.Error(), "request_id", req.ID))
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return
	}

	h.log.Info("Released request under approval window", logger.F(
		"request_id", req.ID,
		"session_id", sess.ID,
		"secrets_count", len(req.Secrets),
		"machine", req.RequesterMachine,
		"requester_ip", req.RequesterIP,
	))

	h.writeJSON(w, http.StatusAccepted, RequestResponse{
		Token:     req.Token,
		StatusURL: baseURL + "/status/" + req.Token,
		ExpiresAt: req.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		Message:   "Request released under an open approval window. Poll the status_url to retrieve the secret.",
	})
}

// sessionGrant returns the approval window req opened, for the client to keep.
func sessionGrant(req *models.ApprovalRequest) *SessionGrant {
	if req.SessionToken == "" {
		return nil
	}
	return &SessionGrant{
		Token:     req.SessionToken,
		ExpiresAt: req.SessionExpiresAt.Format(time.RFC3339),
	}
}

// HandleStatus handles GET /status/{token}
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/status/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	baseURL := h.config.WebhookBaseURL
	if baseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	var resp StatusResponse
	switch req.Status {
	case models.StatusPending:
		resp = StatusResponse{
			Status:  "pending",
			Message: "Waiting for human approval. Continue polling this endpoint.",
		}
	case models.StatusApproved:
		resp = StatusResponse{
			Status:    "approved",
			Message:   "Request approved! Retrieve your secret from secret_url.",
			SecretURL: baseURL + "/secret/" + token,
		}
	case models.StatusDenied:
		resp = StatusResponse{
			Status:  "denied",
			Message: "Request was denied by the approver.",
		}
	case models.StatusExpired:
		resp = StatusResponse{
			Status:  "expired",
			Message: "Request has expired. Please submit a new request.",
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// HandleSecret handles GET /secret/{token}
func (h *Handler) HandleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/secret/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	if !req.CanRetrieveSecret() {
		h.writeError(w, http.StatusForbidden, "not_approved", "Request is not approved or has expired")
		return
	}

	// Batch mode: multiple secrets requested or field filtering specified
	if len(req.Secrets) > 1 || (len(req.Secrets) == 1 && len(req.Secrets[0].Fields) > 0) {
		result := make(map[string]map[string]string)

		for _, s := range req.Secrets {
			vault := s.Vault
			if vault == "" {
				vault = "_auto_"
			}

			var allFields map[string]string
			var actualName string

			if vault == "_auto_" {
				var err error
				allFields, _, actualName, err = h.opClient.FindSecretAcrossVaults(s.SecretName)
				if err != nil {
					h.log.Error("Failed to find secret", logger.F("error", err.Error(), "secret", s.SecretName))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
			} else {
				var err error
				allFields, err = h.opClient.GetSecret(vault, s.SecretName)
				if err != nil {
					h.log.Error("Failed to fetch secret", logger.F("error", err.Error(), "secret", s.SecretName, "vault", vault))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
				actualName = s.SecretName
			}

			// Filter fields if specified
			if len(s.Fields) > 0 {
				filtered := make(map[string]string)
				for _, f := range s.Fields {
					if val, ok := allFields[f]; ok {
						filtered[f] = val
					}
				}
				result[actualName] = filtered
			} else {
				result[actualName] = allFields
			}
		}

		h.log.Info("Batch secrets retrieved", logger.F("request_id", req.ID, "count", len(result)))
		h.store.Delete(token)
		h.writeJSON(w, http.StatusOK, BatchSecretResponse{Secrets: result, Session: sessionGrant(req)})
		return
	}

	// Legacy single-item mode
	var secret map[string]string
	var actualVault, actualSecret string

	if req.Vault == "_auto_" {
		secret, actualVault, actualSecret, err = h.opClient.FindSecretAcrossVaults(req.SecretName)
		if err != nil {
			h.log.Error("Failed to find secret across vaults", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", err.Error())
			return
		}
	} else {
		secret, err = h.opClient.GetSecret(req.Vault, req.SecretName)
		if err != nil {
			h.log.Error("Failed to fetch secret from 1Password", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName, "vault", req.Vault))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", "Failed to retrieve secret from 1Password")
			return
		}
		actualVault = req.Vault
		actualSecret = req.SecretName
	}

	h.log.Info("Secret retrieved", logger.F("request_id", req.ID, "secret", actualSecret, "vault", actualVault))
	h.store.Delete(token)
	h.writeJSON(w, http.StatusOK, SecretResponse{Secret: secret, Session: sessionGrant(req)})
}

// HandleCallback acts on a button the approver pressed. The button's data is
// "<action>:<request ID>", or "endsession:<session ID>".
func (h *Handler) HandleCallback(callback *telegram.CallbackQuery) {
	action, requestID, ok := strings.Cut(callback.Data, ":")
	if !ok {
		h.notifier.AnswerCallbackQuery(callback.ID, "Invalid callback data")
		return
	}

	approver := callback.From.Username
	if approver == "" {
		approver = callback.From.FirstName
	}

	if action == "endsession" {
		h.endSession(callback.ID, requestID, approver)
		return
	}

	req, err := h.store.GetByID(requestID)
	if err == store.ErrNotFound {
		h.notifier.AnswerCallbackQuery(callback.ID, "Request not found or expired")
		return
	}
	if err != nil {
		h.log.Error("Error fetching request", logger.F("error", err.Error(), "request_id", requestID))
		h.notifier.AnswerCallbackQuery(callback.ID, "Internal error")
		return
	}

	if req.Status == models.StatusExpired || (req.Status == models.StatusPending && req.IsExpired()) {
		h.notifier.AnswerCallbackQuery(callback.ID, "Request expired")
		return
	}

	if req.Status != models.StatusPending {
		h.notifier.AnswerCallbackQuery(callback.ID, "Request already processed")
		return
	}

	switch action {
	case "session":
		if req.SessionTTL <= 0 {
			h.notifier.AnswerCallbackQuery(callback.ID, "Unknown action")
			return
		}
		token, sess, err := h.sessions.Create(req.RequesterMachine, req.SessionTTL)
		if err != nil {
			h.log.Error("Error opening approval window", logger.F("error", err.Error(), "request_id", req.ID))
			h.notifier.AnswerCallbackQuery(callback.ID, "Internal error")
			return
		}
		req.SessionToken = token
		req.SessionID = sess.ID
		req.SessionExpiresAt = sess.ExpiresAt
		req.Approve()
		if err := h.store.Update(req); err != nil {
			h.log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
		}
		h.notifier.AnswerCallbackQuery(callback.ID, "Approved, window open")
		if req.TelegramMsgID != 0 {
			h.notifier.UpdateMessageApproved(req.TelegramMsgID, req, approver)
		}
		h.log.Info("Request approved, approval window opened", logger.F(
			"request_id", req.ID,
			"session_id", sess.ID,
			"machine", req.RequesterMachine,
			"approver", approver,
		))

	case "approve":
		req.Approve()
		if err := h.store.Update(req); err != nil {
			h.log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
		}
		h.notifier.AnswerCallbackQuery(callback.ID, "Approved!")
		if req.TelegramMsgID != 0 {
			h.notifier.UpdateMessageApproved(req.TelegramMsgID, req, approver)
		}
		h.log.Info("Request approved", logger.F("request_id", req.ID, "approver", approver))

	case "deny":
		req.Deny()
		if err := h.store.Update(req); err != nil {
			h.log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
		}
		h.notifier.AnswerCallbackQuery(callback.ID, "Denied")
		if req.TelegramMsgID != 0 {
			h.notifier.UpdateMessageDenied(req.TelegramMsgID, req, approver)
		}
		h.log.Info("Request denied", logger.F("request_id", req.ID, "approver", approver))

	default:
		h.notifier.AnswerCallbackQuery(callback.ID, "Unknown action")
	}
}

// endSession closes an approval window, and with it every other window of the
// same machine.
func (h *Handler) endSession(callbackID, sessionID, endedBy string) {
	machine, ended := h.sessions.End(sessionID)
	if ended == 0 {
		h.notifier.AnswerCallbackQuery(callbackID, "Approval window already ended")
		return
	}

	h.notifier.AnswerCallbackQuery(callbackID, "Approval window ended")
	if err := h.notifier.SendSessionEnded(machine, endedBy); err != nil {
		h.log.Error("Failed to report approval window end", logger.F("error", err.Error(), "session_id", sessionID))
	}
	h.log.Info("Approval window ended", logger.F("session_id", sessionID, "machine", machine, "windows", ended, "ended_by", endedBy))
}

// HandleHealth handles GET /health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleClientDownload handles GET /client/{os}/{arch} and legacy GET /client/{arch}
func (h *Handler) HandleClientDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/client/")
	parts := strings.Split(path, "/")

	var goos, arch string
	switch len(parts) {
	case 1:
		// Legacy: /client/{arch} — assumes linux
		goos = "linux"
		arch = parts[0]
	case 2:
		// New: /client/{os}/{arch}
		goos = parts[0]
		arch = parts[1]
	default:
		h.writeError(w, http.StatusBadRequest, "invalid_path", "Use /client/{os}/{arch} or /client/{arch}")
		return
	}

	if goos != "linux" && goos != "darwin" {
		h.writeError(w, http.StatusBadRequest, "invalid_os", "Supported operating systems: linux, darwin")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		h.writeError(w, http.StatusBadRequest, "invalid_arch", "Supported architectures: amd64, arm64")
		return
	}

	clientPath := "/app/clients/client-" + goos + "-" + arch

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=secret-gate")

	http.ServeFile(w, r, clientPath)
}

// HandleSearch handles POST /search - fuzzy search for secrets
func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload SearchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.Query == "" {
		h.writeError(w, http.StatusBadRequest, "missing_query", "query is required")
		return
	}

	limit := payload.Limit
	if limit <= 0 {
		limit = 10
	}

	results, err := h.opClient.SearchSecrets(payload.Query, limit)
	if err != nil {
		h.log.Error("Search failed", logger.F("error", err.Error(), "query", payload.Query))
		h.writeError(w, http.StatusInternalServerError, "search_failed", "Failed to search secrets")
		return
	}

	var items []SearchResultItem
	for _, r := range results {
		items = append(items, SearchResultItem{
			SecretName: r.Item.Title,
			VaultName:  r.VaultName,
			Score:      r.Score,
			MatchType:  r.MatchType,
		})
	}

	h.writeJSON(w, http.StatusOK, SearchResponse{
		Results: items,
		Query:   payload.Query,
	})
}

// HandleFields handles POST /fields - get field metadata without values
func (h *Handler) HandleFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload FieldsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.SecretName == "" {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name is required")
		return
	}

	fields, vaultName, secretName, err := h.opClient.GetItemFields(payload.Vault, payload.SecretName)
	if err != nil {
		h.log.Error("Failed to get item fields", logger.F("error", err.Error(), "secret", payload.SecretName))
		h.writeError(w, http.StatusInternalServerError, "fields_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, FieldsResponse{
		SecretName: secretName,
		VaultName:  vaultName,
		Fields:     fields,
	})
}

// HandleOpenAPI handles GET /openapi.json - returns OpenAPI spec
func (h *Handler) HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	spec := OpenAPISpec()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(spec))
}

// OpenAPISpec returns the OpenAPI 3.0 specification
func OpenAPISpec() string {
	return `{
  "openapi": "3.0.3",
  "info": {
    "title": "Secret Gate API",
    "description": "Human-in-the-loop approval gateway for agent access to secrets. Requests are approved via Telegram before secrets are released. Supports both single-item (legacy) and batch secret requests. The approver can open an approval window for a machine, under which its later requests are released without a new approval and reported to the approver instead.",
    "version": "1.2.0"
  },
  "servers": [
    {"url": "/", "description": "Relative to deployment URL"}
  ],
  "paths": {
    "/request": {
      "post": {
        "summary": "Request access to one or more secrets",
        "description": "Submits a request to access secrets. A Telegram notification will be sent for human approval. Supports two formats: legacy single-item (secret_name at top level) and batch (secrets array). Use /search to find secret names and /fields to discover available fields before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "secrets": {
                    "type": "array",
                    "description": "Batch mode: array of secrets to request. Each item specifies a secret and optionally which fields to retrieve.",
                    "items": {
                      "type": "object",
                      "required": ["secret_name"],
                      "properties": {
                        "secret_name": {
                          "type": "string",
                          "description": "Name of the secret to access"
                        },
                        "vault": {
                          "type": "string",
                          "description": "Optional vault name. If omitted, searches across all vaults."
                        },
                        "fields": {
                          "type": "array",
                          "items": {"type": "string"},
                          "description": "Optional list of field labels to retrieve. If omitted, all fields are returned. Use /fields to discover available field labels."
                        }
                      }
                    }
                  },
                  "secret_name": {
                    "type": "string",
                    "description": "Legacy mode: name of a single secret to access. Use 'secrets' array for batch requests."
                  },
                  "vault": {
                    "type": "string",
                    "description": "Legacy mode: optional vault name. If omitted, searches across all vaults."
                  },
                  "machine": {
                    "type": "string",
                    "description": "Identifier for the requesting machine/agent"
                  },
                  "reason": {
                    "type": "string",
                    "description": "Reason for requesting access (shown in approval notification)"
                  },
                  "session": {
                    "type": "boolean",
                    "description": "Set when the client can hold an approval window. The approver is then also offered to approve for a period (SESSION_TTL), which requires 'machine' to be set."
                  },
                  "session_token": {
                    "type": "string",
                    "description": "Token of the approval window the client holds. If the window is open and was granted to the same 'machine', the request is approved at once and reported to the approver."
                  }
                }
              },
              "examples": {
                "batch": {
                  "summary": "Batch request for multiple secrets with field filtering",
                  "value": {
                    "secrets": [
                      {"secret_name": "homelab-ssh-key", "fields": ["private_key"]},
                      {"secret_name": "database-credentials", "vault": "Infrastructure", "fields": ["username", "password"]}
                    ],
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                },
                "legacy": {
                  "summary": "Legacy single-item request",
                  "value": {
                    "secret_name": "homelab-ssh-key",
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "202": {
            "description": "Request accepted, waiting for approval",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "token": {"type": "string", "description": "Unique token for this request. Use with /status/{token} and /secret/{token}."},
                    "status_url": {"type": "string", "description": "URL to poll for approval status"},
                    "expires_at": {"type": "string", "description": "ISO 8601 timestamp when this request expires"},
                    "message": {"type": "string"},
                    "session_invalid": {"type": "boolean", "description": "True when the session_token that was presented no longer opens anything (expired, ended, or granted to another machine). The request then waits for approval as usual and the client should forget the token."}
                  }
                }
              }
            }
          },
          "503": {
            "description": "The request came under an open approval window but the approver could not be notified, so nothing was released. Try again."
          }
        }
      }
    },
    "/search": {
      "post": {
        "summary": "Search for secrets",
        "description": "Fuzzy search for secrets across all vaults. Use this to find the correct secret name before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                  "query": {
                    "type": "string",
                    "description": "Search query (supports fuzzy matching)"
                  },
                  "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of results"
                  }
                }
              },
              "example": {"query": "ssh", "limit": 5}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Search results",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "query": {"type": "string"},
                    "results": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "secret_name": {"type": "string"},
                          "vault_name": {"type": "string"},
                          "score": {"type": "number"},
                          "match_type": {"type": "string", "enum": ["exact", "prefix", "contains", "fuzzy"]}
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/fields": {
      "post": {
        "summary": "Get field metadata for a secret",
        "description": "Returns the field labels and types for a secret item without exposing any values. Use this to discover which fields are available before making a batch request with field filtering.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                  "secret_name": {
                    "type": "string",
                    "description": "Name of the secret to inspect"
                  },
                  "vault": {
                    "type": "string",
                    "description": "Optional vault name. If omitted, searches across all vaults."
                  }
                }
              },
              "example": {"secret_name": "database-credentials"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Field metadata for the secret",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "secret_name": {"type": "string", "description": "Resolved name of the secret"},
                    "vault_name": {"type": "string", "description": "Vault containing the secret"},
                    "fields": {
                      "type": "array",
                      "description": "List of fields available on this secret",
                      "items": {
                        "type": "object",
                        "properties": {
                          "label": {"type": "string", "description": "Field label (use this in the fields array when requesting)"},
                          "type": {"type": "string", "description": "Field type (e.g., STRING, CONCEALED, URL, EMAIL, OTP)"}
                        }
                      }
                    }
                  }
                },
                "example": {
                  "secret_name": "database-credentials",
                  "vault_name": "Infrastructure",
                  "fields": [
                    {"label": "username", "type": "STRING"},
                    {"label": "password", "type": "CONCEALED"},
                    {"label": "hostname", "type": "STRING"},
                    {"label": "port", "type": "STRING"}
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/status/{token}": {
      "get": {
        "summary": "Check request status",
        "description": "Poll this endpoint to check if your request has been approved or denied.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {
            "description": "Request status",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": {"type": "string", "enum": ["pending", "approved", "denied", "expired"]},
                    "message": {"type": "string"},
                    "secret_url": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/secret/{token}": {
      "get": {
        "summary": "Retrieve approved secret(s)",
        "description": "Retrieve the secret after approval. This is a one-time use endpoint - the token is invalidated after retrieval. Returns batch format (secrets map) for batch requests or legacy format (single secret) for legacy requests.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {
            "description": "Secret data. Response format depends on how the request was made.",
            "content": {
              "application/json": {
                "schema": {
                  "oneOf": [
                    {
                      "type": "object",
                      "description": "Legacy single-item response",
                      "properties": {
                        "secret": {
                          "type": "object",
                          "additionalProperties": {"type": "string"},
                          "description": "Map of field labels to values for the single requested secret"
                        },
                        "session": {"$ref": "#/components/schemas/SessionGrant"}
                      }
                    },
                    {
                      "type": "object",
                      "description": "Batch response containing multiple secrets",
                      "properties": {
                        "secrets": {
                          "type": "object",
                          "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                          },
                          "description": "Map of secret names to their field label-value maps"
                        },
                        "session": {"$ref": "#/components/schemas/SessionGrant"}
                      }
                    }
                  ]
                },
                "examples": {
                  "legacy": {
                    "summary": "Legacy single-item response",
                    "value": {
                      "secret": {
                        "username": "admin",
                        "password": "s3cret"
                      }
                    }
                  },
                  "batch": {
                    "summary": "Batch response with multiple secrets",
                    "value": {
                      "secrets": {
                        "homelab-ssh-key": {
                          "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----..."
                        },
                        "database-credentials": {
                          "username": "admin",
                          "password": "s3cret"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/client/{os}/{arch}": {
      "get": {
        "summary": "Download CLI client",
        "description": "Download the pre-compiled CLI client binary for the specified OS and architecture. Legacy path /client/{arch} is also supported (assumes linux).",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["linux", "darwin"]}
          },
          {
            "name": "arch",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["amd64", "arm64"]}
          }
        ],
        "responses": {
          "200": {
            "description": "Binary file",
            "content": {"application/octet-stream": {}}
          }
        }
      }
    },
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/openapi.json": {
      "get": {
        "summary": "OpenAPI specification",
        "responses": {
          "200": {
            "description": "OpenAPI 3.0 spec",
            "content": {"application/json": {}}
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "SessionGrant": {
        "type": "object",
        "description": "Present only on the secret whose approval opened an approval window. The client keeps the token in memory and presents it as session_token on later requests.",
        "properties": {
          "token": {"type": "string", "description": "Approval window token"},
          "expires_at": {"type": "string", "description": "RFC 3339 timestamp when the window closes"}
        }
      }
    }
  }
}`
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, errCode, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: errCode, Message: message})
}
