package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// RequestStatus represents the approval state of a request
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
)

// SecretRequest represents a single secret in a batch request
type SecretRequest struct {
	SecretName string   `json:"secret_name"`
	Vault      string   `json:"vault,omitempty"`
	Fields     []string `json:"fields,omitempty"` // If empty, return all fields
}

// ApprovalRequest represents a request to access a secret
type ApprovalRequest struct {
	ID               string          `json:"id"`
	Token            string          `json:"token"`
	SecretName       string          `json:"secret_name"`
	Vault            string          `json:"vault"`
	Secrets          []SecretRequest `json:"secrets,omitempty"` // Batch mode
	RequesterMachine string          `json:"requester_machine"`
	RequesterIP      string        `json:"requester_ip"`
	Reason           string        `json:"reason,omitempty"`
	Status           RequestStatus `json:"status"`
	RequestedAt      time.Time     `json:"requested_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	RespondedAt      *time.Time    `json:"responded_at,omitempty"`
	TelegramMsgID    int           `json:"telegram_msg_id,omitempty"`
}

// SecretValue holds the retrieved secret data
type SecretValue struct {
	Fields map[string]string `json:"fields"`
}

// NewApprovalRequest creates a new approval request with a unique token
func NewApprovalRequest(secretName, vault, requesterMachine, requesterIP, reason string, ttl time.Duration) (*ApprovalRequest, error) {
	id, err := generateRandomID(16)
	if err != nil {
		return nil, err
	}

	token, err := generateRandomID(32)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &ApprovalRequest{
		ID:               id,
		Token:            token,
		SecretName:       secretName,
		Vault:            vault,
		RequesterMachine: requesterMachine,
		RequesterIP:      requesterIP,
		Reason:           reason,
		Status:           StatusPending,
		RequestedAt:      now,
		ExpiresAt:        now.Add(ttl),
	}, nil
}

// IsExpired checks if the request has expired
func (r *ApprovalRequest) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// CanRetrieveSecret checks if the secret can be retrieved
func (r *ApprovalRequest) CanRetrieveSecret() bool {
	return r.Status == StatusApproved && !r.IsExpired()
}

// Approve marks the request as approved
func (r *ApprovalRequest) Approve() {
	now := time.Now()
	r.Status = StatusApproved
	r.RespondedAt = &now
}

// Deny marks the request as denied
func (r *ApprovalRequest) Deny() {
	now := time.Now()
	r.Status = StatusDenied
	r.RespondedAt = &now
}

// generateRandomID generates a random hex string of the specified byte length
func generateRandomID(byteLen int) (string, error) {
	bytes := make([]byte, byteLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
