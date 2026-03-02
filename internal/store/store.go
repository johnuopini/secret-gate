package store

import (
	"errors"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

var (
	ErrNotFound      = errors.New("request not found")
	ErrAlreadyExists = errors.New("request already exists")
)

// Store provides thread-safe storage for approval requests
type Store struct {
	mu       sync.RWMutex
	requests map[string]*models.ApprovalRequest // keyed by token
	byID     map[string]*models.ApprovalRequest // keyed by ID for Telegram callbacks
}

// New creates a new Store
func New() *Store {
	return &Store{
		requests: make(map[string]*models.ApprovalRequest),
		byID:     make(map[string]*models.ApprovalRequest),
	}
}

// Save stores an approval request
func (s *Store) Save(req *models.ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.Token]; exists {
		return ErrAlreadyExists
	}

	s.requests[req.Token] = req
	s.byID[req.ID] = req
	return nil
}

// GetByToken retrieves a request by its polling token
func (s *Store) GetByToken(token string) (*models.ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[token]
	if !ok {
		return nil, ErrNotFound
	}

	// Check and update expiration status
	if req.Status == models.StatusPending && req.IsExpired() {
		req.Status = models.StatusExpired
	}

	return req, nil
}

// GetByID retrieves a request by its ID (used for Telegram callbacks)
func (s *Store) GetByID(id string) (*models.ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}

	return req, nil
}

// Update updates an existing request
func (s *Store) Update(req *models.ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.Token]; !exists {
		return ErrNotFound
	}

	s.requests[req.Token] = req
	s.byID[req.ID] = req
	return nil
}

// Delete removes a request from the store
func (s *Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[token]
	if !exists {
		return ErrNotFound
	}

	delete(s.requests, token)
	delete(s.byID, req.ID)
	return nil
}

// Cleanup removes expired requests and returns the number removed
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	now := time.Now()

	for token, req := range s.requests {
		// Remove requests that expired more than 1 hour ago
		if now.After(req.ExpiresAt.Add(time.Hour)) {
			delete(s.requests, token)
			delete(s.byID, req.ID)
			removed++
		}
	}

	return removed
}

// Count returns the number of requests in the store
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.requests)
}

// ListPending returns all pending requests
func (s *Store) ListPending() []*models.ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var pending []*models.ApprovalRequest
	for _, req := range s.requests {
		if req.Status == models.StatusPending && !req.IsExpired() {
			pending = append(pending, req)
		}
	}
	return pending
}
