// Package session holds approval windows: a period during which one machine's
// requests are released without a new Telegram tap.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Session is one open approval window.
type Session struct {
	ID        string
	Machine   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store keeps open sessions in memory, keyed by the SHA-256 of their token so
// the token itself is never held by the server after it is handed out.
type Store struct {
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]Session
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{sessions: make(map[[sha256.Size]byte]Session)}
}

// Create opens a session for machine and returns the token that proves it.
func (s *Store) Create(machine string, ttl time.Duration) (string, Session, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", Session{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return "", Session{}, err
	}

	now := time.Now()
	sess := Session{ID: id, Machine: machine, CreatedAt: now, ExpiresAt: now.Add(ttl)}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sha256.Sum256([]byte(token))] = sess

	return token, sess, nil
}

// Lookup returns the live session a token belongs to.
func (s *Store) Lookup(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sha256.Sum256([]byte(token))]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return Session{}, false
	}
	return sess, true
}

// End closes the session with the given ID and every other session of the same
// machine. It returns that machine and how many sessions were closed.
func (s *Store) End(id string) (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var machine string
	var found bool
	for _, sess := range s.sessions {
		if sess.ID == id {
			machine, found = sess.Machine, true
			break
		}
	}
	if !found {
		return "", 0
	}

	var ended int
	for key, sess := range s.sessions {
		if sess.Machine == machine {
			delete(s.sessions, key)
			ended++
		}
	}
	return machine, ended
}

// Cleanup removes expired sessions and returns how many were removed.
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	now := time.Now()
	for key, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, key)
			removed++
		}
	}
	return removed
}

func randomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
