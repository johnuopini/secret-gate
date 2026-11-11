package main

import (
	"fmt"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
)

// SessionGrant is the approval window the gate hands over with the secret
// whose approval opened it.
type SessionGrant struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"` // RFC 3339
}

// presentWindow asks the gate for an approval window, which the daemon can
// hold, and presents the one the daemon already holds for this gate.
func presentWindow(dc *daemon.Client, server string, payload *RequestPayload) {
	payload.Session = true
	if window, err := dc.Session(server); err == nil && window != nil {
		payload.SessionToken = window.Token
	}
}

// keepWindow hands the approval window the gate just opened to the daemon and
// returns when the window closes.
func keepWindow(dc *daemon.Client, server string, grant SessionGrant) (time.Time, error) {
	expiresAt, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading its expiry: %w", err)
	}
	if err := dc.SetSession(server, grant.Token, expiresAt); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}
