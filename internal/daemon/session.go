package daemon

import (
	"sort"
	"sync"
	"time"
)

// SessionInfo is an approval window held for one gate server. The token is
// what the gate accepts in place of a new approval, so it is kept per server
// and never leaves the daemon except to the client that asks for that server.
type SessionInfo struct {
	Server    string    `json:"server"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// sessionSet holds the approval windows in memory, one per gate server.
type sessionSet struct {
	mu       sync.Mutex
	byServer map[string]SessionInfo
}

func newSessionSet() *sessionSet {
	return &sessionSet{byServer: make(map[string]SessionInfo)}
}

func (s *sessionSet) set(info SessionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byServer[info.Server] = info
}

// get returns the live window held for server.
func (s *sessionSet) get(server string) (SessionInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, ok := s.byServer[server]
	if !ok {
		return SessionInfo{}, false
	}
	if time.Now().After(info.ExpiresAt) {
		delete(s.byServer, server)
		return SessionInfo{}, false
	}
	return info, true
}

// clear forgets the window held for server if it is the one with this token.
func (s *sessionSet) clear(server, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byServer[server].Token == token {
		delete(s.byServer, server)
	}
}

func (s *sessionSet) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byServer = make(map[string]SessionInfo)
}

// live drops closed windows and returns the rest without their tokens.
func (s *sessionSet) live() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var windows []SessionInfo
	for server, info := range s.byServer {
		if now.After(info.ExpiresAt) {
			delete(s.byServer, server)
			continue
		}
		windows = append(windows, SessionInfo{Server: info.Server, ExpiresAt: info.ExpiresAt})
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i].Server < windows[j].Server })
	return windows
}
