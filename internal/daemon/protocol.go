package daemon

const (
	CmdGet          = "get"
	CmdStore        = "store"
	CmdList         = "list"
	CmdFlush        = "flush"
	CmdStatus       = "status"
	CmdStop         = "stop"
	CmdSessionGet   = "session_get"
	CmdSessionSet   = "session_set"
	CmdSessionClear = "session_clear"
)

type Request struct {
	Command    string            `json:"command"`
	SecretName string            `json:"secret_name,omitempty"`
	Vault      string            `json:"vault,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	TTLSeconds int               `json:"ttl_seconds,omitempty"`
	Session    *SessionInfo      `json:"session,omitempty"`
}

type Response struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Entries []CacheEntryInfo  `json:"entries,omitempty"`
	Status  *DaemonStatus     `json:"status,omitempty"`
	Session *SessionInfo      `json:"session,omitempty"`
}

type DaemonStatus struct {
	Uptime     string        `json:"uptime"`
	EntryCount int           `json:"entry_count"`
	SocketPath string        `json:"socket_path"`
	PID        int           `json:"pid"`
	Sessions   []SessionInfo `json:"sessions,omitempty"` // open approval windows, without their tokens
}
