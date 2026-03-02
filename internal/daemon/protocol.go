package daemon

const (
	CmdGet    = "get"
	CmdStore  = "store"
	CmdList   = "list"
	CmdFlush  = "flush"
	CmdStatus = "status"
	CmdStop   = "stop"
)

type Request struct {
	Command    string            `json:"command"`
	SecretName string            `json:"secret_name,omitempty"`
	Vault      string            `json:"vault,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	TTLSeconds int               `json:"ttl_seconds,omitempty"`
}

type Response struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Entries []CacheEntryInfo  `json:"entries,omitempty"`
	Status  *DaemonStatus     `json:"status,omitempty"`
}

type DaemonStatus struct {
	Uptime     string `json:"uptime"`
	EntryCount int    `json:"entry_count"`
	SocketPath string `json:"socket_path"`
	PID        int    `json:"pid"`
}
