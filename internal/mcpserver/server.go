package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler defaults.
const (
	defaultSearchLimit  = 10
	defaultSSHPort      = 22
	defaultSSHTimeout   = 120 * time.Second
	defaultSSHAgentTTL  = 1 * time.Hour
)

// --- Interfaces ---

// DaemonClient provides read-only daemon access.
type DaemonClient interface {
	IsRunning() bool
	StatusInfo() (*DaemonStatusResult, error)
}

// FullDaemonClient provides full daemon access including cache operations.
type FullDaemonClient interface {
	DaemonClient
	Get(secretName, vault string) (map[string]string, error)
	Store(secretName, vault string, fields map[string]string, ttl int) error
	EnsureRunning() error
}

// ProxyClient provides HTTP proxy access to the secret-gate server.
type ProxyClient interface {
	Search(query string, limit int) ([]SearchResultItem, error)
	GetFields(secretName, vault string) (*FieldsResult, error)
	Request(ctx context.Context, secretName, vault, reason string) (*RequestResult, error)
}

// --- Shared types ---

// DaemonStatusResult holds daemon status information.
type DaemonStatusResult struct {
	Running    bool   `json:"running"`
	Uptime     string `json:"uptime,omitempty"`
	EntryCount int    `json:"entry_count"`
	SocketPath string `json:"socket_path,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

// SearchResultItem is a single search result from the proxy.
type SearchResultItem struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// FieldInfo holds field metadata (name and type, no values).
type FieldInfo struct {
	Label string `json:"label"`
	Type  string `json:"type"`
}

// FieldsResult holds the result of inspecting fields.
type FieldsResult struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

// RequestResult holds the result of a secret request.
type RequestResult struct {
	Status          string   `json:"status"`
	SecretName      string   `json:"secret_name"`
	Cached          bool     `json:"cached"`
	FieldsAvailable []string `json:"fields_available,omitempty"`
	Message         string   `json:"message,omitempty"`
}

// ExecResult holds the result of command execution.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// --- Tool Input types ---

type DaemonStatusInput struct{}

type SearchSecretsInput struct {
	Query string `json:"query" jsonschema:"search query for finding secrets in 1Password"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of results (default 10)"`
}

type InspectFieldsInput struct {
	SecretName string `json:"secret_name" jsonschema:"name of the secret to inspect"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name (optional, searches all vaults if omitted)"`
}

type RequestSecretInput struct {
	SecretName string `json:"secret_name" jsonschema:"name of the secret to request"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name (optional)"`
	Reason     string `json:"reason" jsonschema:"reason for requesting access (shown in Telegram approval)"`
}

type ExecWithSecretInput struct {
	SecretName string `json:"secret_name" jsonschema:"name of the previously approved secret"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name (optional)"`
	Field      string `json:"field" jsonschema:"field name to inject as environment variable"`
	EnvVar     string `json:"env_var" jsonschema:"environment variable name to set"`
	Command    string `json:"command" jsonschema:"shell command to execute (runs via sh -c)"`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"working directory for the command"`
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"command timeout in seconds (default 30)"`
}

type SSHWithSecretInput struct {
	SecretName string `json:"secret_name" jsonschema:"SSH key secret name (must be approved and cached)"`
	Host       string `json:"host" jsonschema:"SSH destination (user@host format)"`
	Command    string `json:"command,omitempty" jsonschema:"remote command to execute"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port (default 22)"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"timeout in seconds (default 120)"`
}

// --- Tool Output types ---

type DaemonStatusOutput = DaemonStatusResult

type SearchSecretsOutput struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
	Count   int                `json:"count"`
}

type InspectFieldsOutput = FieldsResult

type RequestSecretOutput = RequestResult

type ExecWithSecretOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	SecretUsed string `json:"secret_used"`
}

type SSHWithSecretOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	SecretUsed string `json:"secret_used"`
}

// --- Config ---

// Config holds configuration for the MCP server.
type Config struct {
	ServerURL   string
	CacheTTLSec int
	SSHAgent    bool
}

// --- Server construction ---

// New creates a new MCP server with all 6 secret-gate tools registered.
func New(cfg Config, dc FullDaemonClient, pc ProxyClient) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "secret-gate",
		Version: "1.0.0",
	}, nil)

	// Register all tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "daemon_status",
		Description: "Check the status of the secret-gate cache daemon. Returns whether it is running, uptime, cached entry count, and socket path.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DaemonStatusInput) (*mcp.CallToolResult, DaemonStatusOutput, error) {
		return handleDaemonStatus(ctx, dc)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_secrets",
		Description: "Search for secrets in 1Password by name. Returns matching secret names, vault names, and match scores. Use this to find the correct secret name before requesting it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SearchSecretsInput) (*mcp.CallToolResult, SearchSecretsOutput, error) {
		return handleSearchSecrets(ctx, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "inspect_fields",
		Description: "List the field names and types for a secret WITHOUT revealing any values. Use this to discover which fields a secret has before requesting or executing with it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input InspectFieldsInput) (*mcp.CallToolResult, InspectFieldsOutput, error) {
		return handleInspectFields(ctx, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "request_secret",
		Description: "Request access to a secret. Triggers a Telegram approval flow. Returns the request status (approved/pending/denied) but NEVER the secret value. After approval, the secret is cached locally. Use exec_with_secret or ssh_with_secret to use the cached secret.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input RequestSecretInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
		return handleRequestSecret(ctx, dc, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec_with_secret",
		Description: "Execute a shell command with a secret field injected as an environment variable. The secret must be previously approved and cached (use request_secret first). The secret value is NEVER returned - it is only available to the subprocess via the environment variable.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecWithSecretInput) (*mcp.CallToolResult, ExecWithSecretOutput, error) {
		return handleExecWithSecret(ctx, dc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_with_secret",
		Description: "SSH to a host using an SSH key from a previously approved secret. The key is added to ssh-agent temporarily, then SSH is executed. The secret must be approved and cached first (use request_secret first).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SSHWithSecretInput) (*mcp.CallToolResult, SSHWithSecretOutput, error) {
		return handleSSHWithSecret(ctx, dc, cfg, input)
	})

	return server
}

// --- Handler functions ---

func handleDaemonStatus(_ context.Context, dc DaemonClient) (*mcp.CallToolResult, DaemonStatusOutput, error) {
	if !dc.IsRunning() {
		return nil, DaemonStatusOutput{
			Running:    false,
			EntryCount: 0,
		}, nil
	}

	status, err := dc.StatusInfo()
	if err != nil {
		return toolError("failed to get daemon status: " + err.Error()), DaemonStatusOutput{}, nil
	}

	return nil, *status, nil
}

func handleSearchSecrets(_ context.Context, pc ProxyClient, input SearchSecretsInput) (*mcp.CallToolResult, SearchSecretsOutput, error) {
	if input.Query == "" {
		return toolError("query is required"), SearchSecretsOutput{}, nil
	}

	limit := input.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
	}

	results, err := pc.Search(input.Query, limit)
	if err != nil {
		return toolError("search failed: " + err.Error()), SearchSecretsOutput{}, nil
	}

	return nil, SearchSecretsOutput{
		Results: results,
		Query:   input.Query,
		Count:   len(results),
	}, nil
}

func handleInspectFields(_ context.Context, pc ProxyClient, input InspectFieldsInput) (*mcp.CallToolResult, InspectFieldsOutput, error) {
	if input.SecretName == "" {
		return toolError("secret_name is required"), InspectFieldsOutput{}, nil
	}

	result, err := pc.GetFields(input.SecretName, input.Vault)
	if err != nil {
		return toolError("failed to get fields: " + err.Error()), InspectFieldsOutput{}, nil
	}

	return nil, *result, nil
}

func handleRequestSecret(ctx context.Context, dc FullDaemonClient, pc ProxyClient, input RequestSecretInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
	if input.SecretName == "" {
		return toolError("secret_name is required"), RequestSecretOutput{}, nil
	}
	if input.Reason == "" {
		return toolError("reason is required — explain why you need this secret so the approver can make an informed decision"), RequestSecretOutput{}, nil
	}

	// Check if already cached in daemon
	if dc.IsRunning() {
		cached, err := dc.Get(input.SecretName, input.Vault)
		if err == nil && cached != nil {
			fieldNames := make([]string, 0, len(cached))
			for k := range cached {
				fieldNames = append(fieldNames, k)
			}
			return nil, RequestSecretOutput{
				Status:          "approved",
				SecretName:      input.SecretName,
				Cached:          true,
				FieldsAvailable: fieldNames,
				Message:         "Secret is already cached and available. Use exec_with_secret or ssh_with_secret to use it.",
			}, nil
		}
	}

	// Submit request via proxy
	result, err := pc.Request(ctx, input.SecretName, input.Vault, input.Reason)
	if err != nil {
		return toolError("failed to request secret: " + err.Error()), RequestSecretOutput{}, nil
	}

	return nil, *result, nil
}

func handleExecWithSecret(ctx context.Context, dc FullDaemonClient, input ExecWithSecretInput) (*mcp.CallToolResult, ExecWithSecretOutput, error) {
	if input.SecretName == "" {
		return toolError("secret_name is required"), ExecWithSecretOutput{}, nil
	}
	if input.Field == "" {
		return toolError("field is required"), ExecWithSecretOutput{}, nil
	}
	if input.EnvVar == "" {
		return toolError("env_var is required"), ExecWithSecretOutput{}, nil
	}
	if input.Command == "" {
		return toolError("command is required"), ExecWithSecretOutput{}, nil
	}

	// Look up secret from daemon cache
	if !dc.IsRunning() {
		return toolError("daemon is not running. Call request_secret first to approve and cache the secret."), ExecWithSecretOutput{}, nil
	}

	fields, err := dc.Get(input.SecretName, input.Vault)
	if err != nil {
		return toolError(fmt.Sprintf("secret %q is not cached. Call request_secret first to approve and cache the secret.", input.SecretName)), ExecWithSecretOutput{}, nil
	}

	fieldValue, ok := fields[input.Field]
	if !ok {
		availableFields := make([]string, 0, len(fields))
		for k := range fields {
			availableFields = append(availableFields, k)
		}
		return toolError(fmt.Sprintf("field %q not found in secret %q. Available fields: %s", input.Field, input.SecretName, strings.Join(availableFields, ", "))), ExecWithSecretOutput{}, nil
	}

	timeout := time.Duration(input.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = defaultExecTimeout
	}

	envVars := map[string]string{
		input.EnvVar: fieldValue,
	}

	result, err := execCommand(ctx, input.Command, envVars, input.WorkingDir, timeout)
	if err != nil {
		return toolError("command execution failed: " + err.Error()), ExecWithSecretOutput{}, nil
	}

	return nil, ExecWithSecretOutput{
		ExitCode:   result.ExitCode,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		SecretUsed: input.SecretName + "/" + input.Field,
	}, nil
}

func handleSSHWithSecret(ctx context.Context, dc FullDaemonClient, cfg Config, input SSHWithSecretInput) (*mcp.CallToolResult, SSHWithSecretOutput, error) {
	if input.SecretName == "" {
		return toolError("secret_name is required"), SSHWithSecretOutput{}, nil
	}
	if input.Host == "" {
		return toolError("host is required"), SSHWithSecretOutput{}, nil
	}

	// Look up secret from daemon cache
	if !dc.IsRunning() {
		return toolError("daemon is not running. Call request_secret first to approve and cache the secret."), SSHWithSecretOutput{}, nil
	}

	fields, err := dc.Get(input.SecretName, input.Vault)
	if err != nil {
		return toolError(fmt.Sprintf("secret %q is not cached. Call request_secret first to approve and cache the secret.", input.SecretName)), SSHWithSecretOutput{}, nil
	}

	// Find SSH key field
	fieldName, keyValue, found := daemon.FindSSHKeyField(fields)
	if !found {
		availableFields := make([]string, 0, len(fields))
		for k := range fields {
			availableFields = append(availableFields, k)
		}
		return toolError(fmt.Sprintf("no SSH private key found in secret %q. Available fields: %s", input.SecretName, strings.Join(availableFields, ", "))), SSHWithSecretOutput{}, nil
	}

	// Add key to ssh-agent
	if cfg.SSHAgent {
		ttl := time.Duration(cfg.CacheTTLSec) * time.Second
		if ttl <= 0 {
			ttl = defaultSSHAgentTTL
		}
		if err := daemon.AddToSSHAgent(keyValue, ttl); err != nil {
			return toolError(fmt.Sprintf("failed to add SSH key (%s) to ssh-agent: %v", fieldName, err)), SSHWithSecretOutput{}, nil
		}
	}

	// Build SSH command
	port := input.Port
	if port <= 0 {
		port = defaultSSHPort
	}
	sshArgs := []string{"-p", fmt.Sprintf("%d", port)}
	sshArgs = append(sshArgs, input.Host)
	if input.Command != "" {
		sshArgs = append(sshArgs, input.Command)
	}

	timeout := time.Duration(input.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultSSHTimeout
	}

	// Build the ssh command string
	sshCmd := "ssh"
	for _, arg := range sshArgs {
		sshCmd += " " + shellQuote(arg)
	}

	result, err := execCommand(ctx, sshCmd, nil, "", timeout)
	if err != nil {
		return toolError("SSH execution failed: " + err.Error()), SSHWithSecretOutput{}, nil
	}

	return nil, SSHWithSecretOutput{
		ExitCode:   result.ExitCode,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		SecretUsed: input.SecretName + "/" + fieldName,
	}, nil
}

// --- Helper functions ---

// toolError creates a tool error result (not a protocol error).
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

// shellQuote quotes a string for use in a shell command.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// If the string doesn't contain special chars, return as-is
	safe := true
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/' || c == ':' || c == '@') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// --- realDaemonClient ---

// realDaemonClient wraps daemon.Client to implement FullDaemonClient.
type realDaemonClient struct {
	mu          sync.Mutex
	client      *daemon.Client
	selfBin     string
	cacheTTLSec int
}

// NewRealDaemonClient creates a FullDaemonClient backed by the real daemon.
func NewRealDaemonClient() FullDaemonClient {
	selfBin, _ := os.Executable()
	return &realDaemonClient{
		client:  daemon.NewClient(daemon.SocketPath()),
		selfBin: selfBin,
		cacheTTLSec: 3600,
	}
}

// NewRealDaemonClientWithConfig creates a FullDaemonClient with specified TTL.
func NewRealDaemonClientWithConfig(cacheTTLSec int) FullDaemonClient {
	selfBin, _ := os.Executable()
	return &realDaemonClient{
		client:  daemon.NewClient(daemon.SocketPath()),
		selfBin: selfBin,
		cacheTTLSec: cacheTTLSec,
	}
}

func (r *realDaemonClient) IsRunning() bool {
	return r.client.IsRunning()
}

func (r *realDaemonClient) StatusInfo() (*DaemonStatusResult, error) {
	status, err := r.client.Status()
	if err != nil {
		return nil, err
	}
	return &DaemonStatusResult{
		Running:    true,
		Uptime:     status.Uptime,
		EntryCount: status.EntryCount,
		SocketPath: status.SocketPath,
		PID:        status.PID,
	}, nil
}

func (r *realDaemonClient) Get(secretName, vault string) (map[string]string, error) {
	return r.client.Get(secretName, vault)
}

func (r *realDaemonClient) Store(secretName, vault string, fields map[string]string, ttl int) error {
	return r.client.Store(secretName, vault, fields, ttl)
}

func (r *realDaemonClient) EnsureRunning() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client.IsRunning() {
		return nil
	}
	client, err := daemon.EnsureDaemon(r.selfBin, r.cacheTTLSec)
	if err != nil {
		return err
	}
	r.client = client
	return nil
}
