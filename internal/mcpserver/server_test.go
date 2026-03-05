package mcpserver

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// --- Mock implementations ---

type mockDaemonClient struct {
	running    bool
	statusInfo *DaemonStatusResult
	statusErr  error
	cache      map[string]map[string]string // key = "name:vault"
	storeErr   error
	ensureErr  error
}

func newMockDaemonClient(running bool) *mockDaemonClient {
	return &mockDaemonClient{
		running: running,
		cache:   make(map[string]map[string]string),
	}
}

func (m *mockDaemonClient) cacheKey(name, vault string) string {
	return name + ":" + vault
}

func (m *mockDaemonClient) IsRunning() bool {
	return m.running
}

func (m *mockDaemonClient) StatusInfo() (*DaemonStatusResult, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	if m.statusInfo != nil {
		return m.statusInfo, nil
	}
	return &DaemonStatusResult{
		Running:    true,
		Uptime:     "1h0m0s",
		EntryCount: len(m.cache),
		SocketPath: "/tmp/test.sock",
		PID:        12345,
	}, nil
}

func (m *mockDaemonClient) Get(secretName, vault string) (map[string]string, error) {
	key := m.cacheKey(secretName, vault)
	if fields, ok := m.cache[key]; ok {
		return fields, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockDaemonClient) Store(secretName, vault string, fields map[string]string, ttl int) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	key := m.cacheKey(secretName, vault)
	m.cache[key] = fields
	return nil
}

func (m *mockDaemonClient) EnsureRunning() error {
	if m.ensureErr != nil {
		return m.ensureErr
	}
	m.running = true
	return nil
}

type mockProxyClient struct {
	searchResults []SearchResultItem
	searchErr     error
	fieldsResult  *FieldsResult
	fieldsErr     error
	requestResult *RequestResult
	requestErr    error
}

func (m *mockProxyClient) Search(query string, limit int) ([]SearchResultItem, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	return m.searchResults, nil
}

func (m *mockProxyClient) GetFields(secretName, vault string) (*FieldsResult, error) {
	if m.fieldsErr != nil {
		return nil, m.fieldsErr
	}
	return m.fieldsResult, nil
}

func (m *mockProxyClient) Request(_ context.Context, secretName, vault, reason string) (*RequestResult, error) {
	if m.requestErr != nil {
		return nil, m.requestErr
	}
	return m.requestResult, nil
}

// --- daemon_status tests ---

func TestHandleDaemonStatus_NotRunning(t *testing.T) {
	dc := newMockDaemonClient(false)
	result, output, err := handleDaemonStatus(context.Background(), dc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result (auto-construct from output)")
	}
	if output.Running {
		t.Error("expected running=false")
	}
	if output.EntryCount != 0 {
		t.Errorf("expected entry_count=0, got %d", output.EntryCount)
	}
}

func TestHandleDaemonStatus_Running(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.statusInfo = &DaemonStatusResult{
		Running:    true,
		Uptime:     "2h30m",
		EntryCount: 5,
		SocketPath: "/run/user/1000/secret-gate.sock",
		PID:        9999,
	}
	result, output, err := handleDaemonStatus(context.Background(), dc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if !output.Running {
		t.Error("expected running=true")
	}
	if output.Uptime != "2h30m" {
		t.Errorf("expected uptime 2h30m, got %s", output.Uptime)
	}
	if output.EntryCount != 5 {
		t.Errorf("expected 5 entries, got %d", output.EntryCount)
	}
	if output.PID != 9999 {
		t.Errorf("expected PID 9999, got %d", output.PID)
	}
}

func TestHandleDaemonStatus_StatusError(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.statusErr = fmt.Errorf("socket broken")
	result, _, err := handleDaemonStatus(context.Background(), dc)
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result (tool error)")
	}
	if !result.IsError {
		t.Error("expected IsError=true")
	}
}

// --- search_secrets tests ---

func TestHandleSearchSecrets_EmptyQuery(t *testing.T) {
	pc := &mockProxyClient{}
	result, _, err := handleSearchSecrets(context.Background(), pc, SearchSecretsInput{Query: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for empty query")
	}
}

func TestHandleSearchSecrets_Success(t *testing.T) {
	pc := &mockProxyClient{
		searchResults: []SearchResultItem{
			{SecretName: "db-creds", VaultName: "Infrastructure", Score: 0.95, MatchType: "exact"},
			{SecretName: "db-backup-key", VaultName: "Backups", Score: 0.7, MatchType: "prefix"},
		},
	}
	result, output, err := handleSearchSecrets(context.Background(), pc, SearchSecretsInput{Query: "db", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.Query != "db" {
		t.Errorf("expected query='db', got %q", output.Query)
	}
	if output.Count != 2 {
		t.Errorf("expected count=2, got %d", output.Count)
	}
	if len(output.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(output.Results))
	}
	if output.Results[0].SecretName != "db-creds" {
		t.Errorf("expected first result 'db-creds', got %q", output.Results[0].SecretName)
	}
}

func TestHandleSearchSecrets_ProxyError(t *testing.T) {
	pc := &mockProxyClient{searchErr: fmt.Errorf("server unreachable")}
	result, _, err := handleSearchSecrets(context.Background(), pc, SearchSecretsInput{Query: "ssh"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error")
	}
}

func TestHandleSearchSecrets_DefaultLimit(t *testing.T) {
	pc := &mockProxyClient{searchResults: []SearchResultItem{}}
	result, output, err := handleSearchSecrets(context.Background(), pc, SearchSecretsInput{Query: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.Count != 0 {
		t.Errorf("expected count=0, got %d", output.Count)
	}
}

// --- inspect_fields tests ---

func TestHandleInspectFields_EmptyName(t *testing.T) {
	pc := &mockProxyClient{}
	result, _, err := handleInspectFields(context.Background(), pc, InspectFieldsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for empty secret_name")
	}
}

func TestHandleInspectFields_Success(t *testing.T) {
	pc := &mockProxyClient{
		fieldsResult: &FieldsResult{
			SecretName: "db-creds",
			VaultName:  "Infrastructure",
			Fields: []FieldInfo{
				{Label: "username", Type: "STRING"},
				{Label: "password", Type: "CONCEALED"},
				{Label: "hostname", Type: "STRING"},
			},
		},
	}
	result, output, err := handleInspectFields(context.Background(), pc, InspectFieldsInput{SecretName: "db-creds"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.SecretName != "db-creds" {
		t.Errorf("expected secret_name='db-creds', got %q", output.SecretName)
	}
	if len(output.Fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(output.Fields))
	}
	if output.Fields[1].Label != "password" || output.Fields[1].Type != "CONCEALED" {
		t.Errorf("unexpected second field: %+v", output.Fields[1])
	}
}

func TestHandleInspectFields_ProxyError(t *testing.T) {
	pc := &mockProxyClient{fieldsErr: fmt.Errorf("not found")}
	result, _, err := handleInspectFields(context.Background(), pc, InspectFieldsInput{SecretName: "nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error")
	}
}

// --- request_secret tests ---

func TestHandleRequestSecret_EmptyName(t *testing.T) {
	dc := newMockDaemonClient(true)
	pc := &mockProxyClient{}
	result, _, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for empty secret_name")
	}
}

func TestHandleRequestSecret_EmptyReason(t *testing.T) {
	dc := newMockDaemonClient(true)
	pc := &mockProxyClient{}
	result, _, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{SecretName: "my-secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for empty reason")
	}
}

func TestHandleRequestSecret_CacheHit(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.cache["my-secret:"] = map[string]string{
		"username": "admin",
		"password": "secret123",
	}
	pc := &mockProxyClient{}

	result, output, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{SecretName: "my-secret", Reason: "need creds for deploy"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.Status != "approved" {
		t.Errorf("expected status=approved, got %q", output.Status)
	}
	if !output.Cached {
		t.Error("expected cached=true")
	}
	if len(output.FieldsAvailable) != 2 {
		t.Errorf("expected 2 fields available, got %d", len(output.FieldsAvailable))
	}
	// CRITICAL: output must NOT contain secret values
	if output.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestHandleRequestSecret_CacheMiss_Approved(t *testing.T) {
	dc := newMockDaemonClient(true)
	pc := &mockProxyClient{
		requestResult: &RequestResult{
			Status:          "approved",
			SecretName:      "new-secret",
			Cached:          true,
			FieldsAvailable: []string{"key1", "key2"},
			Message:         "Secret approved and cached.",
		},
	}

	result, output, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{
		SecretName: "new-secret",
		Reason:     "deploying",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.Status != "approved" {
		t.Errorf("expected status=approved, got %q", output.Status)
	}
	if !output.Cached {
		t.Error("expected cached=true")
	}
}

func TestHandleRequestSecret_Denied(t *testing.T) {
	dc := newMockDaemonClient(false)
	pc := &mockProxyClient{
		requestResult: &RequestResult{
			Status:     "denied",
			SecretName: "forbidden-secret",
			Cached:     false,
			Message:    "Request was denied.",
		},
	}

	result, output, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{SecretName: "forbidden-secret", Reason: "testing denied flow"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.Status != "denied" {
		t.Errorf("expected status=denied, got %q", output.Status)
	}
	if output.Cached {
		t.Error("expected cached=false")
	}
}

func TestHandleRequestSecret_ProxyError(t *testing.T) {
	dc := newMockDaemonClient(false)
	pc := &mockProxyClient{requestErr: fmt.Errorf("network error")}

	result, _, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{SecretName: "my-secret", Reason: "testing proxy error"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error")
	}
}

func TestHandleRequestSecret_DoesNotReturnSecretValues(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.cache["sensitive:vault1"] = map[string]string{
		"api_key":  "sk-1234567890abcdef",
		"password": "P@ssw0rd!",
	}
	pc := &mockProxyClient{}

	_, output, err := handleRequestSecret(context.Background(), dc, pc, RequestSecretInput{SecretName: "sensitive", Vault: "vault1", Reason: "checking for leaks"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no secret values leak
	outputStr := fmt.Sprintf("%+v", output)
	if strings.Contains(outputStr, "sk-1234567890abcdef") {
		t.Error("SECRET VALUE LEAKED: api_key value found in output")
	}
	if strings.Contains(outputStr, "P@ssw0rd!") {
		t.Error("SECRET VALUE LEAKED: password value found in output")
	}
	// Field names are OK to return
	foundAPIKey := false
	foundPassword := false
	for _, f := range output.FieldsAvailable {
		if f == "api_key" {
			foundAPIKey = true
		}
		if f == "password" {
			foundPassword = true
		}
	}
	if !foundAPIKey || !foundPassword {
		t.Error("expected field names to be listed")
	}
}

// --- exec_with_secret tests ---

func TestHandleExecWithSecret_MissingFields(t *testing.T) {
	dc := newMockDaemonClient(true)
	ctx := context.Background()

	tests := []struct {
		name  string
		input ExecWithSecretInput
	}{
		{"empty secret_name", ExecWithSecretInput{Field: "f", EnvVar: "E", Command: "echo"}},
		{"empty field", ExecWithSecretInput{SecretName: "s", EnvVar: "E", Command: "echo"}},
		{"empty env_var", ExecWithSecretInput{SecretName: "s", Field: "f", Command: "echo"}},
		{"empty command", ExecWithSecretInput{SecretName: "s", Field: "f", EnvVar: "E"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := handleExecWithSecret(ctx, dc, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatal("expected tool error")
			}
		})
	}
}

func TestHandleExecWithSecret_DaemonNotRunning(t *testing.T) {
	dc := newMockDaemonClient(false)
	result, _, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "s", Field: "f", EnvVar: "E", Command: "echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error")
	}
}

func TestHandleExecWithSecret_NotCached(t *testing.T) {
	dc := newMockDaemonClient(true)
	result, _, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "uncached-secret", Field: "password", EnvVar: "DB_PASS", Command: "echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for uncached secret")
	}
}

func TestHandleExecWithSecret_FieldNotFound(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.cache["my-secret:"] = map[string]string{
		"username": "admin",
		"password": "secret",
	}

	result, _, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "my-secret",
		Field:  "nonexistent",
		EnvVar:     "SECRET",
		Command:    "echo test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for missing field")
	}
}

func TestHandleExecWithSecret_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	dc := newMockDaemonClient(true)
	dc.cache["my-secret:"] = map[string]string{
		"password": "s3cret",
	}

	result, output, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "my-secret",
		Field:  "password",
		EnvVar:     "MY_SECRET_PASSWORD",
		Command:    "echo $MY_SECRET_PASSWORD",
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if output.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d. stderr: %s", output.ExitCode, output.Stderr)
	}
	if strings.TrimSpace(output.Stdout) != "s3cret" {
		t.Errorf("expected stdout='s3cret', got %q", strings.TrimSpace(output.Stdout))
	}
	if output.SecretUsed != "my-secret/password" {
		t.Errorf("expected secret_used='my-secret/password', got %q", output.SecretUsed)
	}
}

func TestHandleExecWithSecret_CommandFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	dc := newMockDaemonClient(true)
	dc.cache["my-secret:"] = map[string]string{
		"key": "value",
	}

	result, output, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "my-secret",
		Field:  "key",
		EnvVar:     "K",
		Command:    "exit 42",
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result (exit code conveyed in output)")
	}
	if output.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", output.ExitCode)
	}
}

func TestHandleExecWithSecret_SecretNotInOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	dc := newMockDaemonClient(true)
	dc.cache["cred:"] = map[string]string{
		"token": "supersecretvalue",
	}

	// The command doesn't echo the secret, so it shouldn't appear in output
	result, output, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "cred",
		Field:  "token",
		EnvVar:     "AUTH_TOKEN",
		Command:    "echo 'done'",
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if strings.Contains(output.Stdout, "supersecretvalue") {
		t.Error("secret value should not appear in stdout when command doesn't print it")
	}
}

func TestHandleExecWithSecret_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	dc := newMockDaemonClient(true)
	dc.cache["my-secret:"] = map[string]string{
		"key": "val",
	}

	tmpDir := os.TempDir()
	result, output, err := handleExecWithSecret(context.Background(), dc, ExecWithSecretInput{
		SecretName: "my-secret",
		Field:  "key",
		EnvVar:     "K",
		Command:    "pwd",
		WorkingDir: tmpDir,
		TimeoutSec: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result")
	}
	if !strings.Contains(strings.TrimSpace(output.Stdout), "tmp") {
		t.Errorf("expected output to contain tmp dir, got %q", output.Stdout)
	}
}

// --- ssh_with_secret tests ---

func TestHandleSSHWithSecret_MissingFields(t *testing.T) {
	dc := newMockDaemonClient(true)
	cfg := Config{SSHAgent: true, CacheTTLSec: 3600}
	ctx := context.Background()

	tests := []struct {
		name  string
		input SSHWithSecretInput
	}{
		{"empty secret_name", SSHWithSecretInput{Host: "example.com"}},
		{"empty host", SSHWithSecretInput{SecretName: "ssh-key"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := handleSSHWithSecret(ctx, dc, cfg, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || !result.IsError {
				t.Fatal("expected tool error")
			}
		})
	}
}

func TestHandleSSHWithSecret_DaemonNotRunning(t *testing.T) {
	dc := newMockDaemonClient(false)
	cfg := Config{SSHAgent: true, CacheTTLSec: 3600}
	result, _, err := handleSSHWithSecret(context.Background(), dc, cfg, SSHWithSecretInput{
		SecretName: "ssh-key", Host: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error")
	}
}

func TestHandleSSHWithSecret_NotCached(t *testing.T) {
	dc := newMockDaemonClient(true)
	cfg := Config{SSHAgent: true, CacheTTLSec: 3600}
	result, _, err := handleSSHWithSecret(context.Background(), dc, cfg, SSHWithSecretInput{
		SecretName: "nonexistent-key", Host: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for uncached secret")
	}
}

func TestHandleSSHWithSecret_NoSSHKeyInFields(t *testing.T) {
	dc := newMockDaemonClient(true)
	dc.cache["not-an-ssh-key:"] = map[string]string{
		"username": "admin",
		"password": "p@ss",
	}
	cfg := Config{SSHAgent: true, CacheTTLSec: 3600}

	result, _, err := handleSSHWithSecret(context.Background(), dc, cfg, SSHWithSecretInput{
		SecretName: "not-an-ssh-key", Host: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected tool error for no SSH key")
	}
}

// --- executor tests ---

func TestExecCommand_SimpleEcho(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	result, err := execCommand(context.Background(), "echo hello", nil, "", 5*1000000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if strings.TrimSpace(result.Stdout) != "hello" {
		t.Errorf("expected stdout='hello', got %q", strings.TrimSpace(result.Stdout))
	}
}

func TestExecCommand_EnvVarInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	envVars := map[string]string{
		"TEST_SECRET": "my_value",
	}
	result, err := execCommand(context.Background(), "echo $TEST_SECRET", envVars, "", 5*1000000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "my_value" {
		t.Errorf("expected stdout='my_value', got %q", strings.TrimSpace(result.Stdout))
	}
}

func TestExecCommand_NonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	result, err := execCommand(context.Background(), "exit 7", nil, "", 5*1000000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 7 {
		t.Errorf("expected exit code 7, got %d", result.ExitCode)
	}
}

func TestExecCommand_Stderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	result, err := execCommand(context.Background(), "echo error_msg >&2", nil, "", 5*1000000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Stderr, "error_msg") {
		t.Errorf("expected stderr to contain 'error_msg', got %q", result.Stderr)
	}
}

func TestExecCommand_MultipleEnvVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	envVars := map[string]string{
		"VAR_A": "alpha",
		"VAR_B": "beta",
	}
	result, err := execCommand(context.Background(), "echo ${VAR_A}_${VAR_B}", envVars, "", 5*1000000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "alpha_beta" {
		t.Errorf("expected 'alpha_beta', got %q", strings.TrimSpace(result.Stdout))
	}
}

// --- shellQuote tests ---

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "''"},
		{"simple", "simple"},
		{"with space", "'with space'"},
		{"it's", "'it'\\''s'"},
		{"host.example.com", "host.example.com"},
		{"user@host", "user@host"},
		{"-o StrictHostKeyChecking=no", "'-o StrictHostKeyChecking=no'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.expected {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// --- Server construction test ---

func TestNew_CreatesServer(t *testing.T) {
	dc := newMockDaemonClient(true)
	pc := &mockProxyClient{}
	cfg := Config{
		ServerURL:   "http://localhost:8080",
		CacheTTLSec: 3600,
		SSHAgent:    true,
	}

	server := New(cfg, dc, pc)
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}
