package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestIntegration_FullFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	// 1. Create mock HTTP proxy server
	var mockURL string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(searchResponse{
				Results: []SearchResultItem{
					{SecretName: "test-key", VaultName: "test-vault", Score: 1.0, MatchType: "exact"},
				},
				Query: "test",
			})

		case r.URL.Path == "/fields" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(fieldsResponse{
				SecretName: "test-key",
				VaultName:  "test-vault",
				Fields: []FieldInfo{
					{Label: "password", Type: "concealed"},
				},
			})

		case r.URL.Path == "/request" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(requestResponse{
				Token:     "test-token",
				StatusURL: mockURL + "/status/test-token",
				ExpiresAt: "2099-01-01T00:00:00Z",
			})

		case r.URL.Path == "/status/test-token" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(statusResponse{
				Status:    "approved",
				SecretURL: mockURL + "/secret/test-token",
			})

		case r.URL.Path == "/secret/test-token" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(secretResponse{
				Secret: map[string]string{"password": "test-value"},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()
	mockURL = mockServer.URL

	// 2. Create mock daemon client
	dc := newMockDaemonClient(true)

	// 3. Create real httpProxyClient pointing to mock server
	pc := NewHTTPProxyClient(mockServer.URL, dc, 3600, false)

	ctx := context.Background()

	// 4. Test search_secrets
	t.Run("search_secrets", func(t *testing.T) {
		result, output, err := handleSearchSecrets(ctx, pc, SearchSecretsInput{Query: "test", Limit: 5})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Fatalf("expected nil result, got tool error: %+v", result)
		}
		if output.Count != 1 {
			t.Errorf("expected 1 result, got %d", output.Count)
		}
		if output.Results[0].SecretName != "test-key" {
			t.Errorf("expected secret_name='test-key', got %q", output.Results[0].SecretName)
		}
		if output.Results[0].VaultName != "test-vault" {
			t.Errorf("expected vault_name='test-vault', got %q", output.Results[0].VaultName)
		}
		if output.Results[0].MatchType != "exact" {
			t.Errorf("expected match_type='exact', got %q", output.Results[0].MatchType)
		}
	})

	// 5. Test inspect_fields
	t.Run("inspect_fields", func(t *testing.T) {
		result, output, err := handleInspectFields(ctx, pc, InspectFieldsInput{SecretName: "test-key"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Fatalf("expected nil result, got tool error: %+v", result)
		}
		if output.SecretName != "test-key" {
			t.Errorf("expected secret_name='test-key', got %q", output.SecretName)
		}
		if len(output.Fields) != 1 {
			t.Fatalf("expected 1 field, got %d", len(output.Fields))
		}
		if output.Fields[0].Label != "password" {
			t.Errorf("expected field label='password', got %q", output.Fields[0].Label)
		}
		if output.Fields[0].Type != "concealed" {
			t.Errorf("expected field type='concealed', got %q", output.Fields[0].Type)
		}
	})

	// 6. Test request_secret (full polling flow through real httpProxyClient)
	t.Run("request_secret", func(t *testing.T) {
		result, output, err := handleRequestSecret(ctx, dc, pc, RequestSecretInput{
			SecretName: "test-key",
			Reason:     "integration test",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Fatalf("expected nil result, got tool error: %+v", result)
		}
		if output.Status != "approved" {
			t.Errorf("expected status='approved', got %q", output.Status)
		}
		if !output.Cached {
			t.Error("expected cached=true")
		}
		if len(output.FieldsAvailable) != 1 || output.FieldsAvailable[0] != "password" {
			t.Errorf("expected fields_available=['password'], got %v", output.FieldsAvailable)
		}

		// Verify the secret was actually cached in the daemon
		cached, err := dc.Get("test-key", "")
		if err != nil {
			t.Fatalf("secret not cached in daemon: %v", err)
		}
		if cached["password"] != "test-value" {
			t.Errorf("expected cached password='test-value', got %q", cached["password"])
		}
	})

	// 7. Test exec_with_secret using the cached secret
	t.Run("exec_with_secret", func(t *testing.T) {
		// The secret was cached by the request_secret step above,
		// but also pre-populate to make this test independent
		dc.cache["test-key:"] = map[string]string{"password": "test-value"}

		result, output, err := handleExecWithSecret(ctx, dc, ExecWithSecretInput{
			SecretName: "test-key",
			Field:      "password",
			EnvVar:     "TEST_SECRET",
			Command:    "printenv TEST_SECRET",
			TimeoutSec: 5,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Fatalf("expected nil result, got tool error: %+v", result)
		}
		if output.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d. stderr: %s", output.ExitCode, output.Stderr)
		}
		if strings.TrimSpace(output.Stdout) != "test-value" {
			t.Errorf("expected stdout='test-value', got %q", strings.TrimSpace(output.Stdout))
		}
		if output.SecretUsed != "test-key/password" {
			t.Errorf("expected secret_used='test-key/password', got %q", output.SecretUsed)
		}
	})
}
