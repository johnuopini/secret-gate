package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Polling and timeout constants for the approval flow.
const (
	defaultPollInterval = 5 * time.Second
	defaultPollTimeout  = 15 * time.Minute
)

// --- HTTP proxy client ---

// httpProxyClient implements ProxyClient using HTTP calls to the secret-gate server.
type httpProxyClient struct {
	serverURL   string
	dc          FullDaemonClient
	cacheTTLSec int
	httpClient  *http.Client
}

// NewHTTPProxyClient creates a ProxyClient that talks to the secret-gate server.
func NewHTTPProxyClient(serverURL string, dc FullDaemonClient, cacheTTLSec int) ProxyClient {
	return &httpProxyClient{
		serverURL:   serverURL,
		dc:          dc,
		cacheTTLSec: cacheTTLSec,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// --- Request/Response types for HTTP API ---

type searchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type searchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

type fieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

type fieldsResponse struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

type requestPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
	Machine    string `json:"machine"`
	Reason     string `json:"reason,omitempty"`
}

type requestResponse struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
}

type statusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type secretResponse struct {
	Secret map[string]string `json:"secret"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// --- ProxyClient implementation ---

func (p *httpProxyClient) Search(query string, limit int) ([]SearchResultItem, error) {
	payload := searchPayload{Query: query, Limit: limit}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling search request: %w", err)
	}

	resp, err := p.httpClient.Post(p.serverURL+"/search", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading search response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("search failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var searchResp searchResponse
	if err := json.Unmarshal(respBody, &searchResp); err != nil {
		return nil, fmt.Errorf("parsing search response: %w", err)
	}

	if searchResp.Results == nil {
		searchResp.Results = []SearchResultItem{}
	}

	return searchResp.Results, nil
}

func (p *httpProxyClient) GetFields(secretName, vault string) (*FieldsResult, error) {
	payload := fieldsPayload{SecretName: secretName, Vault: vault}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling fields request: %w", err)
	}

	resp, err := p.httpClient.Post(p.serverURL+"/fields", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("fields request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading fields response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("fields request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var fieldsResp fieldsResponse
	if err := json.Unmarshal(respBody, &fieldsResp); err != nil {
		return nil, fmt.Errorf("parsing fields response: %w", err)
	}

	return &FieldsResult{
		SecretName: fieldsResp.SecretName,
		VaultName:  fieldsResp.VaultName,
		Fields:     fieldsResp.Fields,
	}, nil
}

func (p *httpProxyClient) Request(ctx context.Context, secretName, vault, reason string) (*RequestResult, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "mcp-agent"
	}

	payload := requestPayload{
		SecretName: secretName,
		Vault:      vault,
		Machine:    hostname,
		Reason:     reason,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	// Step 1: Submit request
	resp, err := p.httpClient.Post(p.serverURL+"/request", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading request response: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		var errResp errorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var reqResp requestResponse
	if err := json.Unmarshal(respBody, &reqResp); err != nil {
		return nil, fmt.Errorf("parsing request response: %w", err)
	}

	// Step 2: Poll for approval with context and deadline
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	deadline := time.After(defaultPollTimeout)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return &RequestResult{
				Status:     "timeout",
				SecretName: secretName,
				Cached:     false,
				Message:    "Timed out waiting for approval.",
			}, nil
		case <-ticker.C:
			status, err := p.checkStatus(reqResp.StatusURL)
			if err != nil {
				continue
			}

			switch status.Status {
			case "pending":
				continue
			case "approved":
				// Step 3: Retrieve secret and cache it
				return p.retrieveAndCache(status.SecretURL, secretName, vault)
			case "denied":
				return &RequestResult{
					Status:     "denied",
					SecretName: secretName,
					Cached:     false,
					Message:    "Request was denied by the approver.",
				}, nil
			case "expired":
				return &RequestResult{
					Status:     "expired",
					SecretName: secretName,
					Cached:     false,
					Message:    "Request expired before approval.",
				}, nil
			default:
				return nil, fmt.Errorf("unknown status: %s", status.Status)
			}
		}
	}
}

func (p *httpProxyClient) checkStatus(url string) (*statusResponse, error) {
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("status check failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading status response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("status check failed with status %d", resp.StatusCode)
	}

	var status statusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("parsing status response: %w", err)
	}

	return &status, nil
}

func (p *httpProxyClient) retrieveAndCache(secretURL, secretName, vault string) (*RequestResult, error) {
	resp, err := p.httpClient.Get(secretURL)
	if err != nil {
		return nil, fmt.Errorf("secret retrieval failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading secret response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("secret retrieval failed with status %d", resp.StatusCode)
	}

	var secretResp secretResponse
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, fmt.Errorf("parsing secret response: %w", err)
	}

	// Build field names list (but NOT values)
	fieldNames := make([]string, 0, len(secretResp.Secret))
	for k := range secretResp.Secret {
		fieldNames = append(fieldNames, k)
	}

	result := &RequestResult{
		Status:          "approved",
		SecretName:      secretName,
		Cached:          true,
		FieldsAvailable: fieldNames,
		Message:         "Secret approved and cached. Use exec_with_secret or ssh_with_secret to use it.",
	}

	// Cache in daemon
	if p.dc != nil {
		if err := p.dc.EnsureRunning(); err != nil {
			result.Message = "Warning: secret approved but daemon failed to start: " + err.Error()
		} else if err := p.dc.Store(secretName, vault, secretResp.Secret, p.cacheTTLSec); err != nil {
			result.Message = "Warning: secret approved but caching failed: " + err.Error()
		}
	}

	return result, nil
}
