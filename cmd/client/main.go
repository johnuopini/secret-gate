package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/johnuopini/secret-gate/internal/clientconfig"
	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/johnuopini/secret-gate/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RequestPayload is sent to initiate a secret request
type RequestPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
	Machine    string `json:"machine"`
	Reason     string `json:"reason,omitempty"`
}

// SearchPayload is sent to search for secrets
type SearchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

// SearchResponse contains search results
type SearchResponse struct {
	Results []SearchResult `json:"results"`
	Query   string         `json:"query"`
}

// SearchResult is a single search result
type SearchResult struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// RequestResponse is returned when a request is created
type RequestResponse struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
}

// StatusResponse is returned when checking status
type StatusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

// SecretResponse contains the retrieved secret
type SecretResponse struct {
	Secret map[string]string `json:"secret"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// FieldsPayload is sent to inspect field metadata
type FieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

// FieldsResponse contains field metadata
type FieldsResponse struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

// FieldInfo holds field metadata
type FieldInfo struct {
	Label string `json:"label"`
	Type  string `json:"type"`
}

func main() {
	// Check for subcommands before flag parsing
	if len(os.Args) >= 2 && os.Args[1] == "daemon" {
		handleDaemonSubcommand(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "mcp" {
		handleMCPSubcommand()
		return
	}

	// Load client config
	cfg := clientconfig.Load()

	// Define flags
	server := flag.String("server", "", "Base URL of the secret-gate server (required)")
	secret := flag.String("secret", "", "Name of the secret to request")
	vault := flag.String("vault", "", "Name of the vault (optional)")
	reason := flag.String("reason", "", "Reason for requesting the secret")
	format := flag.String("format", "plain", "Output format: plain or json")
	field := flag.String("field", "", "Specific field to output (plain format only)")
	pollInterval := flag.Duration("poll-interval", 5*time.Second, "Interval between status polls")
	timeout := flag.Duration("timeout", 15*time.Minute, "Maximum time to wait for approval")
	search := flag.String("search", "", "Search for secrets matching this query")
	searchLimit := flag.Int("search-limit", 10, "Maximum number of search results")
	fields := flag.Bool("fields", false, "Show field names for a secret")
	noCache := flag.Bool("no-cache", false, "Bypass daemon cache for this request")

	flag.Parse()

	// Resolve server URL: flag > config
	if *server == "" {
		*server = cfg.ServerURL
	}

	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: --server is required (or set in config)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  Request secret:  secret-gate --server <url> --secret <name> [--vault <vault>]")
		fmt.Fprintln(os.Stderr, "  Search secrets:  secret-gate --server <url> --search <query>")
		fmt.Fprintln(os.Stderr, "  Inspect fields:  secret-gate --server <url> --secret <name> --fields")
		fmt.Fprintln(os.Stderr, "  Daemon control:  secret-gate daemon <start|stop|status|flush>")
		fmt.Fprintln(os.Stderr, "  MCP server:      secret-gate mcp")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Handle search mode (no caching)
	if *search != "" {
		results, err := searchSecrets(*server, *search, *searchLimit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching: %v\n", err)
			os.Exit(1)
		}

		if *format == "json" {
			output, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(output))
		} else {
			if len(results.Results) == 0 {
				fmt.Println("No results found.")
			} else {
				fmt.Printf("Search results for '%s':\n\n", results.Query)
				for i, r := range results.Results {
					fmt.Printf("%d. %s (vault: %s, match: %s, score: %.2f)\n",
						i+1, r.SecretName, r.VaultName, r.MatchType, r.Score)
				}
			}
		}
		return
	}

	// Handle fields mode (no caching)
	if *fields {
		if *secret == "" {
			fmt.Fprintln(os.Stderr, "Error: --secret is required with --fields")
			os.Exit(1)
		}

		result, err := getFields(*server, *secret, *vault)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting fields: %v\n", err)
			os.Exit(1)
		}

		if *format == "json" {
			output, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(output))
		} else {
			fmt.Printf("Fields for '%s' (vault: %s):\n\n", result.SecretName, result.VaultName)
			for _, f := range result.Fields {
				fmt.Printf("  %s (%s)\n", f.Label, f.Type)
			}
		}
		return
	}

	// Validate required flags for request mode
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: --secret is required (or use --search to find secrets)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  Request secret:  secret-gate --server <url> --secret <name> [--vault <vault>]")
		fmt.Fprintln(os.Stderr, "  Search secrets:  secret-gate --server <url> --search <query>")
		fmt.Fprintln(os.Stderr, "  Inspect fields:  secret-gate --server <url> --secret <name> --fields")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// --- Daemon cache integration ---
	var daemonClient *daemon.Client
	if !*noCache {
		selfBin, _ := os.Executable()
		cacheTTLSec := int(cfg.CacheTTL.Seconds())
		dc, err := daemon.EnsureDaemon(selfBin, cacheTTLSec)
		if err != nil {
			// Daemon failed to start — proceed without cache
			fmt.Fprintf(os.Stderr, "Warning: daemon cache unavailable: %v\n", err)
		} else {
			daemonClient = dc

			// Try cache lookup
			cached, err := dc.Get(*secret, *vault)
			if err == nil {
				fmt.Fprintf(os.Stderr, "Cache hit for %s\n", *secret)

				// Handle SSH agent (on cache hit, key may already be added)
				if cfg.SSHAgentIntegration {
					handleSSHAgent(cached, cfg)
				}

				outputSecret(cached, *format, *field)
				return
			}
		}
	}

	// --- Normal proxy flow (cache miss or no cache) ---

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	payload := RequestPayload{
		SecretName: *secret,
		Vault:      *vault,
		Machine:    hostname,
		Reason:     *reason,
	}

	reqResp, err := submitRequest(*server, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting request: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Request submitted. Waiting for approval...\n")
	fmt.Fprintf(os.Stderr, "Token: %s\n", reqResp.Token)
	fmt.Fprintf(os.Stderr, "Expires: %s\n", reqResp.ExpiresAt)

	deadline := time.Now().Add(*timeout)
	var secretURL string

	for time.Now().Before(deadline) {
		status, err := checkStatus(reqResp.StatusURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking status: %v\n", err)
			time.Sleep(*pollInterval)
			continue
		}

		switch status.Status {
		case "pending":
			fmt.Fprintf(os.Stderr, ".")
			time.Sleep(*pollInterval)
			continue
		case "approved":
			fmt.Fprintln(os.Stderr, "\nApproved!")
			secretURL = status.SecretURL
		case "denied":
			fmt.Fprintln(os.Stderr, "\nRequest denied.")
			os.Exit(1)
		case "expired":
			fmt.Fprintln(os.Stderr, "\nRequest expired.")
			os.Exit(1)
		default:
			fmt.Fprintf(os.Stderr, "\nUnknown status: %s\n", status.Status)
			os.Exit(1)
		}

		break
	}

	if secretURL == "" {
		fmt.Fprintln(os.Stderr, "\nTimeout waiting for approval.")
		os.Exit(1)
	}

	secretResp, err := retrieveSecret(secretURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret: %v\n", err)
		os.Exit(1)
	}

	// Cache the result in daemon
	if daemonClient != nil {
		cacheTTLSec := int(cfg.CacheTTL.Seconds())
		if err := daemonClient.Store(*secret, *vault, secretResp.Secret, cacheTTLSec); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cache secret: %v\n", err)
		}
	}

	// Handle SSH agent integration
	if cfg.SSHAgentIntegration {
		handleSSHAgent(secretResp.Secret, cfg)
	}

	outputSecret(secretResp.Secret, *format, *field)
}

// handleSSHAgent detects SSH private keys in fields and adds them to ssh-agent
func handleSSHAgent(fields map[string]string, cfg *clientconfig.Config) {
	fieldName, keyValue, found := daemon.FindSSHKeyField(fields)
	if !found {
		return
	}

	ttl := cfg.CacheTTL
	if err := daemon.AddToSSHAgent(keyValue, ttl); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to add SSH key to agent: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Added SSH key (%s) to ssh-agent (TTL: %s)\n", fieldName, ttl)
	}
}

// outputSecret prints the secret fields in the requested format
func outputSecret(secretFields map[string]string, format, field string) {
	if format == "json" {
		output, _ := json.MarshalIndent(secretFields, "", "  ")
		fmt.Println(string(output))
	} else {
		if field != "" {
			if val, ok := secretFields[field]; ok {
				fmt.Println(val)
			} else {
				fmt.Fprintf(os.Stderr, "Field not found: %s\n", field)
				fmt.Fprintf(os.Stderr, "Available fields: ")
				for k := range secretFields {
					fmt.Fprintf(os.Stderr, "%s ", k)
				}
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}
		} else {
			for k, v := range secretFields {
				fmt.Printf("%s=%s\n", k, v)
			}
		}
	}
}

// handleDaemonSubcommand processes daemon subcommands
func handleDaemonSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: secret-gate daemon <start|stop|status|flush|run>")
		os.Exit(1)
	}

	switch args[0] {
	case "run":
		// Internal: called by EnsureDaemon to start the background server
		runFlags := flag.NewFlagSet("daemon run", flag.ExitOnError)
		socket := runFlags.String("socket", daemon.SocketPath(), "Unix socket path")
		cacheTTL := runFlags.Int("cache-ttl", 3600, "Cache TTL in seconds")
		idleTimeout := runFlags.Int("idle-timeout", 300, "Idle timeout in seconds")
		runFlags.Parse(args[1:])

		if err := daemon.RunDaemon(*socket, *cacheTTL, *idleTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
			os.Exit(1)
		}

	case "start":
		cfg := clientconfig.Load()
		selfBin, _ := os.Executable()
		cacheTTLSec := int(cfg.CacheTTL.Seconds())
		client, err := daemon.EnsureDaemon(selfBin, cacheTTLSec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting daemon: %v\n", err)
			os.Exit(1)
		}
		status, _ := client.Status()
		fmt.Printf("Daemon running (PID: %d, socket: %s)\n", status.PID, status.SocketPath)

	case "stop":
		client := daemon.NewClient(daemon.SocketPath())
		if !client.IsRunning() {
			fmt.Println("Daemon is not running.")
			return
		}
		if err := client.StopDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping daemon: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Daemon stopped.")

	case "status":
		client := daemon.NewClient(daemon.SocketPath())
		if !client.IsRunning() {
			fmt.Println("Daemon is not running.")
			return
		}
		status, err := client.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Daemon running\n")
		fmt.Printf("  PID:      %d\n", status.PID)
		fmt.Printf("  Uptime:   %s\n", status.Uptime)
		fmt.Printf("  Entries:  %d\n", status.EntryCount)
		fmt.Printf("  Socket:   %s\n", status.SocketPath)

	case "flush":
		client := daemon.NewClient(daemon.SocketPath())
		if !client.IsRunning() {
			fmt.Println("Daemon is not running.")
			return
		}
		if err := client.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Cache flushed.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: secret-gate daemon <start|stop|status|flush>")
		os.Exit(1)
	}
}

// --- Existing helper functions (unchanged) ---

func submitRequest(server string, payload RequestPayload) (*RequestResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(server+"/request", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var reqResp RequestResponse
	if err := json.Unmarshal(respBody, &reqResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &reqResp, nil
}

func checkStatus(url string) (*StatusResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var status StatusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &status, nil
}

func retrieveSecret(url string) (*SecretResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var secretResp SecretResponse
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &secretResp, nil
}

func searchSecrets(server, query string, limit int) (*SearchResponse, error) {
	payload := SearchPayload{
		Query: query,
		Limit: limit,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(server+"/search", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var searchResp SearchResponse
	if err := json.Unmarshal(respBody, &searchResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &searchResp, nil
}

func getFields(server, secretName, vault string) (*FieldsResponse, error) {
	payload := FieldsPayload{
		SecretName: secretName,
		Vault:      vault,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(server+"/fields", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var fieldsResp FieldsResponse
	if err := json.Unmarshal(respBody, &fieldsResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &fieldsResp, nil
}

// handleMCPSubcommand starts the MCP server with stdio transport.
func handleMCPSubcommand() {
	cfg := clientconfig.Load()

	if cfg.ServerURL == "" {
		fmt.Fprintln(os.Stderr, "Error: server URL is required for MCP mode")
		fmt.Fprintln(os.Stderr, "Set SECRET_GATE_URL env var or configure server_url in ~/.config/secret-gate/config.json")
		os.Exit(1)
	}

	cacheTTLSec := int(cfg.CacheTTL.Seconds())
	if cacheTTLSec <= 0 {
		cacheTTLSec = 3600
	}

	// Create daemon client
	dc := mcpserver.NewRealDaemonClientWithConfig(cacheTTLSec)

	// Try to ensure daemon is running (non-fatal if it fails)
	_ = dc.EnsureRunning()

	// Create proxy client
	pc := mcpserver.NewHTTPProxyClient(cfg.ServerURL, dc, cacheTTLSec)

	// Create MCP server config
	mcpCfg := mcpserver.Config{
		ServerURL:   cfg.ServerURL,
		CacheTTLSec: cacheTTLSec,
		SSHAgent:    cfg.SSHAgentIntegration,
	}

	// Create and run MCP server
	server := mcpserver.New(mcpCfg, dc, pc)

	fmt.Fprintln(os.Stderr, "secret-gate MCP server starting (stdio transport)...")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}
