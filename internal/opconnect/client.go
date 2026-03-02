package opconnect

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Client wraps the 1Password Connect API
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Item represents a 1Password item
type Item struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Vault   Vault   `json:"vault"`
	Fields  []Field `json:"fields"`
	Version int     `json:"version"`
}

// Vault represents a 1Password vault reference
type Vault struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Field represents a field in a 1Password item
type Field struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

// New creates a new 1Password Connect client
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetVaults returns all accessible vaults
func (c *Client) GetVaults() ([]Vault, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/v1/vaults", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var vaults []Vault
	if err := json.NewDecoder(resp.Body).Decode(&vaults); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return vaults, nil
}

// GetItemByTitle fetches an item by vault ID and item title
func (c *Client) GetItemByTitle(vaultID, itemTitle string) (*Item, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/items?filter=title eq \"%s\"", c.baseURL, vaultID, itemTitle)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var items []Item
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("item not found: %s", itemTitle)
	}

	// Get the full item with all fields
	return c.GetItem(vaultID, items[0].ID)
}

// GetItem fetches a full item by vault ID and item ID
func (c *Client) GetItem(vaultID, itemID string) (*Item, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/items/%s", c.baseURL, vaultID, itemID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var item Item
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &item, nil
}

// GetSecret retrieves a secret item and returns it as a map of field labels to values
func (c *Client) GetSecret(vaultName, itemTitle string) (map[string]string, error) {
	// First, find the vault ID by name
	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var vaultID string
	for _, v := range vaults {
		if v.Name == vaultName || v.ID == vaultName {
			vaultID = v.ID
			break
		}
	}

	if vaultID == "" {
		return nil, fmt.Errorf("vault not found: %s", vaultName)
	}

	// Get the item
	item, err := c.GetItemByTitle(vaultID, itemTitle)
	if err != nil {
		return nil, fmt.Errorf("getting item: %w", err)
	}

	// Convert fields to a map
	fields := make(map[string]string)
	for _, f := range item.Fields {
		if f.Label != "" {
			fields[f.Label] = f.Value
		}
	}

	return fields, nil
}

// HealthCheck verifies connectivity to 1Password Connect
func (c *Client) HealthCheck() error {
	req, err := http.NewRequest("GET", c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy status: %d", resp.StatusCode)
	}

	return nil
}

// SearchResult represents a fuzzy search match
type SearchResult struct {
	Item       Item    `json:"item"`
	VaultName  string  `json:"vault_name"`
	VaultID    string  `json:"vault_id"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"` // "exact", "prefix", "contains", "fuzzy"
}

// FieldInfo holds metadata about a field without its value
type FieldInfo struct {
	Label string `json:"label"`
	Type  string `json:"type"`
}

// GetItemFields returns field metadata for an item without values
func (c *Client) GetItemFields(vaultName, itemTitle string) ([]FieldInfo, string, string, error) {
	var item *Item
	var actualVault, actualTitle string

	if vaultName == "" || vaultName == "_auto_" {
		// Cross-vault search
		results, err := c.SearchSecrets(itemTitle, 5)
		if err != nil {
			return nil, "", "", fmt.Errorf("searching secrets: %w", err)
		}
		if len(results) == 0 {
			return nil, "", "", fmt.Errorf("item not found: %s", itemTitle)
		}
		best := results[0]
		if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
			var suggestions []string
			for _, r := range results {
				suggestions = append(suggestions, r.Item.Title)
			}
			return nil, "", "", fmt.Errorf("no exact match for '%s'. Did you mean: %s", itemTitle, strings.Join(suggestions, ", "))
		}
		item, err = c.GetItem(best.VaultID, best.Item.ID)
		if err != nil {
			return nil, "", "", fmt.Errorf("getting item: %w", err)
		}
		actualVault = best.VaultName
		actualTitle = best.Item.Title
	} else {
		// Direct vault lookup
		vaults, err := c.GetVaults()
		if err != nil {
			return nil, "", "", fmt.Errorf("listing vaults: %w", err)
		}
		var vaultID string
		for _, v := range vaults {
			if v.Name == vaultName || v.ID == vaultName {
				vaultID = v.ID
				actualVault = v.Name
				break
			}
		}
		if vaultID == "" {
			return nil, "", "", fmt.Errorf("vault not found: %s", vaultName)
		}
		item, err = c.GetItemByTitle(vaultID, itemTitle)
		if err != nil {
			return nil, "", "", fmt.Errorf("getting item: %w", err)
		}
		actualTitle = item.Title
	}

	var fields []FieldInfo
	for _, f := range item.Fields {
		if f.Label != "" {
			fields = append(fields, FieldInfo{
				Label: f.Label,
				Type:  f.Type,
			})
		}
	}

	return fields, actualVault, actualTitle, nil
}

// ListItemsInVault returns all items in a vault (titles only, no fields)
func (c *Client) ListItemsInVault(vaultID string) ([]Item, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/items", c.baseURL, vaultID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var items []Item
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return items, nil
}

// SearchSecrets searches for secrets across all vaults using fuzzy matching
func (c *Client) SearchSecrets(query string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 10
	}

	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var results []SearchResult
	queryLower := strings.ToLower(query)

	for _, vault := range vaults {
		items, err := c.ListItemsInVault(vault.ID)
		if err != nil {
			// Skip vaults we can't access
			continue
		}

		for _, item := range items {
			titleLower := strings.ToLower(item.Title)
			score, matchType := fuzzyScore(queryLower, titleLower)

			if score > 0 {
				results = append(results, SearchResult{
					Item:      item,
					VaultName: vault.Name,
					VaultID:   vault.ID,
					Score:     score,
					MatchType: matchType,
				})
			}
		}
	}

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	// Limit results
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// FindSecretAcrossVaults finds a secret by name across all vaults
// Returns the best match or an error if not found
func (c *Client) FindSecretAcrossVaults(secretName string) (map[string]string, string, string, error) {
	results, err := c.SearchSecrets(secretName, 5)
	if err != nil {
		return nil, "", "", fmt.Errorf("searching secrets: %w", err)
	}

	if len(results) == 0 {
		return nil, "", "", fmt.Errorf("secret not found: %s", secretName)
	}

	// Use the best match
	best := results[0]

	// Only accept exact or very close matches for actual retrieval
	if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
		// Return suggestions instead
		var suggestions []string
		for _, r := range results {
			suggestions = append(suggestions, r.Item.Title)
		}
		return nil, "", "", fmt.Errorf("no exact match for '%s'. Did you mean: %s", secretName, strings.Join(suggestions, ", "))
	}

	// Get the full item
	item, err := c.GetItem(best.VaultID, best.Item.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("getting item: %w", err)
	}

	// Convert fields to a map
	fields := make(map[string]string)
	for _, f := range item.Fields {
		if f.Label != "" {
			fields[f.Label] = f.Value
		}
	}

	return fields, best.VaultName, best.Item.Title, nil
}

// fuzzyScore calculates a match score between query and target
// Returns score (0-1) and match type
func fuzzyScore(query, target string) (float64, string) {
	// Exact match
	if query == target {
		return 1.0, "exact"
	}

	// Prefix match
	if strings.HasPrefix(target, query) {
		return 0.9, "prefix"
	}

	// Contains match
	if strings.Contains(target, query) {
		// Score based on position and length ratio
		idx := strings.Index(target, query)
		posScore := 1.0 - float64(idx)/float64(len(target))
		lenScore := float64(len(query)) / float64(len(target))
		return 0.7 * (posScore*0.5 + lenScore*0.5), "contains"
	}

	// Fuzzy match using Levenshtein-like scoring
	// Check if all query chars appear in order in target
	qi := 0
	matches := 0
	for ti := 0; ti < len(target) && qi < len(query); ti++ {
		if target[ti] == query[qi] {
			matches++
			qi++
		}
	}

	if qi == len(query) {
		// All query characters found in order
		score := float64(matches) / float64(max(len(query), len(target)))
		return score * 0.5, "fuzzy"
	}

	// Check word-based matching (e.g., "ssh" matches "homelab-ssh-key")
	queryWords := strings.FieldsFunc(query, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	targetWords := strings.FieldsFunc(target, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})

	wordMatches := 0
	for _, qw := range queryWords {
		for _, tw := range targetWords {
			if strings.Contains(tw, qw) || strings.Contains(qw, tw) {
				wordMatches++
				break
			}
		}
	}

	if wordMatches > 0 {
		score := float64(wordMatches) / float64(len(queryWords))
		return score * 0.4, "fuzzy"
	}

	return 0, ""
}
