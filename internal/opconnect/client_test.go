package opconnect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeConnect serves one vault ("HomeLab") holding one item with the given
// title, answering the same routes 1Password Connect does.
func fakeConnect(t *testing.T, title string) *Client {
	t.Helper()

	item := Item{
		ID:    "item-1",
		Title: title,
		Fields: []Field{
			{ID: "f1", Type: "STRING", Label: "username", Value: "deploy"},
			{ID: "f2", Type: "CONCEALED", Label: "password", Value: "s3cret"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]Vault{{ID: "vault-1", Name: "HomeLab"}})
	})
	mux.HandleFunc("GET /v1/vaults/vault-1/items", func(w http.ResponseWriter, r *http.Request) {
		matches := []Item{}
		if r.URL.Query().Get("filter") == `title eq "`+title+`"` {
			matches = append(matches, Item{ID: item.ID, Title: item.Title})
		}
		json.NewEncoder(w).Encode(matches)
	})
	mux.HandleFunc("GET /v1/vaults/vault-1/items/item-1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(item)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return New(srv.URL, "test-token")
}

func TestGetSecret_NamedVault_ReturnsFieldValues(t *testing.T) {
	client := fakeConnect(t, "llm-proxy")

	secret, err := client.GetSecret("HomeLab", "llm-proxy")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	if secret["password"] != "s3cret" {
		t.Errorf("password = %q, want %q", secret["password"], "s3cret")
	}
}

func TestGetItemFields_NamedVault_ReturnsLabelsAndTypes(t *testing.T) {
	client := fakeConnect(t, "llm-proxy")

	fields, vault, title, err := client.GetItemFields("HomeLab", "llm-proxy")
	if err != nil {
		t.Fatalf("GetItemFields: %v", err)
	}

	if vault != "HomeLab" || title != "llm-proxy" {
		t.Errorf("resolved %q in %q, want %q in %q", title, vault, "llm-proxy", "HomeLab")
	}
	want := []FieldInfo{{Label: "username", Type: "STRING"}, {Label: "password", Type: "CONCEALED"}}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v, want %v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Errorf("fields[%d] = %v, want %v", i, fields[i], want[i])
		}
	}
}

func TestGetSecret_TitleWithReservedCharacters_FindsItem(t *testing.T) {
	client := fakeConnect(t, "db & cache #1")

	secret, err := client.GetSecret("HomeLab", "db & cache #1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	if secret["username"] != "deploy" {
		t.Errorf("username = %q, want %q", secret["username"], "deploy")
	}
}
