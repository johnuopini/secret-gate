package opconnect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// filterClause is one `title eq "..."` term of a Connect item filter.
var filterClause = regexp.MustCompile(`^title eq "(.*)"$`)

// fakeVault is one vault of the fake Connect.
type fakeVault struct {
	name       string
	titles     []string
	unreadable bool // listing its items fails
}

// fakeConnect serves one vault ("HomeLab") holding one item per given title.
func fakeConnect(t *testing.T, titles ...string) *Client {
	t.Helper()

	return fakeConnectVaults(t, fakeVault{name: "HomeLab", titles: titles})
}

// fakeConnectVaults serves the given vaults over the same routes 1Password
// Connect answers. Items are numbered across the vaults in the order given:
// item N has the ID "item-N" and the password "s3cret-N".
//
// Like Connect, it reads the items filter as `title eq "..."` terms joined by
// "or", and lists every item of a vault when there is no filter.
func fakeConnectVaults(t *testing.T, vaults ...fakeVault) *Client {
	t.Helper()

	mux := http.NewServeMux()
	listed := make([]Vault, len(vaults))
	n := 0
	for v, vault := range vaults {
		id := fmt.Sprintf("vault-%d", v+1)
		listed[v] = Vault{ID: id, Name: vault.name}

		items := make([]Item, len(vault.titles))
		for i, title := range vault.titles {
			n++
			items[i] = Item{
				ID:    fmt.Sprintf("item-%d", n),
				Title: title,
				Fields: []Field{
					{ID: "f1", Type: "STRING", Label: "username", Value: "deploy"},
					{ID: "f2", Type: "CONCEALED", Label: "password", Value: fmt.Sprintf("s3cret-%d", n)},
				},
			}
		}

		mux.HandleFunc("GET /v1/vaults/"+id+"/items", func(w http.ResponseWriter, r *http.Request) {
			if vault.unreadable {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			wanted := map[string]bool{}
			filter := r.URL.Query().Get("filter")
			for _, clause := range strings.Split(filter, " or ") {
				if m := filterClause.FindStringSubmatch(clause); m != nil {
					wanted[m[1]] = true
				}
			}

			matches := []Item{}
			for _, item := range items {
				if filter == "" || wanted[item.Title] {
					matches = append(matches, Item{ID: item.ID, Title: item.Title})
				}
			}
			json.NewEncoder(w).Encode(matches)
		})
		mux.HandleFunc("GET /v1/vaults/"+id+"/items/{id}", func(w http.ResponseWriter, r *http.Request) {
			for _, item := range items {
				if item.ID == r.PathValue("id") {
					json.NewEncoder(w).Encode(item)
					return
				}
			}
			http.NotFound(w, r)
		})
	}
	mux.HandleFunc("GET /v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(listed)
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

	if secret["password"] != "s3cret-1" {
		t.Errorf("password = %q, want %q", secret["password"], "s3cret-1")
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

func TestGetSecret_TitleWithADoubleQuote_FindsItem(t *testing.T) {
	client := fakeConnect(t, "other", `my "prod" key`)

	secret, err := client.GetSecret("HomeLab", `my "prod" key`)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}

	if secret["password"] != "s3cret-2" {
		t.Errorf("password = %q, want %q", secret["password"], "s3cret-2")
	}
}

func TestGetSecret_NameThatRewritesTheFilter_ReturnsNoOtherItem(t *testing.T) {
	// The approver is shown the requested name. A name that closes the quote
	// and adds its own term must not release the item that term points at.
	client := fakeConnect(t, "llm-proxy")

	secret, err := client.GetSecret("HomeLab", `no-such-item" or title eq "llm-proxy`)
	if err == nil {
		t.Fatalf("GetSecret released an item under another name: %v", secret)
	}
	if !strings.Contains(err.Error(), "item not found") {
		t.Errorf("error = %v, want item not found", err)
	}
}

func TestGetSecret_TwoItemsWithTheSameTitle_ReleasesNeither(t *testing.T) {
	client := fakeConnect(t, "db", "db")

	secret, err := client.GetSecret("HomeLab", "db")
	if err == nil {
		t.Fatalf("GetSecret picked one of two items titled db: %v", secret)
	}
	if !strings.Contains(err.Error(), "2 items") {
		t.Errorf("error = %v, want it to say 2 items share the title", err)
	}
}

func TestGetSecret_NoItemWithThatTitle_IsNotFound(t *testing.T) {
	client := fakeConnect(t, "llm-proxy")

	_, err := client.GetSecret("HomeLab", "llm")
	if err == nil || !strings.Contains(err.Error(), "item not found") {
		t.Errorf("error = %v, want item not found", err)
	}
}

func TestFindExactSecretAcrossVaults_ReturnsTheOneItemWithThatTitle(t *testing.T) {
	client := fakeConnectVaults(t,
		fakeVault{name: "HomeLab", titles: []string{"llm-proxy"}},
		fakeVault{name: "Kustom", titles: []string{"db"}},
	)

	secret, vault, err := client.FindExactSecretAcrossVaults("db")
	if err != nil {
		t.Fatalf("FindExactSecretAcrossVaults: %v", err)
	}
	if vault != "Kustom" || secret["password"] != "s3cret-2" {
		t.Errorf("found password %q in vault %q, want s3cret-2 in Kustom", secret["password"], vault)
	}
}

func TestFindExactSecretAcrossVaults_NameThatOnlyComesClose_ReturnsNothingAndNamesTheItem(t *testing.T) {
	client := fakeConnectVaults(t,
		fakeVault{name: "HomeLab", titles: []string{"db"}},
		fakeVault{name: "Kustom", titles: []string{"llm-proxy"}},
	)

	for _, name := range []string{"llm", "LLM-Proxy"} {
		secret, _, err := client.FindExactSecretAcrossVaults(name)
		if err == nil {
			t.Fatalf("FindExactSecretAcrossVaults(%q) settled for another item: %v", name, secret)
		}
		if !strings.Contains(err.Error(), `"llm-proxy"`) {
			t.Errorf("error for %q = %v, want it to name llm-proxy as the closest title", name, err)
		}
	}
}

func TestFindExactSecretAcrossVaults_SameTitleInTwoVaults_ReturnsNeither(t *testing.T) {
	client := fakeConnectVaults(t,
		fakeVault{name: "HomeLab", titles: []string{"db"}},
		fakeVault{name: "Kustom", titles: []string{"db"}},
	)

	secret, _, err := client.FindExactSecretAcrossVaults("db")
	if err == nil {
		t.Fatalf("FindExactSecretAcrossVaults picked one of two items titled db: %v", secret)
	}
	for _, want := range []string{"2 items", "HomeLab", "Kustom"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestFindExactSecretAcrossVaults_AVaultThatCannotBeListed_ReturnsNothing(t *testing.T) {
	client := fakeConnectVaults(t,
		fakeVault{name: "HomeLab", titles: []string{"db"}},
		fakeVault{name: "Kustom", unreadable: true},
	)

	secret, _, err := client.FindExactSecretAcrossVaults("db")
	if err == nil {
		t.Fatalf("FindExactSecretAcrossVaults returned %v without seeing every vault", secret)
	}
	if !strings.Contains(err.Error(), "Kustom") {
		t.Errorf("error = %v, want it to name the vault that could not be listed", err)
	}
}
