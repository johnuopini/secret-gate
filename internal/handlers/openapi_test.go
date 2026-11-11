package handlers

import (
	"encoding/json"
	"testing"
)

// specAt walks the OpenAPI document down path and returns the object there.
func specAt(t *testing.T, path ...string) map[string]any {
	t.Helper()

	var node map[string]any
	if err := json.Unmarshal([]byte(OpenAPISpec()), &node); err != nil {
		t.Fatalf("the OpenAPI spec is not valid JSON: %v", err)
	}
	for i, key := range path {
		next, ok := node[key].(map[string]any)
		if !ok {
			t.Fatalf("the OpenAPI spec has no object at %v", path[:i+1])
		}
		node = next
	}
	return node
}

func TestOpenAPISpec_DescribesTheApprovalWindow(t *testing.T) {
	if version := specAt(t, "info")["version"]; version != "1.2.0" {
		t.Errorf("spec version = %v, want 1.2.0", version)
	}

	request := specAt(t, "paths", "/request", "post", "requestBody", "content", "application/json", "schema", "properties")
	for _, field := range []string{"session", "session_token"} {
		if _, ok := request[field]; !ok {
			t.Errorf("POST /request does not describe %q", field)
		}
	}

	responses := specAt(t, "paths", "/request", "post", "responses")
	if _, ok := responses["503"]; !ok {
		t.Error("POST /request does not describe the 503 of a release that could not be reported")
	}
	accepted := specAt(t, "paths", "/request", "post", "responses", "202", "content", "application/json", "schema", "properties")
	if _, ok := accepted["session_invalid"]; !ok {
		t.Error(`the 202 of POST /request does not describe "session_invalid"`)
	}

	secret := specAt(t, "paths", "/secret/{token}", "get", "responses", "200", "content", "application/json", "schema")
	shapes, _ := secret["oneOf"].([]any)
	if len(shapes) != 2 {
		t.Fatalf("GET /secret/{token} describes %d response shapes, want 2", len(shapes))
	}
	for _, shape := range shapes {
		properties, _ := shape.(map[string]any)["properties"].(map[string]any)
		if _, ok := properties["session"]; !ok {
			t.Errorf("a response shape of GET /secret/{token} does not describe %q: %v", "session", shape)
		}
	}
}
