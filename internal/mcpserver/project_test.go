package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/merkleye/mcp-server/internal/config"
)

func TestProjectListKeepsPaginationAndShrinksItems(t *testing.T) {
	raw := map[string]any{
		"matches": []any{
			map[string]any{
				"id": 1.0, "domain": "example.com", "severity": "high",
				"certificate":     map[string]any{"pem": "…40KB of certificate…"},
				"risk_components": []any{"a", "b", "c"},
				"enrichment":      map[string]any{"lots": "of detail"},
			},
		},
		"next_cursor": "42",
		"total":       910.0,
	}

	out, ok := projectList(raw, "matches", matchSummary).(map[string]any)
	if !ok {
		t.Fatal("projectList did not return an object")
	}
	if out["next_cursor"] != "42" || out["total"] != 910.0 {
		t.Fatalf("pagination was disturbed: %v", out)
	}

	item := out["matches"].([]any)[0].(map[string]any)
	if item["severity"] != "high" || item["domain"] != "example.com" {
		t.Fatalf("summary lost a field triage needs: %v", item)
	}
	// The whole point: the bulky fields must not survive into a list result.
	for _, dropped := range []string{"certificate", "risk_components", "enrichment"} {
		if _, present := item[dropped]; present {
			t.Fatalf("%q survived projection — a 500-item page of these is what exhausts an agent's context", dropped)
		}
	}
	if out["_note"] == nil {
		t.Fatal("no note telling the agent these are summaries")
	}
}

// A nil slice marshals to JSON null, and an agent handed `"matches": null`
// cannot iterate it. Always an array, never null.
func TestProjectListEmptyIsAnArrayNotNull(t *testing.T) {
	out := projectList(map[string]any{"next_cursor": nil}, "matches", matchSummary)

	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["matches"]) != "[]" {
		t.Fatalf("matches = %s, want []", decoded["matches"])
	}
}

// An absent field must be absent, not null: an agent reading "issuer": null may
// conclude the certificate has no issuer, when the projection simply had none.
func TestPickFieldsOmitsRatherThanNulls(t *testing.T) {
	got := pickFields(map[string]any{"id": 1.0, "issuer": nil}, []string{"id", "issuer", "severity"})

	if _, present := got["issuer"]; present {
		t.Fatal("a nil field was emitted rather than omitted")
	}
	if _, present := got["severity"]; present {
		t.Fatal("an absent field was invented")
	}
	if got["id"] != 1.0 {
		t.Fatalf("id = %v", got["id"])
	}
}

func TestClampLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Tools.DefaultLimit = 20
	cfg.Tools.MaxLimit = 100
	s := &Server{cfg: cfg}

	cases := []struct{ in, want int }{
		{0, 20},    // unset falls to the default
		{-5, 20},   // nonsense falls to the default
		{50, 50},   // a reasonable ask is honoured
		{500, 100}, // the API's own ceiling is not the agent's
	}
	for _, c := range cases {
		if got := s.clampLimit(c.in); got != c.want {
			t.Fatalf("clampLimit(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseTimeInsistsOnRFC3339(t *testing.T) {
	if _, err := parseTime("2026-08-19T02:07:00Z", "since"); err != nil {
		t.Fatalf("a valid RFC 3339 timestamp was rejected: %v", err)
	}
	// The shapes a model is most likely to guess.
	for _, bad := range []string{"2026-08-19", "19/08/2026", "1787443620", "yesterday"} {
		if _, err := parseTime(bad, "since"); err == nil {
			t.Fatalf("parseTime(%q) was accepted", bad)
		}
	}
}
