package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Read-only defaults on. Connecting a write-scoped token is not the same as
// consenting to an agent mutating things, so an omitted key must not mean
// "writes allowed".
func TestReadOnlyDefaultsOn(t *testing.T) {
	if !Default().IsReadOnly() {
		t.Fatal("tools.read_only defaulted to false")
	}

	cfg, err := Load(writeConfig(t, "tools:\n  default_limit: 5\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsReadOnly() {
		t.Fatal("an omitted tools.read_only was read as false")
	}
}

func TestReadOnlyExplicitFalseIsHonoured(t *testing.T) {
	cfg, err := Load(writeConfig(t, "tools:\n  read_only: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.IsReadOnly() {
		t.Fatal("an explicit read_only: false was ignored")
	}
}

// A typo in a monitoring tool is a silent misconfiguration, which is worse than
// a crash — so an unknown key is an error, not something to skip.
func TestUnknownKeyIsRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "tools:\n  read_onlyy: false\n"))
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "read_onlyy") {
		t.Fatalf("err = %v, want it to name the offending key", err)
	}
}

func TestValidationNamesTheOffendingKey(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"bad mode", "auth:\n  mode: maybe\n", "auth.mode"},
		{"empty base url", "merkleye:\n  base_url: \"\"\n", "merkleye.base_url"},
		{"relative base url", "merkleye:\n  base_url: /api\n", "merkleye.base_url"},
		{"limits inverted", "tools:\n  default_limit: 50\n  max_limit: 10\n", "tools.default_limit"},
		{"oidc mode without oidc enabled", "auth:\n  mode: oidc\n", "auth.oidc.enabled"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, c.body))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to name %s", err, c.want)
			}
		})
	}
}

// Without a resource identifier there is nothing for an audience to be bound
// to, and the confused-deputy defence has nothing to check against. Enabling
// OIDC without one has to be refused rather than defaulted.
func TestOIDCRequiresAPublicURL(t *testing.T) {
	_, err := Load(writeConfig(t, "auth:\n  mode: both\n  oidc:\n    enabled: true\n"))
	if err == nil {
		t.Fatal("OIDC was enabled without a resource identifier")
	}
	if !strings.Contains(err.Error(), "server.public_url") {
		t.Fatalf("err = %v, want it to name server.public_url", err)
	}
}

func TestOIDCWithPublicURLIsAccepted(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
server:
  public_url: https://mcp.example.com
auth:
  mode: both
  oidc:
    enabled: true
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.AcceptsOIDC() || !cfg.AcceptsBearer() {
		t.Fatalf("mode both accepted bearer=%v oidc=%v", cfg.AcceptsBearer(), cfg.AcceptsOIDC())
	}
	if got, want := cfg.ResourceMetadataURL(), "https://mcp.example.com/.well-known/oauth-protected-resource"; got != want {
		t.Fatalf("ResourceMetadataURL = %q, want %q", got, want)
	}
}

// oidc.enabled alone does not make the server accept OIDC — the mode has to
// admit it too. Otherwise a half-configured deployment advertises a flow it
// then refuses.
func TestOIDCEnabledButModeBearerAcceptsOnlyBearer(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
server:
  public_url: https://mcp.example.com
auth:
  mode: bearer
  oidc:
    enabled: true
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AcceptsOIDC() {
		t.Fatal("mode bearer accepted OIDC")
	}
}

// A destructive flag that silently does nothing is worse than an error: the
// operator believes they enabled something they did not.
func TestDestructiveWithoutWritesIsRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "tools:\n  destructive: true\n"))
	if err == nil {
		t.Fatal("tools.destructive was accepted while read_only was true")
	}
	if !strings.Contains(err.Error(), "tools.destructive") {
		t.Fatalf("err = %v, want it to name tools.destructive", err)
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	t.Setenv("MERKLEYE_API_URL", "https://merkleye.internal")
	t.Setenv("MERKLEYE_API_TOKEN", "mk_live_from_env")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Merkleye.BaseURL != "https://merkleye.internal" {
		t.Fatalf("BaseURL = %q", cfg.Merkleye.BaseURL)
	}
	if cfg.Merkleye.StaticToken != "mk_live_from_env" {
		t.Fatalf("StaticToken = %q", cfg.Merkleye.StaticToken)
	}
}

// Every problem at once, so a misconfigured deployment needs one round trip to
// fix rather than five.
func TestValidationReportsEveryProblem(t *testing.T) {
	_, err := Load(writeConfig(t, "auth:\n  mode: nope\nmerkleye:\n  base_url: \"\"\n"))
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "auth.mode") || !strings.Contains(msg, "merkleye.base_url") {
		t.Fatalf("err = %v, want both problems reported", err)
	}
}
