package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/config"
	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

func newTestServer(t *testing.T, mutate func(*config.Config)) *mcp.Server {
	t.Helper()

	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	api, err := merkleyeapi.New("http://127.0.0.1:1", cfg.Merkleye.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, api, "mk_live_test")
}

// listTools drives a real client against the server over an in-memory
// transport, so what is asserted is what a client actually sees — not what the
// registration code believes it registered.
func listTools(t *testing.T, srv *mcp.Server) map[string]*mcp.Tool {
	t.Helper()
	ctx := context.Background()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close() //nolint:errcheck // test teardown

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close() //nolint:errcheck // test teardown

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}

// Read-only is the default, and it has to actually remove the mutating tools
// rather than merely refuse them at call time: a tool an agent can see is a
// tool it will try, and a wasted turn is a worse experience than a tool that
// was never offered.
func TestReadOnlyServerExposesNoMutatingTools(t *testing.T) {
	tools := listTools(t, newTestServer(t, nil))

	if _, ok := tools["list_matches"]; !ok {
		t.Fatal("list_matches is missing from a read-only server")
	}
	for _, mutating := range []string{
		"acknowledge_matches", "allowlist_from_match", "add_domain",
		"update_domain", "remove_domain", "purge_domain", "test_notification_channel",
	} {
		if _, present := tools[mutating]; present {
			t.Fatalf("%q is exposed on a read-only server", mutating)
		}
	}
}

func TestWritesEnabledStillWithholdsDestructiveTools(t *testing.T) {
	tools := listTools(t, newTestServer(t, func(c *config.Config) {
		writes := false
		c.Tools.ReadOnly = &writes
	}))

	if _, ok := tools["acknowledge_matches"]; !ok {
		t.Fatal("acknowledge_matches is missing with writes enabled")
	}
	// Irreversible and outward-facing tools need their own opt-in: an agent
	// that can purge history or page someone at 3am by accident is a bug here.
	for _, destructive := range []string{"purge_domain", "test_notification_channel"} {
		if _, present := tools[destructive]; present {
			t.Fatalf("%q is exposed without tools.destructive", destructive)
		}
	}
}

func TestDestructiveToolsAreOptIn(t *testing.T) {
	tools := listTools(t, newTestServer(t, func(c *config.Config) {
		writes := false
		c.Tools.ReadOnly = &writes
		c.Tools.Destructive = true
	}))

	for _, name := range []string{"purge_domain", "test_notification_channel"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("%q is missing with tools.destructive set", name)
		}
		// Clients use this hint to decide what to confirm with a human. Getting
		// it wrong on a purge is the difference between a prompt and a silent
		// irreversible delete.
		if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
			t.Fatalf("%q is not annotated as destructive", name)
		}
	}
}

// Tool names are a public interface: users write them into agent configs and
// agents learn them. This pins the read surface so a rename has to be
// deliberate rather than incidental.
func TestReadToolNamesAreStable(t *testing.T) {
	tools := listTools(t, newTestServer(t, nil))

	want := []string{
		"search", "list_matches", "get_match", "list_domains", "get_domain",
		"list_variants", "list_all_variants", "get_domain_caa", "get_domain_dns_provider",
		"get_certificate", "list_allowlist", "get_summary", "get_audit_log",
	}
	for _, name := range want {
		if _, ok := tools[name]; !ok {
			t.Fatalf("tool %q is missing", name)
		}
	}
	if len(tools) != len(want) {
		got := make([]string, 0, len(tools))
		for name := range tools {
			got = append(got, name)
		}
		t.Fatalf("read-only surface has %d tools, want %d: %v", len(tools), len(want), got)
	}
}

// Every tool needs a description: it is the entire basis on which a model
// decides whether to call it.
func TestEveryToolIsDescribed(t *testing.T) {
	tools := listTools(t, newTestServer(t, func(c *config.Config) {
		writes := false
		c.Tools.ReadOnly = &writes
		c.Tools.Destructive = true
	}))

	for name, tool := range tools {
		if tool.Description == "" {
			t.Errorf("tool %q has no description", name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", name)
		}
	}
}

// A tool call with no credential must come back as a readable tool error, not
// a protocol error: an agent can read and act on the former.
func TestMissingCredentialIsAToolError(t *testing.T) {
	cfg := config.Default()
	api, err := merkleyeapi.New("http://127.0.0.1:1", cfg.Merkleye.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, api: api} // no static token, no request context

	res, err := s.call(context.Background(), func(context.Context) (any, error) {
		t.Fatal("the API was called without a credential")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("call returned a protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("a missing credential was not reported as a tool error")
	}
}

// Read tools must say they are read-only. A client uses this to decide whether
// to confirm with a human, and a list call that prompts like a mutation trains
// people to click through the prompts that do matter.
func TestReadToolsAreAnnotatedReadOnly(t *testing.T) {
	tools := listTools(t, newTestServer(t, nil))

	for name, tool := range tools {
		if tool.Annotations == nil {
			t.Errorf("read tool %q has no annotations", name)
			continue
		}
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("read tool %q is not annotated read-only", name)
		}
		if tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
			t.Errorf("read tool %q does not explicitly disclaim being destructive", name)
		}
	}
}

// The inverse: nothing that mutates may claim to be read-only.
func TestMutatingToolsAreNotAnnotatedReadOnly(t *testing.T) {
	all := listTools(t, newTestServer(t, func(c *config.Config) {
		writes := false
		c.Tools.ReadOnly = &writes
		c.Tools.Destructive = true
	}))
	readOnly := listTools(t, newTestServer(t, nil))

	for name, tool := range all {
		if _, isRead := readOnly[name]; isRead {
			continue
		}
		if tool.Annotations != nil && tool.Annotations.ReadOnlyHint {
			t.Errorf("mutating tool %q is annotated read-only", name)
		}
	}
}
