// Package mcpserver builds the MCP surface over the Merkleye API.
//
// Three decisions shape everything here, all recorded in docs/PLAN.md:
//
//  1. Tools are curated, not generated. Merkleye's API has 63 operations; an
//     agent handed 63 tools chooses worse and spends its context on the menu.
//     What is exposed is the triage workflow, and reference data is a resource
//     rather than a tool.
//
//  2. Tool names come from the spec's operationIds, so a URL change upstream
//     never silently renames a tool in somebody's saved agent config.
//
//  3. Results are projected small. The API caps a match page at 500; a tool
//     that can return 500 Match objects will exhaust an agent's context and
//     produce a worse answer than one returning 20. See project.go.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/auth"
	"github.com/merkleye/mcp-server/internal/config"
	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// Version is stamped at build time.
var Version = "dev"

// Server holds what every tool handler needs.
type Server struct {
	cfg config.Config
	api *merkleyeapi.API

	// staticToken is the stdio transport's credential. Empty under HTTP, where
	// each request carries its own and ambient authority would be a bug.
	staticToken string
}

// New builds the MCP server and registers the whole surface.
func New(cfg config.Config, api *merkleyeapi.API, staticToken string) *mcp.Server {
	s := &Server{cfg: cfg, api: api, staticToken: staticToken}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "merkleye",
		Title:   "Merkleye",
		Version: Version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})

	s.registerReadTools(srv)
	if !cfg.IsReadOnly() {
		s.registerWriteTools(srv)
		if cfg.Tools.Destructive {
			s.registerDestructiveTools(srv)
		}
	}
	s.registerResources(srv)
	s.registerPrompts(srv)

	return srv
}

// instructions is the model-facing description of what this server watches.
// It carries the domain facts an agent cannot infer and will otherwise get
// wrong.
const instructions = `Merkleye is a Certificate Transparency watchtower. It watches CT logs for
certificates issued on lookalikes of domains you own, scores them, and lets you
triage the results.

Vocabulary:
  - A "domain" is something you own and watch.
  - A "variant" is a generated lookalike of a watched domain (typosquats,
    homographs, TLD swaps). Generation produces names only, never live state.
  - A "match" is an observed certificate whose SANs hit a watched domain or one
    of its variants. This is the thing you triage.
  - "Acknowledging" a match marks it as seen. It does not suppress future
    matches; allowlisting the lookalike does.

Facts that matter when you compare names:
  - Match keys are punycode A-labels. Comparing a Unicode name against them
    matches nothing, silently.
  - A variant's "registration" is RDAP's answer and "ns_resolves" is DNS's.
    Neither is written from a lookup that failed, so absent is not "no".
  - Issuer matching is a case-insensitive substring, not equality.

Start with search or list_matches. List results are compact summaries; use
get_match or get_domain for the full record. Page with next_cursor rather than
raising the limit.`

// token returns the Merkleye credential for this request.
//
// Under HTTP it comes from the authenticated request context, so a tool always
// acts as the caller and never with authority of its own. Under stdio there is
// no request and no other caller, so the configured token stands in.
func (s *Server) token(ctx context.Context) (string, error) {
	if tok, ok := auth.APITokenFromContext(ctx); ok {
		return tok, nil
	}
	if s.staticToken != "" {
		return s.staticToken, nil
	}
	return "", fmt.Errorf("no Merkleye credential for this request")
}

// call runs fn with the caller's credential attached and renders the result.
func (s *Server) call(ctx context.Context, fn func(ctx context.Context) (any, error)) (*mcp.CallToolResult, error) {
	tok, err := s.token(ctx)
	if err != nil {
		return toolError(err), nil
	}

	value, err := fn(merkleyeapi.WithToken(ctx, tok))
	if err != nil {
		return toolError(err), nil
	}
	return toolJSON(value)
}

// toolError renders a failure as a tool result rather than a protocol error.
//
// An agent can read and act on a tool result; a JSON-RPC error just ends the
// call. Scope refusals in particular are worth explaining, because "you need
// write scope" tells the agent to stop trying rather than to retry.
func toolError(err error) *mcp.CallToolResult {
	msg := err.Error()
	switch {
	case merkleyeapi.IsUnauthorized(err):
		msg = "Merkleye rejected the credential (401). The token may be expired or revoked."
	case merkleyeapi.IsForbidden(err):
		msg = "Merkleye refused this operation (403): the credential lacks the required scope. " +
			"Do not retry — a different tool or a wider-scoped token is needed."
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// toolJSON renders a value as both readable text and structured content.
func toolJSON(value any) (*mcp.CallToolResult, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode tool result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
	}, nil
}
