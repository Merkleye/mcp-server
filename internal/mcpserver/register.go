package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// add registers a tool, inferring the argument schema from In.
//
// A thin wrapper over mcp.AddTool so every registration in this package reads
// the same and the generic parameters stay out of the call sites.
func add[In any](srv *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[In, any]) {
	mcp.AddTool(srv, tool, h)
}

// wrap adapts a plain "do the API call" function to a tool handler.
//
// Out is `any` and always nil: results travel as text content, which every MCP
// client renders, rather than as structured output that older clients ignore.
// The JSON is already indented and readable — see toolJSON.
func (s *Server) wrap(ctx context.Context, fn func(ctx context.Context) (any, error)) (*mcp.CallToolResult, any, error) {
	res, err := s.call(ctx, fn)
	return res, nil, err
}

// addRead registers a read-only tool, annotating it as such.
//
// The annotation is what an MCP client uses to decide whether to confirm with a
// human before running. It is advisory — merkleye enforces regardless — but
// leaving it off makes a client treat a list call like a mutation and prompt
// for it, which trains people to click through prompts that do matter.
//
// Setting it here rather than at each registration means a read tool cannot be
// added without it.
func addRead[In any](srv *mcp.Server, tool *mcp.Tool, h mcp.ToolHandlerFor[In, any]) {
	if tool.Annotations == nil {
		tool.Annotations = &mcp.ToolAnnotations{Title: tool.Title}
	}
	tool.Annotations.ReadOnlyHint = true
	// A read tool is trivially idempotent and cannot destroy anything; saying
	// so explicitly stops a client inferring otherwise from the zero value.
	destructive := false
	tool.Annotations.DestructiveHint = &destructive
	tool.Annotations.IdempotentHint = true
	mcp.AddTool(srv, tool, h)
}

func writeHints(title string, destructive bool) *mcp.ToolAnnotations {
	d := destructive
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: &d,
		// Acknowledging the same match twice is not the same as acknowledging
		// it once in any way a caller can observe, but creating a domain twice
		// is a conflict. Only the genuinely repeatable ones claim idempotence.
		IdempotentHint: false,
	}
}
