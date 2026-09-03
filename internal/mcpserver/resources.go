package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// Reference data is a resource, not a tool.
//
// The CA catalog, the plugin roster and the settings blocks are things an agent
// reads to interpret a match, not actions it takes. Modelling them as tools
// would put five more entries in a tool list the model has to read on every
// turn, to no benefit — a resource is fetched when it is wanted and costs
// nothing when it is not.

func (s *Server) registerResources(srv *mcp.Server) {
	type resource struct {
		uri, name, title, description string
		fetch                         func(ctx context.Context) (any, error)
	}

	resources := []resource{
		{
			uri: "merkleye://summary", name: "summary", title: "Dashboard rollup",
			description: "Counts and health across every watched domain.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().GetSummary(ctx, &merkleyeapi.GetSummaryParams{}))
			},
		},
		{
			uri: "merkleye://cas", name: "known-cas", title: "Known CA catalog",
			description: "The CA catalog CAA generation resolves against. Issuer matching is a " +
				"case-insensitive substring, not equality, because intermediates rotate without notice.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().ListKnownCAs(ctx))
			},
		},
		{
			uri: "merkleye://plugins", name: "plugins", title: "Ingestion plugins",
			description: "Which CT ingestion sources are running and their checkpoint state.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().ListPlugins(ctx))
			},
		},
		{
			uri: "merkleye://config", name: "config", title: "Effective configuration",
			description: "The deployment's effective configuration, secrets redacted.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().GetConfig(ctx))
			},
		},
		{
			uri: "merkleye://settings/scoring", name: "scoring-settings", title: "Severity thresholds",
			description: "The thresholds that turn a risk score into a severity.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().GetScoringSettings(ctx))
			},
		},
		{
			uri: "merkleye://settings/variants", name: "variant-settings", title: "Variant generation defaults",
			description: "Default fuzzers, TLDs and caps for lookalike generation.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().GetVariantSettings(ctx))
			},
		},
		{
			uri: "merkleye://settings/notifications", name: "notification-settings", title: "Alert delivery settings",
			description: "Which severities are delivered where.",
			fetch: func(ctx context.Context) (any, error) {
				return merkleyeapi.Decode(s.api.Gen().GetNotificationSettings(ctx))
			},
		},
	}

	for _, r := range resources {
		fetch := r.fetch
		uri := r.uri
		srv.AddResource(&mcp.Resource{
			URI:         uri,
			Name:        r.name,
			Title:       r.title,
			Description: r.description,
			MIMEType:    "application/json",
		}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return s.readResource(ctx, uri, fetch)
		})
	}
}

func (s *Server) readResource(ctx context.Context, uri string, fetch func(ctx context.Context) (any, error)) (*mcp.ReadResourceResult, error) {
	tok, err := s.token(ctx)
	if err != nil {
		return nil, err
	}

	value, err := fetch(merkleyeapi.WithToken(ctx, tok))
	if err != nil {
		// Unlike a tool call, a resource read has no IsError channel — a
		// failure here has to be a protocol error, so it is worth making the
		// message say which resource and why.
		return nil, fmt.Errorf("read %s: %w", uri, err)
	}

	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", uri, err)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(encoded),
		}},
	}, nil
}
