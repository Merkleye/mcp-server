package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// Mutating tools. Registered only when tools.read_only is false.
//
// Read-only is the default deliberately: connecting a write-scoped token is
// not the same as consenting to an agent mutating things, and an agent has no
// confirmation dialog between intent and effect. Merkleye still enforces
// scopes on every one of these — this gate is the operator's, not a
// replacement for the server's.

type acknowledgeArgs struct {
	IDs  []int64 `json:"ids" jsonschema:"Match ids to acknowledge"`
	Note string  `json:"note,omitempty" jsonschema:"Why these were triaged this way. Recorded in the audit log"`
}

type allowlistMatchArgs struct {
	ID     int64  `json:"id" jsonschema:"The match to mark as not a threat"`
	Reason string `json:"reason,omitempty" jsonschema:"Why this is benign. Unexplained allowlist entries are indistinguishable from mistakes six months later"`
}

type addDomainArgs struct {
	Domain string `json:"domain" jsonschema:"Domain to watch, A-label or Unicode. Normalized to A-label on save. Must not start with *."`
	// Required by the API rather than optional, and worth saying why: without
	// it every routine renewal alerts as critical.
	ExpectedIssuers   []string `json:"expected_issuers" jsonschema:"Required. CAs legitimately issuing for this domain, matched case-insensitively as substrings, e.g. [\"Let's Encrypt\"]. Without at least one, every routine renewal alerts as critical"`
	IncludeSubdomains bool     `json:"include_subdomains,omitempty" jsonschema:"Also match certificates for subdomains"`
	MaxValidityDays   int      `json:"max_validity_days,omitempty" jsonschema:"0 (default) means unenforced"`
}

type updateDomainArgs struct {
	ID                int64 `json:"id" jsonschema:"The watched domain to update"`
	Enabled           *bool `json:"enabled,omitempty" jsonschema:"Pause or resume watching without deleting"`
	IncludeSubdomains *bool `json:"include_subdomains,omitempty" jsonschema:"Also match certificates for subdomains"`
}

type allowlistVariantArgs struct {
	ID     int64  `json:"id" jsonschema:"The variant to mark as benign"`
	Reason string `json:"reason,omitempty" jsonschema:"Why this lookalike is benign. Unexplained allowlist entries are indistinguishable from mistakes six months later"`
}

type addAllowlistArgs struct {
	FQDN   string `json:"fqdn" jsonschema:"The registrable domain (eTLD+1) to stop alerting on"`
	Reason string `json:"reason,omitempty" jsonschema:"Why this is benign"`
}

type previewVariantsArgs struct {
	Domain      string   `json:"domain" jsonschema:"Domain to preview generation for. Need not be watched — preview before deciding to watch"`
	Algorithms  []string `json:"algorithms,omitempty" jsonschema:"dnstwist fuzzers to run instead of the full set, e.g. [\"homoglyph\",\"tld-swap\"]"`
	TLDs        []string `json:"tlds,omitempty" jsonschema:"TLDs to permute against instead of the configured defaults"`
	MaxVariants int      `json:"max_variants,omitempty" jsonschema:"Cap on generated names for this preview"`
}

func (s *Server) registerWriteTools(srv *mcp.Server) {
	add(srv, &mcp.Tool{
		Name:  "acknowledge_matches",
		Title: "Acknowledge matches",
		Description: "Mark matches as triaged. This records that a human (or you, on their behalf) has seen them; " +
			"it does NOT stop future matches for the same lookalike — allowlist_from_match does that.",
		Annotations: writeHints("Acknowledge matches", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args acknowledgeArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.AcknowledgeMatchesJSONRequestBody{Ids: pointersTo(args.IDs)}
			if args.Note != "" {
				body.Note = &args.Note
			}
			return merkleyeapi.Decode(s.api.Gen().AcknowledgeMatches(ctx, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:  "allowlist_from_match",
		Title: "Mark a match as not a threat",
		Description: "Allowlist the lookalike behind a match, so it stops alerting from now on. " +
			"Stronger than acknowledging: this suppresses future matches too. Always give a reason.",
		Annotations: writeHints("Allowlist from match", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args allowlistMatchArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.AllowlistMatchJSONRequestBody{}
			if args.Reason != "" {
				body.Reason = &args.Reason
			}
			return merkleyeapi.Decode(s.api.Gen().AllowlistMatch(ctx, args.ID, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "rescore_match",
		Title:       "Rescore a match",
		Description: "Recompute a match's risk score and components against the current scoring settings.",
		Annotations: writeHints("Rescore match", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().RescoreMatch(ctx, args.ID))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "add_domain",
		Title:       "Watch a domain",
		Description: "Start watching a domain. expected_issuers is required — see its description for why.",
		Annotations: writeHints("Watch a domain", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args addDomainArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.CreateDomainJSONRequestBody{
				Domain: args.Domain,
				// Never nil: the schema requires the key, and a nil slice
				// marshals to JSON null against an array the server insists on.
				ExpectedIssuers: pointersTo(args.ExpectedIssuers),
			}
			if args.IncludeSubdomains {
				body.IncludeSubdomains = &args.IncludeSubdomains
			}
			if args.MaxValidityDays > 0 {
				body.MaxValidityDays = &args.MaxValidityDays
			}
			return merkleyeapi.Decode(s.api.Gen().CreateDomain(ctx, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "update_domain",
		Title:       "Update a watched domain",
		Description: "Pause, resume, or change subdomain matching for a watched domain.",
		Annotations: writeHints("Update a domain", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args updateDomainArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().UpdateDomain(ctx, args.ID, merkleyeapi.UpdateDomainJSONRequestBody{
				Enabled:           args.Enabled,
				IncludeSubdomains: args.IncludeSubdomains,
			}))
		})
	})

	add(srv, &mcp.Tool{
		Name:  "remove_domain",
		Title: "Stop watching a domain",
		Description: "Soft-delete a watched domain. Reversible: the domain and its history remain, and " +
			"list_domains with status=deleted finds it again.",
		Annotations: writeHints("Stop watching a domain", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().DeleteDomain(ctx, args.ID))
		})
	})

	add(srv, &mcp.Tool{
		Name:  "allowlist_variant",
		Title: "Mark a lookalike as benign",
		Description: "Allowlist a generated variant directly, without waiting for it to produce a match. " +
			"Use when a lookalike is known to be ours or a partner's. Reversible with unallowlist_variant.",
		Annotations: writeHints("Allowlist a variant", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args allowlistVariantArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.AllowlistVariantJSONRequestBody{}
			if args.Reason != "" {
				body.Reason = &args.Reason
			}
			return merkleyeapi.Decode(s.api.Gen().AllowlistVariant(ctx, args.ID, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "unallowlist_variant",
		Title:       "Resume alerting on a lookalike",
		Description: "Undo allowlist_variant, so this lookalike alerts again.",
		Annotations: writeHints("Un-allowlist a variant", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().UnallowlistVariant(ctx, args.ID))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "add_allowlist_entry",
		Title:       "Allowlist a lookalike",
		Description: "Stop alerting on a registrable domain outright, without going through a specific match.",
		Annotations: writeHints("Allowlist a lookalike", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args addAllowlistArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.CreateAllowlistEntryJSONRequestBody{Fqdn: args.FQDN}
			if args.Reason != "" {
				body.Reason = &args.Reason
			}
			return merkleyeapi.Decode(s.api.Gen().CreateAllowlistEntry(ctx, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "remove_allowlist_entry",
		Title:       "Remove an allowlist entry",
		Description: "Resume alerting on a previously allowlisted name.",
		Annotations: writeHints("Remove an allowlist entry", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().DeleteAllowlistEntry(ctx, args.ID))
		})
	})

	add(srv, &mcp.Tool{
		Name:  "preview_variants",
		Title: "Dry-run variant generation",
		Description: "Generate lookalike names for a domain without storing anything. Generation produces " +
			"names only, never live registration state — that is what list_variants reports.",
		Annotations: writeHints("Preview variants", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args previewVariantsArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			body := merkleyeapi.PreviewVariantsJSONRequestBody{Domain: args.Domain}
			if len(args.Algorithms) > 0 {
				body.Algorithms = &args.Algorithms
			}
			if len(args.TLDs) > 0 {
				body.Tlds = &args.TLDs
			}
			if args.MaxVariants > 0 {
				body.MaxVariants = &args.MaxVariants
			}
			return merkleyeapi.Decode(s.api.Gen().PreviewVariants(ctx, body))
		})
	})

	add(srv, &mcp.Tool{
		Name:        "regenerate_variants",
		Title:       "Regenerate a domain's lookalikes",
		Description: "Run generation again for a watched domain and store the result as a new variant set.",
		Annotations: writeHints("Regenerate variants", false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().RegenerateDomainVariants(ctx, args.ID, &merkleyeapi.RegenerateDomainVariantsParams{}))
		})
	})
}

// registerDestructiveTools adds what cannot be undone or what reaches a human.
//
// Behind tools.destructive, off even when writes are on. Purging destroys
// history irreversibly, and a test notification pages whoever is on call. An
// agent that can do either by accident is a bug in this repo, not in merkleye.
func (s *Server) registerDestructiveTools(srv *mcp.Server) {
	add(srv, &mcp.Tool{
		Name:  "purge_domain",
		Title: "Permanently delete a domain",
		Description: "IRREVERSIBLE. Permanently deletes a soft-deleted domain and its history. " +
			"There is no undo and no backup taken. Confirm with a human before calling this.",
		Annotations: writeHints("Permanently delete a domain", true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().PurgeDomain(ctx, args.ID))
		})
	})

	add(srv, &mcp.Tool{
		Name:  "test_notification_channel",
		Title: "Send a test notification",
		Description: "Sends a REAL message through a configured channel — Slack, email, Discord, webhook. " +
			"A human will receive it. Do not call this to check configuration without being asked to.",
		Annotations: writeHints("Send a test notification", true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args struct {
		ChannelID int64 `json:"channel_id" jsonschema:"The notification channel to fire a test through"`
	},
	) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().TestNotificationChannel(ctx, merkleyeapi.TestNotificationChannelJSONRequestBody{
				ChannelId: args.ChannelID,
			}))
		})
	})
}

// pointersTo converts a slice of values into the slice of pointers the
// generated request bodies want.
//
// merkleye@2ce4b5e declares these array items as nullable — `type: [integer,
// "null"]` for match ids, `[string, "null"]` for expected issuers — so the
// generator renders them as []*T. Nothing here ever sends a null element; the
// pointers exist only to match the declared shape. Always returns a non-nil
// slice, because a nil one marshals to JSON null against a schema that requires
// an array.
func pointersTo[T any](values []T) []*T {
	out := make([]*T, 0, len(values))
	for i := range values {
		out = append(out, &values[i])
	}
	return out
}
