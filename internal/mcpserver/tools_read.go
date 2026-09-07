package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// Argument structs. Field docs become the JSON Schema descriptions the model
// reads, so they are written for a model that has never seen this API — that
// is the only documentation it gets.

type searchArgs struct {
	Query string `json:"query" jsonschema:"Search term, matched case-insensitively as a substring against domains, matches and variants"`
	Limit int    `json:"limit,omitempty" jsonschema:"Maximum results per category"`
}

type listMatchesArgs struct {
	Domain       string   `json:"domain,omitempty" jsonschema:"Exact watched-domain name to restrict to, e.g. example.com"`
	Severity     []string `json:"severity,omitempty" jsonschema:"Severities to include, any of: suppressed, info, medium, high, critical. Omit for all"`
	Acknowledged *bool    `json:"acknowledged,omitempty" jsonschema:"false shows only untriaged matches - the usual starting point"`
	MatchedName  string   `json:"matched_name,omitempty" jsonschema:"Case-insensitive substring of the observed SAN. Must be a punycode A-label, not Unicode"`
	IssuerOrg    string   `json:"issuer_org,omitempty" jsonschema:"Case-insensitive substring of the certificate issuer organization"`
	RiskScoreMin int      `json:"risk_score_min,omitempty" jsonschema:"Lowest risk score to include"`
	CreatedAfter string   `json:"created_after,omitempty" jsonschema:"Only matches first seen at or after this RFC 3339 UTC timestamp, e.g. 2026-08-19T02:07:00Z"`
	Cursor       int64    `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call. Page with this rather than raising the limit"`
	Limit        int      `json:"limit,omitempty" jsonschema:"Results per page"`
}

type idArgs struct {
	ID int64 `json:"id" jsonschema:"Numeric identifier"`
}

type listDomainsArgs struct {
	Status string `json:"status,omitempty" jsonschema:"live (default), deleted, or all. deleted is the only way to find a soft-deleted domain's id"`
	Cursor int64  `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Results per page"`
}

type listVariantsArgs struct {
	DomainID     int64  `json:"domain_id" jsonschema:"The watched domain whose generated lookalikes to list"`
	Registration string `json:"registration,omitempty" jsonschema:"RDAP verdict: registered, unregistered, or unknown. unknown means no RDAP answer was available, which is not the same as unregistered"`
	Algorithm    string `json:"algorithm,omitempty" jsonschema:"Restrict to one dnstwist fuzzer, e.g. homoglyph"`
	Cursor       int64  `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
	Limit        int    `json:"limit,omitempty" jsonschema:"Results per page"`
}

type listAllVariantsArgs struct {
	Query        string `json:"query,omitempty" jsonschema:"Case-insensitive substring of the lookalike's own name"`
	DomainID     int64  `json:"domain_id,omitempty" jsonschema:"Restrict to one watched domain's lookalikes. Omit for every watched domain at once"`
	Registration string `json:"registration,omitempty" jsonschema:"RDAP verdict: registered, unregistered, or unknown. unknown means no RDAP answer was available, which is not the same as unregistered"`
	Resolves     *bool  `json:"resolves,omitempty" jsonschema:"Whether the name has an A or AAAA record. Omit to not filter - false is a real answer, not the absence of one"`
	HasMX        *bool  `json:"has_mx,omitempty" jsonschema:"Whether the name publishes any MX host. A lookalike that takes mail is a phishing capability a parked one does not have"`
	Cursor       int64  `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
	Limit        int    `json:"limit,omitempty" jsonschema:"Results per page"`
}

type auditArgs struct {
	Actor  string `json:"actor,omitempty" jsonschema:"Restrict to one actor"`
	Action string `json:"action,omitempty" jsonschema:"Restrict to one action, e.g. match.acknowledge"`
	Since  string `json:"since,omitempty" jsonschema:"RFC 3339 UTC lower bound, e.g. 2026-08-19T02:07:00Z"`
	Cursor int64  `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Results per page"`
}

type summaryArgs struct {
	Window string `json:"window,omitempty" jsonschema:"Go duration bounding the windowed counts, e.g. 168h for the last week"`
}

type certArgs struct {
	SHA256 string `json:"sha256" jsonschema:"Certificate SHA-256, 64 lowercase hex characters. Dedup is on this, never the serial - two CAs can issue the same serial"`
	PEM    bool   `json:"pem,omitempty" jsonschema:"Return the raw PEM instead of the parsed record. Only available where the deployment retains certificates"`
}

func (s *Server) registerReadTools(srv *mcp.Server) {
	addRead(srv, &mcp.Tool{
		Name:  "search",
		Title: "Search Merkleye",
		Description: "Search domains, matches and variants in one request. The best starting point " +
			"when you have a name or fragment and do not yet know what kind of thing it is.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			limit := s.clampLimit(args.Limit)
			return merkleyeapi.Decode(s.api.Gen().Search(ctx, &merkleyeapi.SearchParams{
				Q:     args.Query,
				Limit: &limit,
			}))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:  "list_matches",
		Title: "List matches",
		Description: "Matches across every watched domain, newest first. Returns compact summaries — " +
			"use get_match for the full certificate and risk breakdown. Filter with acknowledged=false " +
			"to see only what still needs triage.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args listMatchesArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.ListMatchesParams{Acknowledged: args.Acknowledged}
			limit := s.clampLimit(args.Limit)
			params.Limit = &limit
			setIfNotEmpty(&params.Domain, args.Domain)
			setIfNotEmpty(&params.MatchedName, args.MatchedName)
			if len(args.Severity) > 0 {
				// merkleye@2ce4b5e made severity a repeated typed parameter
				// rather than one comma-separated string.
				severities := make([]merkleyeapi.ListMatchesParamsSeverity, 0, len(args.Severity))
				for _, sev := range args.Severity {
					severities = append(severities, merkleyeapi.ListMatchesParamsSeverity(sev))
				}
				params.Severity = &severities
			}
			setIfNotEmpty(&params.IssuerOrg, args.IssuerOrg)
			if args.RiskScoreMin > 0 {
				params.RiskScoreMin = &args.RiskScoreMin
			}
			if args.Cursor > 0 {
				params.Cursor = &args.Cursor
			}
			if args.CreatedAfter != "" {
				t, err := parseTime(args.CreatedAfter, "created_after")
				if err != nil {
					return nil, err
				}
				params.CreatedAfter = &t
			}

			value, err := merkleyeapi.Decode(s.api.Gen().ListMatches(ctx, params))
			if err != nil {
				return nil, err
			}
			return projectList(value, "matches", matchSummary), nil
		})
	})

	addRead(srv, &mcp.Tool{
		Name:  "get_match",
		Title: "Match detail",
		Description: "One match in full: the certificate, the risk breakdown that produced its severity, " +
			"and enrichment. Use after list_matches narrows things down.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().GetMatch(ctx, args.ID))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "list_domains",
		Title:       "List watched domains",
		Description: "Domains Merkleye is watching. Compact summaries; use get_domain for the full record.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args listDomainsArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.ListDomainsParams{}
			limit := s.clampLimit(args.Limit)
			params.Limit = &limit
			if args.Status != "" {
				status := merkleyeapi.ListDomainsParamsStatus(args.Status)
				params.Status = &status
			}
			if args.Cursor > 0 {
				params.Cursor = &args.Cursor
			}

			value, err := merkleyeapi.Decode(s.api.Gen().ListDomains(ctx, params))
			if err != nil {
				return nil, err
			}
			return projectList(value, "domains", domainSummary), nil
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_domain",
		Title:       "Domain detail",
		Description: "One watched domain in full, including its issuer policy and counts.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().GetDomain(ctx, args.ID))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:  "list_variants",
		Title: "List generated lookalikes",
		Description: "Lookalikes generated for a watched domain. registration is RDAP's answer and " +
			"ns_resolves is DNS's; neither is written from a failed lookup, so \"unknown\" means " +
			"nobody answered, not that the name is free.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args listVariantsArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.ListDomainVariantsParams{}
			limit := s.clampLimit(args.Limit)
			params.Limit = &limit
			setIfNotEmpty(&params.Registration, args.Registration)
			setIfNotEmpty(&params.Algorithm, args.Algorithm)
			if args.Cursor > 0 {
				params.Cursor = &args.Cursor
			}

			value, err := merkleyeapi.Decode(s.api.Gen().ListDomainVariants(ctx, args.DomainID, params))
			if err != nil {
				return nil, err
			}
			return projectList(value, "variants", variantSummary), nil
		})
	})

	addRead(srv, &mcp.Tool{
		Name:  "list_all_variants",
		Title: "List lookalikes across every domain",
		Description: "Generated lookalikes across all watched domains at once, rather than one domain's. " +
			"Use for hunting rather than investigating: a registered lookalike that resolves and " +
			"publishes MX has a phishing capability a parked name does not, and this is how you find " +
			"those. registration is RDAP's answer and resolves/has_mx are DNS's; neither is written " +
			"from a lookup that failed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args listAllVariantsArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.ListVariantsParams{
				Resolves: args.Resolves,
				HasMx:    args.HasMX,
			}
			limit := s.clampLimit(args.Limit)
			params.Limit = &limit
			setIfNotEmpty(&params.Registration, args.Registration)
			setIfNotEmpty(&params.Q, args.Query)
			if args.DomainID > 0 {
				params.DomainId = &args.DomainID
			}
			if args.Cursor > 0 {
				params.Cursor = &args.Cursor
			}

			value, err := merkleyeapi.Decode(s.api.Gen().ListVariants(ctx, params))
			if err != nil {
				return nil, err
			}
			return projectList(value, "variants", variantSummary), nil
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_domain_caa",
		Title:       "Generate CAA records",
		Description: "CAA records generated from a domain's issuer policy — what to publish in DNS so other CAs cannot issue for it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().GetDomainCAA(ctx, args.ID, &merkleyeapi.GetDomainCAAParams{}))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_domain_dns_provider",
		Title:       "Detect DNS host",
		Description: "The domain's DNS host, inferred from its nameservers.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args idArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			return merkleyeapi.Decode(s.api.Gen().GetDomainDNSProvider(ctx, args.ID))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_certificate",
		Title:       "Certificate detail",
		Description: "One observed certificate by SHA-256 of its DER. Set pem=true for the raw PEM.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args certArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			if args.PEM {
				pem, err := merkleyeapi.DecodeRaw(s.api.Gen().GetCertificatePEM(ctx, args.SHA256))
				if err != nil {
					return nil, err
				}
				return map[string]any{"sha256": args.SHA256, "pem": pem}, nil
			}
			return merkleyeapi.Decode(s.api.Gen().GetCertificate(ctx, args.SHA256))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "list_allowlist",
		Title:       "List allowlisted lookalikes",
		Description: "Names Merkleye deliberately stops alerting on. Small and human-curated, so it is never paginated.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			value, err := merkleyeapi.Decode(s.api.Gen().ListAllowlist(ctx))
			if err != nil {
				return nil, err
			}
			return projectList(value, "entries", allowlistSummary), nil
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_summary",
		Title:       "Dashboard rollup",
		Description: "Counts and health across every watched domain. Cheap; a good first call to orient yourself.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args summaryArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.GetSummaryParams{}
			setIfNotEmpty(&params.Window, args.Window)
			return merkleyeapi.Decode(s.api.Gen().GetSummary(ctx, params))
		})
	})

	addRead(srv, &mcp.Tool{
		Name:        "get_audit_log",
		Title:       "Audit log",
		Description: "Append-only record of every mutation: who changed what, when. Use it to answer \"who acknowledged this\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args auditArgs) (*mcp.CallToolResult, any, error) {
		return s.wrap(ctx, func(ctx context.Context) (any, error) {
			params := &merkleyeapi.ListAuditLogParams{}
			limit := s.clampLimit(args.Limit)
			params.Limit = &limit
			setIfNotEmpty(&params.Actor, args.Actor)
			setIfNotEmpty(&params.Action, args.Action)
			if args.Cursor > 0 {
				cursor := merkleyeapi.Cursor(args.Cursor)
				params.Cursor = &cursor
			}
			if args.Since != "" {
				t, err := parseTime(args.Since, "since")
				if err != nil {
					return nil, err
				}
				params.Since = &t
			}

			value, err := merkleyeapi.Decode(s.api.Gen().ListAuditLog(ctx, params))
			if err != nil {
				return nil, err
			}
			return projectList(value, "entries", auditSummary), nil
		})
	})
}

// parseTime insists on RFC 3339 and says so when it does not get it.
//
// Timestamps are RFC 3339, UTC, Z-suffixed everywhere in Merkleye — never a
// Unix epoch, never a local-time string. A model that guesses "2026-08-19"
// gets a usable error rather than a 400 from three layers down.
func parseTime(value, field string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %q is not an RFC 3339 timestamp (want e.g. 2026-08-19T02:07:00Z)", field, value)
	}
	return t.UTC(), nil
}

func setIfNotEmpty(dst **string, value string) {
	if value != "" {
		v := value
		*dst = &v
	}
}
