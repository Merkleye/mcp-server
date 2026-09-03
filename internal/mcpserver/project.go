package mcpserver

// Result projection.
//
// This is a correctness concern, not a tidiness one. GET /api/v1/matches
// accepts limit up to 500, and a Match carries the full certificate, the risk
// breakdown and enrichment. Handing an agent 500 of those exhausts its context
// and produces a worse answer than handing it 20 summaries and letting it ask
// for the two that matter.
//
// So: list tools project each item down to what triage actually reads, always
// return the cursor, and point at the detail tool for the rest.

// matchSummary is what a match looks like in a list.
var matchSummary = []string{
	"id",
	"domain_id",
	"domain",
	"matched_name",
	"common_name",
	"severity",
	"risk_score",
	"acknowledged",
	"issuer",
	"not_before",
	"not_after",
	"seen_at",
	"certificate_sha256",
}

var domainSummary = []string{
	"id",
	"name",
	"status",
	"created_at",
	"variant_count",
	"match_count",
}

var variantSummary = []string{
	"id",
	"name",
	"kind",
	"registration",
	"ns_resolves",
	"variant_set_id",
	"created_at",
}

var allowlistSummary = []string{
	"id",
	"name",
	"reason",
	"created_at",
	"created_by",
}

var auditSummary = []string{
	"id",
	"actor",
	"action",
	"entity_type",
	"entity_id",
	"at",
}

// pickFields keeps only the named keys, and only when present. Absent keys are
// skipped rather than emitted as null: an agent reading `"issuer": null` may
// conclude the certificate has no issuer, when in truth this projection did
// not carry one.
func pickFields(obj map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if v, ok := obj[f]; ok && v != nil {
			out[f] = v
		}
	}
	return out
}

// projectList rewrites a list response so its items are summaries, leaving
// pagination and totals untouched.
//
// Every list response keeps its items key as an array even when empty. A nil
// slice would marshal to JSON null against a shape the agent expects to
// iterate — the same bug class that has twice reached merkleye's CI.
func projectList(value any, itemsKey string, fields []string) any {
	obj, ok := value.(map[string]any)
	if !ok {
		return value
	}

	rawItems, ok := obj[itemsKey].([]any)
	if !ok {
		obj[itemsKey] = []any{}
		return obj
	}

	items := make([]any, 0, len(rawItems))
	for _, raw := range rawItems {
		if item, ok := raw.(map[string]any); ok {
			items = append(items, pickFields(item, fields))
		} else {
			items = append(items, raw)
		}
	}
	obj[itemsKey] = items

	// Say so explicitly rather than letting an agent infer completeness from a
	// short page: a summary that silently omits fields invites a wrong
	// conclusion about a certificate.
	obj["_note"] = "Items are summaries. Use the matching detail tool for the full record, and next_cursor to page."
	return obj
}

// clampLimit keeps a caller-supplied limit inside the configured bounds.
//
// An agent asking for 500 is not malicious, it is optimising for one round
// trip; the cap is what stops that from costing it the rest of its context.
func (s *Server) clampLimit(requested int) int {
	switch {
	case requested <= 0:
		return s.cfg.Tools.DefaultLimit
	case requested > s.cfg.Tools.MaxLimit:
		return s.cfg.Tools.MaxLimit
	default:
		return requested
	}
}
