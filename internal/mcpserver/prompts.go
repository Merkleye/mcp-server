package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Prompts encode the workflows an operator actually runs, so a user gets a
// good first turn without having to know the tool names or the order to call
// them in. They are the difference between "here are 22 tools" and "here is
// how triage works".

func (s *Server) registerPrompts(srv *mcp.Server) {
	srv.AddPrompt(&mcp.Prompt{
		Name:        "triage-recent-matches",
		Title:       "Triage recent matches",
		Description: "Walk the untriaged matches from a recent window and sort real threats from noise.",
		Arguments: []*mcp.PromptArgument{
			{Name: "window", Description: "How far back to look, e.g. 7d or 24h. Defaults to 7d.", Required: false},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		window := argOr(req, "window", "7d")
		return prompt(fmt.Sprintf(`Triage Merkleye's untriaged matches from the last %s.

1. Call get_summary to orient yourself.
2. Call list_matches with acknowledged=false, highest severity first. Page with
   next_cursor rather than raising the limit.
3. For anything that is not obviously benign, call get_match for the full
   certificate and risk breakdown.

For each match decide, and say which and why:
  - A legitimate certificate for our own domain from an unexpected CA. Check the
    issuer against the domain's expected_issuers before calling it a threat.
  - A benign lookalike we do not control (a partner, a CDN, a parked name).
  - A likely phishing or impersonation certificate.

Then report your findings and propose actions. Do not acknowledge or allowlist
anything until I have agreed to it.`, window))
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "investigate-certificate",
		Title:       "Investigate a certificate",
		Description: "Dig into one match or certificate and assess whether it is a real threat.",
		Arguments: []*mcp.PromptArgument{
			{Name: "subject", Description: "A match id, a certificate SHA-256, or a domain name.", Required: true},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		subject := argOr(req, "subject", "")
		return prompt(fmt.Sprintf(`Investigate %q in Merkleye and tell me whether it is a real threat.

Start with search if you are not sure what kind of identifier that is. Then
gather the full picture: get_match for the risk breakdown, get_certificate for
the certificate itself, and list_variants for the watched domain if the name
looks like a generated lookalike.

Weigh at least:
  - Is the issuer among the domain's expected_issuers? Matching is a
    case-insensitive substring, not equality.
  - What are the other SANs on the certificate?
  - Is the lookalike registered, and does it resolve? "unknown" means RDAP or
    DNS did not answer, which is not the same as "no".
  - How close is the name to ours, and in what way — homoglyph, typo, TLD swap?

Give me a verdict with your reasoning and a recommended action.`, subject))
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "onboard-domain",
		Title:       "Onboard a domain",
		Description: "Add a domain to Merkleye with a sensible issuer policy and check its posture.",
		Arguments: []*mcp.PromptArgument{
			{Name: "domain", Description: "The domain to start watching.", Required: true},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		domain := argOr(req, "domain", "")
		return prompt(fmt.Sprintf(`Help me start watching %q with Merkleye.

1. Call preview_variants to show me what lookalikes would be generated, so I can
   see whether the fuzzer and TLD defaults suit this domain.
2. Ask me which CAs legitimately issue for it. This matters: without at least
   one expected issuer, every routine renewal will alert as critical. If I do
   not know, tell me how to find out:
     openssl s_client -connect %s:443 -servername %s </dev/null 2>/dev/null \
       | openssl x509 -noout -issuer
3. Once I confirm, call add_domain.
4. Then call get_domain_caa and get_domain_dns_provider, and show me the CAA
   records to publish and where to publish them.

Confirm with me before adding anything.`, domain, domain, domain))
	})
}

func prompt(text string) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: text},
		}},
	}, nil
}

func argOr(req *mcp.GetPromptRequest, name, fallback string) string {
	if req == nil || req.Params == nil {
		return fallback
	}
	if v, ok := req.Params.Arguments[name]; ok && v != "" {
		return v
	}
	return fallback
}
