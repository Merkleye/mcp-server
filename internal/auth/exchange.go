package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// OIDC — SCAFFOLD.
//
// The shape is settled and wired; the upstream endpoint it calls does not
// exist yet. See docs/PLAN.md §4.4.
//
// Merkleye's API accepts only bearer tokens today. Its OIDC support is
// half-built and unexercised: ent/schema/ops.go already carries
// issued_via {bearer, oidc} and idp_subject, internal/config has the full
// OIDCAuth block with validation, and internal/api.ScopesFromGroups maps group
// claims onto scopes — but nothing mints an OIDC-issued row, because no route
// performs the exchange.
//
// The remaining upstream work is POST /api/v1/auth/token/exchange
// (RFC 8693-shaped): validated OIDC access token in, short-lived api_tokens
// row out with issued_via="oidc", idp_subject=<sub>, and
// expires_at = min(subject token exp, configured cap).
//
// Everything an IdP-specific implementation would need — issuer discovery,
// JWKS fetch and rotation, algorithm allowlist, iss/exp/nbf, and the audience
// binding that is the confused-deputy defence — lives on merkleye's side of
// that call, deliberately. This package must never grow a second copy of it:
// two places validating tokens is two places to disagree about who a caller
// is.
//
// What is real here: the routing that gets an OIDC token down this path
// (LooksLikeJWT), the per-subject token cache, the RFC 9728 discovery surface
// (metadata.go), and an error that says plainly what is missing rather than
// failing open or pretending to authenticate.
// ─────────────────────────────────────────────────────────────────────────────

// ErrExchangeUnavailable is returned while the upstream exchange route is
// still unimplemented.
//
// It deliberately fails closed and says why. The alternative an implementer
// might reach for — treating an unverifiable OIDC token as anonymous, or
// falling back to a service token — would mean this server granting authority
// merkleye never approved, which is the one thing its design forbids.
var ErrExchangeUnavailable = errors.New("OIDC token exchange is not implemented upstream yet")

// Exchanger turns a validated-by-merkleye OIDC access token into a scoped
// Merkleye API token.
//
// The interface is the seam: swapping the scaffold for the real client is a
// constructor change in cmd/, not a change to the verifier, the cache, or any
// tool.
type Exchanger interface {
	// Exchange presents subjectToken to merkleye and returns the Merkleye API
	// token minted for that identity. Like Identity.WhoAmI, a rejected token
	// is (nil, nil) and only a failed call is a non-nil error — the caller has
	// to tell "your token is bad" from "I could not ask".
	Exchange(ctx context.Context, subjectToken string) (*Principal, error)
}

// UnimplementedExchanger is the scaffold. It is what a deployment gets today
// when auth.oidc.enabled is true.
type UnimplementedExchanger struct{}

func (UnimplementedExchanger) Exchange(context.Context, string) (*Principal, error) {
	return nil, ErrExchangeUnavailable
}

// exchange runs the OIDC path, caching the minted token per subject token so a
// conversation of twenty tool calls does not mint twenty API tokens.
func (v *Verifier) exchange(ctx context.Context, subjectToken string) (*Principal, error) {
	if p, ok := v.cachedFor(subjectToken); ok {
		return p, nil
	}

	if v.exchanger == nil {
		return nil, fmt.Errorf("%w: %w", sdkauth.ErrInvalidToken, ErrExchangeUnavailable)
	}

	p, err := v.exchanger.Exchange(ctx, subjectToken)
	if err != nil {
		if errors.Is(err, ErrExchangeUnavailable) {
			// Not the caller's fault and not a bad token: this deployment
			// cannot complete an OIDC sign-in at all. Say so exactly.
			return nil, fmt.Errorf("%w: %w", sdkauth.ErrOAuth, err)
		}
		return nil, fmt.Errorf("token exchange unavailable: %w", err)
	}
	if p == nil {
		return nil, fmt.Errorf("%w: identity provider token was rejected", sdkauth.ErrInvalidToken)
	}

	p.Kind = KindOIDC
	v.store(subjectToken, p)
	return p, nil
}

// cachedFor returns a cached principal that is still comfortably valid.
func (v *Verifier) cachedFor(subjectToken string) (*Principal, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	e, ok := v.cache[subjectToken]
	if !ok {
		return nil, false
	}
	// The margin is why this is not just `time.Now().Before(e.expires)`: a
	// token that expires during the upstream call it was fetched for is a
	// confusing 401 in the middle of an agent's turn.
	if !e.expires.IsZero() && time.Now().Add(v.cacheTTLMargn).After(e.expires) {
		delete(v.cache, subjectToken)
		return nil, false
	}
	return e.principal, true
}

func (v *Verifier) store(subjectToken string, p *Principal) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache[subjectToken] = cachedToken{principal: p, expires: p.ExpiresAt}
}
