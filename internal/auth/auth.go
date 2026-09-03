// Package auth turns an inbound credential into the Merkleye API token used
// for the caller's downstream requests.
//
// This server authorizes nothing. It holds no scope logic, no issuer config,
// no JWKS cache and no audience list; merkleye is the only thing that decides
// whether a token is good and what it may do. What lives here is the mechanics
// of getting the caller's authority to merkleye intact:
//
//   - a Merkleye API token is passed straight through (Verifier.verifyBearer),
//   - an OIDC access token is exchanged upstream for a scoped Merkleye token
//     (Exchanger) — scaffolded, see exchange.go.
//
// The result is that a compromised process here cannot read or write anything
// a caller could not, because it never holds authority of its own.
package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Kind is which sort of credential a caller presented.
type Kind string

const (
	KindBearer Kind = "bearer"
	KindOIDC   Kind = "oidc"
)

// extraKey is where the resolved downstream Merkleye token is stashed on the
// SDK's TokenInfo, so tool handlers can retrieve it from the request context
// without a second lookup.
const extraKey = "merkleye_token"

// Principal is the caller as merkleye described them.
type Principal struct {
	Subject   string
	Scopes    []string
	Kind      Kind
	APIToken  string
	ExpiresAt time.Time
}

// TokenInfo renders the principal in the shape the SDK's auth middleware
// stores on the request context.
//
// UserID matters beyond logging: the streamable transport uses it to bind an
// MCP session to one user, so a session cannot be picked up by a different
// caller who happens to guess its id.
func (p *Principal) TokenInfo() *auth.TokenInfo {
	return &auth.TokenInfo{
		Scopes:     p.Scopes,
		Expiration: p.ExpiresAt,
		UserID:     p.Subject,
		Extra: map[string]any{
			extraKey:  p.APIToken,
			"kind":    string(p.Kind),
			"subject": p.Subject,
		},
	}
}

// APITokenFromContext returns the Merkleye token to use for this request's
// downstream calls, as placed there by the auth middleware.
func APITokenFromContext(ctx context.Context) (string, bool) {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil || ti.Extra == nil {
		return "", false
	}
	tok, ok := ti.Extra[extraKey].(string)
	return tok, ok && tok != ""
}

// PrincipalDescription returns a short, non-secret description of the caller
// for logs and span attributes. Never includes the token itself.
func PrincipalDescription(ctx context.Context) string {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil || ti.Extra == nil {
		return "anonymous"
	}
	subject, _ := ti.Extra["subject"].(string)
	kind, _ := ti.Extra["kind"].(string)
	if subject == "" {
		subject = "unknown"
	}
	return kind + ":" + subject
}

// Identity is the slice of the Merkleye API this package needs: confirm who a
// bearer token belongs to. Narrowed to one method so tests can fake it.
type Identity interface {
	// WhoAmI calls GET /api/v1/auth/me with token. It returns a nil principal
	// and a nil error when merkleye rejects the token, and a non-nil error
	// only when the call itself failed — the caller must be able to tell "your
	// token is bad" from "I could not ask".
	WhoAmI(ctx context.Context, token string) (*Principal, error)
}

// Verifier implements the SDK's TokenVerifier over both credential types.
type Verifier struct {
	identity      Identity
	exchanger     Exchanger
	acceptBearer  bool
	acceptOIDC    bool
	cacheTTLMargn time.Duration
	identityTTL   time.Duration

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	principal *Principal
	expires   time.Time
}

// DefaultIdentityTTL is how long a verified bearer token is trusted before it
// is re-checked against merkleye. See revalidateAt.
const DefaultIdentityTTL = 5 * time.Minute

// NewVerifier wires the two credential paths. Either may be disabled, and at
// least one must be enabled or the server accepts nothing.
func NewVerifier(identity Identity, exchanger Exchanger, acceptBearer, acceptOIDC bool, cacheTTLMargin, identityTTL time.Duration) *Verifier {
	if identityTTL <= 0 {
		identityTTL = DefaultIdentityTTL
	}
	return &Verifier{
		identity:      identity,
		exchanger:     exchanger,
		acceptBearer:  acceptBearer,
		acceptOIDC:    acceptOIDC,
		cacheTTLMargn: cacheTTLMargin,
		identityTTL:   identityTTL,
		cache:         map[string]cachedToken{},
	}
}

// Verify is the [auth.TokenVerifier] entry point.
//
// The credential type is decided structurally and once. There is deliberately
// no "try bearer, fall back to OIDC": a fallback doubles the failure modes,
// makes a 401 impossible to explain, and hands an attacker two oracles to
// probe instead of one.
func (v *Verifier) Verify(ctx context.Context, token string, _ *httpRequest) (*auth.TokenInfo, error) {
	p, err := v.Resolve(ctx, token)
	if err != nil {
		return nil, err
	}
	return p.TokenInfo(), nil
}

// Resolve is Verify without the SDK types, so the stdio transport and tests
// can use the same path.
func (v *Verifier) Resolve(ctx context.Context, token string) (*Principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: no credential presented", auth.ErrInvalidToken)
	}

	if LooksLikeJWT(token) {
		if !v.acceptOIDC {
			return nil, fmt.Errorf("%w: this deployment does not accept OIDC access tokens", auth.ErrInvalidToken)
		}
		return v.exchange(ctx, token)
	}

	if !v.acceptBearer {
		return nil, fmt.Errorf("%w: this deployment does not accept Merkleye API tokens", auth.ErrInvalidToken)
	}
	return v.verifyBearer(ctx, token)
}

// verifyBearer passes the token to merkleye and believes the answer.
//
// We cannot verify it ourselves and should not try: merkleye holds the
// argon2id hashes, and its store deliberately collapses every failure mode
// (malformed, unknown, expired, wrong secret) into one indistinguishable
// result so a handler cannot leak which it was. Reimplementing that check here
// would recreate exactly the leak it exists to prevent.
func (v *Verifier) verifyBearer(ctx context.Context, token string) (*Principal, error) {
	// The SDK's middleware runs on every HTTP request, so without this cache a
	// conversation of twenty tool calls is twenty round trips to /auth/me.
	if p, ok := v.cachedFor(token); ok {
		return p, nil
	}

	p, err := v.identity.WhoAmI(ctx, token)
	if err != nil {
		// The upstream call failed. That is not the caller's fault and
		// retrying may help, so it must not be reported as a bad token.
		return nil, fmt.Errorf("identity check unavailable: %w", err)
	}
	if p == nil {
		return nil, fmt.Errorf("%w: invalid or expired Merkleye API token", auth.ErrInvalidToken)
	}
	p.Kind = KindBearer
	p.APIToken = token
	p.ExpiresAt = v.revalidateAt(p.ExpiresAt)

	v.store(token, p)
	return p, nil
}

// revalidateAt decides when a verified principal must be checked again.
//
// Two things force this to be a real value rather than "whenever merkleye says
// the token expires":
//
//   - A Merkleye API token may have no expiry at all (expires_at is nullable),
//     and the SDK's middleware rejects a TokenInfo with a zero Expiration
//     outright. A non-expiring token is perfectly valid and must work.
//   - Nothing tells us when a token is revoked. Trusting a cached verdict
//     forever would mean a revoked token keeps working for the life of the
//     process; a bounded horizon makes revocation take effect within it.
//
// So: re-check every identityTTL, or sooner if merkleye's own expiry is sooner
// — never later, because past that point the token genuinely is dead.
func (v *Verifier) revalidateAt(upstreamExpiry time.Time) time.Time {
	horizon := time.Now().Add(v.identityTTL)
	if !upstreamExpiry.IsZero() && upstreamExpiry.Before(horizon) {
		return upstreamExpiry
	}
	return horizon
}

// LooksLikeJWT reports whether a credential is structurally a JWS compact
// serialization: three base64url segments whose first decodes to a JOSE header
// naming an algorithm.
//
// This is a *routing* decision, not a security one — nothing here is trusted,
// and merkleye validates the token during the exchange. It only has to be
// unambiguous, so that one credential takes one code path and produces one
// verdict.
func LooksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	// Cheap structural check rather than a full JSON parse: the header must be
	// a JSON object naming "alg". A Merkleye opaque token that happened to
	// contain two dots will not satisfy this.
	h := string(header)
	return strings.HasPrefix(strings.TrimSpace(h), "{") && strings.Contains(h, `"alg"`)
}

// ErrNoCredential is returned by resolvers when nothing was presented.
var ErrNoCredential = errors.New("no credential presented")
