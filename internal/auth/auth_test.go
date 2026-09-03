package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// jwtLike builds a structurally valid JWS compact serialization. The signature
// is nonsense on purpose: nothing here verifies one, and a test that implied
// otherwise would be describing a security property this package does not have.
func jwtLike(header string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(`{"sub":"user"}`)) + ".c2ln"
}

func TestLooksLikeJWT(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"typical RS256", jwtLike(`{"alg":"RS256","kid":"abc","typ":"JWT"}`), true},
		{"alg none is still structurally a JWT", jwtLike(`{"alg":"none"}`), true},

		// The routing must not mistake an opaque Merkleye token for a JWT.
		// These are the shapes that could plausibly collide.
		{"opaque token", "mk_live_7f3a9c2e8b1d4f6a", false},
		{"opaque token with dots", "mk.live.7f3a9c2e", false},
		{"two segments", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0", false},
		{"four segments", jwtLike(`{"alg":"RS256"}`) + ".extra", false},
		{"empty segment", "eyJhbGciOiJSUzI1NiJ9..c2ln", false},
		{"header is not base64url", "!!!.eyJzdWIiOiJ1In0.c2ln", false},
		{"header is not JSON", base64.RawURLEncoding.EncodeToString([]byte("plain")) + ".YQ.c2ln", false},
		{"header JSON without alg", jwtLike(`{"typ":"JWT"}`), false},
		{"empty", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LooksLikeJWT(c.token); got != c.want {
				t.Fatalf("LooksLikeJWT(%q) = %v, want %v", c.token, got, c.want)
			}
		})
	}
}

// fakeIdentity implements Identity with the three-way outcome the real one has.
type fakeIdentity struct {
	principal *Principal
	err       error
	calls     int
}

func (f *fakeIdentity) WhoAmI(context.Context, string) (*Principal, error) {
	f.calls++
	return f.principal, f.err
}

func newVerifier(id Identity, ex Exchanger, bearer, oidc bool) *Verifier {
	return NewVerifier(id, ex, bearer, oidc, time.Minute, 5*time.Minute)
}

func TestResolveBearerPassthrough(t *testing.T) {
	id := &fakeIdentity{principal: &Principal{Subject: "svc-triage", Scopes: []string{"read"}}}
	v := newVerifier(id, nil, true, false)

	p, err := v.Resolve(context.Background(), "mk_live_abc")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Kind != KindBearer {
		t.Fatalf("Kind = %q, want %q", p.Kind, KindBearer)
	}
	// The whole point of the bearer path: the token goes downstream untouched.
	if p.APIToken != "mk_live_abc" {
		t.Fatalf("APIToken = %q, want the presented token verbatim", p.APIToken)
	}
	if p.Subject != "svc-triage" {
		t.Fatalf("Subject = %q, want svc-triage", p.Subject)
	}
}

func TestResolveRejectedBearerIsInvalidToken(t *testing.T) {
	// (nil, nil) means merkleye said no.
	v := newVerifier(&fakeIdentity{}, nil, true, false)

	_, err := v.Resolve(context.Background(), "mk_live_bad")
	if !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// A merkleye outage must not read as "your credentials are wrong" — that would
// tell every user at once to go re-authenticate against a server that is fine.
func TestResolveUpstreamFailureIsNotInvalidToken(t *testing.T) {
	v := newVerifier(&fakeIdentity{err: errors.New("connection refused")}, nil, true, false)

	_, err := v.Resolve(context.Background(), "mk_live_abc")
	if err == nil {
		t.Fatal("want an error")
	}
	if errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("an upstream failure was reported as a bad token: %v", err)
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err = %v, want it to say the check was unavailable", err)
	}
}

// Discrimination is one decision, not a cascade. A JWT presented where only
// bearer is accepted must be refused outright rather than tried as an opaque
// token — otherwise every credential probes two code paths.
func TestResolveDoesNotFallBackBetweenCredentialTypes(t *testing.T) {
	id := &fakeIdentity{principal: &Principal{Subject: "should-not-be-reached"}}
	v := newVerifier(id, UnimplementedExchanger{}, true, false)

	_, err := v.Resolve(context.Background(), jwtLike(`{"alg":"RS256"}`))
	if !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if id.calls != 0 {
		t.Fatalf("the bearer path ran for a JWT (%d calls) — that is the fallback this test forbids", id.calls)
	}
}

func TestResolveBearerRefusedWhenOIDCOnly(t *testing.T) {
	id := &fakeIdentity{principal: &Principal{Subject: "nope"}}
	v := newVerifier(id, UnimplementedExchanger{}, false, true)

	_, err := v.Resolve(context.Background(), "mk_live_abc")
	if !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
	if id.calls != 0 {
		t.Fatalf("the bearer path ran while disabled (%d calls)", id.calls)
	}
}

// The OIDC scaffold must fail closed and say why. Failing open — treating an
// unverifiable token as anonymous, or falling back to a service token — is the
// one outcome the design forbids.
func TestOIDCScaffoldFailsClosedWithAnExplanation(t *testing.T) {
	v := newVerifier(&fakeIdentity{}, UnimplementedExchanger{}, false, true)

	_, err := v.Resolve(context.Background(), jwtLike(`{"alg":"RS256","kid":"k1"}`))
	if err == nil {
		t.Fatal("an OIDC token was accepted while the exchange is unimplemented")
	}
	if !errors.Is(err, ErrExchangeUnavailable) {
		t.Fatalf("err = %v, want it to wrap ErrExchangeUnavailable", err)
	}
	if !errors.Is(err, sdkauth.ErrOAuth) {
		t.Fatalf("err = %v, want it to be an OAuth protocol error rather than a bad-token error", err)
	}
}

func TestResolveEmptyCredential(t *testing.T) {
	v := newVerifier(&fakeIdentity{}, nil, true, true)
	if _, err := v.Resolve(context.Background(), "   "); !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

// stubExchanger stands in for the upstream exchange once it exists.
type stubExchanger struct {
	principal *Principal
	calls     int
}

func (s *stubExchanger) Exchange(context.Context, string) (*Principal, error) {
	s.calls++
	return s.principal, nil
}

func TestExchangedTokenIsCachedPerSubjectToken(t *testing.T) {
	ex := &stubExchanger{principal: &Principal{
		Subject:   "user-123",
		Scopes:    []string{"read", "write"},
		APIToken:  "mk_oidc_minted",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	v := newVerifier(&fakeIdentity{}, ex, false, true)

	token := jwtLike(`{"alg":"RS256","kid":"k1"}`)
	for range 3 {
		p, err := v.Resolve(context.Background(), token)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if p.Kind != KindOIDC || p.APIToken != "mk_oidc_minted" {
			t.Fatalf("principal = %+v", p)
		}
	}
	if ex.calls != 1 {
		t.Fatalf("exchanged %d times, want 1 — a conversation of many tool calls must not mint many tokens", ex.calls)
	}
}

// A token that expires during the call it was fetched for is a confusing 401
// mid-turn. The margin is what prevents that, so it is worth a test.
func TestExpiringTokenIsNotServedFromCache(t *testing.T) {
	ex := &stubExchanger{principal: &Principal{
		Subject:   "user-123",
		APIToken:  "mk_oidc_minted",
		ExpiresAt: time.Now().Add(10 * time.Second),
	}}
	v := NewVerifier(&fakeIdentity{}, ex, false, true, time.Minute, 5*time.Minute)

	token := jwtLike(`{"alg":"RS256"}`)
	if _, err := v.Resolve(context.Background(), token); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := v.Resolve(context.Background(), token); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ex.calls != 2 {
		t.Fatalf("exchanged %d times, want 2: a token inside the expiry margin must be re-minted", ex.calls)
	}
}

func TestTokenInfoCarriesTheDownstreamToken(t *testing.T) {
	p := &Principal{Subject: "svc", Kind: KindBearer, APIToken: "mk_live_abc", Scopes: []string{"read"}}
	ti := p.TokenInfo()

	// UserID is not decoration: the streamable transport binds a session to it,
	// so a session cannot be picked up by a different caller.
	if ti.UserID != "svc" {
		t.Fatalf("UserID = %q, want svc", ti.UserID)
	}
	if got, _ := ti.Extra[extraKey].(string); got != "mk_live_abc" {
		t.Fatalf("Extra[%q] = %q, want the downstream token", extraKey, got)
	}
	if got, _ := ti.Extra["kind"].(string); got != string(KindBearer) {
		t.Fatalf("Extra[kind] = %q", got)
	}
}

func TestPrincipalDescriptionWithoutCredential(t *testing.T) {
	if got := PrincipalDescription(context.Background()); got != "anonymous" {
		t.Fatalf("PrincipalDescription = %q, want anonymous", got)
	}
}

func TestAPITokenFromContextWithoutCredential(t *testing.T) {
	if _, ok := APITokenFromContext(context.Background()); ok {
		t.Fatal("APITokenFromContext reported a token where none was authenticated")
	}
}

// A Merkleye API token may legitimately have no expiry (expires_at is
// nullable), and the SDK's middleware rejects a TokenInfo with a zero
// Expiration outright — "token missing expiration", a 401 for a perfectly good
// token. Found by a live pass against a real server, not by any unit test that
// existed at the time.
func TestNonExpiringTokenGetsARevalidationHorizon(t *testing.T) {
	id := &fakeIdentity{principal: &Principal{Subject: "svc", Scopes: []string{"read"}}}
	v := newVerifier(id, nil, true, false)

	p, err := v.Resolve(context.Background(), "mk_live_forever")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.ExpiresAt.IsZero() {
		t.Fatal("a non-expiring token produced a zero expiration, which the SDK middleware rejects")
	}
	if p.TokenInfo().Expiration.IsZero() {
		t.Fatal("TokenInfo carried a zero Expiration")
	}
	if p.ExpiresAt.After(time.Now().Add(6 * time.Minute)) {
		t.Fatalf("revalidation horizon %v is further out than the identity TTL", p.ExpiresAt)
	}
}

// Merkleye's own expiry wins when it is sooner: past that point the token
// genuinely is dead, and trusting it longer would be trusting our own cache
// over the server.
func TestUpstreamExpiryWinsWhenSooner(t *testing.T) {
	soon := time.Now().Add(30 * time.Second)
	id := &fakeIdentity{principal: &Principal{Subject: "svc", ExpiresAt: soon}}
	v := newVerifier(id, nil, true, false)

	p, err := v.Resolve(context.Background(), "mk_live_short")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !p.ExpiresAt.Equal(soon) {
		t.Fatalf("ExpiresAt = %v, want merkleye's own %v", p.ExpiresAt, soon)
	}
}

// The auth middleware runs per HTTP request, so an uncached bearer path makes a
// twenty-call conversation twenty round trips to /auth/me.
func TestBearerIdentityIsCached(t *testing.T) {
	id := &fakeIdentity{principal: &Principal{Subject: "svc", Scopes: []string{"read"}}}
	v := newVerifier(id, nil, true, false)

	for range 5 {
		if _, err := v.Resolve(context.Background(), "mk_live_abc"); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if id.calls != 1 {
		t.Fatalf("asked merkleye %d times, want 1", id.calls)
	}
}
