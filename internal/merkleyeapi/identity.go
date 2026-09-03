package merkleyeapi

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Caller is the API's Principal schema, flattened.
//
// Named Caller rather than Principal because the generated client already
// declares a Principal for the same schema, with every field a pointer and
// scopes as a named enum slice. This is the shape the rest of the server
// actually wants.
type Caller struct {
	Subject   string     `json:"subject"`
	Display   string     `json:"display"`
	Scopes    []string   `json:"scopes"`
	IssuedVia string     `json:"issued_via"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// WhoAmI asks merkleye who a token belongs to (GET /api/v1/auth/me).
//
// Three outcomes, and keeping them apart is the whole point of the signature:
//
//	(principal, nil) — merkleye accepted the token
//	(nil, nil)       — merkleye rejected it; the caller should 401
//	(nil, err)       — the call itself failed; the caller should 5xx
//
// Collapsing the last two would turn a merkleye outage into "your credentials
// are wrong" for every user at once.
func (a *API) WhoAmI(ctx context.Context, token string) (*Caller, error) {
	ctx = WithToken(ctx, token)

	resp, err := a.gen.GetCurrentPrincipal(ctx)
	if err != nil {
		return nil, fmt.Errorf("call auth/me: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}

	value, err := Decode(resp, nil)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("auth/me returned %T, want an object", value)
	}

	p := &Caller{
		Subject:   stringField(obj, "subject"),
		Display:   stringField(obj, "display"),
		IssuedVia: stringField(obj, "issued_via"),
	}
	if raw, ok := obj["scopes"].([]any); ok {
		// Always a slice, never nil: this crosses back out as JSON, and a nil
		// slice marshals to `null` where consumers expect an array. That exact
		// bug has reached merkleye's CI more than once.
		p.Scopes = make([]string, 0, len(raw))
		for _, s := range raw {
			if str, ok := s.(string); ok {
				p.Scopes = append(p.Scopes, str)
			}
		}
	} else {
		p.Scopes = []string{}
	}
	if s := stringField(obj, "expires_at"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			p.ExpiresAt = &t
		}
	}
	return p, nil
}

func stringField(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

// AuthConfig mirrors GET /api/v1/auth/config, the public "how do I sign in
// here" document.
//
// It is where the OAuth discovery facts come from once merkleye carries them,
// so adding or changing an IdP stays a backend config change and this server
// is neither rebuilt nor redeployed. Today merkleye returns only the four
// fields below; the issuer, authorization-server metadata URL and resource
// identifier are part of the upstream work described in docs/PLAN.md §4.4.
type AuthConfig struct {
	OIDCEnabled   bool    `json:"oidc_enabled"`
	ProviderName  string  `json:"provider_name"`
	LoginURL      *string `json:"login_url"`
	BearerEnabled bool    `json:"bearer_enabled"`

	// Issuer and AuthorizationServers are populated once upstream grows them.
	// Empty is not an error here: a deployment on an older merkleye simply
	// falls back to auth.oidc.authorization_servers in local config.
	Issuer               string   `json:"issuer,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
}

// FetchAuthConfig reads the public sign-in document. No credential required —
// it is asked before anyone can be authenticated.
func (a *API) FetchAuthConfig(ctx context.Context) (*AuthConfig, error) {
	value, err := Decode(a.gen.GetAuthConfig(ctx))
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("auth/config returned %T, want an object", value)
	}

	cfg := &AuthConfig{
		ProviderName: stringField(obj, "provider_name"),
		Issuer:       stringField(obj, "issuer"),
	}
	cfg.OIDCEnabled, _ = obj["oidc_enabled"].(bool)
	cfg.BearerEnabled, _ = obj["bearer_enabled"].(bool)
	if raw, ok := obj["authorization_servers"].([]any); ok {
		cfg.AuthorizationServers = make([]string, 0, len(raw))
		for _, s := range raw {
			if str, ok := s.(string); ok {
				cfg.AuthorizationServers = append(cfg.AuthorizationServers, str)
			}
		}
	}
	return cfg, nil
}
