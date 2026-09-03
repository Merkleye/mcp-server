// Package config loads and validates the server's YAML configuration.
//
// Validation is strict and every error names the offending key, the same
// posture merkleye's internal/config takes and for the same reason: a typo in
// a monitoring tool is a silent misconfiguration, which is worse than a crash.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole server configuration.
type Config struct {
	Server   Server   `yaml:"server"`
	Merkleye Merkleye `yaml:"merkleye"`
	Auth     Auth     `yaml:"auth"`
	Tools    Tools    `yaml:"tools"`
}

type Server struct {
	// Bind is the Streamable HTTP listen address. Ignored under --transport=stdio.
	Bind string `yaml:"bind"`
	// PublicURL is this server's externally reachable base URL, and therefore
	// its OAuth resource identifier. It is what an access token's `aud` must
	// name, so it has to be the URL clients actually reach — not a loopback
	// address that only means something inside the container.
	PublicURL string `yaml:"public_url"`
}

type Merkleye struct {
	// BaseURL is the Merkleye API root, e.g. https://merkleye.internal:8080.
	BaseURL string `yaml:"base_url"`
	// Timeout bounds a single upstream API call.
	Timeout time.Duration `yaml:"timeout"`
	// StaticToken is a Merkleye API token used for every upstream call.
	//
	// stdio only, and it is ambient authority — the one place this server
	// holds a credential of its own rather than deriving one from the caller.
	// That is acceptable for a single developer running the binary on their
	// own machine against their own token, and is refused for the HTTP
	// transport, where callers are plural and must each bring their own.
	// Prefer the MERKLEYE_API_TOKEN environment variable over writing it here.
	StaticToken string `yaml:"static_token"`
}

// Mode selects which inbound credential types are accepted.
type Mode string

const (
	ModeBearer Mode = "bearer"
	ModeOIDC   Mode = "oidc"
	ModeBoth   Mode = "both"
)

type Auth struct {
	Mode Mode `yaml:"mode"`
	OIDC OIDC `yaml:"oidc"`
	// IdentityCacheTTL is how long a verified bearer token is trusted before
	// merkleye is asked about it again.
	//
	// It is two things at once. The auth middleware runs on every HTTP request,
	// so without a cache a twenty-call conversation is twenty round trips to
	// /auth/me. And nothing notifies us when a token is revoked, so this is
	// also the window within which a revocation takes effect. Shorter is safer
	// and chattier.
	IdentityCacheTTL time.Duration `yaml:"identity_cache_ttl"`
}

// OIDC configures the OAuth 2.1 resource-server surface.
//
// Note what is *not* here: no issuer URL, no JWKS endpoint, no algorithm
// allowlist, no audience list. All IdP knowledge lives in the Merkleye
// backend, which validates the token during the exchange (see
// internal/auth.Exchanger). This server only advertises where to authenticate
// and relays the challenge. That is what keeps one place deciding whether a
// token is good — the same place that decides what it may do.
type OIDC struct {
	Enabled bool `yaml:"enabled"`
	// DiscoveryFromAPI populates the protected resource metadata document from
	// merkleye's GET /api/v1/auth/config rather than from static values below,
	// so adding or changing an IdP is a backend config change and nothing here
	// is rebuilt or redeployed.
	DiscoveryFromAPI bool `yaml:"discovery_from_api"`
	// AuthorizationServers is the static fallback for the above — used when
	// discovery_from_api is false, or as a seed before the first successful
	// fetch.
	AuthorizationServers []string `yaml:"authorization_servers"`
	// ScopesSupported is advertised in the resource metadata and in the
	// WWW-Authenticate challenge.
	ScopesSupported []string `yaml:"scopes_supported"`
	// TokenCacheTTLMargin trims the cached exchanged-token lifetime so a token
	// is never spent in the last moments before it expires.
	TokenCacheTTLMargin time.Duration `yaml:"token_cache_ttl_margin"`
}

type Tools struct {
	// ReadOnly refuses every mutating tool. Defaults to true: connecting a
	// write-scoped token is not the same as consenting to an agent mutating
	// things, and an agent is not a UI with a confirmation dialog.
	ReadOnly *bool `yaml:"read_only"`
	// Destructive additionally exposes the irreversible and the outward-facing
	// — purging a domain destroys history, and a test notification pages a
	// real human. Off by default even when ReadOnly is false.
	Destructive bool `yaml:"destructive"`
	// DefaultLimit and MaxLimit bound list results. The API itself allows up
	// to 500 matches per page; a tool that can return 500 Match objects will
	// exhaust an agent's context and produce a worse answer than one that
	// returns 20. See internal/mcpserver.
	DefaultLimit int `yaml:"default_limit"`
	MaxLimit     int `yaml:"max_limit"`
}

// Default returns the configuration before any file or environment overrides.
func Default() Config {
	readOnly := true
	return Config{
		Server: Server{Bind: "127.0.0.1:8090"},
		Merkleye: Merkleye{
			BaseURL: "http://127.0.0.1:8080",
			Timeout: 30 * time.Second,
		},
		Auth: Auth{
			Mode:             ModeBearer,
			IdentityCacheTTL: 5 * time.Minute,
			OIDC: OIDC{
				DiscoveryFromAPI:    true,
				ScopesSupported:     []string{"read", "write", "admin"},
				TokenCacheTTLMargin: time.Minute,
			},
		},
		Tools: Tools{
			ReadOnly:     &readOnly,
			DefaultLimit: 20,
			MaxLimit:     100,
		},
	}
}

// Load reads path (empty means defaults only), applies environment overrides,
// and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true) // an unknown key is a typo, not something to ignore
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	if v := os.Getenv("MERKLEYE_API_URL"); v != "" {
		cfg.Merkleye.BaseURL = v
	}
	if v := os.Getenv("MERKLEYE_API_TOKEN"); v != "" {
		cfg.Merkleye.StaticToken = v
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports every problem at once rather than the first, so a
// misconfigured deployment needs one round trip to fix instead of five.
func (c Config) Validate() error {
	var errs []error

	if c.Merkleye.BaseURL == "" {
		errs = append(errs, errors.New("merkleye.base_url: required"))
	} else if u, err := url.Parse(c.Merkleye.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("merkleye.base_url: %q is not an absolute URL", c.Merkleye.BaseURL))
	}
	if c.Merkleye.Timeout <= 0 {
		errs = append(errs, errors.New("merkleye.timeout: must be positive"))
	}

	switch c.Auth.Mode {
	case ModeBearer, ModeOIDC, ModeBoth:
	default:
		errs = append(errs, fmt.Errorf("auth.mode: %q is not valid (bearer|oidc|both)", c.Auth.Mode))
	}

	if c.Auth.Mode == ModeOIDC && !c.Auth.OIDC.Enabled {
		errs = append(errs, errors.New("auth.oidc.enabled: must be true when auth.mode is \"oidc\", or no credential type would be accepted"))
	}

	if c.Auth.OIDC.Enabled {
		if c.Server.PublicURL == "" {
			// Without this there is no resource identifier to bind an audience
			// to, and the confused-deputy defence has nothing to check against.
			errs = append(errs, errors.New("server.public_url: required when auth.oidc.enabled — it is this server's OAuth resource identifier"))
		}
		if !c.Auth.OIDC.DiscoveryFromAPI && len(c.Auth.OIDC.AuthorizationServers) == 0 {
			errs = append(errs, errors.New("auth.oidc.authorization_servers: required when auth.oidc.discovery_from_api is false"))
		}
	}

	if c.Auth.IdentityCacheTTL <= 0 {
		errs = append(errs, errors.New("auth.identity_cache_ttl: must be positive"))
	}

	if c.Tools.DefaultLimit <= 0 {
		errs = append(errs, errors.New("tools.default_limit: must be positive"))
	}
	if c.Tools.MaxLimit <= 0 {
		errs = append(errs, errors.New("tools.max_limit: must be positive"))
	}
	if c.Tools.DefaultLimit > c.Tools.MaxLimit {
		errs = append(errs, fmt.Errorf("tools.default_limit: %d exceeds tools.max_limit %d", c.Tools.DefaultLimit, c.Tools.MaxLimit))
	}
	if c.Tools.Destructive && c.IsReadOnly() {
		errs = append(errs, errors.New("tools.destructive: has no effect while tools.read_only is true — set read_only: false as well, or drop it"))
	}

	return errors.Join(errs...)
}

// IsReadOnly reports the effective read-only setting. Tools.ReadOnly is a
// pointer so that an omitted key defaults to true while an explicit
// `read_only: false` is distinguishable from it.
func (c Config) IsReadOnly() bool {
	return c.Tools.ReadOnly == nil || *c.Tools.ReadOnly
}

// AcceptsBearer and AcceptsOIDC report which inbound credential types the
// configured mode admits.
func (c Config) AcceptsBearer() bool {
	return c.Auth.Mode == ModeBearer || c.Auth.Mode == ModeBoth
}

func (c Config) AcceptsOIDC() bool {
	return (c.Auth.Mode == ModeOIDC || c.Auth.Mode == ModeBoth) && c.Auth.OIDC.Enabled
}

// ResourceMetadataURL is where this server publishes RFC 9728 protected
// resource metadata.
func (c Config) ResourceMetadataURL() string {
	return strings.TrimSuffix(c.Server.PublicURL, "/") + "/.well-known/oauth-protected-resource"
}
