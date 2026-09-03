package auth

import (
	"context"

	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// APIIdentity adapts the Merkleye API client to the Identity interface.
//
// The adapter exists so this package depends on a one-method interface rather
// than the client, which is what lets the credential logic be tested without
// an HTTP server anywhere in sight.
type APIIdentity struct{ API *merkleyeapi.API }

// WhoAmI implements Identity, preserving the three-way outcome exactly: a
// rejected token is (nil, nil), a failed call is an error.
func (a APIIdentity) WhoAmI(ctx context.Context, token string) (*Principal, error) {
	p, err := a.API.WhoAmI(ctx, token)
	if err != nil || p == nil {
		return nil, err
	}

	out := &Principal{
		Subject: p.Subject,
		Scopes:  p.Scopes,
	}
	if out.Scopes == nil {
		out.Scopes = []string{}
	}
	if p.ExpiresAt != nil {
		out.ExpiresAt = *p.ExpiresAt
	}
	// merkleye reports how the token itself was issued. An OIDC-issued API
	// token presented directly as a bearer is still the bearer path from this
	// server's point of view — it arrived as an opaque Merkleye token, not as
	// an IdP JWT — so Kind is set by the caller, not from here.
	return out, nil
}
