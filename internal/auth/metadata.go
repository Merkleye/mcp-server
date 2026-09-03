package auth

import (
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// httpRequest is an alias so auth.go's Verify signature reads without dragging
// net/http through the credential logic, which is transport-independent.
type httpRequest = http.Request

// ResourceMetadata builds this server's RFC 9728 protected resource metadata.
//
// This document, plus the WWW-Authenticate challenge on a 401, is the entire
// OAuth surface here. It tells an MCP client where to authenticate; the client
// runs the flow itself and comes back with a token. We are never in the
// authorization-code path, and we hold no client credentials.
//
// resource is this server's own identifier, and it is what a token's `aud`
// must name when merkleye validates it during the exchange. It therefore has
// to be the URL clients actually reach.
func ResourceMetadata(resource string, authorizationServers, scopes []string) *oauthex.ProtectedResourceMetadata {
	return &oauthex.ProtectedResourceMetadata{
		Resource:             strings.TrimSuffix(resource, "/"),
		AuthorizationServers: authorizationServers,
		ScopesSupported:      scopes,
		BearerMethodsSupported: []string{
			// Header only. A token in a query string lands in access logs,
			// proxy logs and browser history.
			"header",
		},
	}
}

// MetadataHandler serves the document above with the CORS headers a browser-
// based MCP client needs for discovery.
func MetadataHandler(md *oauthex.ProtectedResourceMetadata) http.Handler {
	return auth.ProtectedResourceMetadataHandler(md)
}

// RequireCredential is the middleware that authenticates every MCP request.
//
// On rejection the SDK emits `WWW-Authenticate: Bearer resource_metadata="…"`,
// which is how a client discovers where to authenticate rather than simply
// failing. resourceMetadataURL is empty for a bearer-only deployment: there is
// no OAuth flow to point anyone at, and advertising one that cannot complete
// would send clients into a login they can never finish.
func RequireCredential(v *Verifier, resourceMetadataURL string, scopes []string) func(http.Handler) http.Handler {
	opts := &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
		// Deliberately not set: merkleye enforces scopes, and a scope list
		// here would be this server making an authorization decision. It
		// exists in the metadata document as advertisement, not as a gate.
		Scopes: nil,
	}
	_ = scopes
	return auth.RequireBearerToken(v.Verify, opts)
}
