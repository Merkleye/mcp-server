// Command merkleye-mcp serves Merkleye's Certificate Transparency findings
// over the Model Context Protocol.
//
// Two transports, one tool surface:
//
//	--transport=stdio  a local process an MCP client launches. The credential
//	                   comes from MERKLEYE_API_TOKEN; there is one caller, and
//	                   it is whoever started the process.
//	--transport=http   Streamable HTTP. Every request carries its own
//	                   credential, so one server serves many callers and none
//	                   of them inherits another's authority.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/merkleye/mcp-server/internal/auth"
	"github.com/merkleye/mcp-server/internal/config"
	"github.com/merkleye/mcp-server/internal/mcpserver"
	"github.com/merkleye/mcp-server/internal/merkleyeapi"
)

// version is overridden at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if err := run(); err != nil {
		// stderr, never stdout: under stdio the protocol owns stdout, and a
		// stray line there corrupts the JSON-RPC stream rather than showing up
		// as a friendly error.
		fmt.Fprintf(os.Stderr, "merkleye-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", os.Getenv("MERKLEYE_MCP_CONFIG"), "Path to the YAML config file")
		transport  = flag.String("transport", "stdio", "Transport: stdio or http")
		showVer    = flag.Bool("version", false, "Print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return nil
	}
	mcpserver.Version = version

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	api, err := merkleyeapi.New(cfg.Merkleye.BaseURL, cfg.Merkleye.Timeout)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *transport {
	case "stdio":
		return runStdio(ctx, cfg, api, logger)
	case "http":
		return runHTTP(ctx, cfg, api, logger)
	default:
		return fmt.Errorf("--transport: %q is not valid (stdio|http)", *transport)
	}
}

// runStdio serves one local caller over stdin/stdout.
//
// The static token is ambient authority — the one place this server holds a
// credential rather than deriving one from the caller. That is acceptable here
// and only here: there is exactly one caller, and it is the person who started
// the process with their own token.
func runStdio(ctx context.Context, cfg config.Config, api *merkleyeapi.API, logger *slog.Logger) error {
	if cfg.Merkleye.StaticToken == "" {
		return errors.New("stdio transport needs a Merkleye API token: set MERKLEYE_API_TOKEN or merkleye.static_token")
	}

	// Fail at startup rather than on the first tool call. A client that
	// launched us will surface a startup error; a tool failing three turns into
	// a conversation just looks like the agent being unreliable.
	checkCtx, cancel := context.WithTimeout(ctx, cfg.Merkleye.Timeout)
	defer cancel()
	principal, err := api.WhoAmI(checkCtx, cfg.Merkleye.StaticToken)
	if err != nil {
		return fmt.Errorf("cannot reach the Merkleye API at %s: %w", cfg.Merkleye.BaseURL, err)
	}
	if principal == nil {
		return fmt.Errorf("merkleye rejected the configured API token")
	}
	logger.Info("authenticated to merkleye",
		"subject", principal.Subject,
		"scopes", principal.Scopes,
		"read_only", cfg.IsReadOnly())

	srv := mcpserver.New(cfg, api, cfg.Merkleye.StaticToken)
	return srv.Run(ctx, &mcp.StdioTransport{})
}

// runHTTP serves many callers over Streamable HTTP, each with their own
// credential.
func runHTTP(ctx context.Context, cfg config.Config, api *merkleyeapi.API, logger *slog.Logger) error {
	if cfg.Merkleye.StaticToken != "" {
		// Refused rather than ignored. A static token under HTTP would mean
		// every caller silently acting as one identity, which is both a
		// privilege escalation and an audit log that names the wrong person.
		return errors.New("merkleye.static_token / MERKLEYE_API_TOKEN must not be set for the http transport: " +
			"each caller presents their own credential")
	}

	// No static token, so nothing is captured here: the server reads the
	// caller's credential from each request's context.
	srv := mcpserver.New(cfg, api, "")

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv
	}, nil)

	verifier := auth.NewVerifier(
		auth.APIIdentity{API: api},
		auth.UnimplementedExchanger{}, // OIDC scaffold — see internal/auth/exchange.go
		cfg.AcceptsBearer(),
		cfg.AcceptsOIDC(),
		cfg.Auth.OIDC.TokenCacheTTLMargin,
		cfg.Auth.IdentityCacheTTL,
	)

	mux := http.NewServeMux()

	// The OAuth discovery surface. Advertised only when OIDC is enabled: a
	// resource metadata document pointing at a flow this deployment cannot
	// complete would send clients into a login that never finishes.
	resourceMetadataURL := ""
	if cfg.AcceptsOIDC() {
		resourceMetadataURL = cfg.ResourceMetadataURL()
		md := auth.ResourceMetadata(
			cfg.Server.PublicURL,
			authorizationServers(ctx, api, cfg, logger),
			cfg.Auth.OIDC.ScopesSupported,
		)
		mux.Handle("/.well-known/oauth-protected-resource", auth.MetadataHandler(md))
		logger.Info("OIDC enabled",
			"resource", md.Resource,
			"authorization_servers", md.AuthorizationServers,
			"note", "token exchange is not implemented upstream yet; OIDC sign-in will be refused with an explanation")
	}

	mux.Handle("/mcp", auth.RequireCredential(verifier, resourceMetadataURL, cfg.Auth.OIDC.ScopesSupported)(handler))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Discarded deliberately: the only way this fails is the caller having
		// gone away mid-write, and there is nothing left to tell them.
		_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
	})

	httpSrv := &http.Server{
		Addr:              cfg.Server.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logger.Info("listening",
		"bind", cfg.Server.Bind,
		"mode", cfg.Auth.Mode,
		"read_only", cfg.IsReadOnly(),
		"destructive", cfg.Tools.Destructive)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// authorizationServers resolves who issues tokens for this resource.
//
// Preferring merkleye's own answer is what keeps "any OIDC-compliant IdP" a
// backend config change: swap the IdP there and this server picks it up on
// restart with nothing rebuilt. The static list is the fallback for a merkleye
// that does not yet publish it — which is every merkleye today, since those
// discovery fields are part of the same upstream work as the exchange.
func authorizationServers(ctx context.Context, api *merkleyeapi.API, cfg config.Config, logger *slog.Logger) []string {
	if !cfg.Auth.OIDC.DiscoveryFromAPI {
		return cfg.Auth.OIDC.AuthorizationServers
	}

	fetchCtx, cancel := context.WithTimeout(ctx, cfg.Merkleye.Timeout)
	defer cancel()

	authCfg, err := api.FetchAuthConfig(fetchCtx)
	if err != nil {
		logger.Warn("could not read merkleye's auth config; falling back to auth.oidc.authorization_servers", "err", err)
		return cfg.Auth.OIDC.AuthorizationServers
	}

	switch {
	case len(authCfg.AuthorizationServers) > 0:
		return authCfg.AuthorizationServers
	case authCfg.Issuer != "":
		return []string{authCfg.Issuer}
	default:
		logger.Warn("merkleye's auth config carries no issuer yet; falling back to auth.oidc.authorization_servers")
		return cfg.Auth.OIDC.AuthorizationServers
	}
}
