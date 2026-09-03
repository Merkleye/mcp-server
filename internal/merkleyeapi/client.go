// Package merkleyeapi wraps the generated Merkleye API client.
//
// The generated half (client.gen.go, produced by `mise run generate` from
// api/openapi.yaml) builds requests. This half supplies the transport: OTEL
// instrumentation, the per-caller credential, and a decode step that turns a
// response into generic JSON for projection into a tool result.
//
// Responses are decoded generically on purpose. Tool results are compact,
// agent-shaped projections rather than a field-by-field mapping of 60 response
// types, so the generated response-parsing layer would be dead weight — see
// internal/merkleyeapi/codegen.yaml.
package merkleyeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/merkleye/mcp-server/internal/merkleyeapi"

// Tracer is resolved unconditionally: it is a no-op provider when OTEL is
// disabled or unreachable, so instrumenting costs nothing at runtime and
// enabling tracing later needs no code changes. Never gate span creation on a
// config flag.
func Tracer() trace.Tracer { return otel.Tracer(tracerName) }

// tokenKey carries the caller's Merkleye token down to the request editor.
type tokenKey struct{}

// WithToken returns a context whose API calls authenticate as token.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

func tokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(tokenKey{}).(string)
	return t
}

// API is the wrapped client.
type API struct {
	gen     *Client
	baseURL string
}

// New builds a client against baseURL.
//
// The transport is otelhttp-wrapped, so every upstream call gets a span
// without a call site having to remember one — this is the code that leaves
// the process, and merkleye's observability contract says it gets traced.
func New(baseURL string, timeout time.Duration) (*API, error) {
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}

	gen, err := NewClient(strings.TrimSuffix(baseURL, "/"),
		WithHTTPClient(httpClient),
		WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			// The credential comes from the context, never from the client, so
			// one shared client serves every caller and none of them inherits
			// another's authority. A request with no token in context is sent
			// unauthenticated and merkleye answers 401 — which is correct, and
			// far better than silently borrowing someone else's token.
			if tok := tokenFrom(ctx); tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			req.Header.Set("Accept", "application/json")
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("build merkleye client: %w", err)
	}
	return &API{gen: gen, baseURL: strings.TrimSuffix(baseURL, "/")}, nil
}

// Gen exposes the generated client so callers can use its operationId-named
// methods directly — ListDomainMatches, AcknowledgeMatches, Search.
func (a *API) Gen() *Client { return a.gen }

// StatusError is a non-2xx response from merkleye.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("merkleye API returned %d", e.Code)
	}
	return fmt.Sprintf("merkleye API returned %d: %s", e.Code, e.Message)
}

// IsUnauthorized reports whether err is merkleye rejecting the credential.
func IsUnauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized)
}

// IsForbidden reports whether err is merkleye refusing on scope grounds.
func IsForbidden(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusForbidden
}

// maxBody bounds what a single upstream response may occupy. The API caps a
// match page at 500 items and certificates carry PEM, so an unbounded read is
// a memory footgun in a process that serves many sessions.
const maxBody = 8 << 20

// Decode reads an API response into a generic JSON value.
//
// It closes the body — every call site is `Decode(a.Gen().Something(...))`, so
// making the caller responsible for closing would mean remembering it sixty
// times.
func Decode(resp *http.Response, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if readErr != nil {
		return nil, fmt.Errorf("read response: %w", readErr)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &StatusError{Code: resp.StatusCode, Message: errorMessage(body)}
	}
	if len(body) == 0 || resp.StatusCode == http.StatusNoContent {
		return map[string]any{"ok": true}, nil
	}

	var out any
	if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
		return nil, fmt.Errorf("decode response: %w", jsonErr)
	}
	return out, nil
}

// DecodeRaw is Decode for endpoints that do not return JSON — certificate PEM,
// for instance.
func DecodeRaw(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if readErr != nil {
		return "", fmt.Errorf("read response: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &StatusError{Code: resp.StatusCode, Message: errorMessage(body)}
	}
	return string(body), nil
}

// errorMessage pulls the human-readable part out of an error body. Merkleye
// answers with either a bare {"error": "..."} or an RFC 7807 Problem; both are
// worth relaying, because "invalid cursor" is actionable and "400" is not.
func errorMessage(body []byte) string {
	var probe struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
		Title  string `json:"title"`
	}
	if err := json.Unmarshal(body, &probe); err == nil {
		for _, s := range []string{probe.Error, probe.Detail, probe.Title} {
			if s != "" {
				return s
			}
		}
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 200 {
		trimmed = trimmed[:200] + "…"
	}
	return trimmed
}

// Annotate attaches an outcome to the surrounding span.
//
// Pure in-memory logic does not need its own span; attributes on the request
// span are the right granularity, and the namespace keeps them from colliding
// with anything semconv defines.
func Annotate(ctx context.Context, kv ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(kv...)
}
