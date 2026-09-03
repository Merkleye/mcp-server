# Merkleye MCP Server — buildout plan

Status: **plan, not yet built.** Nothing below has been implemented.

An MCP server that puts Merkleye's Certificate Transparency watchtower in
front of an LLM agent: "what lookalike certs showed up for our domains this
week, which are real, acknowledge the noise." It is a client of the Merkleye
API and owns no data of its own.

The whole surface derives from `api/openapi.yaml` in
[`merkleye/merkleye`](https://github.com/merkleye/merkleye) — that spec is the
product boundary, and the discipline merkleye-ui follows (generate the client
in CI, fail the build on drift) applies here too.

---

## 1. Constraints inherited from merkleye

From the core repo's `AGENTS.md` and `docs/DESIGN.md`. Not negotiable.

- **The OpenAPI spec is the only contract.** No database access, no
  `/internal/v1/*` routes (loopback-only, deliberately out of spec), no
  reimplementing logic that lives in `internal/match` or `internal/score`.
- **One permission model.** DESIGN §11: OIDC exchanges an IdP token for one of
  the same scoped `api_tokens` rows a service would use, "so there is no
  second permission model to keep in sync."
- **Timestamps are RFC 3339, UTC, Z-suffixed** — tool arguments, tool results,
  logs.
- **OTEL instrumentation is a MUST.** Anything leaving the process gets a
  span; custom attributes namespaced `merkleye.mcp.<field>`.
- **A live E2E pass is required before anything ships.** Unit tests against a
  fake IdP and a fake API are necessary and never sufficient.
- **Never nil, always `[]T{}`.** The bug class that has reached CI twice
  upstream (a nil Go slice marshalling to JSON `null` against a schema
  requiring an array) applies verbatim to tool results.

## 2. Toolchain

**mise-en-place owns tools and tasks.** `mise.toml` is the single source of
truth for both — `mise install` provisions, `mise run <task>` executes, and CI
runs the same tasks so there is no second definition of what "check" means.
Task names match merkleye's Makefile targets (`check`, `fmt-check`, `vet`,
`lint`, `govulncheck`, `test`, `generate`, `spec`) so muscle memory carries
between repos.

```toml
[tools]
go             = "1.27.1"   # matches merkleye's mise.toml
golangci-lint  = "2.13.2"   # matches merkleye's mise.toml
node           = "22"       # npm distribution (§5.2), not implementation
"go:github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen" = "..."
"npm:@modelcontextprotocol/inspector" = "..."   # conformance (§9)
```

| Choice | Value | Why |
| --- | --- | --- |
| Language | Go 1.27 | Same toolchain, lint config and container story as merkleye; the API client generates from the same spec. |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk` **v1.7.0** | Official SDK. Negotiates protocol `2026-07-28`, back-compatible to `2024-11-05`. Ships `auth.RequireBearerToken` (pluggable `TokenVerifier`, emits the RFC 9728 `WWW-Authenticate` challenge) and `auth.ProtectedResourceMetadataHandler` — the two pieces §4 needs, rather than hand-rolled. |
| API client | generated from a pinned `openapi.yaml` | §3.1 |
| Transports | Streamable HTTP + stdio | §5 |
| Container | `Containerfile`, not `Dockerfile` | merkleye convention. |

### 2.1 Repo layout

```
cmd/merkleye-mcp/        # single binary; --transport=http|stdio
internal/mcpserver/      # tool/resource/prompt registration
internal/auth/           # inbound credential handling (§4)
internal/merkleyeapi/    # generated client + otelhttp wrapper
internal/config/         # strict YAML validation, errors naming the bad key
internal/telemetry/      # OTEL wiring, mirrors merkleye's
api/openapi.yaml         # pinned copy of the upstream spec (§3.1)
npm/                     # thin launcher package (§5.2) — no Node implementation
```

Also mirrored from merkleye: `.golangci.yml`, `.githooks/`, `.releaserc.json`
+ semantic-release, `Containerfile`, `AGENTS.md` with `CLAUDE.md` importing it.

## 3. Architecture

```
  Claude Code · Claude Desktop · LiteLLM
        │  Streamable HTTP (or stdio) + Authorization: Bearer <opaque | OIDC JWT>
        ▼
  merkleye-mcp   ── discriminates the credential, never authorizes
        │  HTTPS + Authorization: Bearer <merkleye api_token>
        ▼
  merkleyed      ── the only thing that authorizes anything, and the only
        │           thing that talks to an IdP
        ▼
  Postgres
```

Stateless apart from one cache: exchanged Merkleye tokens keyed by IdP
subject. It holds **no ambient authority** — every downstream call carries a
credential derived from the caller's own, so a compromised MCP process cannot
read or write anything a caller could not.

### 3.1 Keeping the client honest

`api/openapi.yaml` is vendored at a pinned upstream version; `mise run
generate` regenerates the client (`oapi-codegen`). CI adds a **drift job**:
fetch the spec from the pinned merkleye release artifact, diff against the
vendored copy, fail on difference. A silently-broken integration becomes a red
build — the reason the two-repo split exists at all.

### 3.2 `operationId`s — what they are, and why we want them upstream

An `operationId` is an optional unique string naming one operation (one
path + method pair) in an OpenAPI document:

```yaml
  /api/v1/domains/{id}/matches:
    get:
      operationId: listDomainMatches    # ← this
```

It changes nothing on the wire. It is a *name for the operation* that
tooling uses instead of inventing one.

**Upstream has zero, across all 63 operations.** Every generator therefore
synthesises a name from the method and path. `oapi-codegen` would give us
`GetApiV1DomainsIdMatches`. Four consequences, in increasing order of how much
they actually hurt:

1. **Call sites read like URLs.** `GetApiV1DomainsIdMatches(ctx, id, params)`
   instead of `ListDomainMatches(ctx, id, params)`.
2. **The name is coupled to the URL.** Rename the path `/matches` →
   `/findings` and every generated symbol changes, breaking compilation in
   every consumer — for a URL change that is not a contract change at all.
   With an `operationId`, the path can move and the name holds still.
3. **Two consumers invent two different names.** merkleye-ui's TypeScript
   generator and our Go generator synthesise differently from the same
   operation, so there is no shared vocabulary for "that call" across repos,
   in code or in review.
4. **MCP tool names are a public interface.** Users write them into agent
   configs and saved prompts; agents learn them. A tool name derived from a
   path silently changes when a URL changes, breaking those configs with no
   error anyone sees. Tool names must be anchored to something stable, and
   `operationId` is exactly that anchor.

`operationId` is also what spectral and schemathesis use to label findings, so
upstream's contract-test output gets more readable as a side effect.

**Proposal:** contribute `operationId`s to `api/openapi.yaml` upstream —
camelCase verb+noun, unique document-wide (`listDomains`, `createDomain`,
`getDomain`, `patchDomain`, `deleteDomain`, `restoreDomain`, `purgeDomain`,
`listDomainMatches`, `acknowledgeMatches`, …). Mechanical, additive, and it
benefits merkleye-ui identically.

**One real cost, to coordinate rather than discover:** the wire contract is
untouched, but *generated client symbols in merkleye-ui will all be renamed*.
merkleye-ui generates from this spec in CI and fails on drift, so the upstream
spec PR needs a matching merkleye-ui PR landing with it. Non-breaking for the
API, breaking for generated code.

**If that coordination isn't wanted:** keep a checked-in operation→name map in
this repo and fail our build when an operation appears the map doesn't cover.
Solves 1 and 4 for us only; 2 and 3 stay broken.

## 4. Authentication

The server accepts both credential types. Both arrive as
`Authorization: Bearer <x>`.

**Decided: all IdP knowledge lives in the merkleye backend.** Any
OIDC-compliant IdP is supported, and the MCP server is not where that support
lives — it holds no issuer config, no JWKS cache, no `alg` allowlist, no
audience list. That is a real simplification and it keeps §1's "one permission
model" honest: there is exactly one place that decides whether a token is
good, and it is the same place that decides what the token may do.

### 4.1 Credential discrimination

- **Merkleye API token** — opaque, argon2id-hashed server-side, scoped
  `read | write | admin`.
- **OIDC access token** — a JWT from whatever IdP the deployment configured.

Discriminate structurally: a JWT is three base64url segments with a decodable
JOSE header carrying `alg`/`kid`; anything else is opaque. **Never try one and
fall back to the other** — a fallback doubles the failure modes, makes 401
reasons ambiguous, and hands an attacker two oracles. One credential, one code
path, one verdict. `auth.mode: bearer | oidc | both` lets an operator disable
either outright.

### 4.2 Bearer tokens — pass-through, never verified here

We cannot verify them: merkleye holds the argon2id hashes, and
`store.VerifyAPIToken` deliberately collapses every failure (malformed,
unknown, expired, wrong secret) into one indistinguishable nil so a handler
cannot leak which it was. Re-implementing that here would recreate the leak it
prevents.

So: attach the token downstream and let merkleye decide. One
`GET /api/v1/auth/me` on first use learns the subject and scopes — for
logging, for the SDK's `TokenInfo.UserID` (which binds a session to one user
and blocks session hijacking), and to hide tools the caller cannot use.
**That hiding is presentation only**; merkleye enforces regardless, and in the
core repo's own words "the UI never treats its own check as security."

### 4.3 OIDC — resource server for discovery, backend for validation

Per the MCP authorization spec, but split so validation stays upstream:

**Ours (discovery and challenge only):**
- `GET /.well-known/oauth-protected-resource` via
  `auth.ProtectedResourceMetadataHandler`, advertising this server's resource
  identifier and its authorization server. Contents come from merkleye's
  `/api/v1/auth/config` (see §4.4), so adding an IdP is a backend config
  change and nothing here is rebuilt or redeployed.
- 401 with `WWW-Authenticate: Bearer resource_metadata="…"` via
  `auth.RequireBearerToken`, which is how an MCP client discovers where to
  authenticate. We are never in the authorization-code path.

**Merkleye's (all of it):** OIDC discovery on the configured issuer, JWKS
fetch and rotation, `alg` allowlist, `iss`, `exp`/`nbf`, and — critically —
**`aud` bound to the MCP server's resource identifier**, the confused-deputy
defence the MCP spec names explicitly. A token minted for another service in
the same IdP must not be spendable here. Group claims map to scopes through
the existing `internal/api.ScopesFromGroups`, including its rule that an
unmapped group falls back to a configured default never permitted to be
`admin`.

### 4.4 Upstream work in `merkleye/merkleye` — Option A, confirmed

Merkleye is already extended for OIDC but nothing exercises it. Verified
against `main` (`7b3bea0`):

| Piece | State |
| --- | --- |
| `ent/schema/ops.go` | Ready. `issued_via` enum `{bearer, oidc}`, `idp_subject` "recorded for audit when issued_via=oidc". **No migration needed.** |
| `internal/config` | Ready. Full `OIDCAuth` with strict validation — `issuer_url`/`client_id` required when enabled, `default_scope` refused if `admin` so unmapped groups cannot fail open. |
| `internal/api.ScopesFromGroups` | Written, correct, **zero production callers.** Tests only. |
| `Authenticator.Middleware` | Already prefers `idp_subject` as the Principal subject for an OIDC row. Tested against a hand-built record. |
| The exchange | **Missing.** `NewAuthenticator`'s comment: "OIDC code exchange is still unimplemented … that lands as its own piece of work." |

So the work is finishing a half-built path, not introducing one. Two additions:

**1. `POST /api/v1/auth/token/exchange`** — RFC 8693-shaped:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<OIDC access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
resource=<the MCP server's resource identifier>
```

Validates the subject token against the configured issuer (§4.3), maps groups
via `ScopesFromGroups`, and mints an `api_tokens` row with
`issued_via="oidc"`, `idp_subject=<sub>`,
`expires_at = min(subject token exp, configured cap)`. Returns the raw token
and its expiry. First production caller of `ScopesFromGroups`.

Why this and not the alternatives: it is the design DESIGN §11 already
specifies; audit rows name the human rather than a shared service account —
the difference between an audit log and a log; and the browser OIDC flow needs
the identical exchange, so MCP is the first caller, not a special case.

**2. Extend `GET /api/v1/auth/config`** with the discovery facts §4.3 needs —
issuer URL, authorization-server metadata URL, resource identifier, supported
scopes. It already reports `oidc_enabled` / `bearer_enabled` and is already
public (asked before anyone can authenticate), so this is additive.

Both need a spec entry and a `make test-contract` pass upstream.

#### 4.4.1 "Untested" is a real risk, plus one confirmed bug

Nothing exercises the OIDC path end to end today, so phase 2 cannot treat
these pieces as known-good — it is the thing that proves them.

- **`GET /api/v1/auth/config` advertises a route that does not exist.**
  `handleAuthConfig` returns `login_url: "/api/v1/auth/login"` whenever
  `auth.oidc.enabled` is true; `internal/api/router.go` registers only
  `/api/v1/auth/config` and `/api/v1/auth/me`. Enable OIDC today and the UI is
  pointed at a 404. Worth fixing upstream on its own, and the exchange work
  should settle what lives under `/api/v1/auth/*` rather than adding a third
  half-route.
- **`ScopesFromGroups` has never seen a real IdP's claims.** Its tests feed it
  Go string slices. Whether a given IdP emits the group claim under the
  configured name, as strings rather than objects, in the casing the mapping
  expects, is unverified — and "any OIDC-compliant IdP" makes that variance
  the normal case, not an edge one. The §9 live E2E settles it, and the
  mapping likely needs to become configurable rather than the current
  hardcoded `merkleye-admin` / `merkleye_admins` list.

#### 4.4.2 Dynamic client registration — the compatibility catch

Claude Desktop's custom-connector flow authenticates by running the OAuth
handshake itself, and the smooth path is **Dynamic Client Registration**
(RFC 7591). Many enterprise IdPs do not support DCR, or disable it. With
"any OIDC-compliant IdP" as the target, assuming DCR would strand a
meaningful share of deployments at "add connector" with no way forward.

Mitigation, in preference order:

1. **A DCR shim in merkleye** alongside the exchange route: accept RFC 7591
   registration requests and return a pre-provisioned `client_id`/`client_secret`
   from config. This is what LiteLLM does for the same reason, and it makes
   every IdP look DCR-capable to every MCP client.
2. **Pre-registered credentials**, where the client supports them — Claude
   Code takes `--client-id` / `--client-secret` / `--callback-port` for
   exactly this. Claude Desktop's connector UI is less accommodating.

Recommend (1), scoped into the same upstream PR as the exchange, since both
are "merkleye is the OAuth-facing component" work.

### 4.5 Write safety

Scope enforcement is merkleye's job. Two things stay ours, because an agent is
not a UI:

- **`tools.read_only` defaults to true.** Connecting a write-scoped token is
  not the same as consenting to an agent mutating things.
- **Irreversible operations are not exposed at all by default.**
  `DELETE /api/v1/domains/{id}/purge` destroys history;
  `POST /api/v1/notifications/test` sends a real message to a real channel.
  Both sit behind `tools.destructive: true`, off by default. An agent that can
  page someone at 3am by accident is a bug in this repo.

## 5. Deployment and client compatibility

Target: Claude Code, Claude Desktop, and LiteLLM, without a per-client build.

### 5.1 What each client actually supports

| Client | Transports | Auth it can present |
| --- | --- | --- |
| **Claude Code** | http (recommended), stdio, sse (deprecated), ws | Full OAuth with DCR automatically; `--client-id`/`--client-secret`/`--callback-port` without DCR; static `--header "Authorization: Bearer …"`; `headersHelper` script for rotating tokens |
| **Claude Desktop** | stdio via `claude_desktop_config.json`; remote **only** via Settings → Connectors | The connector flow runs its own OAuth handshake and does not expose arbitrary headers — so for remote use **OAuth is effectively required**, and a static bearer token only works over stdio |
| **LiteLLM** | http, sse, stdio | `auth_type: bearer_token` with a stored token; full OAuth 2.1 — PRM discovery, `WWW-Authenticate`, DCR forwarding, PKCE; `upstream_token_header` when the token must go somewhere other than `Authorization` |

Two conclusions fall out. Every client speaks Streamable HTTP, so that is the
primary transport. And Claude Desktop's remote path makes §4.3/§4.4.2 load-
bearing rather than nice-to-have: **without OAuth there is no Claude Desktop
connector**, and without a DCR answer there is no Claude Desktop connector
against a non-DCR IdP.

### 5.2 One binary, three distribution channels

Not a rewrite in Node, and not a Go binary for some clients and a Node one for
others. One Go binary, packaged three ways:

1. **Container image** — `ghcr.io/merkleye/mcp-server`, multi-arch
   (`linux/amd64`, `linux/arm64`) with an SPDX SBOM, through the same
   `semantic-release` pipeline merkleye uses for its three images. **This is
   the reference deployment**: the shared Streamable HTTP endpoint that Claude
   Desktop connectors and LiteLLM point at.
2. **npm launcher** — `@merkleye/mcp-server`, publishing the platform binaries
   as `optionalDependencies` with a tiny shim that execs the right one (the
   esbuild/turbo pattern). **Zero Node implementation.** It exists so
   `npx -y @merkleye/mcp-server` drops into a `claude_desktop_config.json`
   stdio entry or `claude mcp add … -- npx …` with no install step, which is
   the lowest-friction path for a single developer.
3. **Plain binaries + checksums** on GitHub Releases, for `mise`/`ubi`
   installs and for anyone who wants neither Docker nor npm.

### 5.3 Sidecar or standalone

**Standalone service alongside `merkleyed`, not a loopback sidecar.** Two
reasons, both structural: remote MCP clients must reach it directly, and
audience binding (§4.3) requires it to have its own stable, externally
meaningful resource identifier — which a loopback-only process does not have.

It can still be *run* as a sidecar where that suits — the binary does not care,
and an in-cluster LiteLLM talking to it over the pod network is a perfectly
good topology. That is a deployment choice, not the reference one.

For a developer who wants Claude Desktop against a remote OIDC-protected
instance but cannot use the connector UI, `npx mcp-remote` already bridges
stdio to a remote OAuth server. We do not need to write that.

## 6. Tool surface

63 operations. **Do not map them 1:1** — an agent handed 63 tools chooses
worse and spends its context on the menu. ~22 tools around the real workflows;
reference data becomes resources.

**Triage (the primary loop)** — `search` · `list_matches` · `get_match` ·
`acknowledge_matches` · `allowlist_from_match` · `rescore_match` ·
`get_certificate`

**Domains** — `list_domains` · `get_domain` · `add_domain` · `update_domain` ·
`remove_domain` · `get_domain_policies` · `set_domain_policies`

**Variants** — `list_variants` · `list_variant_changes` · `preview_variants` ·
`regenerate_variants`

**Posture** — `get_domain_caa` · `get_domain_dns_provider` · `get_summary` ·
`get_audit_log`

**Allowlist** — `list_allowlist` · `add_allowlist_entry` ·
`remove_allowlist_entry`

Excluded by default: purge, notification test-delivery, plugin config writes,
settings writes (reachable via `tools.destructive` / `read_only`).

Tool names are anchored to upstream `operationId`s (§3.2) so a URL change
never silently renames a tool in someone's saved agent config.

### 6.1 Result sizing — a correctness issue, not a nicety

`Match` is a large object and `/api/v1/matches` accepts `limit` up to 500. A
tool that can return 500 of them will blow an agent's context and produce a
worse answer than one returning 20.

- `limit` defaults to 20, hard-capped well below the API's 500;
- every list tool returns `next_cursor` and documents paging — cursor, not
  offset, because rows insert continuously and an offset skips whatever landed
  between pages;
- list results carry a **compact projection** (id, domain, common name,
  severity, score, seen-at, acknowledged); `get_match` returns the full object.
  The agent pages summaries and drills into what matters.

Tool descriptions carry the domain facts an agent cannot infer and will
otherwise get wrong: match keys are punycode A-labels, severity ordering, what
acknowledging does and does not do, and that a variant's `registration` is
RDAP's answer while `ns_resolves` is DNS's.

## 7. Resources and prompts

**Resources** (read-only, URI-addressed, cheap to re-read):
`merkleye://summary`, `merkleye://config`, `merkleye://cas`,
`merkleye://plugins`, `merkleye://settings/{variants,scoring,notifications}`,
`merkleye://domain/{id}`, `merkleye://match/{id}`.

**Prompts**: `triage-recent-matches`, `onboard-domain`,
`investigate-certificate`.

## 8. Live match feed — phase 4, flagged

`GET /api/v1/matches/stream` is SSE, one event per newly-persisted match, no
replay on connect. MCP has no arbitrary server-push, but it has resource
subscriptions: subscribe a session to `merkleye://matches/recent`, back it
with the upstream SSE connection, emit `notifications/resources/updated` per
match.

Last, and behind a flag: it holds one upstream connection per subscribed
session, and the endpoint 501s where no live feed is wired up. A client that
falls behind misses events **by design** — recovery is a cursor-paged
`list_matches`, and the tool descriptions must say so rather than implying the
stream is lossless.

## 9. Testing gates

- **Unit** — the credential path gets an adversarial table, not a happy path:
  opaque token shaped like a JWT, JWT shaped like an opaque token, exchange
  returning 401/403/500, exchange latency and cache expiry races, a cached
  token expiring mid-call.
- **Contract** — the generated client compiles against the vendored spec, and
  the drift job (§3.1) proves the vendored spec is the real one.
- **Conformance** — MCP Inspector against a running server, both transports.
- **Client compatibility, per release** — Claude Code over http and stdio,
  Claude Desktop connector and stdio, LiteLLM `auth_type: bearer_token` and
  OAuth. §5.1 is researched, not tested; each row becomes a checklist item.
- **Live E2E, required before shipping** — real `merkleyed` (via
  `merkleyed token create`) plus a real IdP, driven by a real MCP client. This
  is merkleye's rule that a mock passing is necessary and never sufficient,
  and it is the **first** exercise of merkleye's OIDC path, so it proves
  `ScopesFromGroups` and the `issued_via="oidc"` row as well as our own code.

## 10. Phasing

| Phase | Contents | Done when |
| --- | --- | --- |
| 0 | Repo scaffold, mise tools + tasks, CI, vendored spec, generated client, drift job | `mise run check` green on an empty tool set |
| 1 | stdio transport, bearer pass-through, read-only triage tools, npm launcher | An agent answers "what matched this week" against a local merkleyed, from Claude Code and Claude Desktop |
| 2 | **Upstream:** exchange route + `auth/config` discovery fields + DCR shim (§4.4). **Here:** Streamable HTTP, protected resource metadata, 401 challenge, exchange + cache | Live E2E against a real IdP; Claude Desktop custom connector completes its OAuth handshake |
| 3 | Write tools behind `read_only`, resources, prompts | Full triage loop, live E2E |
| 4 | Live match subscriptions (§8) | Flagged, off by default |
| — | `operationId`s upstream + matching merkleye-ui PR (§3.2) | Spec side open as [merkleye/merkleye#48](https://github.com/Merkleye/merkleye/pull/48); merkleye-ui PR still needed |

Phase 1 is deliberately shippable alone: bearer-only, stdio-only, read-only is
genuinely useful and validates the tool surface before OAuth lands.

## 11. Open decisions

1. **Is the upstream PR ours to open or the core team's?** Phase 2 is blocked
   on it either way.
2. **DCR shim (§4.4.2) — in scope for that same PR?** Recommend yes; without
   an answer, Claude Desktop only works against DCR-capable IdPs.
3. **`operationId`s (§3.2) — done upstream.**
   [merkleye/merkleye#48](https://github.com/Merkleye/merkleye/pull/48) adds
   all 63 and makes `make spec` fail without one. Still needs a coordinated
   merkleye-ui PR before it merges, because every generated symbol there
   renames.
4. **Does the group→scope mapping become configurable?** Currently a hardcoded
   `merkleye-admin` / `merkleye_admins` list, which "any OIDC IdP" outgrows
   immediately.

## 12. Deliberately deferred

- **Sampling / elicitation.** No use case a tool result doesn't cover.
- **Writing to `/internal/v1/*`.** Loopback-only and out of spec on purpose.
- **Caching Merkleye responses.** A watchtower's value is freshness; a stale
  match list is worse than a slow one. (The exchanged-token cache is not this:
  it caches a credential, not an answer.)
- **Any classification, scoring, or matching logic here.** That lives in
  `internal/match`, `internal/score`, `internal/policy` and stays there. If a
  tool needs a judgement the API doesn't expose, the fix is an upstream
  endpoint, not a second implementation.
