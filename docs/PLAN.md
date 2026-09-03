# Merkleye MCP Server — buildout plan

Status: **plan, not yet built.** This repository is empty; this document is
its first commit. Nothing below has been implemented.

An MCP server that puts Merkleye's Certificate Transparency watchtower in
front of an LLM agent: "what lookalike certs showed up for our domains this
week, which are real, acknowledge the noise." It is a client of the Merkleye
API and owns no data of its own.

The whole surface is derived from `api/openapi.yaml` in
[`merkleye/merkleye`](https://github.com/merkleye/merkleye) — that spec is the
product boundary, and the same discipline merkleye-ui follows (generate the
client in CI, fail the build on drift) applies here.

---

## 1. Constraints inherited from merkleye

These are not negotiable; they come from the core repo's `AGENTS.md` and
`docs/DESIGN.md` and this repo has to honour them to be a good citizen.

- **The OpenAPI spec is the only contract.** No reaching into the database,
  no `/internal/v1/*` routes (loopback-only, deliberately out of spec), no
  reimplementing classification logic that lives in `internal/match` or
  `internal/score`.
- **One permission model.** DESIGN §11: OIDC exchanges an IdP token for one of
  the same scoped `api_tokens` rows a service would use, "so there is no
  second permission model to keep in sync." A design where this MCP server
  decides who may write is a second permission model. §4 below is mostly
  about avoiding that.
- **Timestamps are RFC 3339, UTC, Z-suffixed.** Everywhere — tool arguments,
  tool results, logs.
- **OTEL instrumentation is a MUST, not an opt-in.** Anything leaving the
  process gets a span; custom attributes are namespaced. Ours become
  `merkleye.mcp.<field>`.
- **A live E2E pass is required before anything ships.** Unit tests against a
  fake IdP and a fake API are necessary and never sufficient. For this repo
  that means: a real `merkleyed`, a real IdP, a real MCP client.
- **Never nil, always `[]T{}`.** The bug class that has already reached CI
  twice in the core repo (a nil Go slice marshalling to JSON `null` against a
  schema that requires an array) applies verbatim to tool results, which are
  JSON on a wire an agent parses.

## 2. Toolchain and shape

| Choice | Value | Why |
| --- | --- | --- |
| Language | Go 1.27 (mise-pinned `1.27.1`, matching merkleye) | Same toolchain, same lint config, same container story, and the API client generates from the same spec. |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk` v1.6.1 | Official SDK. Ships `auth.RequireBearerToken` with a pluggable `TokenVerifier` and `auth.ProtectedResourceMetadataHandler` (RFC 9728) — exactly the two pieces §4 needs, rather than hand-rolling them. |
| Protocol revision | negotiates `2025-11-25`, back-compatible to `2024-11-05` | What v1.6.1 supports. `2026-06-30` exists as a constant in the SDK but is not yet in its supported set; we take it when the SDK does. |
| API client | generated from a pinned `openapi.yaml` | See §3.1. |
| Transports | Streamable HTTP (primary), stdio (local/dev) | Streamable HTTP is the only one that can carry OAuth. stdio exists so a developer can point a local agent at a local `merkleyed` with a token in the environment. |
| Container | `Containerfile`, not `Dockerfile` | merkleye convention. |

### 2.1 Repo layout

```
cmd/merkleye-mcp/        # single binary; --transport=http|stdio
internal/mcpserver/      # tool/resource/prompt registration, the MCP surface
internal/auth/           # inbound verification: bearer passthrough + OIDC RS
internal/merkleyeapi/    # generated client + hand-written wrapper (otelhttp)
internal/config/         # strict YAML validation, errors naming the bad key
internal/telemetry/      # OTEL wiring, mirrors merkleye's
api/openapi.yaml         # pinned copy of the upstream spec (see §3.1)
docs/                    # this file, then DESIGN.md / OPERATIONS.md
```

Scaffolding mirrored from merkleye so a reviewer moving between repos finds
what they expect: `mise.toml` (go 1.27.1, golangci-lint 2.13.2), `Makefile`
with the same target names (`check`, `fmt-check`, `vet`, `lint`,
`govulncheck`, `test`, `spec`), `.golangci.yml`, `.githooks/`,
`.releaserc.json` + semantic-release, `AGENTS.md` with `CLAUDE.md` importing
it.

## 3. Architecture

```
  MCP client (Claude, an agent)
        │  Streamable HTTP + Authorization: Bearer <opaque | JWT>
        ▼
  merkleye-mcp  ── verifies/discriminates the credential (§4)
        │  HTTPS + Authorization: Bearer <merkleye api_token>
        ▼
  merkleyed  ── the only thing that authorizes anything
        │
        ▼
  Postgres
```

The MCP server is stateless apart from two caches: the IdP's JWKS, and
(under §4.4 Option A) exchanged Merkleye tokens keyed by IdP subject. It holds
no ambient authority: **every downstream call carries a credential derived
from the caller's own**, so a compromised MCP process cannot read or write
anything a caller could not.

### 3.1 Keeping the client honest

`api/openapi.yaml` is vendored here at a pinned upstream version and the
client is generated from it by `make generate` (`oapi-codegen`, same posture
as merkleye's `make generate` for the ent client). CI adds a **drift job**:
fetch the spec from the pinned merkleye release artifact, diff against the
vendored copy, fail on difference. That turns a silently-broken integration
into a red build — which is the whole reason the two-repo split exists.

Upstream has **no `operationId`s** (0 across 63 operations). Generated method
names would therefore be derived from path+method and would churn whenever a
path changes. Two ways out:

- **Preferred:** contribute `operationId`s to `api/openapi.yaml` upstream. Low
  risk, benefits merkleye-ui identically, makes generated names stable and
  readable in both consumers.
- Otherwise: keep a checked-in name-mapping file here and fail the build when
  an operation appears that the map doesn't cover.

## 4. Authentication — the core of this work

The requirement is that the server accepts **both** OIDC and bearer-token
authentication. Both arrive the same way — `Authorization: Bearer <x>` — so
this splits into four questions: which credential is this, how is each
verified, what authority does it grant downstream, and what does the server
tell an unauthenticated client.

### 4.1 Credential discrimination

Two token types on one header:

- **Merkleye API token** — opaque, argon2id-hashed server-side, scoped
  `read | write | admin`. Not parseable, not verifiable by us.
- **OIDC access token** — a JWT from the deployment's IdP (Authentik in the
  reference deployment).

Discriminate structurally: a JWT is three base64url segments separated by
dots with a decodable JOSE header carrying `alg` and `kid`. Anything else is
treated as opaque. **Do not try one and fall back to the other** — a
fallback path doubles the failure modes, makes 401 reasons ambiguous, and
gives an attacker two oracles. One credential, one code path, one verdict.

Config can also pin the mode (`auth.mode: bearer | oidc | both`) so an
operator who runs only one kind can turn the other off entirely.

### 4.2 Bearer tokens — pass-through, never verified here

The MCP server does **not** verify Merkleye API tokens. It cannot: merkleye
holds the argon2id hashes, and `store.VerifyAPIToken` deliberately collapses
every failure mode (malformed, unknown, expired, wrong secret) into one
indistinguishable nil so a handler cannot leak which it was. Re-implementing
that here would recreate exactly the leak it prevents.

So: attach the presented token to the downstream request and let merkleye
decide. A 401 from `/api/v1/auth/me` is relayed as a 401 with a
`WWW-Authenticate` challenge. On the first request of a session we call
`GET /api/v1/auth/me` once to learn the principal's subject and scopes — used
for logging, for `TokenInfo.UserID` (the SDK uses it to bind a session to one
user and block session hijacking), and to hide tools the caller cannot use.
**That hiding is presentation only.** merkleye enforces regardless, and, in
the core repo's own words, "the UI never treats its own check as security" —
neither do we.

### 4.3 OIDC — the server is an OAuth 2.1 resource server

Per the MCP authorization spec, with the SDK doing the mechanical parts:

- `GET /.well-known/oauth-protected-resource` via
  `auth.ProtectedResourceMetadataHandler`, advertising this server's resource
  identifier and the IdP as its authorization server. This is what lets an
  MCP client discover where to authenticate and run the flow itself; we are
  never in the authorization-code path.
- `auth.RequireBearerToken` with `ResourceMetadataURL` set, so a 401 carries
  `WWW-Authenticate: Bearer resource_metadata="…"`.
- A custom `auth.TokenVerifier` that validates, in order:
  1. signature against the issuer's JWKS (cached, honouring `kid` rotation,
     with a bounded refresh on unknown `kid` so rotation isn't a DoS vector);
  2. `alg` against an allowlist — **reject `none`, reject symmetric algs
     outright**, which closes the classic "sign an HS256 token with the
     published RSA public key" confusion;
  3. `iss` equals the configured issuer exactly;
  4. **`aud` contains this server's own resource identifier.** This is the
     confused-deputy defence the MCP spec calls out by name: a token minted
     for some other service in the same IdP must not be spendable here. It is
     the single most important check in the list;
  5. `exp` / `nbf` with a small fixed clock skew.
- Group claim (`auth.oidc.group_claim`) maps to scopes with the **same
  mapping merkleye already uses** — `internal/api.ScopesFromGroups`, including
  its rule that an unmapped group falls back to a configured default that is
  never allowed to be `admin`. Unrecognised groups must not fail open.

### 4.4 Turning an OIDC identity into Merkleye authority — decision needed

This is the one genuinely open architectural question, because **merkleye's
API today accepts only bearer tokens.** `internal/api.NewAuthenticator` says
so outright: "OIDC code exchange is still unimplemented … that lands as its
own piece of work." The `api_tokens` row already carries `issued_via` and
`idp_subject`, so the data model anticipates OIDC-issued rows; nothing mints
them yet.

**Option A — token exchange in merkleye (recommended).**
Add one route upstream: `POST /api/v1/auth/token/exchange`, RFC 8693-shaped.
It takes a validated OIDC access token, maps groups to scopes via the
existing `ScopesFromGroups`, and mints a short-lived `api_tokens` row with
`issued_via="oidc"`, `idp_subject=<sub>`, and
`expires_at = min(token exp, configured cap)`. The MCP server exchanges once
per caller identity and caches until shortly before expiry.

- One permission model, exactly as DESIGN §11 already specifies.
- Audit rows attribute to the human's IdP subject, not a shared service
  account — which is the difference between an audit log and a log.
- It is the same exchange the browser OIDC flow will need, so this is work
  the core repo owes itself regardless; MCP is just the first caller.
- Cost: an upstream route + handler + spec entry + `make test-contract` pass.
  Probably no migration — the columns exist, to be confirmed against
  `ent/schema`.

**Option B — MCP holds a service token and enforces scopes itself.**
One Merkleye token in config; the MCP server maps groups to scopes and
refuses tool calls above the caller's level.

- Rejected as the default. It is a second permission model in a second repo,
  drifting from the first the day either changes, and every audit row reads
  as the service account, so the log cannot answer "who acknowledged this."
- Keep as an explicitly-flagged fallback (`auth.oidc.mode: service_token`)
  for deployments that cannot upgrade the core, logging a loud warning on
  every startup, the way `certstream`'s `calidog_public` source does.

**Option C — merkleye validates OIDC JWTs directly on every request.**
Extend `Authenticator.Middleware` to accept a JWT bearer; the MCP server
becomes a pure pass-through for both credential types.

- Thinnest MCP server, and arguably where this belongs eventually.
- But it puts JWKS validation in the hot path of every API request, and we
  still need our own audience validation to be a compliant MCP resource
  server — so it does not actually delete §4.3, it only deletes §4.4.
- Revisit when browser OIDC lands upstream.

**Recommendation: A**, because it is the design already recorded upstream
rather than a new one, and because it is the only option where the audit log
names a person.

### 4.5 Write safety

Scope enforcement is merkleye's job. Two things are still ours, because an
agent is not a UI:

- **`tools.read_only` defaults to true.** An operator who connects a
  write-scoped token still has to opt in before an agent can mutate anything.
- **Irreversible operations are not exposed at all by default.**
  `DELETE /api/v1/domains/{id}/purge` destroys history; `POST
  /api/v1/notifications/test` sends a real message to a real channel. Both sit
  behind `tools.destructive: true`, off by default. An agent that can page
  someone at 3am by accident is a bug in this repo, not in merkleye.

## 5. Tool surface

63 operations. **Do not map them 1:1** — an agent handed 63 tools chooses
worse and spends its context on the menu. The surface is a curated ~22 tools
around the actual workflows, with reference data exposed as resources instead.

**Triage (the primary loop)**
`search` · `list_matches` · `get_match` · `acknowledge_matches` ·
`allowlist_from_match` · `rescore_match` · `get_certificate`

**Domains**
`list_domains` · `get_domain` · `add_domain` · `update_domain` ·
`remove_domain` · `get_domain_policies` · `set_domain_policies`

**Variants**
`list_variants` · `list_variant_changes` · `preview_variants` ·
`regenerate_variants`

**Posture**
`get_domain_caa` · `get_domain_dns_provider` · `get_summary` ·
`get_audit_log`

**Allowlist**
`list_allowlist` · `add_allowlist_entry` · `remove_allowlist_entry`

Excluded by default: purge, notification test-delivery, plugin config writes,
settings writes (all reachable via `tools.destructive` / `read_only`).

### 5.1 Result sizing — a correctness issue, not a nicety

`Match` is a large object and `/api/v1/matches` accepts `limit` up to 500. A
tool that can return 500 of them will blow an agent's context and produce a
worse answer than one that returns 20. Therefore:

- tool `limit` defaults to 20, hard-capped well below the API's 500;
- every list tool returns `next_cursor` and says in its description how to
  page — cursor, not offset, because rows insert continuously and an offset
  skips whatever landed between pages;
- list results carry a **compact projection** (id, domain, common name,
  severity, score, seen-at, acknowledged) and `get_match` returns the full
  object. The agent pages summaries and drills into what matters.

Tool descriptions carry the domain facts an agent cannot infer and will
otherwise get wrong: match keys are punycode A-labels, severity ordering,
what acknowledging does and does not do, and that a variant's `registration`
is RDAP's answer while `ns_resolves` is DNS's.

## 6. Resources and prompts

**Resources** (read-only, URI-addressed, cheap to re-read):
`merkleye://summary`, `merkleye://config`, `merkleye://cas`,
`merkleye://plugins`, `merkleye://settings/{variants,scoring,notifications}`,
`merkleye://domain/{id}`, `merkleye://match/{id}`.

**Prompts**: `triage-recent-matches`, `onboard-domain`,
`investigate-certificate`.

## 7. Live match feed — phase 4, flagged

`GET /api/v1/matches/stream` is SSE, one event per newly-persisted match,
with no replay on connect. MCP has no arbitrary server-push, but it does have
resource subscriptions: subscribe a session to `merkleye://matches/recent`,
back it with the upstream SSE connection, emit
`notifications/resources/updated` on each new match.

Deliberately last and behind a flag: it holds one upstream connection per
subscribed session, and the endpoint 501s where no live feed is wired up.
A client that falls behind misses events by design — the recovery is a
cursor-paged `list_matches`, and the tool descriptions must say so rather
than implying the stream is lossless.

## 8. Testing gates

- **Unit** — the auth verifier gets an adversarial table, not a happy path:
  wrong `aud`, wrong `iss`, expired, not-yet-valid, unknown `kid`,
  `alg: none`, HS256 signed with the IdP's public key, JWKS unreachable,
  JWKS rotated mid-flight, opaque token shaped like a JWT, JWT shaped like an
  opaque token.
- **Contract** — the generated client compiles against the vendored spec, and
  the drift job (§3.1) proves the vendored spec is the real one.
- **Conformance** — the official MCP Inspector against a running server, both
  transports.
- **Live E2E, required before shipping** — real `merkleyed` (via
  `merkleyed token create`) plus a real IdP, driven by a real MCP client. This
  is the merkleye rule that a mock passing is necessary and never sufficient,
  and it is where an audience-validation bug or a `null`-instead-of-`[]`
  result actually shows up.

## 9. Phasing

| Phase | Contents | Done when |
| --- | --- | --- |
| 0 | Repo scaffold, mise/Makefile/CI/lint, vendored spec, generated client, drift job | `make check` green on an empty tool set |
| 1 | stdio transport, bearer pass-through, read-only triage tools | An agent can answer "what matched this week" against a local merkleyed |
| 2 | Streamable HTTP, OIDC resource server (§4.3), resource metadata, audience binding | Live E2E against a real IdP; **depends on the §4.4 decision** |
| 3 | Write tools behind `read_only`, resources, prompts | Full triage loop, live E2E |
| 4 | Live match subscriptions (§7) | Flagged, off by default |

Phase 1 is deliberately shippable on its own: bearer-only, stdio-only, read-only
is genuinely useful and validates the tool surface before OIDC lands.

## 10. Decisions needed before phase 2

1. **§4.4 — Option A, B, or C?** A needs an upstream PR to
   `merkleye/merkleye` (one route, spec entry, contract test). This is the
   critical path for OIDC and nothing in phase 2 starts without it.
2. **IdP** — is Authentik the only target, or must multiple issuers be
   supported concurrently?
3. **Deployment topology** — sidecar next to `merkleyed` on loopback, or an
   independently-exposed service with its own TLS and hostname? It changes
   the resource identifier and therefore the audience check.
4. **`operationId`s upstream** — yes, or a local name map? (§3.1)

Working assumption on all of them, if no answer arrives: A, Authentik-only
with the config shaped for multi-issuer later, independently exposed, and
`operationId`s contributed upstream.

## 11. Deliberately deferred

- **Sampling / elicitation.** No use case yet that a tool result doesn't cover.
- **Writing to `/internal/v1/*`.** Loopback-only and out of spec on purpose.
- **Caching Merkleye responses.** A watchtower's value is freshness; a stale
  match list is worse than a slow one.
- **Any classification, scoring, or matching logic here.** That lives in
  `internal/match`, `internal/score`, `internal/policy` and stays there. If a
  tool needs a judgement the API doesn't expose, the fix is an upstream
  endpoint, not a second implementation.
