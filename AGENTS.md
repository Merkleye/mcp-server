# merkleye-mcp — working notes

MCP server over the Merkleye API. Read `docs/PLAN.md` first; it records the
architecture and the decisions the code depends on, including the ones still
open.

This repo is a **client of merkleye/merkleye and nothing else**. It owns no
data, and it authorizes nothing.

## Invariants — do not break these without reading the rationale

- **This server authorizes nothing.** Merkleye enforces scopes; there is no
  scope logic here, and adding some would be a second permission model in a
  second repo, drifting from the first the day either changes. `tools.read_only`
  and `tools.destructive` are the operator's gates on what an agent may reach,
  never a substitute for the server's checks.
- **No ambient authority under HTTP.** Every downstream call carries a
  credential derived from the caller's own, so a compromised process here
  cannot read or write anything a caller could not. `merkleye.static_token` is
  refused outright for the http transport, and stdio is the single-caller
  exception, not a precedent.
- **Bearer tokens are passed through, never verified here.** Merkleye holds the
  argon2id hashes and deliberately collapses every failure mode into one
  indistinguishable result so a handler cannot leak which it was.
  Reimplementing that check would recreate the leak it prevents.
- **All IdP knowledge lives in merkleye.** No issuer config, no JWKS cache, no
  algorithm allowlist, no audience list in this repo. Two places validating
  tokens is two places to disagree about who a caller is. What lives here is
  discovery (RFC 9728 metadata) and the 401 challenge.
- **Credential discrimination is one decision, not a cascade.** A JWT takes the
  OIDC path, anything else takes the bearer path, and there is no fallback
  between them. A fallback doubles the failure modes, makes a 401 impossible to
  explain, and hands an attacker two oracles.
- **The OIDC path fails closed.** While the upstream exchange is unimplemented,
  an OIDC token is refused with an explanation. Never treat an unverifiable
  token as anonymous, and never fall back to a service token.
- **Never nil, always `[]T{}`.** A nil Go slice marshals to JSON `null`, and an
  agent handed `"matches": null` cannot iterate it. This bug class has reached
  merkleye's CI twice; tool results are JSON on a wire an agent parses.
- **No classification, scoring or matching logic here.** That lives in
  merkleye's `internal/match`, `internal/score` and `internal/policy`. If a tool
  needs a judgement the API does not expose, the fix is an upstream endpoint,
  not a second implementation.

## Conventions

- Timestamps are RFC 3339, UTC, Z-suffixed — tool arguments, tool results,
  logs. Never a Unix epoch, never local time. Same rule as merkleye.
- Config validation is strict, reports every problem at once, and every message
  names the offending key. A typo in a monitoring tool is a silent
  misconfiguration, which is worse than a crash.
- **Tool names come from the spec's operationIds.** A tool name is a public
  interface — people write them into agent configs and agents learn them — so
  it must not be derived from a URL that may move. See merkleye's `AGENTS.md`,
  "operationIds are required". Renaming a tool is a breaking change; adding one
  is not.
- Tool and argument descriptions are the only documentation a model gets. Write
  them for a reader who has never seen this API, and put the domain facts it
  cannot infer in them: A-labels, what acknowledging does and does not do, that
  a variant's `registration` is RDAP's answer and `ns_resolves` is DNS's.
- The generated client (`internal/merkleyeapi/client.gen.go`) is not committed
  and never hand-edited. `mise run generate` after a clone.
- **merkleye's OpenAPI spec is never stored in this repository.** Not vendored,
  not committed, not in history. It is merkleye's private product contract and
  is not ours to redistribute. `api/openapi.yaml` is gitignored and written by
  `scripts/fetch-spec.sh` from the commit in `api/SPEC_VERSION` — a bare SHA,
  which discloses nothing. If you ever find yourself about to `git add` it, the
  answer is no.
- **The spec is never edited either.** When it declares something the generator
  cannot handle, the fix goes in `scripts/prepare-spec.py`, which writes a
  gitignored build copy. Patching the fetched file would be patching a
  contract merkleye actually serves, and the next fetch would silently undo it.
- `mise.toml` owns tools *and* tasks; CI runs the same tasks. Container images
  use `Containerfile`, not `Dockerfile`.

## Upgrading to a newer merkleye

1. Put the new commit SHA in `api/SPEC_VERSION`. That is the whole change —
   there is no vendored copy to re-sync and no drift to check, because the
   build reads the pinned upstream commit directly.
2. `mise run generate` — it fetches and validates the spec, then
   `scripts/prepare-spec.py` reports how many parameter unions it collapsed. A
   warning about an `anyOf` it left alone is the thing to read: an unhandled
   union is how `undefined: N0` comes back.
3. `mise run check`, then fix what the compiler objects to. Contract changes
   arrive as type errors, which is the point of generating rather than
   hand-writing the client.
4. Diff the operation list. New operations are opportunities, not obligations —
   add a tool only where it serves a workflow, and remember that 63 tools is
   worse than 20.
5. Run the live pass. Query-parameter serialisation in particular is invisible
   to the compiler: `severity` is declared `style: form, explode: false`, so it
   goes over the wire comma-joined, and only a real request shows that.

## Result sizing is a correctness concern

`GET /api/v1/matches` accepts `limit` up to 500 and a `Match` carries the full
certificate, risk breakdown and enrichment. A tool that can return 500 of those
exhausts an agent's context and produces a *worse* answer than one returning
20 summaries it can drill into.

So: list tools project items down to what triage reads, cap the limit well
below the API's, always return `next_cursor`, and say in the result that the
items are summaries. `internal/mcpserver/project.go` is where that lives.

## Observability

Same contract as merkleye — read `docs/OBSERVABILITY.md` there.

- Anything leaving the process gets a span. The API client goes through
  `otelhttp.NewTransport`, so call sites do not have to remember one.
- Custom attributes are namespaced `merkleye.mcp.<field>` — never a bare key
  that could collide with a semconv-defined one.
- Instrument unconditionally. `Tracer()` resolves to a no-op provider when OTEL
  is disabled or unreachable, so this costs nothing at runtime and enabling
  tracing later needs no code changes. Never gate span creation on a config
  flag.
- **Never log a token value.** Not at debug, not in a span attribute, not in an
  error. `auth.PrincipalDescription` exists so there is an easy right answer.

## Before pushing

```bash
mise run check   # fmt-check + vet + lint + govulncheck + test + spec drift
```

`mise run hooks` (a dependency of every other task) points git at `.githooks/`,
so a local commit already runs the fast subset.

**`mise run lint` may refuse to start**, with "the Go language version used to
build golangci-lint is lower than the targeted Go version". That is not a
finding in your code: the golangci-lint release pinned in `mise.toml` is itself
built with an older Go than this module targets, and merkleye has the same
mismatch. CI lints through `golangci-lint-action`, which fetches a build
matching the runner's toolchain, so a PR still gets a real answer. Move the
`mise.toml` pin forward once a release built with a new enough Go exists, and
drop the action.

**`mise run check` cannot see a broken integration.** It runs no live server
and talks to no real merkleye, so it is blind to a tool that 500s on input the
schema allows, a projection that drops a field triage needs, or an auth path
that works against a fake and not against the real thing. Two gates cover that,
and neither is optional:

- **The spec fetch** (`mise run generate`) is the contract gate. It reads the
  pinned commit directly, so a stale or diverged local copy is not a failure
  mode that exists any more; instead the failure mode is a bad pin, and the
  fetch fails loudly on a 404 rather than falling back to anything.

  It needs a token that can read merkleye — `MERKLEYE_BACKEND_TOKEN`, `GH_TOKEN`
  or `GITHUB_TOKEN`, in that order — and **fails without one**, deliberately:
  there is nothing to build against. Note the default `GITHUB_TOKEN` in Actions
  is scoped to this repository only and cannot read merkleye.

  `MERKLEYE_BACKEND_TOKEN` is an **organization secret**, shared by every
  Merkleye repo that reads the backend. It is named for the access it grants,
  not for this repo's use of it, so don't rename it here to something
  spec-specific — the point is that one name works everywhere.

  When an upstream spec PR merges, pin to the *merged* commit on `main`, not
  the branch commit: a squash merge gives the change a new SHA and the branch
  is usually deleted, so the old pin 404s.
- **A live E2E pass before anything ships.** Run the binary against a real
  `merkleyed` (mint a token with `merkleyed token create`) driven by a real MCP
  client — Claude Code, Claude Desktop, or the MCP Inspector. A mock passing is
  necessary, never sufficient; this is merkleye's rule and it applies here for
  the same reason.

When OIDC becomes real, its live pass is also the **first** exercise of
merkleye's OIDC path — `ScopesFromGroups` has never seen a real IdP's claims.
Expect to find something.

## Client compatibility

Changes to the transport, the auth surface or the tool schemas need a pass
against all three targets before release, because they differ in what they can
present:

| Client | Transports | Auth |
| --- | --- | --- |
| Claude Code | http, stdio, sse (deprecated), ws | OAuth with DCR automatically; `--client-id`/`--client-secret`/`--callback-port` without it; static `--header`; `headersHelper` |
| Claude Desktop | stdio via `claude_desktop_config.json`; remote only via Settings → Connectors | The connector flow runs its own OAuth and does not expose arbitrary headers, so a static token works over stdio only |
| LiteLLM | http, sse, stdio | `auth_type: bearer_token`, or full OAuth 2.1 with PRM discovery and DCR forwarding |

Claude Desktop's remote path is why OAuth is load-bearing rather than
nice-to-have, and why a non-DCR IdP needs the shim described in
`docs/PLAN.md` §4.4.2.
