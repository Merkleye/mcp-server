# merkleye-mcp

Model Context Protocol server for [Merkleye](https://github.com/merkleye/merkleye),
a Certificate Transparency watchtower.

Puts Merkleye's findings in front of an LLM agent — *"what lookalike
certificates showed up for our domains this week, which are real, acknowledge
the noise"* — as MCP tools, resources and prompts. It is a client of the
Merkleye API and owns no data of its own; the whole surface is derived from
merkleye's OpenAPI contract, which is the product boundary.

**That contract is not stored here.** It is merkleye's private product
boundary, so this repository holds only the commit it is pinned to
(`api/SPEC_VERSION`, a bare SHA) and fetches the spec at build time. Building
therefore needs a token that can read `merkleye/merkleye` — see
[Development](#development).

## Status

**Phase 1–3 built. OIDC is scaffolded, not finished.**

| | |
| --- | --- |
| Bearer-token auth | Working. Passed through to merkleye, which is the only thing that can verify it. |
| OIDC auth | **Scaffolded.** Discovery and the 401 challenge are real; sign-in is refused with an explanation until merkleye grows `POST /api/v1/auth/token/exchange`. See [`docs/PLAN.md` §4.4](docs/PLAN.md). |
| stdio transport | Working. |
| Streamable HTTP | Working. |
| Tools / resources / prompts | 13 read tools, 12 write tools behind `read_only: false`, 2 destructive behind `destructive: true`, 8 resources, 3 prompts. |
| Live match subscriptions | Not started (phase 4). |

## Quick start

### Claude Desktop or Claude Code, locally (stdio)

```bash
export MERKLEYE_API_TOKEN="$(merkleyed token create -name agent -scope read)"
export MERKLEYE_API_URL="http://localhost:8080"

claude mcp add --transport stdio merkleye -- /path/to/merkleye-mcp
```

For Claude Desktop, the same binary goes in `claude_desktop_config.json` under
`mcpServers` — it launches MCP servers as child processes over stdio.

### Shared deployment (Streamable HTTP)

```bash
merkleye-mcp --transport=http --config /etc/merkleye-mcp/config.yaml
```

Each caller presents their own credential; a static token is refused outright
for this transport. Point Claude Code at it with
`claude mcp add --transport http merkleye https://mcp.example.com/mcp`, or add
it as a custom connector in Claude Desktop, or register it in LiteLLM's
`mcp_servers`.

See [`deploy/config.example.yaml`](deploy/config.example.yaml) for every option.

## How authentication works

Two credential types arrive the same way, `Authorization: Bearer <x>`, and are
told apart structurally — a JWT takes the OIDC path, anything else takes the
bearer path. There is deliberately no fallback between them.

- **Merkleye API token** — passed straight through. This server does not verify
  it and should not: merkleye holds the argon2id hashes and deliberately
  collapses every failure mode into one indistinguishable result, which
  re-implementing here would undo.
- **OIDC access token** — exchanged upstream for a scoped Merkleye token. All
  IdP knowledge (issuer discovery, JWKS, algorithms, and the audience binding
  that is the confused-deputy defence) lives in merkleye, so any
  OIDC-compliant provider works and adding one is a backend config change.
  This server only publishes RFC 9728 protected resource metadata and the 401
  challenge that points at it.

The consequence worth stating plainly: **this server holds no authority of its
own** under HTTP. Every downstream call carries a credential derived from the
caller's, so a compromised process here cannot read or write anything a caller
could not.

## Safety defaults

- `tools.read_only` is **on**. Connecting a write-scoped token is not the same
  as consenting to an agent mutating things.
- `tools.destructive` is **off** even when writes are on. Purging a domain
  destroys history irreversibly; a test notification pages a real human.
- List tools return compact summaries capped well below the API's 500-per-page
  limit. This is a correctness matter, not tidiness: 500 full `Match` objects
  exhaust an agent's context and produce a worse answer than 20 summaries it
  can drill into.

## Development

```bash
export MERKLEYE_BACKEND_TOKEN=<token that can read merkleye/merkleye>

mise install       # provision the pinned toolchain
mise run generate  # fetch the pinned spec, then generate the API client
mise run check     # fmt + vet + lint + govulncheck + tests
```

`mise run generate` fetches merkleye's OpenAPI spec from the commit pinned in
[`api/SPEC_VERSION`](api/SPEC_VERSION), validates it, and generates the client
from it. Neither the spec nor the generated client (~22k lines) is committed.

To move to a newer merkleye: put the new commit SHA in `api/SPEC_VERSION` and
run `mise run generate && mise run check`. There is no vendored copy to re-sync
and no drift to check, because the build always reads the pinned upstream
commit directly.

`mise.toml` owns tools *and* tasks, and CI runs the same tasks.

- [`docs/PLAN.md`](docs/PLAN.md) — architecture, the authentication design, the
  tool surface, phasing, and the decisions still open.
- [`AGENTS.md`](AGENTS.md) — invariants and conventions. Read before changing
  auth, tool names, or result shapes.

## License

Apache-2.0, for this repository only.

merkleye itself is not open source, and this server does not redistribute any
part of it: the OpenAPI contract it builds against is fetched at build time and
never stored here (see [Development](#development)). What is licensed here is
the MCP server — a client of that API — and nothing else.
