# merkleye-mcp

Model Context Protocol server for [Merkleye](https://github.com/merkleye/merkleye),
a Certificate Transparency watchtower.

Puts Merkleye's findings in front of an LLM agent — "what lookalike
certificates showed up for our domains this week, which are real, acknowledge
the noise" — as MCP tools, resources and prompts. It is a client of the
Merkleye API and owns no data of its own; everything it exposes is derived
from `api/openapi.yaml` in the core repo, which is the product boundary.

Authenticates callers two ways: Merkleye API bearer tokens (passed through to
the API, which is the only thing that can verify them) and OIDC access tokens
from any OIDC-compliant identity provider. All IdP knowledge lives in the
Merkleye backend — this server acts as an OAuth 2.1 resource server for
discovery and challenge only, and exchanges a caller's OIDC token for a scoped
Merkleye token rather than validating it itself.

One Go binary, distributed as a container image, an `npx`-able npm launcher,
and plain release binaries. Speaks Streamable HTTP and stdio, so it works with
Claude Code, Claude Desktop and LiteLLM without a per-client build.

## Status

**Not built yet.** This repository currently contains the buildout plan only.

- [`docs/PLAN.md`](docs/PLAN.md) — architecture, the authentication design,
  the tool surface, phasing, and the decisions still open.

## License

Apache-2.0, matching the core repository.
