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
from the deployment's identity provider, where this server acts as an OAuth
2.1 resource server.

## Status

**Not built yet.** This repository currently contains the buildout plan only.

- [`docs/PLAN.md`](docs/PLAN.md) — architecture, the authentication design,
  the tool surface, phasing, and the decisions still open.

## License

Apache-2.0, matching the core repository.
