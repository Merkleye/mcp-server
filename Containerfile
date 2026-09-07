# Merkleye MCP server.
#
# Prerequisite: api/openapi.yaml must be present in the build context.
#
# It is merkleye's private product contract and is not stored in this
# repository, so the build cannot fetch it and neither can this Containerfile —
# doing so would mean handing a GitHub token to the builder. Run
# `./scripts/fetch-spec.sh` first (it needs MERKLEYE_BACKEND_TOKEN); the spec is
# consumed by the build stage only and never reaches the final image.
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

WORKDIR /src

# python3/py3-yaml are for scripts/prepare-spec.py, which collapses the spec's
# empty-string parameter unions into something oapi-codegen can generate from.
RUN apk add --no-cache git python3 py3-yaml

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Fail here, loudly, rather than three steps later with a generator error that
# does not say what is actually missing.
RUN test -f api/openapi.yaml || { \
      echo "api/openapi.yaml is missing from the build context."; \
      echo "Run ./scripts/fetch-spec.sh before building — see the header of this file."; \
      exit 1; \
    }

# The API client is not committed (~22k lines, fully derived from the spec).
# `go tool` resolves oapi-codegen from go.mod's tool directive, so the image
# builds it at the same version mise and CI use — one pin, not three.
RUN python3 scripts/prepare-spec.py \
 && go tool oapi-codegen -config internal/merkleyeapi/codegen.yaml api/openapi.codegen.yaml

ARG OCI_VERSION=0.0.0
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${OCI_VERSION}" \
      -o /merkleye-mcp ./cmd/merkleye-mcp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG OCI_VERSION=0.0.0
ARG OCI_REVISION=unknown
ARG OCI_CREATED=unknown
ARG OCI_REF_NAME=dev
ARG OCI_SOURCE=https://github.com/merkleye/mcp-server

LABEL org.opencontainers.image.title="Merkleye MCP server" \
      org.opencontainers.image.description="Model Context Protocol server for Merkleye" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.url="${OCI_SOURCE}" \
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.ref.name="${OCI_REF_NAME}"

# Only the compiled binary crosses the stage boundary: the spec, the generated
# client and the toolchain all stay behind in the build stage.
COPY --from=build /merkleye-mcp /merkleye-mcp

# Non-root, no shell, no package manager. This process brokers other people's
# credentials; it needs none of them.
USER nonroot:nonroot

EXPOSE 8090

ENTRYPOINT ["/merkleye-mcp"]
CMD ["--transport=http"]
