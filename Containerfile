# Merkleye MCP server.
FROM golang:1.27-alpine AS build

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The API client is not committed (~16k lines, fully derived from
# api/openapi.yaml). Regenerate it as part of the build so the image is
# reproducible from the spec alone.
RUN go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen \
      -config internal/merkleyeapi/codegen.yaml api/openapi.yaml

ARG OCI_VERSION=0.0.0
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${OCI_VERSION}" \
      -o /merkleye-mcp ./cmd/merkleye-mcp

FROM gcr.io/distroless/static-debian12:nonroot

ARG OCI_VERSION=0.0.0
ARG OCI_REVISION=unknown
ARG OCI_CREATED=unknown
ARG OCI_REF_NAME=dev
ARG OCI_SOURCE=https://github.com/merkleye/mcp-server

LABEL org.opencontainers.image.title="Merkleye MCP server" \
      org.opencontainers.image.description="Model Context Protocol server for Merkleye" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.url="${OCI_SOURCE}" \
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.ref.name="${OCI_REF_NAME}"

COPY --from=build /merkleye-mcp /merkleye-mcp

# Non-root, no shell, no package manager. This process brokers other people's
# credentials; it needs none of them.
USER nonroot:nonroot

EXPOSE 8090

ENTRYPOINT ["/merkleye-mcp"]
CMD ["--transport=http"]
