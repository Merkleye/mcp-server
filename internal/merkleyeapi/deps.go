package merkleyeapi

// Keeps github.com/oapi-codegen/runtime in the module graph.
//
// client.gen.go imports it — the generated code calls into it to serialize
// query parameters — but that file is gitignored, so it does not exist in a
// fresh checkout. `go mod tidy` sees no importer and drops the dependency,
// after which the next `mise run generate` produces a client that will not
// compile.
//
// That is not hypothetical: it is exactly what happened to Renovate's
// dependency PRs, which run tidy against a clean tree and each proposed
// removing this module. A blank import here makes the dependency visible to
// the module graph from committed source, so tidy keeps it whether or not the
// generated client is present.
//
// The alternative is committing the ~22k-line generated client, which is worse
// for the reasons in AGENTS.md.
import _ "github.com/oapi-codegen/runtime"
