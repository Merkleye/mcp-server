#!/usr/bin/env bash
# The vendored api/openapi.yaml must be byte-identical to the upstream release
# it claims to pin. A silently-diverged copy is the failure mode this whole
# two-repo split exists to prevent: the client would generate cleanly against a
# contract the server no longer serves, and nothing would notice until a tool
# call 404s in front of an agent.
#
# Also re-checks what merkleye's own `make spec` checks — every operation has a
# unique operationId — because this repo's tool names are derived from them
# (see AGENTS.md, "Tool names come from operationIds").
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

SPEC="api/openapi.yaml"
PIN_FILE="api/SPEC_VERSION"

python3 - "$SPEC" <<'PY'
import sys, yaml

spec = sys.argv[1]
with open(spec) as f:
    doc = yaml.safe_load(f)

METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
errs, seen = [], {}
for path, item in (doc.get("paths") or {}).items():
    for method, op in item.items():
        if method not in METHODS or not isinstance(op, dict):
            continue
        where = f"{method.upper()} {path}"
        op_id = op.get("operationId")
        if not op_id:
            errs.append(f"{where}: missing operationId")
        elif op_id in seen:
            errs.append(f"{where}: operationId {op_id!r} already used by {seen[op_id]}")
        else:
            seen[op_id] = where

if errs:
    print(f"{spec}: {len(errs)} problem(s)", file=sys.stderr)
    for e in errs:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)

print(f"{spec} OK ({len(seen)} operations)")
PY

# Drift check. Skipped without network (a local pre-commit hook must not need
# it); CI's spec job runs with network and is the authoritative gate.
if [ ! -f "$PIN_FILE" ]; then
	echo "$PIN_FILE missing — cannot verify which upstream release is pinned" >&2
	exit 1
fi
pin="$(tr -d '[:space:]' < "$PIN_FILE")"
url="https://raw.githubusercontent.com/merkleye/merkleye/${pin}/api/openapi.yaml"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if ! curl -fsSL --max-time 30 "$url" -o "$tmp"; then
	echo "could not fetch ${url} — skipping drift check (CI's spec job is authoritative)" >&2
	exit 0
fi

if ! diff -q "$SPEC" "$tmp" >/dev/null; then
	echo "api/openapi.yaml has drifted from merkleye@${pin}:" >&2
	diff -u "$SPEC" "$tmp" | head -60 >&2
	echo >&2
	echo "Re-vendor it and regenerate the client, or move the pin in $PIN_FILE." >&2
	exit 1
fi

echo "api/openapi.yaml matches merkleye@${pin}"
