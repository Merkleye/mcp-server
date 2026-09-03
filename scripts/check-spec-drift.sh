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

# Drift check.
#
# merkleye is a private repository, so an unauthenticated raw.githubusercontent
# fetch answers 404 for everything — including specs that are perfectly present.
# Reading it therefore needs a credential, and the absence of one is a reason to
# skip rather than to fail: a local pre-commit hook must work offline and
# without a token. CI supplies one, and CI is the authoritative gate.
if [ ! -f "$PIN_FILE" ]; then
	echo "$PIN_FILE missing — cannot verify which upstream release is pinned" >&2
	exit 1
fi
pin="$(tr -d '[:space:]' < "$PIN_FILE")"

token="${MERKLEYE_SPEC_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
if [ -z "$token" ]; then
	echo "no GitHub token (MERKLEYE_SPEC_TOKEN / GH_TOKEN / GITHUB_TOKEN) — skipping drift check." >&2
	echo "merkleye is private, so this check needs a credential. CI's spec job is authoritative." >&2
	exit 0
fi

url="https://api.github.com/repos/merkleye/merkleye/contents/api/openapi.yaml?ref=${pin}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# A 404 and a dead network are not the same thing, and collapsing them is how a
# drift check quietly stops checking. With a token in hand, a 404 means the
# pinned commit does not carry this spec — the pin is wrong, which is exactly
# the condition this script exists to catch. Only a transport failure skips.
status="$(curl -sSL --max-time 30 \
	-H "Authorization: Bearer ${token}" \
	-H "Accept: application/vnd.github.raw" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	-w '%{http_code}' "$url" -o "$tmp" 2>/dev/null || echo "000")"

case "$status" in
	200)
		;;
	000)
		echo "could not reach api.github.com — skipping drift check (CI's spec job is authoritative)" >&2
		exit 0
		;;
	401 | 403)
		echo "GitHub returned HTTP ${status}: the token cannot read merkleye/merkleye." >&2
		echo "Grant it read access to that repository, or unset it to skip this check locally." >&2
		exit 1
		;;
	*)
		echo "GitHub returned HTTP ${status} for api/openapi.yaml at ${pin}." >&2
		echo "The commit pinned in ${PIN_FILE} does not carry it. It may point at a branch that has" >&2
		echo "since been deleted or squash-merged — re-pin to the merged commit on main." >&2
		exit 1
		;;
esac

if ! diff -q "$SPEC" "$tmp" >/dev/null; then
	echo "api/openapi.yaml has drifted from merkleye@${pin}:" >&2
	diff -u "$SPEC" "$tmp" | head -60 >&2
	echo >&2
	echo "Re-vendor it and regenerate the client, or move the pin in $PIN_FILE." >&2
	exit 1
fi

echo "api/openapi.yaml matches merkleye@${pin}"
