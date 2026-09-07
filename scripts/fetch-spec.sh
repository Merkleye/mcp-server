#!/usr/bin/env bash
# Fetch merkleye's OpenAPI spec for this build. Never stored in this repo.
#
# api/openapi.yaml is merkleye's private product contract. It is not ours to
# redistribute, and this repository does not carry a copy — api/openapi.yaml is
# gitignored and this script writes it fresh from the commit pinned in
# api/SPEC_VERSION. The pin is a bare commit SHA, which discloses nothing.
#
# That is also why there is no drift check any more: there is no vendored copy
# to drift. The build reads the pinned upstream commit directly, so the client
# is always generated from exactly the contract that commit serves. Moving to a
# newer merkleye is a one-line change to api/SPEC_VERSION.
#
# merkleye is private, so this needs a credential that can read it:
# MERKLEYE_BACKEND_TOKEN, GH_TOKEN or GITHUB_TOKEN, in that order.
#
# MERKLEYE_BACKEND_TOKEN is an organization secret, named for what it grants —
# read access to the merkleye backend repository — rather than for what any one
# consumer does with it, so every repo that needs the backend uses the same
# name. In Actions the default GITHUB_TOKEN is scoped to *this* repository and
# can never read merkleye.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

PIN_FILE="api/SPEC_VERSION"
OUT="api/openapi.yaml"

if [ ! -f "$PIN_FILE" ]; then
	echo "$PIN_FILE is missing — nothing says which upstream commit to build against." >&2
	exit 1
fi
pin="$(tr -d '[:space:]' < "$PIN_FILE")"

# Already fetched for this exact pin? Generation runs on every task, and
# re-downloading a 3000-line spec each time is pure latency.
if [ -f "$OUT" ] && [ -f "api/.spec-fetched-at" ] && [ "$(cat api/.spec-fetched-at)" = "$pin" ]; then
	echo "$OUT already present for merkleye@${pin}"
	exit 0
fi

token="${MERKLEYE_BACKEND_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
if [ -z "$token" ]; then
	cat >&2 <<'MSG'
No GitHub token available (MERKLEYE_BACKEND_TOKEN, GH_TOKEN or GITHUB_TOKEN).

merkleye is private and its OpenAPI spec is not vendored here, so the client
cannot be generated without a credential that can read merkleye/merkleye.

  export MERKLEYE_BACKEND_TOKEN=<a PAT or App token with read access>

In GitHub Actions, the default GITHUB_TOKEN is scoped to this repository only
and will not work. MERKLEYE_BACKEND_TOKEN is an organization secret; check that
this repository is in its access list.
MSG
	exit 1
fi

url="https://api.github.com/repos/merkleye/merkleye/contents/api/openapi.yaml?ref=${pin}"

mkdir -p api
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

status="$(curl -sSL --max-time 60 \
	-H "Authorization: Bearer ${token}" \
	-H "Accept: application/vnd.github.raw" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	-w '%{http_code}' "$url" -o "$tmp" 2>/dev/null || echo "000")"

case "$status" in
	200) ;;
	000)
		echo "could not reach api.github.com to fetch the spec." >&2
		exit 1
		;;
	401 | 403)
		echo "GitHub returned HTTP ${status}: the token cannot read merkleye/merkleye." >&2
		exit 1
		;;
	404)
		# GitHub answers 404 rather than 403 for a private repository the token
		# cannot see, so as to not leak its existence. That makes "your token
		# lacks access" and "that commit does not exist" the same status code.
		# One extra request tells them apart, which is the difference between a
		# five-minute fix and an afternoon.
		repo_status="$(curl -sSL --max-time 30 \
			-H "Authorization: Bearer ${token}" \
			-H "X-GitHub-Api-Version: 2022-11-28" \
			-w '%{http_code}' "https://api.github.com/repos/merkleye/merkleye" \
			-o /dev/null 2>/dev/null || echo "000")"

		if [ "$repo_status" != "200" ]; then
			# Name the credential. "A token cannot read merkleye" is a fact;
			# "the token is acting as <who>, with these scopes" is usually the
			# fix, because the wrong identity or a missing scope is visible at a
			# glance. Never prints the token itself.
			whoami_body="$(mktemp)"
			whoami_headers="$(mktemp)"
			whoami_status="$(curl -sSL --max-time 30 \
				-H "Authorization: Bearer ${token}" \
				-H "X-GitHub-Api-Version: 2022-11-28" \
				-D "$whoami_headers" -o "$whoami_body" \
				-w '%{http_code}' "https://api.github.com/user" 2>/dev/null || echo "000")"

			identity="could not be determined"
			case "$whoami_status" in
				200)
					login="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("login","?"))' "$whoami_body" 2>/dev/null || echo "?")"
					identity="a user token acting as '${login}'"
					;;
				403 | 401)
					# App installation tokens have no /user; that is expected,
					# and points at a different fix (install the App).
					identity="most likely a GitHub App installation token (no /user identity)"
					;;
			esac

			# Classic PATs advertise their scopes on every response; fine-grained
			# ones send the header empty, which is itself a useful signal.
			# `|| true` is load-bearing. A fine-grained PAT sends no
			# x-oauth-scopes header, so grep exits 1; under `set -euo pipefail`
			# that kills the script inside the command substitution, before any
			# of the diagnostics below print. The first version of this code did
			# exactly that and turned a helpful error into a silent exit 1.
			scopes="$(grep -i '^x-oauth-scopes:' "$whoami_headers" 2>/dev/null | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true)"
			rm -f "$whoami_body" "$whoami_headers"

			echo "Credential in use: ${identity}." >&2
			if [ -n "$scopes" ]; then
				echo "Classic PAT scopes: ${scopes} (reading a private repo needs 'repo')." >&2
			else
				echo "No x-oauth-scopes header: a fine-grained PAT or an App token." >&2
				echo "Fine-grained PATs must list merkleye/merkleye explicitly and grant Contents: Read." >&2
			fi
			echo >&2

			cat >&2 <<MSG
The token cannot read merkleye/merkleye (GET /repos/merkleye/merkleye returned
HTTP ${repo_status}).

Either status means the same thing here: 404 because GitHub hides a private
repository a token cannot see, 403 because it can see it but may not read it.
Either way this is an access problem, not a bad pin.

In GitHub Actions the default GITHUB_TOKEN is scoped to this repository only
and can never read merkleye. MERKLEYE_BACKEND_TOKEN is the organization secret
that does; if it is set, check that this repository is in its access list and
that the token itself still has read access to merkleye/merkleye.
MSG
		else
			cat >&2 <<MSG
The token can read merkleye/merkleye, but api/openapi.yaml does not exist at
${pin}.

The commit in ${PIN_FILE} is wrong: most likely it names a branch commit that
was squash-merged (which re-hashes it) and whose branch has since been deleted.
Re-pin to the merged commit on merkleye's main.
MSG
		fi
		exit 1
		;;
	*)
		echo "GitHub returned HTTP ${status} fetching the spec." >&2
		exit 1
		;;
esac

# Sanity-check before anything downstream trusts it: a truncated download or an
# HTML error page would otherwise surface as a baffling generator failure.
python3 - "$tmp" <<'PY'
import sys, yaml

with open(sys.argv[1]) as f:
    doc = yaml.safe_load(f)

if not isinstance(doc, dict) or "openapi" not in doc or "paths" not in doc:
    sys.exit("fetched file is not an OpenAPI document")

METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
errs, seen = [], {}
for path, item in (doc.get("paths") or {}).items():
    for method, op in item.items():
        if method not in METHODS or not isinstance(op, dict):
            continue
        where = f"{method.upper()} {path}"
        op_id = op.get("operationId")
        # Tool names are derived from these, so a missing or duplicated one is
        # a contract problem for this repo specifically. See AGENTS.md.
        if not op_id:
            errs.append(f"{where}: missing operationId")
        elif op_id in seen:
            errs.append(f"{where}: operationId {op_id!r} already used by {seen[op_id]}")
        else:
            seen[op_id] = where

if errs:
    for e in errs:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(f"{len(errs)} problem(s) in the fetched spec")

print(f"fetched spec OK ({len(seen)} operations)")
PY

mv "$tmp" "$OUT"
trap - EXIT
printf '%s' "$pin" > api/.spec-fetched-at
echo "$OUT written from merkleye@${pin}"
