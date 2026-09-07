#!/usr/bin/env python3
"""Prepare api/openapi.yaml for oapi-codegen.

Writes api/openapi.codegen.yaml, a build artifact (gitignored) that the client
is generated from. api/openapi.yaml itself is never touched: it stays
byte-identical to the upstream commit pinned in api/SPEC_VERSION so
scripts/check-spec-drift.sh keeps working. Editing it in place would either
break that check or, worse, be absorbed by re-pinning — and then this repo
would generate a client against a contract merkleye does not serve.

Exactly one transformation, applied mechanically:

    anyOf: [ <real schema>, { type: string, maxLength: 0 } ]   ->   <real schema>

merkleye/merkleye#51 gave every optional scalar query parameter that shape so
schemathesis could send `?param=` and get a documented answer: the real type, or
empty. It is a faithful description of what the server accepts.

It defeats the generator, though. oapi-codegen renders an anyOf as a union type
and emits As/From/Merge methods referring to member types (N0, N1) it never
declares, so the package does not compile:

    client.gen.go: undefined: N0

Collapsing loses nothing a Go client can express. The empty arm means "sent, but
blank", which is indistinguishable to the server from not sending the parameter
at all — and absence is what a nil pointer already means in the generated
params. So the union collapses to the arm that carries information.

The rule is deliberately narrow: two arms, one of which is *only* an
empty-string constraint. Anything else is left alone and reported, so a new
union shape upstream surfaces as a generator error to look at rather than being
silently mangled here.
"""

import copy
import sys

import yaml

SPEC = "api/openapi.yaml"
OUT = "api/openapi.codegen.yaml"


def is_empty_string_arm(arm) -> bool:
    """True for a schema that constrains a value to the empty string, nothing more."""
    return (
        isinstance(arm, dict)
        and arm.get("maxLength") == 0
        and set(arm) <= {"maxLength", "type"}
        and arm.get("type", "string") == "string"
    )


def collapse(node, path="$", stats=None, unhandled=None):
    if isinstance(node, dict):
        arms = node.get("anyOf")
        if isinstance(arms, list):
            real = [a for a in arms if not is_empty_string_arm(a)]
            if len(arms) == 2 and len(real) == 1 and isinstance(real[0], dict):
                merged = {k: v for k, v in node.items() if k != "anyOf"}
                # The surviving arm wins on any key it defines: sibling keys on
                # the union (type, description) are context, not overrides.
                merged.update(real[0])
                stats.append(path)
                return {k: collapse(v, f"{path}.{k}", stats, unhandled) for k, v in merged.items()}
            unhandled.append(path)
        return {k: collapse(v, f"{path}.{k}", stats, unhandled) for k, v in node.items()}
    if isinstance(node, list):
        return [collapse(v, f"{path}[{i}]", stats, unhandled) for i, v in enumerate(node)]
    return node


def main() -> int:
    with open(SPEC) as f:
        doc = yaml.safe_load(f)

    stats: list[str] = []
    unhandled: list[str] = []
    out = collapse(copy.deepcopy(doc), stats=stats, unhandled=unhandled)

    with open(OUT, "w") as f:
        yaml.safe_dump(out, f, sort_keys=False, width=100, allow_unicode=True)

    print(f"{OUT}: collapsed {len(stats)} empty-string unions")
    if unhandled:
        # Not fatal — generation may well succeed — but say so, because an
        # unexpected union is how "undefined: N0" comes back.
        print(f"warning: {len(unhandled)} anyOf construct(s) left as-is:", file=sys.stderr)
        for p in unhandled[:10]:
            print(f"  {p}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
