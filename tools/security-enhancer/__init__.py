"""Security Enhancer: a GitVault blocking checker for pre-release hardening.

Two stages, cheapest first:

  1. a static checklist evaluated on the immutable Git objects of the outgoing
     range -- no repository code is executed and no repository script is parsed,
     so a provable regression is refused locally and costs no token;
  2. only if stage one finds no regression, an isolated Pi review with a
     fresh conversation over the same range, judging the seven domains that need
     judgement rather than shapes.

The audit only ever refuses. It does not stage, edit, commit or fix anything;
the working tree is byte-identical before and after a run.

The shared machinery -- sanitization, the review object, receipts, the Pi
review process and the range orchestration -- lives in audit_engine.py and is
identical for every checker. What remains here is Security Enhancer's own
contract: its domains, its surface reporting and its tool surface.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))

import audit_engine as engine  # noqa: E402
import security_stage1 as stage1  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
DOMAINS = ("dependency_supply_chain", "ci_workflow_authority", "secret_handling",
           "transport_security", "authz_defaults", "container_runtime", "release_artifacts")

# The engine's contract surface, re-exported for callers and tests that hold
# this module.
sanitize = engine.sanitize
sanitize_source = engine.sanitize_source
safe_path = engine.safe_path
git = engine.git
write_json = engine.write_json
credential = engine.credential
declared_runtime = engine.declared_runtime
review_ranges = engine.review_ranges
EMPTY_TREE = engine.EMPTY_TREE
SENSITIVE_PARTS = engine.SENSITIVE_PARTS
SENSITIVE_SUFFIXES = engine.SENSITIVE_SUFFIXES
SENSITIVE_PREFIXES = engine.SENSITIVE_PREFIXES
TEMPLATE_NAMES = engine.TEMPLATE_NAMES
RUNTIME_VALUE = engine.RUNTIME_VALUE
PI_THINKING = engine.PI_THINKING


class Review(engine.Review):
    """Security Enhancer's review object: the engine's machinery plus the
    surfaces the static stage flagged, which the verdict must account for."""
    DOMAINS = DOMAINS
    ROOT = ROOT

    def inventory_extra(self):
        return {"surfaces": self.surfaces}

    def receipt_extra(self):
        return {"surfaces": self.surfaces}


def tool_plan(review):
    """The checker's tool surface as data: the same list feeds the Pi
    extension manifest and the `--serve-tools` dispatch table."""
    return [
        ("security_context",
         "Inspect the immutable outgoing range. Start with inventory (it lists the surfaces the "
         "static stage already reported), then diff every changed file to its end; read is 400 "
         "lines with start; find is a literal search over the range. Credential containers are "
         "unavailable by design.",
         {"operation": {"type": "string", "enum": ["inventory", "list", "diff", "read", "find"]},
          "path": {"type": "string"}, "pattern": {"type": "string"}, "text": {"type": "string"},
          "start": {"type": "integer"}, "offset": {"type": "integer"},
          "revision": {"type": "string", "enum": ["outgoing", "base"]}},
         ["operation"], review.context),
        ("security_submit_review",
         "Submit the final hardening verdict once, with all seven domains accounted for.",
         {"verdict": {"type": "string", "enum": ["pass", "block", "incomplete"]},
          "summary": {"type": "string"},
          "coverage": engine.coverage_schema(DOMAINS),
          "findings": {"type": "array", "items": engine.finding_schema(Review.finding_keys)},
          "unknowns": {"type": "array", "items": {"type": "string"}}},
         ["verdict", "summary", "coverage", "findings", "unknowns"], review.submit),
    ]


def _stage1_lines(summary):
    lines = [f"{hit['path']}:{hit['line']} {hit['rule']} → {hit['remedy']}" for hit in summary["hits"]]
    lines += [f"notice {surface['path']}:{surface['line']} {surface['rule']}" for surface in summary["surfaces"]]
    return lines



SPEC = engine.CheckerSpec(
    name="security-enhancer",
    label="Security Enhancer",
    description="Security Enhancer GitVault checker",
    domains=DOMAINS,
    tool_plan=tool_plan,
    make_review=lambda run_dir: Review(run_dir),
    task=lambda review: (
        "Review the outgoing changes with the Security Enhancer tools and submit one final "
        "verdict: start with inventory, read every changed diff to its end, judge all seven "
        "domains, and account for every surface the static stage reported. No arbitrary turn "
        "or time limit applies."),
    root=ROOT,
    stage1=lambda repo, targets: stage1.audit_all(repo, targets),
    stage1_lines=_stage1_lines,
    stage_label="static",
    refusal="The static security checklist refused this operation; nothing was published",
    scope_extra=lambda target, summary: {"kind": target["kind"],
                                         "surfaces": (summary or {}).get("surfaces", [])},
)


engine.bind(globals(), SPEC)


if __name__ == "__main__":
    sys.exit(main())
