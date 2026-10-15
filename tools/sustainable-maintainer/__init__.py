"""Sustainable Maintainer: a GitVault blocking checker for maintainability.

Two stages, cheapest first:

  1. a deterministic, entirely local scan of the outgoing revision -- conflict
     markers, merge artifacts and editor/OS junk refused before any of it is
     described to a model; a refusal here never costs a token;
  2. only if stage one passes, an isolated Pi review with a fresh
     conversation over the same immutable range, judging the six domains that
     need semantics rather than shapes: module structure, contracts, craft,
     duplication, tests and evolution residue.

The audit only ever refuses. It does not stage, edit, commit or fix anything;
the working tree is byte-identical before and after a run.

The shared machinery -- sanitization, the review object, receipts, the Pi
review process and the range orchestration -- lives in audit_engine.py and is
identical for every checker. What remains here is Sustainable Maintainer's own
contract: its domains, its deterministic stage wiring and its tool surface.
"""
from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))

import audit_engine as engine  # noqa: E402
import maintainer_stage1 as stage1  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
# The six domains a review must account for. They are coverage items rather
# than pattern lists on purpose: where a boundary belongs, whether a copy is
# justified and what a change leaves behind are judgements about the code
# around them, and a pattern that matched every smell would report style
# preferences as findings.
DOMAINS = ("structure", "contracts", "craft", "duplication", "tests", "evolution")

# The engine's contract surface, re-exported for callers and tests that hold
# this module.
sanitize = engine.sanitize
sanitize_source = engine.sanitize_source
safe_path = engine.safe_path
git = engine.git
write_json = engine.write_json
credential = engine.credential
declared_runtime = engine.declared_runtime
origin_slug = engine.origin_slug
review_ranges = engine.review_ranges
EMPTY_TREE = engine.EMPTY_TREE
SENSITIVE_PARTS = engine.SENSITIVE_PARTS
SENSITIVE_SUFFIXES = engine.SENSITIVE_SUFFIXES
SENSITIVE_PREFIXES = engine.SENSITIVE_PREFIXES
TEMPLATE_NAMES = engine.TEMPLATE_NAMES
RUNTIME_VALUE = engine.RUNTIME_VALUE
PI_THINKING = engine.PI_THINKING


class Review(engine.Review):
    """Sustainable Maintainer's review object: the engine's machinery bound to
    this checker's domains and payload directory."""
    DOMAINS = DOMAINS
    ROOT = ROOT


def tool_plan(review):
    """The checker's tool surface as data: the same list feeds the Pi
    extension manifest and the `--serve-tools` dispatch table."""
    return [
        ("maintainer_context",
         f"Inspect the immutable outgoing range. Start with inventory, then diff every changed "
         f"file to its end; read is {engine.READ_PAGE_LINES} lines with start and revision; list globs the snapshot; "
         "find is a literal search over the range — use it to locate the original a change "
         "duplicates, the callers a contract serves, or the documentation a decision should "
         "update. Credential containers are unavailable by design.",
         {"operation": {"type": "string", "enum": ["inventory", "list", "diff", "read", "find"]},
          "path": {"type": "string"}, "pattern": {"type": "string"}, "text": {"type": "string"},
          "start": {"type": "integer"}, "offset": {"type": "integer"},
          "revision": {"type": "string", "enum": ["outgoing", "base"]}},
         ["operation"], review.context),
        ("maintainer_submit_review",
         "Submit the final maintainability verdict once, with every domain accounted for.",
         {"verdict": {"type": "string", "enum": ["pass", "block", "incomplete"]},
          "summary": {"type": "string"},
          "coverage": engine.coverage_schema(DOMAINS),
          "findings": {"type": "array", "items": engine.finding_schema(Review.finding_keys)},
          "unknowns": {"type": "array", "items": {"type": "string"}}},
         ["verdict", "summary", "coverage", "findings", "unknowns"], review.submit),
    ]


SPEC = engine.CheckerSpec(
    name="sustainable-maintainer",
    label="Sustainable Maintainer",
    description="Sustainable Maintainer GitVault checker",
    domains=DOMAINS,
    tool_plan=tool_plan,
    make_review=lambda run_dir: Review(run_dir),
    task=lambda review: (
        "Review the outgoing changes with the Sustainable Maintainer tools and submit one "
        "final verdict: start with inventory, read every changed diff to its end, then "
        "judge all six domains. No arbitrary turn or time limit applies."),
    root=ROOT,
    stage1=lambda repo, targets: stage1.audit_all(repo, targets),
    refusal="The deterministic audit refused this operation; nothing was published",
    scope_extra=lambda target, summary: {"kind": target["kind"]},
)


engine.bind(globals(), SPEC)


if __name__ == "__main__":
    sys.exit(main())
