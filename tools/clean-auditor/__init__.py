"""Clean Auditor: a GitVault blocking checker for privacy and confidentiality.

Two stages, cheapest first:

  1. a deterministic, entirely local scan of the outgoing revision -- a
     credential shape or a withheld name, refused before any of it is described
     to a model; a refusal here never costs a token;
  2. only if stage one passes, an isolated Pi review with a fresh
     conversation over the same immutable range, judging the six domains that
     need semantics rather than shapes, plus two standing items: whether the
     project's tooling keeps its data out of the repository, and whether its
     parameters live in configuration rather than in code.

The audit only ever refuses. It does not stage, edit, commit or fix anything;
the working tree is byte-identical before and after a run.

The shared machinery -- sanitization, the review object, receipts, the Pi
review process and the range orchestration -- lives in audit_engine.py and is
identical for every checker. What remains here is Clean Auditor's own
contract: its domains, its deterministic stage wiring and its tool surface.
"""
from __future__ import annotations

from pathlib import Path
import sys

# The checker runs from a neutral directory with `-I` (no PYTHONPATH, no cwd
# import), so the package's own modules are found explicitly. Their names carry
# the checker's own prefix: two checkers sharing a process (the test suite) must
# not collide on a top-level module name like `stage1`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))

import audit_engine as engine  # noqa: E402
import clean_stage1 as stage1  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
# The six domains, plus two items that are not domains at all: whether the tools
# this project uses keep their data out of it, and whether its parameters live in
# configuration rather than in code. Both are coverage items rather than pattern
# lists on purpose. Which directories a project's tooling owns is a judgement
# about that project, and a hardcoded list would either miss a tool or refuse a
# project that tracks such a directory deliberately; where a parameter belongs is
# a judgement about the code around it, and a pattern that matched every literal
# would report arithmetic as a finding.
DOMAINS = ("privacy", "business_secret", "operations_data", "machine_path",
           "personal_info", "credentials", "tooling", "hardcoding")

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
    """Clean Auditor's review object: the engine's machinery bound to this
    checker's domains and payload directory."""
    DOMAINS = DOMAINS
    ROOT = ROOT


def tool_plan(review):
    """The checker's tool surface as data: the same list feeds the Pi
    extension manifest and the `--serve-tools` dispatch table."""
    return [
        ("clean_context",
         f"Inspect the immutable outgoing range. Start with inventory, then diff every changed "
         f"file to its end; read is {engine.READ_PAGE_LINES} lines with start; find is a literal "
         "search over the range. Credential containers are unavailable by design.",
         {"operation": {"type": "string", "enum": ["inventory", "list", "diff", "read", "find"]},
          "path": {"type": "string"}, "pattern": {"type": "string"}, "text": {"type": "string"},
          "start": {"type": "integer"}, "offset": {"type": "integer"},
          "revision": {"type": "string", "enum": ["outgoing", "base"]}},
         ["operation"], review.context),
        ("clean_submit_review",
         "Submit the final privacy verdict once, with every domain and both standing "
         "items accounted for.",
         {"verdict": {"type": "string", "enum": ["pass", "block", "incomplete"]},
          "summary": {"type": "string"},
          "coverage": engine.coverage_schema(DOMAINS),
          "findings": {"type": "array", "items": engine.finding_schema(Review.finding_keys)},
          "unknowns": {"type": "array", "items": {"type": "string"}}},
         ["verdict", "summary", "coverage", "findings", "unknowns"], review.submit),
    ]


def _stage1(repo, targets):
    """The deterministic audit: withheld names and credential shapes.

    The withheld list lives in the checker installation, outside any
    repository - a repository cannot unwithhold a name by committing a file
    that names it. Names are matched case-insensitively on whole words; a hit
    is reported by file and line, never by the name itself. The list's owner
    may still publish: the name simply must not appear in what ships.

    The repository's own origin remote decides which list applies - a mirror
    of a withheld project still withholds its names, because the origin slug
    still resolves; a remote that is a local path (a sandbox, a mirror) is
    simply not a repository any exemption can name.
    """
    return stage1.audit_all(repo, targets, stage1.withheld_names(repo_slug=origin_slug(repo)))


SPEC = engine.CheckerSpec(
    name="clean-auditor",
    label="Clean Auditor",
    description="Clean Auditor GitVault checker",
    domains=DOMAINS,
    tool_plan=tool_plan,
    make_review=lambda run_dir: Review(run_dir),
    task=lambda review: (
        "Review the outgoing changes with the Clean Auditor tools and submit one final "
        "verdict: start with inventory, read every changed diff to its end, then judge all "
        "six domains and both standing items — whether the project's tooling keeps its data "
        "out of the range, and whether its parameters live in configuration rather than code. "
        "No arbitrary turn or time limit applies."),
    root=ROOT,
    stage1=_stage1,
    session=True,
    refusal="The deterministic audit refused this operation; nothing was published",
    scope_extra=lambda target, summary: {"kind": target["kind"]},
)


engine.bind(globals(), SPEC)


if __name__ == "__main__":
    sys.exit(main())
