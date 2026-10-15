"""Stage one: the deterministic, local scan of the outgoing revision.

Nothing leaves the machine here and nothing is written. What this stage can
prove from the revision itself is refused before any of it is described to a
model, because two of these things must never reach one at all: a credential,
and the existence of a name that is a secret precisely because it is withheld.

Two checks, both GitVault's own:

  * **withheld names** -- the machine-local list of names that must not appear
    in published content. A name already in the tree is already published, so
    the whole revision is searched, not only the changed files.
  * **credential shapes** -- private-key blocks and vendor token formats, matched
    by shape. A field named `token` is not evidence that its value is a
    credential, so a name never decides a match, and the matched value is never
    reported.

The judgement that needs semantics -- privacy, business secrets, operational
data, machine paths, personal information, credentials in context, tooling
hygiene -- belongs to the semantic stage, not here.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from audit_engine import git as _git

# Shapes, not keywords. Ordered most specific first: a label is the first rule
# that matches the line, and `sk-ant-...` is also an `sk-...`.
#
# The expressions are handed to `git grep -E` and then re-checked in Python, so
# they stay inside what POSIX extended regular expressions and `re` both accept:
# no non-capturing groups, no `\b`, no `\d`.
CREDENTIAL_RULES = (
    ("private-key-block", r"-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----"),
    ("aws-access-key", r"(AKIA|ASIA)[A-Z0-9]{16}"),
    ("github-token", r"(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("google-api-key", r"AIza[A-Za-z0-9_-]{35}"),
    ("openai-key", r"sk-[A-Za-z0-9_-]{20,}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("stripe-key", r"(sk|rk)_(live|test)_[A-Za-z0-9]{20,}"),
    ("json-web-token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)

# Names that must never reach published content, read from a file that lives
# outside every repository: the rule is public, the names it withholds are not.
# Publishing the list would publish the very thing it protects, so it is machine
# state (`$XDG_CONFIG_HOME/gitvault/withheld-names.txt`, overridable through
# CLEAN_AUDITOR_WITHHELD), never a repository file.
WITHHELD_ENV = "CLEAN_AUDITOR_WITHHELD"
WITHHELD_DEFAULT = ("gitvault", "withheld-names.txt")


def withheld_path():
    override = os.environ.get(WITHHELD_ENV, "").strip()
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME", "").strip() or str(Path.home() / ".config")
    return Path(base).joinpath(*WITHHELD_DEFAULT)


def _in_scope(repo_slug, scope):
    """Whether a slug (`Owner/Repo`) is the repository a scope names.

    The scope is written as the repository's own name, an owner, or a full slug.
    """
    if not scope:
        return False
    slug, scope = repo_slug.lower(), scope.lower()
    return slug == scope or slug.startswith(f"{scope}/") or slug.endswith(f"/{scope}")


def withheld_names(path=None, repo_slug=""):
    """The withheld names for this repository, one per line, `#` for comments.

    A line may end with `except <owner[/repo]>` to skip that name inside the
    repositories that carry it as their own identity - pushing an internal
    repository whose own name appears throughout its content is not a leak.
    """
    path = Path(path) if path else withheld_path()
    if not path.is_file():
        return []
    names = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, marker, scope = line.partition(" except ")
        name = name.strip()
        if marker and _in_scope(repo_slug, scope.strip()):
            continue
        if name:
            names.append(name)
    return names


def _name_pattern(name):
    """One name, matched however it is spelled: case and separators are not a
    difference, so `Widget Go`, `widget-go` and `WidgetGO` are one name."""
    parts = [re.escape(part) for part in re.split(r"[\s._-]+", name) if part]
    return "[ _.-]*".join(parts) if parts else re.escape(name)


def scan(repo, head, names=()):
    """Every finding in the revision at `head`, as `{path, line, rule}`.

    One `git grep` answers both checks: the patterns go in together and each
    matching line is then labelled in Python, so a whole-revision scan costs one
    process rather than one per rule. `git grep` reads tracked content at that
    revision - exactly what would be published - and skips binaries.

    Neither check ever returns the matched text: a refusal must be actionable
    without repeating the secret, and the developer can read their own line.
    """
    # `git grep -i` matches case-insensitively, so every Python re-check must
    # too - otherwise a line git found would be labelled by nothing at all.
    patterns = [("withheld-name", _name_pattern(name), re.IGNORECASE) for name in names if name.strip()]
    patterns += [(rule, expression, re.IGNORECASE) for rule, expression in CREDENTIAL_RULES]
    if not patterns:
        return []
    argv = ["grep", "-i", "-I", "-n", "-E", "--no-color"]
    for _, expression, _ in patterns:
        argv += ["-e", expression]
    argv.append(head)
    found = _git(repo, *argv, check=False)
    if found.returncode not in (0, 1):
        raise ValueError("The deterministic scan could not read the outgoing revision")

    compiled = [(rule, re.compile(expression, flags)) for rule, expression, flags in patterns]
    prefix = f"{head}:"
    hits = []
    for record in found.stdout.decode("utf-8", "replace").splitlines():
        if not record.startswith(prefix):
            continue
        path, _, rest = record[len(prefix):].partition(":")
        line, _, content = rest.partition(":")
        rule = next((name for name, pattern in compiled if pattern.search(content)), "credential-shape")
        hits.append({"path": path, "line": int(line) if line.isdigit() else 1, "rule": rule})
        if len(hits) >= 20:
            break
    return hits


def audit(repo, target, names=()):
    """Run the deterministic scan for one range. Returns a sanitized summary."""
    hits = scan(repo, target["head"], names)
    refused = ""
    if any(hit["rule"] == "withheld-name" for hit in hits):
        refused = "withheld-name"
    elif hits:
        refused = "credential-shape"
    return {"label": target["label"], "scope": target["scope"], "fallback": target["fallback"],
            "status": refused or "clean", "findings": len(hits), "hits": hits, "refused": refused}


def audit_all(repo, targets, names=()):
    """Run every range; the first refusal stops the stage. Returns (ok, summaries)."""
    summaries = []
    for target in targets:
        summary = audit(repo, target, names)
        summaries.append(summary)
        if summary["refused"]:
            return False, summaries
    return True, summaries
