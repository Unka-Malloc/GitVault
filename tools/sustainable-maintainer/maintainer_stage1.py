"""The local, deterministic stage of the Sustainable Maintainer review.

Hygiene that never needs judgement is decided here, before anything is
described to a model: conflict markers left in text, merge-tool artifacts and
editor/OS junk that should never have entered the tree. Stage one only judges
what the operation introduces or modifies — a deletion is never a finding, and
junk already published is the semantic stage's business, not a reason to block
an unrelated push. A refusal here ends the operation; it is never paraphrased
to a model.
"""
from __future__ import annotations

import re

import audit_engine
from audit_engine import git


# Filenames that are residues of merge tooling, never of deliberate content.
MERGE_ARTIFACT = re.compile(
    r"\.(orig|rej)$"                                # merge/patch residue
    r"|\.(BACKUP|BASE|LOCAL|REMOTE)\.[0-9a-f]{7,}",  # mergetool backups
    re.IGNORECASE,
)

# Filenames an OS or an editor writes, never a repository.
OS_JUNK = re.compile(
    r"(^|/)(\.DS_Store|Thumbs\.db|desktop\.ini)$"   # OS-generated files
    r"|(^|/)\._[^/]+$"                              # AppleDouble sidecars
    r"|\.(swp|swo)$"                                # editor swap
    r"|~$",                                         # editor backup
    re.IGNORECASE,
)

# A marker is a marker only on a line of its own; "=======" under a heading is
# legitimate prose, so it counts only beside a < or > marker in the same file.
SIDE_MARKERS = re.compile(rb"^(<{7}|>{7})( .*)?\r?$")
EQUALS_MARKER = re.compile(rb"^={7}\r?$")

# Content checks do not apply where "lines" mean nothing or a blob is large.
BINARY_HINT = re.compile(
    rb"\.(png|jpe?g|gif|ico|icns|zip|gz|bz2|xz|7z|woff2?|ttf|otf|pdf|jar|war|"
    rb"so|dylib|dll|exe|a|o|wasm|mp[34]|mov|webm|psd|keystore|jks|db|sqlite)$",
    re.IGNORECASE,
)
MAX_FILE_BYTES = 2 * 1024 * 1024


def outgoing_paths(repo, target):
    """Paths the operation carries — what stage one judges. Delegated to the
    shared engine so this stage and the paid stage always see the same set;
    a diff-filter shortcut here once meant paths this stage cleared were not
    the paths the model reviewed."""
    return audit_engine.outgoing_paths(repo, target)


def blob(repo, head, path):
    out = git(repo, "show", f"{head}:{path}", check=False)
    if out.returncode or len(out.stdout) > MAX_FILE_BYTES or b"\0" in out.stdout[:8192]:
        return None
    return out.stdout


def junk_name_hit(path):
    """The hygiene rule a filename violates, or "" when it is clean."""
    if MERGE_ARTIFACT.search(path):
        return "merge-artifact"
    if OS_JUNK.search(path):
        return "os-junk"
    return ""


def marker_lines(content):
    """1-based lines carrying a conflict marker; ======= counts beside < or >."""
    sides, equals = [], []
    for number, line in enumerate(content.split(b"\n"), 1):
        if SIDE_MARKERS.match(line):
            sides.append(number)
        elif EQUALS_MARKER.match(line):
            equals.append(number)
    return sorted(sides + (equals if sides else []))


def deleted_paths(repo, target):
    """Paths the operation removes. Name-only enumeration cannot tell a
    deletion from an addition, and a deletion is never a finding — a junk
    name leaving the tree is the tree getting cleaner, not residue."""
    if target["scope"] != "range":
        return set()
    out = git(repo, "diff", "--name-only", "--no-renames", "-z", "--diff-filter=D",
              target["base"] or audit_engine.EMPTY_TREE, target["head"])
    return {p for p in out.stdout.decode(errors="replace").split("\0") if p}


def audit(repo, target):
    """Check one review target; return its summary, refusing on any hit."""
    hits = []
    deleted = deleted_paths(repo, target)
    for path in outgoing_paths(repo, target):
        if path in deleted:
            continue
        rule = junk_name_hit(path)
        if rule:
            hits.append({"path": path, "line": 0, "rule": rule})
            continue
        if BINARY_HINT.search(path.encode()):
            continue
        content = blob(repo, target["head"], path)
        if content is None:
            continue
        for line in marker_lines(content):
            hits.append({"path": path, "line": line, "rule": "conflict-marker"})
    return {
        "label": target["label"], "scope": target["scope"], "fallback": target["fallback"],
        "status": "refused" if hits else "clean",
        "findings": len(hits),
        "hits": hits,
        "refused": hits[0]["rule"] if hits else "",
    }


def audit_all(repo, targets):
    """Check every target; return (ok, summaries) — False on any refusal."""
    summaries = [audit(repo, target) for target in targets]
    return all(not summary["refused"] for summary in summaries), summaries
