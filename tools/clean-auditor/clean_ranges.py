"""Resolve what a push or a pull request is about to publish.

Both stages must judge the same immutable range, so the resolution lives here
once. Two rules differ from Money Saver's resolver on purpose:

  * a range base must be a real commit. A range with nothing published to
    compare against is reported as a whole-snapshot scan rather than inventing
    an empty tree as its base.
  * a merge request whose head is not local (someone else's PR) is fetched into
    FETCH_HEAD only -- no local branch is created, no tracking ref is moved.
"""
from __future__ import annotations

import os
import subprocess


def git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if check and result.returncode:
        raise ValueError("Git could not read the review snapshot")
    return result


def rev(repo, *args):
    out = git(repo, "rev-parse", *args, check=False)
    return out.stdout.decode().strip() if out.returncode == 0 else ""


def merge_base(repo, left, right):
    out = git(repo, "merge-base", left, right, check=False)
    return out.stdout.decode().strip() if out.returncode == 0 else ""


def short_ref(name):
    return name.removeprefix("refs/heads/") if name else name


def published_elsewhere(repo, commit):
    """True when a remote-tracking ref already contains the commit."""
    out = git(repo, "for-each-ref", "--count=1", "--contains", commit,
              "--format=%(refname)", "refs/remotes", check=False)
    return bool(out.stdout.strip())


def base_for(repo, head, published_tip=None, base_ref=None):
    """The commit a range diffs against, or "" when there is nothing to compare
    against (the caller then scans the whole snapshot)."""
    candidates = []
    if published_tip and published_tip.strip("0"):
        candidates.append(published_tip)
    for ref in ((f"refs/remotes/origin/{short_ref(base_ref)}" if base_ref else None),
                base_ref, "refs/remotes/origin/HEAD"):
        if ref and rev(repo, "--verify", ref):
            candidates.append(ref)
    for candidate in candidates:
        shared = merge_base(repo, head, candidate)
        if shared:
            return shared
    return ""


def fetch_pull_head(repo, number):
    """Fetch a merge request's head into FETCH_HEAD; creates no ref."""
    result = git(repo, "fetch", "--no-tags", "--quiet", "origin",
                 f"refs/pull/{number}/head", check=False)
    if result.returncode:
        raise ValueError("The merge request head could not be fetched for review")


def ranges(repo):
    """Return the ranges to audit, each with kind/label/base/head/scope.

    `scope` is "range" with a commit base, or "snapshot" when no published
    content exists to diff against; `fallback` names why, for the receipt.
    """
    event = os.environ.get("GITVAULT_EVENT", "")
    if event == "pr":
        head_ref = os.environ.get("GITVAULT_PR_HEAD", "").strip()
        base_ref = os.environ.get("GITVAULT_PR_BASE", "").strip()
        number = os.environ.get("GITVAULT_PR_NUMBER", "").strip()
        if number:
            fetch_pull_head(repo, number)
            head = rev(repo, "--verify", "FETCH_HEAD^{commit}")
            label = f"merge request #{number} → {base_ref or 'default'}"
        else:
            head = (rev(repo, "--verify", f"{head_ref}^{{commit}}")
                    or rev(repo, "--verify", f"refs/remotes/origin/{short_ref(head_ref)}^{{commit}}"))
            label = f"pull request {head_ref} → {base_ref or 'default'}"
        if not head:
            raise ValueError("The pull request head is not available locally; "
                             "push the branch through GitVault first")
        base = base_for(repo, head, base_ref=base_ref)
        return [{"kind": "pr", "label": label, "base": base, "head": head, "ref": None,
                 "scope": "range" if base else "snapshot",
                 "fallback": "" if base else "snapshot-no-merge-base"}]
    found = []
    for line in os.environ.get("GITVAULT_PUSH_REFS", "").splitlines():
        fields = line.split()
        if len(fields) != 4:
            continue
        local_ref, local_sha, _remote_ref, remote_sha = fields
        if not local_sha.strip("0"):
            continue  # a deletion publishes nothing
        head = rev(repo, "--verify", f"{local_sha}^{{commit}}")
        if not head or published_elsewhere(repo, head):
            continue  # already-published tips add no unreviewed content
        base = base_for(repo, head, published_tip=remote_sha)
        found.append({"kind": "push", "label": f"push {local_ref}", "base": base, "head": head,
                      "ref": local_ref, "scope": "range" if base else "snapshot",
                      "fallback": "" if base else "snapshot-no-merge-base"})
    deduped, seen = [], set()
    for item in found:
        key = (item["base"], item["head"], item["scope"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
