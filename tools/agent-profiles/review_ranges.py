"""Resolve what a push, a pull request or a release is about to publish.

Both stages must judge the same immutable range, so the resolution lives here
once. Three properties matter:

  * the base is always a real commit. A range with nothing published to compare
    against is reported as a whole-snapshot scan instead of inventing a base;
  * a merge request whose head is not local (someone else's PR) is fetched into
    FETCH_HEAD only -- no local branch is created, no tracking ref is moved;
  * a release is judged as "everything since the previous release", because
    that is the content the release publishes. A release commit is normally
    already on the default branch, so a merge-base against it would describe an
    empty range and the release would never be reviewed at all.
"""
from __future__ import annotations

import os
import subprocess


# audit_engine imports this module, so importing the engine's identical `git`
# back would be a real dependency cycle; this copy stays on purpose.
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


def previous_tag(repo, commit):
    """The most recent tag reachable from this commit's first parent.

    The parent is deliberate: a tag that already exists at the release commit
    itself is the release being published, not the content it introduces.
    """
    out = git(repo, "describe", "--abbrev=0", "--tags", f"{commit}^", check=False)
    return out.stdout.decode().strip() if out.returncode == 0 else ""


def release_range(repo, tag, commit):
    """The content a release publishes: previous tag .. release commit."""
    head = rev(repo, "--verify", f"{commit}^{{commit}}") if commit else ""
    if not head and tag:
        head = rev(repo, "--verify", f"{tag}^{{commit}}")
    if not head:
        raise ValueError("The release commit is not in this checkout; "
                         "publish this release from the tagged working tree")
    previous = previous_tag(repo, head)
    base = merge_base(repo, head, previous) if previous else ""
    fallback = ""
    if not base:
        # No prior release to diff against: what ships is the whole tree.
        fallback = "snapshot-no-previous-release" if not previous else "snapshot-no-merge-base"
    if not base:
        shared = merge_base(repo, head, "refs/remotes/origin/HEAD")
        if shared and shared != head:
            base, fallback = shared, ""
    return {"kind": "release", "label": f"release {tag or head[:12]}", "base": base, "head": head,
            "ref": None, "scope": "range" if base else "snapshot", "fallback": fallback}


def ranges(repo):
    """Return the ranges to audit, each with kind/label/base/head/scope.

    `scope` is "range" with a commit base, or "snapshot" when no published
    content exists to diff against; `fallback` names why, for the receipt.
    """
    event = os.environ.get("GITVAULT_EVENT", "")
    if event == "release":
        return [release_range(repo, os.environ.get("GITVAULT_RELEASE_TAG", "").strip(),
                              os.environ.get("GITVAULT_RELEASE_COMMIT", "").strip())]
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
