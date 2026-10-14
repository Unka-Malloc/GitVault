"""Local profile sync: what the dev site published, and whether this machine still matches.

The prompts and skills an agent runs on live in the Development site's profile
registry, versioned by git tag. This module is the machine's side of that
contract, and it lives in the installed payload so the checker itself can use it:

  * `pull` fetches one published version over the local dashboard, verifies every
    file hash and the whole-version manifest before writing anything, then records
    what it wrote in `installation.json`;
  * `assert_synced` re-hashes the local documents at checker startup. A local
    edit that the dev site never saw is a drift, and a drifted prompt refuses the
    operation: "the dev site is the only source" has to be executable, not
    aspirational.

Being *behind* is not drift. A machine that has not pulled the newest version is
doing nothing wrong, and a gate that refused every push until someone synced
would be switched off within a day.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import urllib.request

DOCUMENTS = ("policy.md", "SKILL.md")
REFERENCES = "documents.json"
# profile.json carries the declared runtime (provider/model/effort): the
# checker reads its synced copy, so the dev site is the only source for what
# the agent runs on, exactly like the prompt and skill documents.
SYNCED = (*DOCUMENTS, REFERENCES, "profile.json")
DEFAULT_URL = "http://127.0.0.1:8891"


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def manifest(files):
    """The whole version as one value: one line per file, sorted."""
    return sha256("".join(f"{name}\t{sha256(files[name])}\n" for name in sorted(files)))


def pull(agent, skill_dir, url=DEFAULT_URL, tag=None):
    """Fetch a published profile version and install it into the skill directory.

    Every hash is checked before the first byte is written, so a truncated or
    tampered download leaves the previous version in place.
    """
    endpoint = f"{url.rstrip('/')}/api/gitvault/profiles/{agent}/bundle"
    if tag:
        endpoint += f"?tag={tag}"
    request = urllib.request.Request(endpoint, headers={"accept": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - a fixed local URL
        bundle = json.load(response)
    files, hashes = bundle["files"], bundle["hashes"]
    if sorted(files) != sorted(hashes):
        raise ValueError("The published profile listing is inconsistent; nothing was written")
    if manifest(files) != bundle["manifest"]:
        raise ValueError("The published profile manifest does not match its files; nothing was written")
    for name, text in files.items():
        if sha256(text) != hashes[name]:
            raise ValueError(f"The published copy of {name} does not match its hash; nothing was written")

    kept = {name: files[name] for name in SYNCED if name in files}
    skill_dir = Path(skill_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)
    for name, text in kept.items():
        (skill_dir / name).write_text(text)
    stale = skill_dir / REFERENCES
    if REFERENCES not in kept and stale.exists():
        stale.unlink()  # the published version consults no references
    version = int(bundle["tag"].rsplit("/v", 1)[1])
    return {"tag": bundle["tag"], "version": version, "manifest": bundle["manifest"],
            "files": {name: hashes[name] for name in kept}}


def drift(installation):
    """Names of the synced documents that no longer match what was published."""
    recorded = (installation.get("synced") or {}).get("files") or {}
    if not recorded:
        return []
    skill_dir = Path(installation.get("skill_dir") or "")
    changed = []
    for name, expected in recorded.items():
        path = skill_dir / name
        if not path.is_file() or sha256(path.read_text()) != expected:
            changed.append(name)
    return changed


def assert_synced(installation):
    """Refuse the operation when a synced document was edited on this machine."""
    changed = drift(installation)
    if changed:
        raise ValueError(
            "the local prompt copy no longer matches what the dev site published "
            f"({', '.join(changed)}); run `python3 tools/<agent>/install.py --pull` to sync")
