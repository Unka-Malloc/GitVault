"""Stage one: the static security checklist, evaluated on immutable Git objects.

No repository code is executed and no repository script is parsed as a program:
every rule reads blobs and diffs as text. That is the whole point -- a checker
that ran the repository's own verifier would be asking the change to certify
itself.

Two classes of rule, deliberately:

  * a REGRESSION is a shape that is wrong on its own: a disabled TLS check, a
    floating CI action, a world-writable install step, an ignore rule that was
    protecting a key file. It refuses the operation at once, so a provable
    security regression is never described to a model and never costs a token.
  * a SURFACE is a new execution or egress path that may well be intended: a
    new install hook, a new hardcoded host, a private address. It is recorded
    and handed to the semantic stage as evidence. Refusing these outright would
    block ordinary work with no repair available, and a gate that cannot be
    satisfied is a gate operators switch off.

Neither class prints the matched text. A hit names the rule, the file and the
line; the developer reads their own change, and an internal host name or a
build-arg value never lands in a log.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import PurePosixPath

MAX_SCAN_BYTES = 1024 * 1024
SKIPPED_DIRS = {"node_modules", "vendor", "third_party", ".venv", "venv", "__pycache__",
                ".mypy_cache", ".pytest_cache", "target", ".git", "bower_components"}
PROSE_SUFFIXES = {".md", ".rst", ".adoc"}
PROSE_NAMES = ("readme", "changelog", "license", "notice", "authors", "contributing")

REMEDIES = {
    "dependency/lockfile-not-updated": "commit the lockfile with the manifest",
    "ci/pull-request-target": "use `pull_request` unless the workflow needs the base repository's secrets",
    "ci/write-all-permissions": "grant the specific permissions the job needs",
    "ci/floating-action-ref": "pin the action to an immutable reference",
    "ci/remote-script-execution": "download, verify and run a pinned artifact instead of piping to a shell",
    "ci/tls-verification-disabled": "keep TLS verification enabled in CI",
    "container/root-user": "run the image as a non-root user",
    "container/privileged": "drop the privileged flag and grant the specific capability needed",
    "container/world-writable": "use the narrowest mode the step needs",
    "container/secret-in-image": "pass secrets at run time, never as an image build argument",
    "container/unpinned-base-image": "pin the base image by tag and digest",
    "hardening/ignore-rule-removed": "restore the ignore rule or untrack the file first",
    "hardening/codeowner-removed": "restore the owner or land the governance change on its own",
    "hardening/registry-source-changed": "keep the registry source unchanged in this change",
    "hardening/credential-file-added": "keep credential files out of the repository",
    "runtime/tls-verification-disabled": "verify certificates in the shipped code path",
    "runtime/debug-enabled": "ship with debug mode disabled",
    "runtime/cors-wildcard-credentials": "name the allowed origins when credentials are sent",
    "surface/dependency-url-source": "confirm this dependency source is intended -- the semantic review will judge it",
    "surface/install-hook-added": "confirm this install hook is intended -- the semantic review will judge it",
    "surface/private-address": "confirm this address is intended to ship -- the semantic review will judge it",
    "surface/plaintext-endpoint": "confirm this plaintext endpoint is intended -- the semantic review will judge it",
}

# An ignore rule that was protecting one of these is a regression, not tidying.
PROTECTED_IGNORE = re.compile(
    r"(?i)(\.env|\.pem|\.key|\.p12|\.pfx|secret|credential|token|password|passwd|\.netrc|"
    r"\.npmrc|\.ssh|id_rsa|id_ed25519|\.db|\.sqlite|\.kdbx|\.tfstate|credential)")

CREDENTIAL_FILES = {".netrc", "_netrc", ".pypirc", ".htpasswd", ".git-credentials",
                    "id_rsa", "id_ed25519", "id_ecdsa", "credentials.json", "secrets.json"}

# manifest -> lockfiles that must move with it when they exist in the tree
MANIFESTS = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "Cargo.toml": ("Cargo.lock",),
    "go.mod": ("go.sum",),
    "Gemfile": ("Gemfile.lock",),
    "composer.json": ("composer.lock",),
    "Pipfile": ("Pipfile.lock",),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
}

SECRET_ARG = re.compile(r"(?i)^\s*(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)"
                        r"(?:\s*=\s*|\s+)(.+?)\s*$")
SECRET_NAME = re.compile(r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|"
                         r"ACCESS_?KEY|CLIENT_?SECRET)")
PLACEHOLDER = re.compile(r"(?i)(your|example|placeholder|changeme|<|\$\{|\$[A-Z_]|\{\{|x{4,}|\*{3,})")


def _git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if check and result.returncode:
        raise ValueError("Git could not read the review snapshot")
    return result


def _is_prose(path):
    name = PurePosixPath(path).name.lower()
    if name.split(".")[0] in PROSE_NAMES:
        return True
    return PurePosixPath(path).suffix.lower() in PROSE_SUFFIXES


def _skipped(path):
    return any(part in SKIPPED_DIRS for part in PurePosixPath(path).parts)


def _changed_paths(repo, target):
    if target["scope"] == "range":
        listing = _git(repo, "diff", "--name-only", "--no-renames", target["base"], target["head"])
    else:
        listing = _git(repo, "ls-tree", "-r", "--name-only", target["head"])
    return [line.strip() for line in listing.stdout.decode("utf-8", "replace").splitlines()
            if line.strip()]


def _blob(repo, target, path):
    """Text of the file at the outgoing revision, or None when it is binary,
    oversized or not a regular file."""
    raw = _git(repo, "cat-file", "blob", f"{target['head']}:{path}", check=False).stdout
    if not raw or b"\0" in raw[:8000] or len(raw) > MAX_SCAN_BYTES:
        return None
    return raw.decode("utf-8", "replace")


def _diff_lines(repo, target, path):
    """(added, removed) line lists for one path, numbered at head and base.

    A snapshot scan has no base: every line of the outgoing revision counts as
    added, and no removal rule can fire.
    """
    if target["scope"] != "range":
        return None, None  # caller reads the blob instead
    out = _git(repo, "diff", "--no-color", "--no-renames", "--unified=0",
               target["base"], target["head"], "--", path).stdout.decode("utf-8", "replace")
    added, removed = [], []
    old_line = new_line = 0
    for line in out.splitlines():
        if line.startswith("@@ "):
            header = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if header:
                old_line, new_line = int(header.group(1)), int(header.group(2))
            continue
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            added.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            removed.append((old_line, line[1:]))
            old_line += 1
    return added, removed


def _is_new_file(repo, target, path):
    if target["scope"] != "range":
        return True  # the whole tree is being judged; a credential file in it is a finding
    return _git(repo, "cat-file", "-e", f"{target['base']}:{path}", check=False).returncode != 0


def _in_tree(repo, target, path):
    return _git(repo, "cat-file", "-e", f"{target['head']}:{path}", check=False).returncode == 0


def _workflow(path):
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def _dockerfile(path):
    name = PurePosixPath(path).name.lower()
    return name.startswith("dockerfile") or name.endswith(".dockerfile") or name == "containerfile"


def _compose(path):
    name = PurePosixPath(path).name.lower()
    return name.startswith(("docker-compose", "compose")) and name.endswith((".yml", ".yaml"))


# (rule, path predicate, regex over an added line)
LINE_RULES = [
    ("ci/pull-request-target", _workflow, re.compile(r"^\s*[\"']?pull_request_target[\"']?\s*:")),
    ("ci/write-all-permissions", _workflow, re.compile(r"permissions\s*:\s*[\"']?write-all")),
    ("ci/floating-action-ref", _workflow,
     re.compile(r"uses\s*:\s*[\w.\-/]+@(?:main|master|HEAD)\b|uses\s*:\s*docker://\S+:latest\b", re.I)),
    ("ci/remote-script-execution", _workflow,
     re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b")),
    ("ci/tls-verification-disabled", _workflow,
     re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0")),
    ("container/root-user", _dockerfile, re.compile(r"^\s*USER\s+(?:root|0)\s*$", re.I)),
    ("container/privileged", _dockerfile, re.compile(r"(?:^|\s)--privileged(?:\s|$)")),
    ("container/privileged", _compose, re.compile(r"^\s*privileged\s*:\s*[\"']?true")),
    ("container/world-writable", _dockerfile, re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*777\b")),
    ("hardening/registry-source-changed",
     lambda p: PurePosixPath(p).name in {".npmrc", "pip.conf", "pip.ini", ".yarnrc.yml", "nuget.config"},
     re.compile(r"(?i)^\s*(?:@[\w.\-]+:)?registry\s*=|^\s*index-url\s*=|npmRegistryServer\s*:")),
]

# Runtime switches are judged on code, not on prose that merely names them, so
# these carry no path predicate: every non-prose file in the range is judged.
CODE_LINE_RULES = [
    ("runtime/tls-verification-disabled", None,
     re.compile(r"verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|"
                r"ssl_verify\s*=\s*false|(?:^|\s)--insecure(?:\s|$)", re.I)),
    ("runtime/debug-enabled", None,
     re.compile(r"(?<![A-Za-z_])DEBUG\s*=\s*True|\bdebug\s*=\s*True")),
]

SURFACE_LINE_RULES = [
    ("surface/dependency-url-source", lambda p: PurePosixPath(p).name == "package.json",
     re.compile(r"[\"'][^\"']+[\"']\s*:\s*[\"'](?:git\+|https?://|github:|gitlab:|bitbucket:|file:|link:)")),
    ("surface/dependency-url-source", lambda p: PurePosixPath(p).name.startswith("requirements")
     and p.endswith(".txt"),
     re.compile(r"^\s*(?:-e\s+)?(?:git\+|https?://)\S")),
    ("surface/dependency-url-source", lambda p: PurePosixPath(p).name == "Cargo.toml",
     re.compile(r"^\s*(?:git|path)\s*=")),
    ("surface/dependency-url-source", lambda p: PurePosixPath(p).name == "go.mod",
     re.compile(r"^\s*replace\s+\S+\s+=>\s+\S*(?:\.\./|https?://|git@)")),
    ("surface/install-hook-added", lambda p: PurePosixPath(p).name == "package.json",
     re.compile(r"[\"'](?:pre|post)?install[\"']\s*:\s*[\"']|[\"']prepare[\"']\s*:\s*[\"']")),
    ("surface/install-hook-added", lambda p: PurePosixPath(p).name == ".npmrc",
     re.compile(r"ignore-scripts\s*=\s*false")),
    ("surface/private-address", None,
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b|\b[\w.\-]+\.(?:internal|corp|lan|intranet)\b")),
    ("surface/plaintext-endpoint", None,
     re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.|www\.w3\.org|"
                r"xmlsoap\.org|json-schema\.org|schema\.org|ns\.adobe\.com)[\w.\-]+")),
]


def _scan_text(path, added, removed):
    """Every rule that reads line content, for one path."""
    regressions, surfaces = [], []
    prose = _is_prose(path)

    def apply(rules, sink, lines):
        for number, line in lines:
            for rule, path_pred, pattern in rules:
                if path_pred is not None and not path_pred(path):
                    continue
                if pattern.search(line):
                    sink.append((number, rule))
                    break

    apply(LINE_RULES, regressions, added)
    if not prose:
        apply(CODE_LINE_RULES, regressions, added)
        apply(SURFACE_LINE_RULES, surfaces, added)

    # Secrets baked into an image, and base images that float.
    if _dockerfile(path):
        for number, line in added:
            arg = SECRET_ARG.match(line)
            if arg and SECRET_NAME.search(arg.group(1)) and not PLACEHOLDER.search(arg.group(2)):
                regressions.append((number, "container/secret-in-image"))
                continue
            image = re.match(r"(?i)^\s*FROM\s+(\S+)(?:\s+AS\s+\S+)?\s*$", line)
            if image:
                reference = image.group(1)
                if "@sha256:" not in reference and (":" not in reference.rsplit("/", 1)[-1]
                                                    or reference.endswith(":latest")):
                    regressions.append((number, "container/unpinned-base-image"))

    # Removals that weaken protection.
    for number, line in removed:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name = PurePosixPath(path).name
        if name == ".gitignore" and PROTECTED_IGNORE.search(line):
            regressions.append((number, "hardening/ignore-rule-removed"))
        elif name.upper().startswith("CODEOWNERS"):
            regressions.append((number, "hardening/codeowner-removed"))

    # A wildcard origin is only a regression together with credentials.
    if not prose:
        wildcard = [n for n, l in added if re.search(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|"
                                                     r"Access-Control-Allow-Origin\s*:\s*\*", l, re.I)]
        credentials = [n for n, l in added if re.search(r"allow_credentials\s*=\s*True|"
                                                        r"Access-Control-Allow-Credentials\s*:\s*true", l, re.I)]
        if wildcard and credentials:
            regressions.append((max(credentials), "runtime/cors-wildcard-credentials"))
    return regressions, surfaces


def audit(repo, target):
    """Run the whole checklist for one range. Returns a sanitized summary."""
    regressions, surfaces = [], []
    paths = [p for p in _changed_paths(repo, target) if not _skipped(p)]

    # Files whose mere presence or newness is the finding.
    for path in paths:
        if PurePosixPath(path).name in CREDENTIAL_FILES and _is_new_file(repo, target, path):
            regressions.append({"path": path, "line": 1, "rule": "hardening/credential-file-added"})
        if PurePosixPath(path).name == "build.rs" and _is_new_file(repo, target, path):
            surfaces.append({"path": path, "line": 1, "rule": "surface/install-hook-added"})

    # A manifest that moves without the lockfile the repository keeps beside it.
    present = set(paths)
    for path in paths:
        locks = MANIFESTS.get(PurePosixPath(path).name)
        if not locks:
            continue
        directory = PurePosixPath(path).parent
        for lock in locks:
            candidate = str(directory / lock) if str(directory) != "." else lock
            if candidate not in present and _in_tree(repo, target, candidate):
                regressions.append({"path": path, "line": 1,
                                    "rule": "dependency/lockfile-not-updated"})
                break

    for path in paths:
        text = _blob(repo, target, path)
        if text is None:
            continue
        added, removed = _diff_lines(repo, target, path)
        if added is None:
            added = list(enumerate(text.splitlines(), 1))
            removed = []
        file_regressions, file_surfaces = _scan_text(path, added, removed)
        regressions.extend({"path": path, "line": n, "rule": r} for n, r in file_regressions)
        surfaces.extend({"path": path, "line": n, "rule": r} for n, r in file_surfaces)

    for hit in [*regressions, *surfaces]:
        hit["remedy"] = REMEDIES[hit["rule"]]
    return {"label": target["label"], "scope": target["scope"], "fallback": target["fallback"],
            "status": "regression" if regressions else "clean",
            "findings": len(regressions), "hits": regressions,
            "surfaces": surfaces,
            "refused": "static-security-regression" if regressions else ""}


def audit_all(repo, targets):
    """Run every range; the first regression stops the stage. Returns (ok, summaries)."""
    summaries = []
    for target in targets:
        summary = audit(repo, target)
        summaries.append(summary)
        if summary["refused"]:
            return False, summaries
    return True, summaries
