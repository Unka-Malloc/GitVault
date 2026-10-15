"""The audit engine every GitVault blocking checker runs on.

One implementation of the shared machinery, so the checkers cannot drift:
sanitization, the sensitive-path contract, the immutable-review object, receipt
reuse, the declared runtime, credential loading, the Pi review process, the
bridge-facing tool server and the range orchestration.

A checker plugs in a ``CheckerSpec``: its domains, its deterministic stage,
its tool surface and the small places its contract genuinely differs. The
engine owns everything else; there is exactly one place where a review can
pass, and every checker passes the same way.

Payload note: checkers run from a neutral directory with ``python -I``, so
this module is located by the importing checker's own ``sys.path`` setup, and
this file's directory is inserted here as well so the sibling shared modules
(``audit_runtime``, ``review_ranges``) resolve in both layouts — beside the
plugin in an installed payload, and under ``tools/agent-profiles`` in the
source tree.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_runtime import DEFAULT_RUNTIME  # noqa: E402
from review_ranges import ranges as review_ranges  # noqa: E402

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # a snapshot review diffs against it

# The retention window for review-run directories, the same convention the
# Rust run-record store applies (src/records.rs): newest 200 survive, and
# nothing older than 90 days. A dir holding report.json may be a reusable
# receipt; one without it may still be a resumable Pi session — both kinds
# live under the same bound. Losing a receipt costs a re-review, never a
# wrong verdict.
MAX_RUNS = 200
MAX_AGE_SECS = 90 * 24 * 60 * 60

# The pagination contract the tools and their descriptions share. Named once
# so a size change cannot leave a tool description promising a page the code
# no longer serves.
READ_PAGE_LINES = 400      # lines per `read` page
DIFF_PAGE_CHARS = 20000    # characters per `diff` page
FIND_PAGE = 100            # matches per `find` reply


def prune_runs(runs_dir, keep=MAX_RUNS, max_age_secs=MAX_AGE_SECS):
    """Drop run directories beyond the retention window. Called once per gate
    run, which is also what keeps the receipt scan in `audited` bounded."""
    if not runs_dir.is_dir():
        return
    cutoff = time.time() - max_age_secs
    dirs = sorted((d for d in runs_dir.iterdir() if d.is_dir()),
                  key=lambda d: d.stat().st_mtime, reverse=True)
    for rank, path in enumerate(dirs):
        if path.stat().st_mtime < cutoff:
            shutil.rmtree(path, ignore_errors=True)
        elif rank >= keep:
            # An unfinished session run is a paid resume point: dropping it by
            # rank would re-charge the range it could have continued. The age
            # bound still applies - a session this stale is not worth resuming.
            resumable = (path / "resume.json").exists() and not (path / "report.json").exists()
            if not resumable:
                shutil.rmtree(path, ignore_errors=True)

# Credential containers and runtime stores are never handed to the semantic
# layer: shipping a key file to a cloud model is itself the leak this gate
# exists to prevent. The deterministic stage judges them instead.
SENSITIVE_PARTS = {".git", ".ssh", ".aws", ".env", ".dev.vars", "secrets", "credentials",
                   "logs", "runtime-data", ".netrc", ".npmrc", "credentials.json", "secrets.json"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
                      ".log", ".jsonl", ".enc", ".tfstate", ".kdbx"}
SENSITIVE_PREFIXES = (".env", ".dev.vars")
# Templates are reviewable: an example file is exactly where a reviewer
# must look for a real value someone forgot to placeholder.
TEMPLATE_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".dev.vars.example"}


# Home and temp prefixes a receipt or a review payload must never spell out:
# the store may not describe the machine. This is one convention on two
# runtimes - records.rs::redact carries the same list, and a drift test pins
# the pair, so adding a marker on one side fails the other.
LOCAL_PATH_MARKERS = ("/Users/", "/home/", "/var/folders/", "C:\\Users\\", "C:/Users/")


def _local_path(text):
    # Earliest marker wins, same as records.rs::redact: a later marker inside a
    # copied span would never be seen again. Runs end at the first stop char,
    # matching the Rust stop set exactly.
    stops = set(' \t\n\r"\'`<')
    out = []
    while text:
        hits = [(text.find(m), m) for m in LOCAL_PATH_MARKERS if text.find(m) >= 0]
        if not hits:
            out.append(text)
            break
        at, marker = min(hits)
        end = len(text)
        for stop in stops:
            found = text.find(stop, at + len(marker))
            if found >= 0:
                end = min(end, found)
        out.append(text[:at] + "[LOCAL_PATH]")
        text = text[end:]
    return "".join(out)


def sanitize(text):
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
                  lambda match: "[PRIVATE_KEY]" + "\n" * match[0].count("\n"), text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b", "[CREDENTIAL]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|password|secret|access[_-]?token|authorization)[\"']?\s*[=:]\s*)[\"'][^\"'\n]+[\"']", r'\1"[REDACTED]"', text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
    text = _local_path(text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", text)
    text = re.sub(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "[PRIVATE_IP]", text)
    return text


def sanitize_source(raw):
    """Endpoint and account identifiers are unnecessary for the domains any
    checker judges. Kept separate from report sanitization so official
    citations survive."""
    text = sanitize(raw)
    text = re.sub(r"(?i)(https?|wss?)://[^\s\"'<>`]+", r"\1://[ENDPOINT]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_ADDRESS]", text)
    text = re.sub(r"(?i)((?:account_id|database_id|zone_id|tenant_id)[\"']?\s*[=:]\s*)[\"'][^\"'\n]+[\"']", r'\1"[IDENTIFIER]"', text)
    text = re.sub(r"(?im)^(\s*(?:[- ]*\s*)?(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z_]*)\s*[=:]\s*)([^\s#]+)", r"\1[REDACTED]", text)
    return text


def outgoing_paths(repo, target):
    """The paths an operation carries - one enumeration so the deterministic
    stage and the paid stage can never judge different sets: a NUL-delimited
    diff for a range, ls-tree for a snapshot. Renames count as delete+add,
    paths with newlines or quotes cannot split entries."""
    if target["scope"] == "range":
        out = git(repo, "diff", "--name-only", "--no-renames", "-z",
                  target["base"] or EMPTY_TREE, target["head"])
    else:
        out = git(repo, "ls-tree", "-rz", "--name-only", target["head"])
    return [p for p in out.stdout.decode(errors="replace").split("\0") if p]


def safe_path(path):
    p = PurePosixPath(path)
    lowering = [x.lower() for x in p.parts]
    if (not path or p.is_absolute() or ".." in p.parts
            or any(x in SENSITIVE_PARTS or (x not in TEMPLATE_NAMES and x.startswith(SENSITIVE_PREFIXES))
                for x in lowering)
            or p.suffix.lower() in SENSITIVE_SUFFIXES):
        raise ValueError("Sensitive or invalid path; contents are unavailable to the reviewer")
    return path


def git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if check and result.returncode:
        raise ValueError("Git could not read the review snapshot")
    return result


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def origin_slug(repo):
    """`owner/name` parsed from the origin remote, for contracts that key off
    the repository identity. A remote that is a local path (a sandbox, a
    mirror) is not a repository any name can identify."""
    remote = git(repo, "remote", "get-url", "origin", check=False).stdout.decode().strip()
    slug = re.sub(r"\.git$", "", re.sub(r"^(?:git@[^:]+:|https?://[^/]+/|ssh://[^/]+/)", "", remote)) if remote else ""
    return slug if re.fullmatch(r"[\w.\-]+/[\w.\-]+", slug or "") else "local/unknown"


# The declared runtime's shape. A published profile.json is the only place a
# provider, model or effort may come from; values are inert labels, never
# paths or endpoints.
RUNTIME_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,79}$")
PI_THINKING = {"off", "minimal", "low", "medium", "high", "xhigh", "max"}


def declared_runtime(settings):
    """The runtime this review runs on. The synced profile.json is the
    configuration mapping; a machine that never pulled it uses the built-in
    default the operator set, never a guess."""
    runtime = dict(DEFAULT_RUNTIME)
    try:
        profile = json.loads((Path(settings["skill_dir"]) / "profile.json").read_text())
    except (OSError, ValueError, KeyError):
        profile = {}
    declared = profile.get("runtime") or {}
    for key in ("provider", "model", "effort"):
        value = declared.get(key)
        if isinstance(value, str) and RUNTIME_VALUE.match(value):
            runtime[key] = value
    effort = {"none": "off"}.get(runtime["effort"], runtime["effort"])
    if effort not in PI_THINKING:
        raise ValueError(f"declared effort is not a Pi thinking level: {runtime['effort']}")
    runtime["effort"] = effort
    return runtime


_COVERAGE_ENTRY = {"type": "object", "properties": {
    "status": {"type": "string", "enum": ["reviewed", "not-applicable", "unknown"]},
    "reason": {"type": "string"}},
    "required": ["status", "reason"], "additionalProperties": False}


def context_schema(operations, revisions=("outgoing", "base")):
    """The shared context tool's parameter surface. One builder so a new key
    cannot land on three checkers while the fourth tells the model a
    different contract."""
    return {"operation": {"type": "string", "enum": list(operations)},
            "path": {"type": "string"}, "pattern": {"type": "string"},
            "text": {"type": "string"}, "start": {"type": "integer"},
            "offset": {"type": "integer"},
            "revision": {"type": "string", "enum": list(revisions)}}


def coverage_schema(domains):
    """The coverage object every submit contract carries: one literal,
    generated per domain set, so four tool manifests cannot drift apart."""
    return {"type": "object",
            "properties": {name: _COVERAGE_ENTRY for name in domains},
            "required": list(domains), "additionalProperties": False}


def finding_schema(keys, extra_properties=None):
    """The findings-entry contract, generated from the same key list the
    validator enforces (``Review.finding_keys``) so the tool manifest and the
    check cannot tell the model different contracts. ``extra_properties``
    adds a checker's genuinely extra keys (e.g. a sources list) without
    duplicating the shared ones."""
    properties = {
        key: ({"type": "integer", "minimum": 1} if key == "line" else {"type": "string"})
        for key in keys}
    properties["severity"] = {"type": "string", "enum": ["blocking", "advisory"]}
    if extra_properties:
        properties.update(extra_properties)
    return {"type": "object", "properties": properties,
            "required": list(keys), "additionalProperties": False}


def credential(path, name):
    # Read only the named credential; never clone an entire personal .env.
    for line in Path(path).read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ") == name:
            value = value.strip().strip("\"'")
            if value:
                return value
    raise ValueError(f"Credential {name} is unavailable")


class Review:
    """Read-only view of the outgoing range, plus the single verdict tool.

    Checker-owned subclasses bind the class attributes; the review machinery
    itself — what may be read, what a verdict must contain, how receipts are
    stamped — is the engine's and cannot drift.
    """

    DOMAINS: tuple = ()
    #: The checker's own directory: policy, bridge and payload files live there.
    ROOT = Path(__file__).resolve().parent
    #: Every key a finding must carry, verbatim.
    finding_keys = ("file", "line", "severity", "evidence", "impact", "remedy", "validation")
    #: The label the "read" operation uses for the reviewed end of the range.
    revision_label = "outgoing"
    #: The key the inventory reply carries the domains under.
    domain_key = "domains"

    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.state = json.loads((self.run_dir / "scope.json").read_text())
        self.repo = self.state["repo"]
        self.tree = self.state["tree"]
        self.base = self.state["base"]
        self.changed = self.state["changed"]
        self.surfaces = self.state.get("surfaces", [])
        self.entries = {}
        self.reviewed = set()
        self.diffs = {}
        self.diff_progress = {}
        self.lock = threading.RLock()
        for record in git(self.repo, "ls-tree", "-rz", self.tree).stdout.split(b"\0"):
            if record:
                metadata, path = record.split(b"\t", 1)
                mode, kind, oid = metadata.decode().split()
                self.entries[path.decode()] = (mode, kind, oid)

    def inventory_extra(self):
        """Checker-specific additions to the inventory reply."""
        return {}

    def context(self, args):
        operation = args["operation"]
        if operation == "inventory":
            return {"changed": self.changed, "kind": self.state.get("kind", ""),
                    self.domain_key: list(self.DOMAINS), **self.inventory_extra()}
        if operation == "list":
            pattern = args.get("pattern", "*")
            return [p for p in self.entries if fnmatch.fnmatchcase(p, pattern)]
        if operation == "diff":
            path = args.get("path")
            if not path:
                raise ValueError('operation "diff" requires a "path" argument')
            path = safe_path(path)
            if path not in self.changed:
                raise ValueError("Path is not part of this review range")
            if path not in self.diffs:
                # A snapshot review has no base commit: every change is a new
                # file, which is exactly a diff against the empty tree.
                raw = git(self.repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                          "--no-color", "--unified=5", self.base or EMPTY_TREE, self.tree, "--", path).stdout.decode("utf-8", "replace")
                self.diffs[path] = sanitize_source(raw)
            diff = self.diffs[path]
            start = max(0, int(args.get("offset", 0)))
            if start > self.diff_progress.get(path, 0):
                raise ValueError("Read the preceding diff page before advancing")
            end = min(len(diff), start + DIFF_PAGE_CHARS)
            self.diff_progress[path] = max(end, self.diff_progress.get(path, 0))
            if self.diff_progress[path] == len(diff):
                self.reviewed.add(path)
            return {"content": diff[start:end], "offset": start, "total_characters": len(diff),
                    "next_offset": end if end < len(diff) else None}
        if operation == "read":
            path = args.get("path")
            if not path:
                raise ValueError('operation "read" requires a "path" argument')
            path = safe_path(path)
            revision = args.get("revision", self.revision_label)
            if revision not in {self.revision_label, "base"}:
                raise ValueError(f"revision must be {self.revision_label} or base")
            if revision == self.revision_label:
                entry = self.entries.get(path)
                if not entry or entry[0] not in {"100644", "100755"}:
                    raise ValueError("Only regular tracked source files can be read")
                blob = entry[2]
            else:
                if not self.base:
                    raise ValueError("This snapshot has no base revision; every path is new")
                blob = f"{self.base}:{path}"
                if git(self.repo, "cat-file", "-e", blob, check=False).returncode:
                    raise ValueError("Path does not exist in the base revision; the change adds it")
            raw = git(self.repo, "cat-file", "blob", blob).stdout
            if b"\0" in raw:
                return {"binary": True, "bytes": len(raw)}
            lines = sanitize_source(raw.decode("utf-8", "replace")).splitlines()
            start = max(1, int(args.get("start", 1)))
            end = min(len(lines), start - 1 + READ_PAGE_LINES)
            return {"total_lines": len(lines),
                    "content": "\n".join(f"{i+1}: {lines[i]}" for i in range(start - 1, end))}
        if operation == "find":
            needle = args.get("text", "")
            if not needle:
                raise ValueError("A literal search string is required")
            out = git(self.repo, "grep", "-I", "-n", "-F", "-e", needle, self.tree, "--", check=False)
            if out.returncode not in {0, 1}:
                raise ValueError("Source search failed")
            matches = []
            for record in out.stdout.decode("utf-8", "replace").splitlines():
                prefix, _, rest = record.partition(":")
                path, _, line = rest.partition(":")
                try:
                    safe_path(path)
                except ValueError:
                    continue
                matches.append(sanitize_source(f"{path}:{line}"))
            return {"matches": matches[:FIND_PAGE], "more": len(matches) > FIND_PAGE}
        raise ValueError("Unknown context operation")

    def submit_extra(self, report, verdict):
        """Checker-specific verdict contract beyond the engine's shape.
        Raise ValueError to reject the submission."""
        return None

    def receipt_extra(self):
        """Checker-specific fields folded into the receipt."""
        return {}

    def submit(self, report):
        write_json(self.run_dir / "draft.json", json.loads(sanitize(json.dumps(report, ensure_ascii=False))))
        if (self.run_dir / "report.json").exists():
            raise ValueError("A verdict has already been submitted")
        verdict = report.get("verdict")
        if verdict not in {"pass", "block", "incomplete"}:
            raise ValueError("Invalid verdict")
        if not report.get("summary") or not isinstance(report.get("findings"), list):
            raise ValueError("Summary and findings are required")
        if set(report.get("coverage", {})) != set(self.DOMAINS):
            raise ValueError("Account for every domain: " + ", ".join(self.DOMAINS))
        if not isinstance(report.get("unknowns"), list):
            raise ValueError("Unknowns must be an explicit list")
        for index, finding in enumerate(report["findings"]):
            for key in self.finding_keys:
                if not finding.get(key):
                    raise ValueError(f"findings[{index}].{key} is required and must not be empty")
            safe_path(finding["file"])
            if finding["severity"] not in {"blocking", "advisory"}:
                raise ValueError("Invalid finding severity")
            if not isinstance(finding["line"], int) or finding["line"] < 1:
                raise ValueError("A positive line is required")
        blocking = any(f["severity"] == "blocking" for f in report["findings"])
        if verdict == "pass" and (blocking or set(self.changed) != self.reviewed):
            raise ValueError("Pass requires every changed diff reviewed and no blocking findings")
        if verdict == "block" and not blocking:
            raise ValueError("Block requires a concrete blocking finding; otherwise use incomplete")
        for domain, coverage in report["coverage"].items():
            if not isinstance(coverage, dict) or coverage.get("status") not in {"reviewed", "not-applicable", "unknown"} or not coverage.get("reason"):
                raise ValueError(f"coverage.{domain} must be {{status, reason}}")
            if verdict == "pass" and coverage["status"] == "unknown":
                raise ValueError("Unknown applicable coverage cannot pass")
        self.submit_extra(report, verdict)
        runtime = self.state.get("runtime") or {}
        receipt = {**report, "provider": runtime.get("provider", ""), "model": runtime.get("model", ""),
                   "reasoning": runtime.get("effort", ""),
                   "tree": self.tree, "gate_status": "pending", **self.receipt_extra()}
        write_json(self.run_dir / "report.json", json.loads(sanitize(json.dumps(receipt, ensure_ascii=False))))
        return {"accepted": True, "verdict": verdict}


class CheckerSpec:
    """The places a checker's contract genuinely differs, as data.

    - ``name``/``label``: the run directory and every printed line.
    - ``domains``: the coverage contract (also bound on the Review subclass).
    - ``stage1``: the deterministic stage — ``callable(repo, targets) ->
      (ok, summaries)``, or None for a checker without one.
    - ``stage1_lines``: per-summary detail lines under the refused report.
    - ``stage_label``: the printed name of that stage ("deterministic"/"static").
    - ``refusal``: the error a stage-one refusal raises.
    - ``tool_plan``: callable(review) -> the checker's tool surface.
    - ``make_review``: callable(run_dir) -> Review (handles mode swaps).
    - ``task``: callable(review) -> the instruction appended to the Pi command.
    - ``scope_extra``: callable(target, summary) -> dict folded into scope.json.
    - ``receipt_after``: callable(report, target, summary, summaries) mutating
      the accepted report before it is written.
    - ``root``: the checker's directory — installation.json, policy.md and the
      Pi bridge live there.

    Every review keeps its Pi session dir so an interrupted run continues
    instead of replaying paid work; there is no no-session mode because a
    paid review that must start over is the failure this engine exists to
    prevent.
    """

    def __init__(self, name, label, description, domains, tool_plan, make_review, task, root,
                 stage1=None, stage1_lines=None, stage_label="deterministic",
                 refusal="", scope_extra=None, receipt_after=None):
        self.name = name
        self.label = label
        self.description = description
        self.root = root
        self.domains = domains
        self.tool_plan = tool_plan
        self.make_review = make_review
        self.task = task
        self.stage1 = stage1
        # The per-hit refusal lines the refused report lists. Shared because a
        # second copy in one payload would silently stop tracking a summary
        # field the other added.
        self.stage1_lines = stage1_lines or (lambda summary: [
            f"{hit['path']}{':' + str(hit['line']) if hit.get('line') else ''} "
            f"{hit.get('rule', summary['refused'])}"
            for hit in summary.get("hits", [])])
        self.stage_label = stage_label
        self.refusal = refusal
        self.scope_extra = scope_extra or (lambda target, summary: {})
        # The default receipt carries the deterministic stage's summaries and
        # the fallback marker — one shape, written once, instead of three
        # identical callbacks drifting apart.
        self.receipt_after = receipt_after or _default_receipt_after

    @property
    def runs_dir(self):
        return f"{self.name}-runs"


def _default_receipt_after(report, target, summary, summaries):
    """The receipt fields every stage-1 checker stamps identically."""
    report["stage1"] = {"ranges": summaries}
    if target["fallback"]:
        report["fallback"] = target["fallback"]


def audited(settings, base, head, runtime, spec):
    """A previous passing review of exactly this range: the deterministic stage
    still runs every time, but the semantic stage is not paid for twice.

    The judged items are part of the key. A receipt written under an earlier
    contract did not answer the questions this run asks, so reusing it would
    let a new coverage item go unanswered while the range reports as passed."""
    for report_path in sorted((Path(settings["profile"]) / spec.runs_dir).glob("*/report.json")):
        try:
            report = json.loads(report_path.read_text())
        except ValueError:
            continue
        if (report.get("review_base") == base and report.get("review_head") == head
                and report.get("review_items") == list(spec.domains)
                and report.get("gate_status") == "passed"
                and report.get("provider") == runtime["provider"] and report.get("model") == runtime["model"]
                and report.get("reasoning") == runtime["effort"]):
            return True
    return False


def resume_dir(runs, key):
    """An unfinished run of exactly this range under this runtime, if one is
    waiting to continue - the resume side of the key `audited` uses for
    receipts. scope.json cannot serve as the key because it is removed when a
    run ends; resume.json is written for that lookup and nothing else."""
    for path in sorted(Path(runs).glob("*/resume.json")):
        try:
            candidate = json.loads(path.read_text())
        except ValueError:
            continue
        if candidate == key and not (path.parent / "report.json").exists():
            return path.parent
    return None


def pi_review(run_dir, settings, runtime, spec, spawn=subprocess.run):
    """Drive one Pi review of the scope in run_dir through the bridge
    extension: Pi owns only the conversation, the Python plugin owns the
    tools, the evidence and the receipt. Returns (usage, duration_ms) or
    raises when the run did not settle into a report; no wall-clock kill, no
    second reviewer. The session directory lives inside run_dir, so an
    interrupted run continues its conversation instead of replaying it."""
    run_dir = Path(run_dir)
    review = spec.make_review(run_dir)
    manifest = [{"name": name, "description": description,
                 "parameters": {"type": "object", "properties": properties, "required": required}}
                for name, description, properties, required, _ in spec.tool_plan(review)]
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LANG", "TMPDIR") if k in os.environ}
    credential_name = f"{runtime['provider'].upper().replace('-', '_')}_API_KEY"
    env.update({"GITVAULT_CHECKER_DIR": str(review.ROOT), "GITVAULT_RUN_DIR": str(run_dir),
                "GITVAULT_PYTHON": sys.executable, "GITVAULT_TOOLS": json.dumps(manifest),
                credential_name: credential(settings["credential_file"], credential_name)})
    prompt = (review.ROOT / "policy.md").read_text() + "\nReview date (UTC): " + dt.datetime.now(dt.timezone.utc).date().isoformat()
    command = [settings.get("pi") or shutil.which("pi") or "pi",
               "--mode", "json", "--print", "--no-mcp", "--no-skills",
               "--no-context-files", "--no-prompt-templates", "--no-extensions",
               "--provider", runtime["provider"], "--model", runtime["model"],
               "--thinking", runtime["effort"],
               "--extension", str(review.ROOT / "pi-bridge.ts"),
               "--tools", ",".join(entry["name"] for entry in manifest),
               "--system-prompt", prompt]
    command += ["--session-dir", str(run_dir)]
    marker = run_dir / "session.used"
    if marker.exists():
        command.append("--continue")
        command.append("Continue this same review from its preserved conversation and draft. "
                       "Correct the outstanding report fields; reuse evidence and do not restart the audit.")
    else:
        command.append(spec.task(review))
    started = time.monotonic()
    result = spawn(command, env=env, cwd=run_dir, capture_output=True, text=True)
    marker.touch()
    # Pi's JSONL stream: assistant messages carry provider usage;
    # agent_settled (not agent_end, which automatic retries can follow) marks
    # a settled run. Output stays private; only the sanitized receipt
    # is exposed by the gate.
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0}
    settled = False
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "agent_settled":
            settled = not event.get("aborted")
        message = event.get("message") or {}
        if event.get("type") == "message_end" and message.get("role") == "assistant":
            seen = message.get("usage") or {}
            usage["input_tokens"] += seen.get("input", 0) or 0
            usage["output_tokens"] += seen.get("output", 0) or 0
            usage["cache_read_tokens"] += seen.get("cacheRead", 0) or 0
            usage["cache_write_tokens"] += seen.get("cacheWrite", 0) or 0
    duration_ms = int((time.monotonic() - started) * 1000)
    has_report = (run_dir / "report.json").exists()
    write_json(run_dir / "completion.json",
               {"completed": bool(settled and has_report and not result.returncode),
                "has_report": has_report,
                "failure_reason": None if settled and has_report and not result.returncode
                else "Pi review did not complete"})
    if result.returncode or not settled or not has_report:
        raise ValueError("Pi did not complete a valid review; publication refused")
    return usage, duration_ms


def review_range(repo, settings, target, summary, stage_summaries, runtime, spec, spawn=subprocess.run):
    """Run one Pi review of an unpublished range. The engine owns the scope,
    the tools and the receipt; Pi is the model runtime driving them through
    the bridge extension."""
    head, base = target["head"], target["base"]
    tree = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{head}^{{tree}}"],
                          capture_output=True, check=True).stdout.decode().strip()
    changed = outgoing_paths(repo, {"scope": "range", "base": base, "head": tree})
    # A path the tool surface refuses is a review that can never complete:
    # "every changed diff reviewed" could not hold even after paying for the
    # semantic stage. Refuse it here, the same way the deterministic stages
    # refuse — naming the path, never its content. This is the same verdict
    # the paid review would return, reached before it costs a token.
    for path in changed:
        try:
            safe_path(path)
        except ValueError:
            raise ValueError(
                f"The range contains '{path}', a path the review contract excludes; "
                "no review could ever pass it, so the publication is refused locally")
    profile = Path(settings["profile"])
    runs = profile / spec.runs_dir
    runs.mkdir(parents=True, exist_ok=True, mode=0o700)
    # The same tuple `audited` keys receipts on: only a run of exactly this
    # range under this runtime may be continued - a wider or different review
    # starts a new session, never borrows a stranger's conversation.
    resume_key = {"base": base, "head": head, "items": list(spec.domains),
                  "provider": runtime["provider"], "model": runtime["model"],
                  "effort": runtime["effort"]}
    run_dir = resume_dir(runs, resume_key)
    if run_dir is None:
        run_dir = Path(tempfile.mkdtemp(prefix="review-", dir=runs))
        write_json(run_dir / "resume.json", resume_key)
    elif any(p.name not in {"scope.json", "resume.json"} for p in run_dir.iterdir()):
        # A prior attempt left work in this dir: mark it so pi_review
        # continues that conversation instead of replaying it.
        (run_dir / "session.used").touch()
    # The receipt reads its provider/model/effort labels from this scope.
    write_json(run_dir / "scope.json", {"repo": str(repo), "tree": tree, "base": base,
                                        "changed": changed, "runtime": runtime,
                                        **spec.scope_extra(target, summary)})
    try:
        print(f"{spec.label}: reviewing {target['label']} with "
              f"{runtime['provider']}/{runtime['model']} ({runtime['effort']})…", flush=True)
        usage, duration_ms = pi_review(run_dir, settings, runtime, spec, spawn)
        report_path = run_dir / "report.json"
        report = json.loads(report_path.read_text())
        if target["ref"] and subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", target["ref"]],
                                            capture_output=True).stdout.decode().strip() != head:
            raise ValueError("The pushed ref moved during review; publication refused")
        report["gate_status"] = "passed" if report["verdict"] == "pass" else "refused"
        report["review_usage"] = {"tokens": usage, "duration_ms": duration_ms}
        report["review_base"] = base
        report["review_head"] = head
        report["review_kind"] = target["kind"]
        # What this pass answered, so a later run under a wider contract does not
        # reuse it (see `audited`).
        report["review_items"] = list(spec.domains)
        spec.receipt_after(report, target, summary, stage_summaries)
        write_json(report_path, report)
        print(f"{spec.label}: {report['verdict']} — {sanitize(report['summary'])}")
        for finding in report["findings"]:
            print(sanitize(f"  {finding['file']}:{finding['line']} [{finding['severity']}] {finding['impact']} → {finding['remedy']}"))
        print(f"{spec.label} report: {report_path}")
        return 0 if report["verdict"] == "pass" else 1
    finally:
        (run_dir / "scope.json").unlink(missing_ok=True)
        report_path = run_dir / "report.json"
        if report_path.exists():
            receipt = json.loads(report_path.read_text())
            if receipt.get("gate_status") == "pending":
                receipt["gate_status"] = "refused"
                write_json(report_path, receipt)
        # An unfinished dir keeps its resume.json and session files: the next
        # gate over this range continues it rather than repaying for it.


def run(repo, settings, spec, spawn=subprocess.run):
    """The checker entry point. Refuses on the first stage that finds a problem;
    a refused audit never touches the working tree."""
    repo = Path(repo).resolve()
    runtime = declared_runtime(settings)
    prune_runs(Path(settings["profile"]) / spec.runs_dir)
    targets = review_ranges(repo)
    if not targets:
        print(f"{spec.label}: nothing unpublished in this operation; no review needed")
        return 0
    summaries = []
    if spec.stage1 is not None:
        ok, summaries = spec.stage1(repo, targets)
        for summary in summaries:
            state = f"refused: {summary['refused']}" if summary.get("refused") else summary["status"]
            extra = f", surfaces={len(summary['surfaces'])}" if "surfaces" in summary else ""
            print(f"{spec.label}: {spec.stage_label} {state} — {summary['label']} "
                  f"({summary['scope']}, findings={summary['findings']}{extra})")
            for line in spec.stage1_lines(summary):
                print(f"  {line}")
        if not ok:
            raise ValueError(spec.refusal)
    for index, target in enumerate(targets):
        if audited(settings, target["base"], target["head"], runtime, spec):
            print(f"{spec.label}: {target['label']} already passed its semantic review "
                  f"({target['head'][:12]}); reusing that verdict")
            continue
        summary = summaries[index] if index < len(summaries) else None
        if review_range(repo, settings, target, summary, summaries, runtime, spec, spawn):
            return 1
    return 0


def _call(review, method):
    def wrapped(args):
        try:
            with review.lock:
                return json.dumps(method(args), ensure_ascii=False)
        except Exception as exc:
            # Tool failures never echo repository content or local paths.
            reason = str(exc) if isinstance(exc, ValueError) else "Evidence unavailable; review cannot pass without it"
            return json.dumps({"error": sanitize(reason), "error_type": type(exc).__name__}, ensure_ascii=False)
    return wrapped


def serve_tools(run_dir, spec):
    """Host this run's tools over JSONL stdio for the Pi bridge extension. One
    long-lived process keeps the review's in-memory state - pages read and
    diff progress - coherent for the whole verdict."""
    review = spec.make_review(run_dir)
    methods = {name: _call(review, method) for name, _, _, _, method in spec.tool_plan(review)}
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            continue
        reply = {"id": request.get("id")}
        method = methods.get(request.get("tool") or "")
        if method is None:
            reply["result"] = json.dumps({"error": "unknown tool", "error_type": "ValueError"})
        else:
            reply["result"] = method(request.get("args") or {})
        sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def main(spec):
    parser = argparse.ArgumentParser(description=spec.description)
    parser.add_argument("--repo")
    parser.add_argument("--serve-tools", action="store_true")
    parser.add_argument("--run")
    args = parser.parse_args()
    if args.serve_tools:
        # Bridge-facing mode: no sync assertion, no gate output - tool replies
        # only, one JSON object per stdout line.
        serve_tools(args.run, spec)
        return 0
    if not args.repo:
        parser.error("--repo is required")
    try:
        settings = json.loads((spec.root / "installation.json").read_text())
        # A prompt copy edited on this machine is not the reviewed prompt.
        import profile_sync
        profile_sync.assert_synced(settings)
        return run(args.repo, settings, spec)
    except (Exception, KeyboardInterrupt) as exc:
        message = sanitize(str(exc)) if isinstance(exc, ValueError) else "Audit unavailable or interrupted; publication refused"
        print(f"{spec.label}: {message}", file=sys.stderr)
        return 1


def bind(ns, spec):
    """Install the standard checker entry points onto a checker module.

    The public surface — ``audited``, ``pi_review``, ``review_range``, ``run``,
    ``serve_tools``, ``main`` — is identical for every checker; generating it
    from the SPEC keeps four modules from drifting into four copies of the
    same forwarding block."""
    # The contract surface tests and callers read off a checker module:
    # installed once here so a new public symbol cannot exist on three
    # checkers and be missing on the fourth.
    for name in ("sanitize", "sanitize_source", "safe_path", "git", "write_json",
                 "credential", "declared_runtime", "origin_slug", "review_ranges",
                 "SENSITIVE_PARTS", "SENSITIVE_SUFFIXES", "SENSITIVE_PREFIXES",
                 "TEMPLATE_NAMES", "EMPTY_TREE", "RUNTIME_VALUE", "PI_THINKING"):
        ns[name] = globals()[name]
    ns["audited"] = lambda settings, base, head, runtime: \
        audited(settings, base, head, runtime, spec)
    ns["pi_review"] = lambda run_dir, settings, runtime, spawn=subprocess.run: \
        pi_review(run_dir, settings, runtime, spec, spawn)
    ns["review_range"] = lambda repo, settings, target, summary, stage_summaries, runtime, spawn=subprocess.run: \
        review_range(repo, settings, target, summary, stage_summaries, runtime, spec, spawn)
    ns["run"] = lambda repo, settings, spawn=subprocess.run: \
        run(repo, settings, spec, spawn)
    ns["serve_tools"] = lambda run_dir: serve_tools(run_dir, spec)
    ns["main"] = lambda: main(spec)
