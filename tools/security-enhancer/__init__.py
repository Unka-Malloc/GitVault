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

# The checker runs from a neutral directory with `-I` (no PYTHONPATH, no cwd
# import), so the package's own modules are found explicitly. Their names carry
# the checker's own prefix: two checkers sharing a process (the test suite) must
# not collide on a top-level module name like `stage1`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))
from security_ranges import ranges as review_ranges  # noqa: E402
import security_stage1 as stage1  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
DOMAINS = ("dependency_supply_chain", "ci_workflow_authority", "secret_handling",
           "transport_security", "authz_defaults", "container_runtime", "release_artifacts")
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # a snapshot review diffs against it
# Credential containers and runtime stores are never handed to the semantic
# layer: shipping a key file to a cloud model is itself the leak this gate
# exists to prevent. The static stage reads them locally instead, which is why
# a registry change in `.npmrc` is still judged.
SENSITIVE_PARTS = {".git", ".ssh", ".aws", ".env", "secrets", "credentials", "logs",
                   "runtime-data", ".netrc", ".npmrc", "credentials.json", "secrets.json"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
                      ".log", ".jsonl", ".enc", ".tfstate", ".kdbx"}
SENSITIVE_PREFIXES = (".env", ".dev.vars")


def sanitize(text):
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----",
                  lambda match: "[PRIVATE_KEY]" + "\n" * match[0].count("\n"), text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b", "[CREDENTIAL]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|password|secret|access[_-]?token|authorization)[\"']?\s*[=:]\s*)[\"'][^\"'\n]+[\"']", r'\1"[REDACTED]"', text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
    text = re.sub(r"(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s\"'`<>]+", "[LOCAL_PATH]", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", text)
    text = re.sub(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "[PRIVATE_IP]", text)
    return text


def sanitize_source(raw):
    """Endpoint and account identifiers are not needed to judge a domain."""
    text = sanitize(raw)
    text = re.sub(r"(?i)(https?|wss?)://[^\s\"'<>`]+", r"\1://[ENDPOINT]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_ADDRESS]", text)
    text = re.sub(r"(?i)((?:account_id|database_id|zone_id|tenant_id)[\"']?\s*[=:]\s*)[\"'][^\"'\n]+[\"']", r'\1"[IDENTIFIER]"', text)
    text = re.sub(r"(?im)^(\s*(?:[- ]*\s*)?(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z_]*)\s*[=:]\s*)([^\s#]+)", r"\1[REDACTED]", text)
    return text


def safe_path(path):
    p = PurePosixPath(path)
    lowering = [x.lower() for x in p.parts]
    if (not path or p.is_absolute() or ".." in p.parts
            or any(x in SENSITIVE_PARTS or x.startswith(SENSITIVE_PREFIXES) for x in lowering)
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


class Review:
    """Read-only view of the outgoing range, plus the single verdict tool."""

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

    def context(self, args):
        operation = args["operation"]
        if operation == "inventory":
            return {"changed": self.changed, "surfaces": self.surfaces,
                    "cost_domains": DOMAINS, "kind": self.state.get("kind", "")}
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
            end = min(len(diff), start + 20000)
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
            revision = args.get("revision", "outgoing")
            if revision not in {"outgoing", "base"}:
                raise ValueError("revision must be outgoing or base")
            if revision == "outgoing":
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
            end = min(len(lines), start + 399)
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
            return {"matches": matches[:100], "more": len(matches) > 100}
        raise ValueError("Unknown context operation")

    def submit(self, report):
        write_json(self.run_dir / "draft.json", json.loads(sanitize(json.dumps(report, ensure_ascii=False))))
        if (self.run_dir / "report.json").exists():
            raise ValueError("A verdict has already been submitted")
        verdict = report.get("verdict")
        if verdict not in {"pass", "block", "incomplete"}:
            raise ValueError("Invalid verdict")
        if not report.get("summary") or not isinstance(report.get("findings"), list):
            raise ValueError("Summary and findings are required")
        if set(report.get("coverage", {})) != set(DOMAINS):
            raise ValueError("Account for every domain: " + ", ".join(DOMAINS))
        if not isinstance(report.get("unknowns"), list):
            raise ValueError("Unknowns must be an explicit list")
        for index, finding in enumerate(report["findings"]):
            for key in ("file", "line", "severity", "evidence", "impact", "remedy", "validation"):
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
        runtime = self.state.get("runtime") or {}
        receipt = {**report, "provider": runtime.get("provider", ""), "model": runtime.get("model", ""),
                   "reasoning": runtime.get("effort", ""),
                   "tree": self.tree, "gate_status": "pending", "surfaces": self.surfaces}
        write_json(self.run_dir / "report.json", json.loads(sanitize(json.dumps(receipt, ensure_ascii=False))))
        return {"accepted": True, "verdict": verdict}


def audited(settings, base, head, runtime):
    """A previous passing review of exactly this range: the static stage still
    runs every time, but the semantic stage is not paid for twice."""
    for report_path in sorted((Path(settings["profile"]) / "security-enhancer-runs").glob("*/report.json")):
        try:
            report = json.loads(report_path.read_text())
        except ValueError:
            continue
        if (report.get("review_base") == base and report.get("review_head") == head
                and report.get("gate_status") == "passed"
                and report.get("provider") == runtime["provider"] and report.get("model") == runtime["model"]
                and report.get("reasoning") == runtime["effort"]):
            return True
    return False


# The declared runtime's shape. A published profile.json is the only place a
# provider, model or effort may come from; values are inert labels, never
# paths or endpoints.
RUNTIME_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,79}$")
PI_THINKING = {"off", "minimal", "low", "medium", "high", "xhigh", "max"}
from audit_runtime import DEFAULT_RUNTIME  # noqa: E402  single source: tools/agent-profiles/audit_runtime.py


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


def credential(path, name):
    # Read only the named credential; never clone an entire personal .env.
    for line in Path(path).read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ") == name:
            value = value.strip().strip("\"'")
            if value:
                return value
    raise ValueError(f"Credential {name} is unavailable")


def pi_review(run_dir, settings, runtime, spawn=subprocess.run):
    """Drive one Pi review of the scope in run_dir through the bridge
    extension: Pi owns only the conversation, the Python plugin owns the
    tools, the evidence and the receipt. Every run is a brand-new session --
    a reviewer that remembered an earlier repository would be judging two
    things at once. Returns (usage, duration_ms) or raises when the run did
    not settle into a report; no wall-clock kill, no second reviewer."""
    run_dir = Path(run_dir)
    review = Review(run_dir)
    manifest = [{"name": name, "description": description,
                 "parameters": {"type": "object", "properties": properties, "required": required}}
                for name, description, properties, required, _ in tool_plan(review)]
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LANG", "TMPDIR") if k in os.environ}
    credential_name = f"{runtime['provider'].upper().replace('-', '_')}_API_KEY"
    env.update({"GITVAULT_CHECKER_DIR": str(ROOT), "GITVAULT_RUN_DIR": str(run_dir),
                "GITVAULT_PYTHON": sys.executable, "GITVAULT_TOOLS": json.dumps(manifest),
                credential_name: credential(settings["credential_file"], credential_name)})
    prompt = (ROOT / "policy.md").read_text() + "\nReview date (UTC): " + dt.datetime.now(dt.timezone.utc).date().isoformat()
    command = [settings.get("pi") or shutil.which("pi") or "pi",
               "--mode", "json", "--print", "--no-mcp", "--no-skills",
               "--no-context-files", "--no-prompt-templates", "--no-extensions", "--no-session",
               "--provider", runtime["provider"], "--model", runtime["model"],
               "--thinking", runtime["effort"],
               "--extension", str(ROOT / "pi-bridge.ts"),
               "--tools", ",".join(spec["name"] for spec in manifest),
               "--system-prompt", prompt,
               "Review the outgoing changes with the Security Enhancer tools and submit one final "
               "verdict: start with inventory, read every changed diff to its end, judge all seven "
               "domains, and account for every surface the static stage reported. No arbitrary turn "
               "or time limit applies."]
    started = time.monotonic()
    result = spawn(command, env=env, cwd=run_dir, capture_output=True, text=True)
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


def review_range(repo, settings, target, summary, stage_summaries, runtime, spawn=subprocess.run):
    head, base = target["head"], target["base"]
    tree = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{head}^{{tree}}"],
                          capture_output=True, check=True).stdout.decode().strip()
    if target["scope"] == "range":
        changed = git(repo, "diff", "--name-only", "--no-renames", "-z", base, tree).stdout.decode().rstrip("\0").split("\0")
    else:
        listing = git(repo, "ls-tree", "-r", "--name-only", "-z", tree).stdout.split(b"\0")
        changed = [p.decode() for p in listing if p]
    changed = [p for p in changed if p]
    profile = Path(settings["profile"])
    runs = profile / "security-enhancer-runs"
    runs.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_dir = Path(tempfile.mkdtemp(prefix="review-", dir=runs))
    # The receipt reads its provider/model/effort labels from this scope.
    write_json(run_dir / "scope.json", {"repo": str(repo), "tree": tree, "base": base,
                                        "changed": changed, "kind": target["kind"],
                                        "surfaces": summary.get("surfaces", []),
                                        "runtime": runtime})
    try:
        print(f"Security Enhancer: reviewing {target['label']} with "
              f"{runtime['provider']}/{runtime['model']} ({runtime['effort']})…", flush=True)
        usage, duration_ms = pi_review(run_dir, settings, runtime, spawn)
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
        report["stage1"] = {"ranges": stage_summaries}
        if target["fallback"]:
            report["fallback"] = target["fallback"]
        write_json(report_path, report)
        print(f"Security Enhancer: {report['verdict']} — {sanitize(report['summary'])}")
        for finding in report["findings"]:
            print(sanitize(f"  {finding['file']}:{finding['line']} [{finding['severity']}] {finding['impact']} → {finding['remedy']}"))
        print(f"Security Enhancer report: {report_path}")
        return 0 if report["verdict"] == "pass" else 1
    finally:
        (run_dir / "scope.json").unlink(missing_ok=True)
        report_path = run_dir / "report.json"
        if report_path.exists():
            receipt = json.loads(report_path.read_text())
            if receipt.get("gate_status") == "pending":
                receipt["gate_status"] = "refused"
                write_json(report_path, receipt)
        else:
            shutil.rmtree(run_dir, ignore_errors=True)


def run(repo, settings, spawn=subprocess.run):
    """The checker entry point. Refuses on the first stage that finds a problem;
    a refused audit never touches the working tree."""
    repo = Path(repo).resolve()
    runtime = declared_runtime(settings)
    targets = review_ranges(repo)
    if not targets:
        print("Security Enhancer: nothing unpublished in this operation; no review needed")
        return 0
    ok, summaries = stage1.audit_all(repo, targets)
    for summary in summaries:
        state = "refused" if summary["refused"] else summary["status"]
        print(f"Security Enhancer: static {state} — {summary['label']} "
              f"({summary['scope']}, findings={summary['findings']}, surfaces={len(summary['surfaces'])})")
        for hit in summary["hits"]:
            print(f"  {hit['path']}:{hit['line']} {hit['rule']} → {hit['remedy']}")
        for surface in summary["surfaces"]:
            print(f"  notice {surface['path']}:{surface['line']} {surface['rule']}")
    if not ok:
        raise ValueError("The static security checklist refused this operation; nothing was published")
    for target, summary in zip(targets, summaries):
        if audited(settings, target["base"], target["head"], runtime):
            print(f"Security Enhancer: {target['label']} already passed its semantic review "
                  f"({target['head'][:12]}); reusing that verdict")
            continue
        if review_range(repo, settings, target, summary, summaries, runtime, spawn):
            return 1
    return 0


def tool_plan(review):
    """The checker's tool surface as data: the same list feeds the Pi
    extension manifest and the `--serve-tools` dispatch table."""
    coverage_schema = {"type": "object", "properties": {
        "status": {"type": "string", "enum": ["reviewed", "not-applicable", "unknown"]},
        "reason": {"type": "string"}}, "required": ["status", "reason"], "additionalProperties": False}
    finding_keys = ["file", "line", "severity", "evidence", "impact", "remedy", "validation"]
    finding_schema = {"type": "object", "properties": {
        **{key: ({"type": "integer", "minimum": 1} if key == "line" else {"type": "string"}) for key in finding_keys},
        "severity": {"type": "string", "enum": ["blocking", "advisory"]}},
        "required": finding_keys, "additionalProperties": False}
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
          "coverage": {"type": "object", "properties": {name: coverage_schema for name in DOMAINS},
                       "required": list(DOMAINS), "additionalProperties": False},
          "findings": {"type": "array", "items": finding_schema},
          "unknowns": {"type": "array", "items": {"type": "string"}}},
         ["verdict", "summary", "coverage", "findings", "unknowns"], review.submit),
    ]


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


def serve_tools(run_dir):
    """Host this run's tools over JSONL stdio for the Pi bridge extension. One
    long-lived process keeps the review's in-memory state - pages read and
    diff progress - coherent for the whole verdict."""
    review = Review(run_dir)
    methods = {name: _call(review, method) for name, _, _, _, method in tool_plan(review)}
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


def main():
    parser = argparse.ArgumentParser(description="Security Enhancer GitVault checker")
    parser.add_argument("--repo")
    parser.add_argument("--serve-tools", action="store_true")
    parser.add_argument("--run")
    args = parser.parse_args()
    if args.serve_tools:
        # Bridge-facing mode: no sync assertion, no gate output - tool replies
        # only, one JSON object per stdout line.
        serve_tools(args.run)
        return 0
    if not args.repo:
        parser.error("--repo is required")
    try:
        settings = json.loads((ROOT / "installation.json").read_text())
        # A prompt copy edited on this machine is not the reviewed prompt.
        import profile_sync
        profile_sync.assert_synced(settings)
        return run(args.repo, settings)
    except (Exception, KeyboardInterrupt) as exc:
        message = sanitize(str(exc)) if isinstance(exc, ValueError) else "Audit unavailable or interrupted; publication refused"
        print(f"Security Enhancer: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
