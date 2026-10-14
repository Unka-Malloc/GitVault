"""Money Saver: isolated tools and the GitVault blocking checker.

The model can read Git objects, fetch catalogued public documentation and submit a
verdict. It cannot execute commands, read arbitrary disk files or edit the index.
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
from html.parser import HTMLParser
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))
# The push/PR/release range contract is shared by every checker: one module,
# copied into each payload by install.py.
from review_ranges import ranges as review_ranges  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
DOMAINS = ("sql", "storage", "network", "compute", "cloudflare", "vps")
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # a snapshot review diffs against it
SENSITIVE_PARTS = {".git", ".ssh", ".aws", ".env", "secrets", "credentials", "logs", "runtime-data", ".dev.vars", ".netrc", ".npmrc", "credentials.json", "secrets.json"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".log", ".jsonl", ".enc", ".tfstate"}
# Tracked dotenv templates are reviewable documentation, not credential
# containers; their contents still pass through sanitize_source.
TEMPLATE_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist", ".dev.vars.example"}


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
    # Endpoints/account identifiers are unnecessary for cost call-chain analysis.
    # Keep this separate from report sanitization so official citations survive.
    text = sanitize(raw)
    text = re.sub(r"(?i)(https?|wss?)://[^\s\"'<>`]+", r"\1://[ENDPOINT]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP_ADDRESS]", text)
    text = re.sub(r"(?i)((?:account_id|database_id|zone_id|tenant_id)[\"']?\s*[=:]\s*)[\"'][^\"'\n]+[\"']", r'\1"[IDENTIFIER]"', text)
    text = re.sub(r"(?im)^(\s*(?:[- ]*\s*)?(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z_]*)\s*[=:]\s*)([^\s#]+)", r"\1[REDACTED]", text)
    return text


def safe_path(path):
    p = PurePosixPath(path)
    if (not path or p.is_absolute() or ".." in p.parts or
        any(x.lower() in SENSITIVE_PARTS or (x.lower() not in TEMPLATE_NAMES and x.lower().startswith((".env.", ".dev.vars."))) for x in p.parts) or
        p.suffix.lower() in SENSITIVE_SUFFIXES):
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


class PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The catalog is operator-owned. Do not follow a documentation redirect
        # to a different authority or carry authentication/query data.
        target = urlsplit(newurl)
        if (target.scheme != "https" or target.netloc != urlsplit(req.full_url).netloc
                or target.username or target.query):
            raise ValueError("Official documentation redirected outside its authority")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Review:
    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.state = json.loads((self.run_dir / "scope.json").read_text())
        self.repo = self.state["repo"]
        self.tree = self.state["tree"]
        self.base = self.state["base"]
        self.changed = self.state["changed"]
        self.catalog = json.loads((ROOT / "documents.json").read_text())
        self.docs = {}
        self.reviewed = set()
        self.diffs = {}
        self.diff_progress = {}
        self.lock = threading.RLock()
        self.entries = {}
        for record in git(self.repo, "ls-tree", "-rz", self.tree).stdout.split(b"\0"):
            if record:
                metadata, path = record.split(b"\t", 1)
                mode, kind, oid = metadata.decode().split()
                self.entries[path.decode()] = (mode, kind, oid)

    def context(self, args):
        operation = args["operation"]
        if operation == "inventory":
            return {"changed": self.changed, "documents": self.catalog, "cost_domains": DOMAINS}
        if operation == "list":
            pattern = args.get("pattern", "*")
            return [p for p in self.entries if fnmatch.fnmatchcase(p, pattern)]
        if operation == "diff":
            path = args.get("path")
            if not path:
                raise ValueError('operation "diff" requires a "path" argument')
            path = safe_path(path)
            if path not in self.changed:
                raise ValueError("Path is not part of this commit")
            if path not in self.diffs:
                # A snapshot review has no base commit: every change is a new
                # file, which is what diffing the empty tree produces.
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
            revision = args.get("revision", "staged")
            if revision not in {"staged", "base"}:
                raise ValueError("revision must be staged or base")
            if revision == "staged":
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
            return {"total_lines": len(lines), "content": "\n".join(f"{i+1}: {lines[i]}" for i in range(start-1, end))}
        if operation == "find":
            needle = args.get("text", "")
            if not needle:
                raise ValueError("A literal search string is required")
            # Git grep searches the immutable tree, not worktree files, with no
            # repository-defined textconv or external process execution.
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

    def document(self, args):
        name = args.get("name")
        if not name:
            raise ValueError('operation "document" requires a "name" argument')
        if name not in self.catalog:
            name = next((key for key, url in self.catalog.items() if url == name), None)
        if name is None:
            raise ValueError("Choose an exact catalog key or listed URL. Keys: " + ", ".join(self.catalog))
        if name not in self.docs:
            url = self.catalog[name]
            req = Request(url, headers={"User-Agent": "Money-Saver/1.0", "Accept": "text/markdown,text/html,text/plain"})
            with build_opener(OfficialRedirects()).open(req) as response:
                raw = response.read().decode("utf-8", "replace")
                if "html" in response.headers.get("Content-Type", ""):
                    parser = PageText()
                    parser.feed(raw)
                    raw = "\n".join(parser.parts)
            self.docs[name] = {"url": url, "accessed": dt.date.today().isoformat(), "content": raw}
        doc = self.docs[name]
        start = max(0, int(args.get("offset", 0)))
        return {**doc, "content": doc["content"][start:start+24000], "total_characters": len(doc["content"]), "offset": start}

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
            raise ValueError("Account for every cost domain")
        if not isinstance(report.get("unknowns"), list):
            raise ValueError("Unknowns must be an explicit list")
        fetched = {d["url"] for d in self.docs.values()}
        for index, finding in enumerate(report["findings"]):
            for key in ("file", "line", "severity", "evidence", "impact", "before_after", "remedy", "validation", "sources"):
                if not finding.get(key):
                    raise ValueError(f"findings[{index}].{key} is required and must not be empty")
            safe_path(finding["file"])
            if finding["severity"] not in {"blocking", "advisory"}:
                raise ValueError("Invalid finding severity")
            if not isinstance(finding["line"], int) or finding["line"] < 1:
                raise ValueError("A positive code line is required")
            if not isinstance(finding["sources"], list) or not all(isinstance(s, str) and s in fetched for s in finding["sources"]):
                raise ValueError(f"findings[{index}].sources must be a list of fetched official URL strings; available: " + ", ".join(sorted(fetched)))
        blocking = any(f["severity"] == "blocking" for f in report["findings"])
        if verdict == "pass" and (blocking or set(self.changed) != self.reviewed):
            raise ValueError("Pass requires every changed diff reviewed and no blocking findings")
        if verdict == "block" and not blocking:
            raise ValueError("Block requires a concrete blocking finding; otherwise use incomplete")
        for domain, coverage in report["coverage"].items():
            if not isinstance(coverage, dict) or coverage.get("status") not in {"reviewed", "not-applicable", "unknown"} or not coverage.get("reason"):
                raise ValueError(f"coverage.{domain} must be {{status: reviewed|not-applicable|unknown, reason: nonempty string}}")
            if verdict == "pass" and coverage["status"] == "unknown":
                raise ValueError("Unknown applicable coverage cannot pass")
        if verdict == "pass" and any(c["status"] == "reviewed" for c in report["coverage"].values()) and not fetched:
            raise ValueError("Applicable cost review requires official documentation")
        runtime = self.state.get("runtime") or {}
        receipt = {**report, "provider": runtime.get("provider", ""), "model": runtime.get("model", ""),
                   "reasoning": runtime.get("effort", ""), "tree": self.tree,
                   "gate_status": "pending",
                   "official_sources": [{k:v for k,v in d.items() if k != "content"} for d in self.docs.values()]}
        write_json(self.run_dir / "report.json", json.loads(sanitize(json.dumps(receipt, ensure_ascii=False))))
        return {"accepted": True, "verdict": verdict}


def _review_for(run_dir):
    review = Review(run_dir)
    if review.state.get("mode") == "full-service":
        import importlib.util
        spec = importlib.util.spec_from_file_location("money_saver_full_audit", ROOT / "full_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        review = module.make_review(Review, run_dir, DOMAINS)
    return review


def tool_plan(review):
    """The checker's tool surface as data: the same list feeds the Pi
    extension manifest and the `--serve-tools` dispatch table."""
    coverage_schema = {"type":"object", "properties":{
        "status":{"type":"string", "enum":["reviewed","not-applicable","unknown"]},
        "reason":{"type":"string"}}, "required":["status","reason"], "additionalProperties":False}
    finding_keys = ["file","line","severity","evidence","impact","before_after","remedy","validation","sources"]
    finding_schema = {"type":"object", "properties":{
        **{key:{"type":"string"} for key in finding_keys if key not in {"line","severity","sources"}},
        "title":{"type":"string"}, "line":{"type":"integer", "minimum":1},
        "severity":{"type":"string", "enum":["blocking","advisory"]},
        "sources":{"type":"array", "items":{"type":"string", "enum":list(review.catalog.values())}}},
        "required":finding_keys, "additionalProperties":False}
    projects_schema = {"type":"object", "properties":{name:coverage_schema for name in getattr(review,"projects",{})},
                       "required":list(getattr(review,"projects",{})), "additionalProperties":False}
    return [
        ("money_context", "Inspect immutable source. Start with inventory for review mode and scope. Commit mode requires every changed diff; full mode requires original_request and per-project coverage. read is 400 lines with start; find/list use pattern glob and offset pagination. Full-mode find supports literal alternatives separated by |.",
         {"operation": {"type":"string", "enum":["inventory","original_request","list","diff","read","find"]},
          "path":{"type":"string"}, "pattern":{"type":"string"}, "text":{"type":"string"},
          "start":{"type":"integer"}, "offset":{"type":"integer"}, "revision":{"type":"string", "enum":["staged","base"]}}, ["operation"], review.context),
        ("money_official_doc", "Fetch an official reference by exact catalog key or listed URL. Cached once per review; offset pages through the same response.",
         {"name":{"type":"string", "enum":[*review.catalog, *review.catalog.values()]}, "offset":{"type":"integer"}}, ["name"], review.document),
        ("money_submit_review", "Submit the final cost decision once. Follow the Money Saver policy's evidence and coverage contract.",
         {"verdict":{"type":"string", "enum":["pass","block","incomplete"]}, "summary":{"type":"string"},
          "coverage":{"type":"object", "properties":{name:coverage_schema for name in DOMAINS}, "required":list(DOMAINS), "additionalProperties":False},
          "findings":{"type":"array", "items":finding_schema},
          "projects":projects_schema,
          "unknowns":{"type":"array", "items":{"type":"string"}}},
         ["verdict","summary","coverage","findings","unknowns"] + (["projects"] if hasattr(review,"projects") else []), review.submit),
    ]


def _call(review, method):
    def wrapped(args):
        try:
            with review.lock:
                return json.dumps(method(args), ensure_ascii=False)
        except Exception as exc:
            # Tool failures never echo HTTP bodies, absolute paths or secrets.
            reason = str(exc) if isinstance(exc, ValueError) else "Evidence unavailable; review cannot pass without it"
            return json.dumps({"error": sanitize(reason), "error_type": type(exc).__name__}, ensure_ascii=False)
    return wrapped


def serve_tools(run_dir):
    """Host this run's tools over JSONL stdio for the Pi bridge extension. One
    long-lived process keeps the review's in-memory state - pages read and
    sources fetched - coherent for the whole verdict."""
    review = _review_for(run_dir)
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


def _rev(repo, *args):
    out = git(repo, "rev-parse", *args, check=False)
    return out.stdout.decode().strip() if out.returncode == 0 else ""


def audited(settings, base, head, runtime):
    """A previous passing review of exactly this range satisfies the boundary:
    the same content cannot become public twice, and a range that already paid
    for the review is not paid for again. The verdict only carries when it
    came from the currently declared runtime.

    The judged items are part of the key. A receipt written under an earlier
    contract did not answer the questions this run asks, so reusing it would
    let a new coverage item go unanswered while the range reports as passed."""
    for report_path in sorted((Path(settings["profile"]) / "money-saver-runs").glob("*/report.json")):
        try:
            report = json.loads(report_path.read_text())
        except ValueError:
            continue
        if (report.get("review_base") == base and report.get("review_head") == head
                and report.get("review_items") == list(DOMAINS)
                and report.get("gate_status") == "passed"
                and report.get("provider") == runtime["provider"] and report.get("model") == runtime["model"]
                and report.get("reasoning") == runtime["effort"]):
            return True
    return False


def pi_review(run_dir, settings, runtime, spawn=subprocess.run):
    """Drive one Pi review of the scope in run_dir through the bridge
    extension: Pi owns only the conversation, the Python plugin owns the
    tools, the evidence and the receipt. Returns (usage, duration_ms) or
    raises when the run did not settle into a report. No wall-clock kill and
    no automatic second reviewer; a resumed run directory continues its
    session instead of replaying finished work."""
    run_dir = Path(run_dir)
    review = _review_for(run_dir)
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
               "--no-context-files", "--no-prompt-templates", "--no-extensions",
               "--provider", runtime["provider"], "--model", runtime["model"],
               "--thinking", runtime["effort"],
               "--extension", str(ROOT / "pi-bridge.ts"),
               "--tools", ",".join(spec["name"] for spec in manifest),
               "--system-prompt", prompt, "--session-dir", str(run_dir)]
    task = ("Perform the assigned full-service audit. Start with inventory and original_request, inspect every selected project including clients and all cancellation/retry paths, fetch applicable official documents and submit a complete report with per-project coverage. No arbitrary turn or time limit applies."
            if review.state.get("mode") == "full-service" else
            "Review the outgoing changes using the Money Saver tools, then submit one final verdict.")
    marker = run_dir / "session.used"
    recovery = run_dir / "recovery-prompt.txt"
    if marker.exists():
        command.append("--continue")
        task = "Continue this same review from its preserved conversation and draft. Correct the outstanding report fields; reuse evidence and do not restart the audit."
    elif recovery.exists():
        task = recovery.read_text()
    command.append(task)
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


def review_range(repo, settings, target, runtime, spawn=subprocess.run):
    """Run one Pi review of an unpublished range. Python owns the scope, the
    tools and the receipt; Pi is the model runtime driving them through the
    bridge extension. No wall-clock kill or automatic second reviewer."""
    head = target["head"]
    base = target["base"]
    tree = _rev(repo, f"{head}^{{tree}}")
    changed = git(repo, "diff", "--name-only", "--no-renames", "-z",
                  base or EMPTY_TREE, tree).stdout.decode().rstrip("\0").split("\0")
    changed = [p for p in changed if p]
    profile = Path(settings["profile"])
    runs = profile / "money-saver-runs"
    runs.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_dir = Path(tempfile.mkdtemp(prefix="review-", dir=runs))
    # The receipt reads its provider/model/effort labels from this scope.
    write_json(run_dir / "scope.json", {"repo": str(repo), "tree": tree, "base": base,
                                        "changed": changed, "runtime": runtime})
    try:
        print(f"Money Saver: reviewing {target['label']} cost with "
              f"{runtime['provider']}/{runtime['model']} ({runtime['effort']})…", flush=True)
        usage, duration_ms = pi_review(run_dir, settings, runtime, spawn)
        report_path = run_dir / "report.json"
        report = json.loads(report_path.read_text())
        if target["ref"] and _rev(repo, "--verify", target["ref"]) != head:
            raise ValueError("The pushed ref moved during review; publication refused")
        report["gate_status"] = "passed" if report["verdict"] == "pass" else "refused"
        report["review_usage"] = {"tokens": usage, "duration_ms": duration_ms}
        report["review_base"] = base
        report["review_head"] = head
        report["review_kind"] = target["kind"]
        report["review_items"] = list(DOMAINS)
        write_json(report_path, report)
        print(f"Money Saver: {report['verdict']} — {sanitize(report['summary'])}")
        for finding in report["findings"]:
            print(sanitize(f"  {finding['file']}:{finding['line']} [{finding['severity']}] {finding['impact']} → {finding['remedy']}"))
        print(f"Money Saver report: {report_path}")
        return 0 if report["verdict"] == "pass" else 1
    finally:
        # Reports are durable; the local scope is scratch data.
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
    """The GitVault checker entry point. The audit sits at the publication
    boundary — a push or a pull request — never on a local commit: only what
    is about to become public is reviewed, and a range a push already paid for
    is not paid for again at pull-request time."""
    repo = Path(repo).resolve()
    runtime = declared_runtime(settings)
    ranges = review_ranges(repo)
    if not ranges:
        print("Money Saver: nothing unpublished in this operation; no review needed")
        return 0
    for target in ranges:
        if audited(settings, target["base"], target["head"], runtime):
            print(f"Money Saver: {target['label']} already passed its semantic review "
                  f"({target['head'][:12]}); reusing that verdict")
            continue
        if review_range(repo, settings, target, runtime, spawn):
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description="Money Saver GitVault checker")
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
        message = sanitize(str(exc)) if isinstance(exc, ValueError) else "Review unavailable or interrupted; commit refused"
        print(f"Money Saver: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
