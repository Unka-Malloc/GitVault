"""Snapshot explicitly selected projects and run a full Money Saver audit once.

Manifest: {"projects": {"relative-label": "/absolute/source"}}.
Original request file: {"conversation_url": "...", "messages": [...], ...}.
No repository, index or production service is changed. Reports remain private.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("money_saver", ROOT / "__init__.py")
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)

SOURCE_SUFFIXES = {".rs", ".go", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".dart",
                   ".py", ".php", ".sql", ".sh", ".swift", ".kt", ".c", ".h", ".cpp", ".vue", ".svelte", ".html", ".css", ".astro"}
MANIFESTS = {"package.json", "Cargo.toml", "go.mod", "pubspec.yaml", "pyproject.toml", "requirements.txt",
             "Dockerfile", "Caddyfile", "nginx.conf", "README.md", "PRODUCT.md", "CONTEXT.md"}
EXCLUDE = {".git", "node_modules", "target", "build", "dist", "vendor", ".dart_tool", ".venv", ".next",
           "__pycache__", "reports", "history-assets", "fixtures", "snapshots", "testdata", "tmp", "cache"}


def eligible(path):
    p = Path(path)
    if set(p.parts) & EXCLUDE or p.name.endswith((".min.js", ".generated.ts", ".g.dart", ".freezed.dart")):
        return False
    try:
        ms.safe_path(path)
    except ValueError:
        return False
    return p.suffix in SOURCE_SUFFIXES or p.name in MANIFESTS or bool(re.match(
        r"^(wrangler\..+|(?:docker-)?compose\..+|Dockerfile\..+)$", p.name))


def snapshot(projects, reuse=None):
    files, coverage = {}, {}
    compared_projects = set(reuse or {}) | set((reuse or {}).values())
    comparison_bytes = {}
    for name, location in projects.items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name):
            raise ValueError("Project label must be a relative identifier")
        root = Path(location).resolve()
        result = subprocess.run(["rg", "--files", "--hidden", "-g", "!.git", "-g", "!node_modules",
                                 "-g", "!target", "-g", "!build", "-g", "!dist", "-g", "!.venv"],
                                cwd=root, capture_output=True, check=False, text=True)
        if result.returncode not in {0, 1}:
            raise ValueError("Could not enumerate selected project")
        count = 0
        for path in sorted(result.stdout.splitlines()):
            if not eligible(path):
                continue
            file = root / path
            if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(root):
                continue
            raw = file.read_bytes()
            if b"\0" in raw:
                continue
            files[f"{name}/{path}"] = ms.sanitize_source(raw.decode("utf-8", "replace"))
            if name in compared_projects:
                comparison_bytes[f"{name}/{path}"] = raw
            count += 1
        coverage[name] = {"source_files":count, "scope":"Current first-party source, manifests and root product/readme documents; includes unstaged and untracked nonignored code. Excludes generated/build/vendor/runtime data, private containers, fixtures and reports."}
    aliases = {}
    for destination, origin in (reuse or {}).items():
        if destination not in coverage or origin not in coverage:
            raise ValueError("Reuse must refer to selected projects")
        shared = []
        for path in list(files):
            if path.startswith(destination+"/"):
                base_path = origin + path[len(destination):]
                if base_path in files and comparison_bytes[path] == comparison_bytes[base_path]:
                    aliases[path] = base_path
                    shared.append(path[len(destination)+1:])
                    del files[path]
        coverage[destination]["identical_source_reused_from"] = origin
        coverage[destination]["identical_files"] = len(shared)
        coverage[destination]["distinct_files"] = coverage[destination]["source_files"] - len(shared)
    return {"files":files, "projects":coverage, "aliases":aliases}


def run(manifest, request_file, output, settings):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    selected = json.loads(Path(manifest).read_text())
    data = snapshot(selected["projects"], selected.get("reuse"))
    ms.write_json(output / "snapshot.json", data)
    ms.write_json(output / "request.json", json.loads(Path(request_file).read_text()))
    repo = output / "objects.git"
    subprocess.run(["git", "init", "--bare", "-q", str(repo)], check=True)
    tree = subprocess.check_output(["git", "-C", str(repo), "hash-object", "-t", "tree", "--stdin", "-w"], input=b"").decode().strip()
    ms.write_json(output / "scope.json", {"mode":"full-service", "repo":str(repo), "tree":tree, "base":tree, "changed":[]})
    return review_existing(output, settings)


def review_existing(output, settings):
    output = Path(output).resolve()
    if (output / "report.json").exists():
        raise ValueError("An existing submitted report must not be re-audited")
    data = json.loads((output / "snapshot.json").read_text())
    status_path = output / "status.json"
    if status_path.exists():
        previous = json.loads(status_path.read_text())
        if previous.get("state") == "running":
            raise ValueError("Review is already marked running; inspect the owning process first")
        history_path = output / "attempts.json"
        attempts = json.loads(history_path.read_text()) if history_path.exists() else []
        attempts.append(previous)
        ms.write_json(history_path, attempts)
    runtime = ms.declared_runtime(settings)
    # Keep the declared runtime in the scope so the receipt labels the engine
    # that actually produced the verdict, even on a resumed directory.
    scope_path = output / "scope.json"
    scope = json.loads(scope_path.read_text())
    scope["runtime"] = runtime
    ms.write_json(scope_path, scope)
    ms.write_json(output / "status.json", {"state":"running", "projects":list(data["projects"]), "files":len(data["files"])})
    try:
        usage, duration_ms = ms.pi_review(output, settings, runtime)
    except ValueError:
        ms.write_json(output / "status.json", {"state":"failed", "report_exists":(output / "report.json").exists()})
        return 1
    report_file = output / "report.json"
    report = json.loads(report_file.read_text())
    report["gate_status"] = "full-audit-complete"
    report["review_usage"] = {"tokens": usage, "duration_ms": duration_ms}
    ms.write_json(report_file, report)
    ms.write_json(output / "status.json", {"state":"completed", "report_exists":True})
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest")
    parser.add_argument("--request")
    parser.add_argument("--output")
    parser.add_argument("--resume")
    args = parser.parse_args()
    try:
        settings = json.loads((ROOT / "installation.json").read_text())
        if args.resume and not any([args.manifest,args.request,args.output]):
            sys.exit(review_existing(args.resume, settings))
        if args.resume or not all([args.manifest,args.request,args.output]):
            parser.error("Use --resume alone, or provide --manifest, --request and --output")
        sys.exit(run(args.manifest, args.request, args.output, settings))
    except Exception as exc:
        print("Money Saver full audit could not complete: " + (ms.sanitize(str(exc)) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
