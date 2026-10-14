"""Read-only full-service audit of an operator-selected, sanitized source snapshot."""
import datetime as dt
import fnmatch
import json
from pathlib import Path
import re


def make_review(base_class, run_dir):
    class FullReview(base_class):
        def __init__(self, directory):
            super().__init__(directory)
            self.snapshot = json.loads((self.run_dir / "snapshot.json").read_text())
            self.files = self.snapshot["files"]
            self.aliases = self.snapshot.get("aliases", {})
            self.projects = self.snapshot["projects"]
            self.reads = set()
            self.original_read = False
            self.changed = []
            progress = self.run_dir / "progress.jsonl"
            if progress.exists():
                for line in progress.read_text().splitlines():
                    evidence = json.loads(line)
                    if evidence["operation"] == "read" and (evidence.get("path") in self.files or evidence.get("path") in self.aliases):
                        self.reads.add(evidence["path"])
                    if evidence["operation"] == "original_request":
                        self.original_read = True
            for path in (self.run_dir / "official-documents").glob("*.json"):
                if path.stem in self.catalog:
                    self.docs[path.stem] = json.loads(path.read_text())

        def event(self, operation, path=None):
            item = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "operation": operation}
            if path:
                item["path"] = path
            with (self.run_dir / "progress.jsonl").open("a") as stream:
                stream.write(json.dumps(item, ensure_ascii=False) + "\n")

        def context(self, args):
            operation = args["operation"]
            if operation != "read":
                self.event(operation, args.get("path"))
            if operation == "inventory":
                return {"mode": "full-service", "projects": self.projects,
                        "documents": self.catalog, "cost_domains": ["sql", "storage", "network", "compute", "cloudflare", "vps"],
                        "instructions": "Read original_request, then inspect every project. list/find accept glob pattern and offset; read returns numbered source. Submit project coverage including exact inspected entry points, data paths, clients and cancellation/retry paths. No source execution or production access."}
            if operation == "original_request":
                self.original_read = True
                return json.loads((self.run_dir / "request.json").read_text())
            if operation == "list":
                paths = [p for p in [*self.files, *self.aliases] if fnmatch.fnmatchcase(p, args.get("pattern", "*"))]
                offset = max(0, int(args.get("offset", 0)))
                return {"paths": paths[offset:offset+200], "total": len(paths),
                        "next_offset": offset+200 if offset+200 < len(paths) else None}
            if operation == "read":
                path = args["path"]
                actual = self.aliases.get(path, path)
                if actual not in self.files:
                    raise ValueError("Path is outside the selected source snapshot")
                lines = self.files[actual].splitlines()
                start = max(1, int(args.get("start", 1)))
                end = min(len(lines), start+399)
                self.reads.add(path)
                self.event("read", path)
                return {"source_reused_from":actual if actual != path else None, "total_lines":len(lines), "content":"\n".join(f"{i+1}: {lines[i]}" for i in range(start-1, end)),
                        "next_line": end+1 if end < len(lines) else None}
            if operation == "find":
                text = args.get("text", "")
                if not text:
                    raise ValueError("Search text is required")
                pattern = args.get("pattern") or args.get("path", "*")
                if "pattern" not in args and "path" in args and pattern not in self.files and pattern not in self.aliases:
                    pattern = pattern.rstrip("/") + "/*"
                matches = []
                # Literal alternatives provide a cheap batched search without regex hazards.
                needles = text.split("|")
                selected = {p: content for p, content in self.files.items() if fnmatch.fnmatchcase(p, pattern)}
                for alias, origin in self.aliases.items():
                    if fnmatch.fnmatchcase(alias, pattern) and origin not in selected:
                        selected[alias] = self.files[origin]
                for path, content in selected.items():
                    if not fnmatch.fnmatchcase(path, pattern):
                        continue
                    for i, line in enumerate(content.splitlines(), 1):
                        if any(n.lower() in line.lower() for n in needles):
                            matches.append(f"{path}:{i}: {line}")
                offset = max(0, int(args.get("offset", 0)))
                return {"matches":matches[offset:offset+100], "total":len(matches),
                        "next_offset":offset+100 if offset+100 < len(matches) else None}
            raise ValueError("Full audits use inventory/original_request/list/read/find")

        def document(self, args):
            name = args["name"]
            if name not in self.catalog:
                name = next((key for key, url in self.catalog.items() if url == name), None)
            if name is None:
                return super().document(args)
            args = {**args, "name":name}
            self.event("official_doc", name)
            known = name in self.docs
            result = super().document(args)
            if not known:
                directory = self.run_dir / "official-documents"
                directory.mkdir(exist_ok=True, mode=0o700)
                path = directory / (name + ".json")
                path.write_text(json.dumps(self.docs[name], ensure_ascii=False))
                path.chmod(0o600)
            return result

        def submit(self, report):
            # Preserve the paid review before validation so corrections can resume
            # from the draft instead of recreating the findings after a failure.
            with (self.run_dir / "draft.json").open("w") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
            (self.run_dir / "draft.json").chmod(0o600)
            self.event("submit_attempt")
            if not self.original_read:
                raise ValueError("Read original_request before deciding")
            coverage = report.get("projects", {})
            if set(coverage) != set(self.projects):
                raise ValueError("projects must contain these exact keys: " + ", ".join(self.projects))
            for name, item in coverage.items():
                if not isinstance(item, dict) or item.get("status") not in {"reviewed", "not-applicable", "unknown"} or not item.get("reason"):
                    raise ValueError(f"projects.{name} must be {{status: reviewed|not-applicable|unknown, reason: nonempty string}}")
                if item["status"] == "reviewed" and not any(p.startswith(name+"/") for p in self.reads):
                    raise ValueError("Read the project's actual source before marking reviewed")
                if item["status"] == "unknown" and report.get("verdict") == "pass":
                    raise ValueError("Unknown project coverage cannot pass")
            for index, finding in enumerate(report.get("findings", [])):
                path, line = finding.get("file"), finding.get("line")
                actual = self.aliases.get(path, path)
                if actual not in self.files or not isinstance(line, int) or not 1 <= line <= len(self.files[actual].splitlines()):
                    raise ValueError(f"findings[{index}] must name one exact listed path and an existing positive integer line; use read to check its location")
                if path not in self.reads:
                    raise ValueError(f"findings[{index}] source context has not been read; read that exact file before submission")
            report["audit_mode"] = "full-service"
            report["original_request_read"] = True
            report["conversation_url"] = json.loads((self.run_dir / "request.json").read_text())["conversation_url"]
            report["read_files"] = sorted(self.reads)
            result = super().submit(report)
            self.event("submitted", report["verdict"])
            return result
    return FullReview(run_dir)
