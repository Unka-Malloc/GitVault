"""Money Saver: isolated tools and the GitVault blocking checker.

The model can read Git objects, fetch catalogued public documentation and submit a
verdict. It cannot execute commands, read arbitrary disk files or edit the index.

The shared machinery -- sanitization, the review object, receipts, the Pi
review process and the range orchestration -- lives in audit_engine.py and is
identical for every checker. What remains here is Money Saver's own contract:
its cost domains, the official-documentation tool, the submission fields that
ground findings in cited sources, and the session continuity a cost review
needs to resume interrupted paid work rather than replay it.
"""
from __future__ import annotations

import datetime as dt
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-profiles"))

import audit_engine as engine  # noqa: E402
# profile_sync is imported lazily in main(): --serve-tools never touches it,
# so the bridge works even where the library is not beside the plugin.

ROOT = Path(__file__).resolve().parent
DOMAINS = ("sql", "storage", "network", "compute", "cloudflare", "vps")

# The engine's contract surface, re-exported for callers and tests that hold
# this module.
sanitize = engine.sanitize
sanitize_source = engine.sanitize_source
safe_path = engine.safe_path
git = engine.git
write_json = engine.write_json
credential = engine.credential
declared_runtime = engine.declared_runtime
review_ranges = engine.review_ranges
EMPTY_TREE = engine.EMPTY_TREE
SENSITIVE_PARTS = engine.SENSITIVE_PARTS
SENSITIVE_SUFFIXES = engine.SENSITIVE_SUFFIXES
SENSITIVE_PREFIXES = engine.SENSITIVE_PREFIXES
TEMPLATE_NAMES = engine.TEMPLATE_NAMES
RUNTIME_VALUE = engine.RUNTIME_VALUE
PI_THINKING = engine.PI_THINKING


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


#: Characters per `document` page — the same pagination contract as the
#: engine's tools, for a page source only this checker serves.
DOC_PAGE_CHARS = 24000


class Review(engine.Review):
    """Money Saver's review object: the engine's machinery plus the official
    documentation catalog, the `document` tool and the submission fields that
    bind every finding to a fetched source."""
    DOMAINS = DOMAINS
    ROOT = ROOT
    domain_key = "cost_domains"
    revision_label = "staged"
    finding_keys = ("file", "line", "severity", "evidence", "impact",
                    "before_after", "remedy", "validation", "sources")

    def __init__(self, run_dir):
        super().__init__(run_dir)
        self.catalog = json.loads((ROOT / "documents.json").read_text())
        self.docs = {}

    def inventory_extra(self):
        return {"documents": self.catalog}

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
        return {**doc, "content": doc["content"][start:start+DOC_PAGE_CHARS], "total_characters": len(doc["content"]), "offset": start}

    def submit_extra(self, report, verdict):
        fetched = {d["url"] for d in self.docs.values()}
        for index, finding in enumerate(report["findings"]):
            if not isinstance(finding["sources"], list) or not all(isinstance(s, str) and s in fetched for s in finding["sources"]):
                raise ValueError(f"findings[{index}].sources must be a list of fetched official URL strings; available: " + ", ".join(sorted(fetched)))
        if verdict == "pass" and any(c["status"] == "reviewed" for c in report["coverage"].values()) and not fetched:
            raise ValueError("Applicable cost review requires official documentation")

    def receipt_extra(self):
        return {"official_sources": [{k: v for k, v in d.items() if k != "content"} for d in self.docs.values()]}


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
    finding_schema = engine.finding_schema(Review.finding_keys, {
        "title": {"type": "string"},
        "sources": {"type": "array", "items": {"type": "string", "enum": list(review.catalog.values())}}})
    return [
        ("money_context", f"Inspect immutable source. Start with inventory for review mode and scope. Commit mode requires every changed diff; full mode requires original_request and per-project coverage. read is {engine.READ_PAGE_LINES} lines with start; find/list use pattern glob and offset pagination. Full-mode find supports literal alternatives separated by |.",
         {"operation": {"type":"string", "enum":["inventory","original_request","list","diff","read","find"]},
          "path":{"type":"string"}, "pattern":{"type":"string"}, "text":{"type":"string"},
          "start":{"type":"integer"}, "offset":{"type":"integer"}, "revision":{"type":"string", "enum":["staged","base"]}}, ["operation"], review.context),
        ("money_official_doc", "Fetch an official reference by exact catalog key or listed URL. Cached once per review; offset pages through the same response.",
         {"name":{"type":"string", "enum":[*review.catalog, *review.catalog.values()]}, "offset":{"type":"integer"}}, ["name"], review.document),
        ("money_submit_review", "Submit the final cost decision once. Follow the Money Saver policy's evidence and coverage contract.",
         {"verdict":{"type":"string", "enum":["pass","block","incomplete"]}, "summary":{"type":"string"},
          "coverage": engine.coverage_schema(DOMAINS),
          "findings":{"type":"array", "items":finding_schema},
          "projects":engine.coverage_schema(getattr(review, "projects", ())),
          "unknowns":{"type":"array", "items":{"type":"string"}}},
         ["verdict","summary","coverage","findings","unknowns"] + (["projects"] if hasattr(review,"projects") else []), review.submit),
    ]


SPEC = engine.CheckerSpec(
    name="money-saver",
    label="Money Saver",
    description="Money Saver GitVault checker",
    domains=DOMAINS,
    tool_plan=tool_plan,
    make_review=_review_for,
    task=lambda review: (
        "Perform the assigned full-service audit. Start with inventory and original_request, "
        "inspect every selected project including clients and all cancellation/retry paths, "
        "fetch applicable official documents and submit a complete report with per-project "
        "coverage. No arbitrary turn or time limit applies."
        if review.state.get("mode") == "full-service" else
        "Review the outgoing changes using the Money Saver tools, then submit one final verdict."),
    root=ROOT,
    session=True,
)


engine.bind(globals(), SPEC)


if __name__ == "__main__":
    sys.exit(main())
