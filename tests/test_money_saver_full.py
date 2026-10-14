import importlib.util
import json
from pathlib import Path
import sys
import unittest

# The full-audit cases extend the money-saver suite by name. That resolves when
# this file is run as a script, and not under `python3 -m unittest tests.…`, which
# puts the repository root rather than this directory on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_money_saver as base_tests
ms, SOURCE = base_tests.ms, base_tests.SOURCE

spec = importlib.util.spec_from_file_location("full_audit", SOURCE / "full_audit.py")
full = importlib.util.module_from_spec(spec)
spec.loader.exec_module(full)
spec = importlib.util.spec_from_file_location("audit_runner", SOURCE / "audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class FullAuditTests(unittest.TestCase):
    setUp = base_tests.MoneySaverTests.setUp
    git = base_tests.MoneySaverTests.git
    report = base_tests.MoneySaverTests.report

    def test_full_scope_original_and_project_coverage(self):
        ms.write_json(self.scope / "snapshot.json", {"files":{"demo/server.py":"def fetch():\n    return 1\n"}, "projects":{"demo":{}}})
        ms.write_json(self.scope / "request.json", {"conversation_url":"https://example.invalid/chat", "messages":["Exact original request"]})
        review = full.make_review(ms.Review, self.scope)
        report = self.report()
        report["projects"] = {"demo":{"status":"reviewed", "reason":"Inspected synthetic service"}}
        with self.assertRaises(ValueError): review.submit(report)
        self.assertTrue((self.scope / "draft.json").exists())
        self.assertEqual(review.context({"operation":"original_request"})["messages"], ["Exact original request"])
        with self.assertRaises(ValueError): review.submit(report)
        self.assertIn("def fetch", review.context({"operation":"read", "path":"demo/server.py"})["content"])
        resumed = full.make_review(ms.Review, self.scope)
        self.assertTrue(resumed.original_read)
        self.assertIn("demo/server.py", resumed.reads)
        self.assertEqual(review.context({"operation":"find", "text":"missing|fetch"})["total"], 1)
        with self.assertRaises(ValueError): review.context({"operation":"read", "path":"../private"})
        review.submit(report)
        saved = json.loads((self.scope / "report.json").read_text())
        self.assertTrue(saved["original_request_read"])

    def test_snapshot_filters_private_data_and_preserves_current_code(self):
        (self.repo / "worker.js").write_text('fetch("https://private.example.invalid/api");\n')
        (self.repo / ".env").write_text("PRIVATE_TOKEN=fixture-only")
        (self.repo / "private.sqlite").write_bytes(b"fixture-only")
        (self.repo / "outside.py").symlink_to(self.root / "private")
        data = audit.snapshot({"demo":str(self.repo)})
        self.assertIn("demo/worker.js", data["files"])
        self.assertIn("[ENDPOINT]", data["files"]["demo/worker.js"])
        self.assertNotIn("private.example", json.dumps(data))
        for name in [".env", "private.sqlite", "outside.py"]:
            self.assertNotIn("demo/"+name, data["files"])

    def test_equal_sources_share_evidence_but_changes_remain(self):
        twin = self.root / "twin"
        twin.mkdir()
        for name in ["worker.js", "distinct.js"]:
            (self.repo / name).write_text("same source" if name == "worker.js" else "first source")
            (twin / name).write_text("same source" if name == "worker.js" else "second source")
        data = audit.snapshot({"first":str(self.repo), "second":str(twin)}, {"second":"first"})
        self.assertEqual(data["aliases"], {"second/worker.js":"first/worker.js"})
        self.assertEqual(data["files"]["second/distinct.js"], "second source")
        (self.repo / "endpoint.js").write_text('fetch("https://first.example.invalid")')
        (twin / "endpoint.js").write_text('fetch("https://second.example.invalid")')
        data = audit.snapshot({"first":str(self.repo), "second":str(twin)}, {"second":"first"})
        self.assertEqual(data["files"]["first/endpoint.js"], data["files"]["second/endpoint.js"])
        self.assertNotIn("second/endpoint.js", data["aliases"])


if __name__ == "__main__":
    __import__("unittest").main()
