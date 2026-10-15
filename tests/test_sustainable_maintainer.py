import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from checker_fixture import CheckerFixture, completed, load_checker

sm = load_checker("sustainable-maintainer")
SOURCE = Path(sm.__file__).parent


class SustainableMaintainerTests(CheckerFixture):
    module = sm

    def stage1(self, target):
        return sm.stage1.audit(self.repo, target)

    def target(self, head, base=None):
        return {"label": "push", "scope": "range",
                "base": base if base is not None else self.base,
                "head": head, "fallback": ""}

    def commit_file(self, name, content, message="change"):
        (self.repo / name).write_text(content)
        self.git("add", name)
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    # -- range resolution ---------------------------------------------------

    def test_range_resolution_never_uses_empty_tree(self):
        # A brand-new branch (remote sha all zeros) with no remote-tracking ref
        # to compare against: the range degrades to a whole-snapshot scan, and
        # the empty tree never becomes a `--base`.
        brand_new = {"GITVAULT_EVENT": "pre-push",
                     "GITVAULT_PUSH_REFS": f"refs/heads/work {self.head} refs/heads/work {'0' * 40}"}
        with patch.dict(os.environ, brand_new):
            targets = sm.review_ranges(self.repo)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["scope"], "snapshot")
        self.assertEqual(targets[0]["base"], "")
        self.assertEqual(targets[0]["fallback"], "snapshot-no-merge-base")
        self.assertNotIn("4b825dc642cb6eb9a060e54bf8d69288fbee4904", json.dumps(targets))

    def test_existing_remote_tip_becomes_the_range_base(self):
        with patch.dict(os.environ, self.push_env):
            targets = sm.review_ranges(self.repo)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["scope"], "range")
        self.assertEqual(targets[0]["base"], self.base)
        self.assertEqual(targets[0]["head"], self.head)

    def test_published_tips_are_skipped(self):
        self.git("update-ref", "refs/remotes/origin/work", self.head)
        with patch.dict(os.environ, self.push_env):
            self.assertEqual(sm.review_ranges(self.repo), [])

    # -- stage one decides before any cloud call ---------------------------

    def test_conflict_markers_refuse_locally_without_the_model(self):
        head = self.commit_file("broken.js",
                                "const a = 1\n<<<<<<< HEAD\nconst b = 2\n=======\nconst b = 3\n>>>>>>> other\n")
        calls = []
        with patch.dict(os.environ, self.push_env_for(head)):
            with self.assertRaises(ValueError):
                sm.run(self.repo, self.settings, spawn=lambda *a, **kw: calls.append(a))
        self.assertEqual(calls, [])

        summary = self.stage1(self.target(head))
        self.assertEqual(summary["refused"], "conflict-marker")
        self.assertEqual([(hit["path"], hit["rule"]) for hit in summary["hits"]],
                         [("broken.js", "conflict-marker")] * 3)

    def test_equals_alone_is_prose_not_a_marker(self):
        head = self.commit_file("NOTES.md", "A heading\n=======\nbody text\n")
        summary = self.stage1(self.target(head))
        self.assertEqual(summary["refused"], "")

    def test_merge_artifacts_and_os_junk_refuse_by_name(self):
        head = self.commit_file("notes.orig", "residue\n")
        summary = self.stage1(self.target(head))
        self.assertEqual(summary["refused"], "merge-artifact")

        head = self.commit_file(".DS_Store", "junk\n")
        summary = self.stage1(self.target(head))
        self.assertEqual(summary["refused"], "os-junk")
        self.assertEqual(summary["hits"][0]["path"], ".DS_Store")

    def test_a_deletion_is_never_a_finding(self):
        self.commit_file("stale.orig", "residue\n")
        self.git("rm", "-q", "stale.orig")
        self.git("commit", "-qm", "remove residue")
        head = self.git("rev-parse", "HEAD")
        base = self.git("rev-parse", "HEAD^")
        summary = self.stage1(self.target(head, base))
        self.assertEqual(summary["refused"], "")
        self.assertEqual(summary["hits"], [])

    def test_a_revision_the_scan_cannot_read_refuses_rather_than_passes(self):
        with self.assertRaises(ValueError):
            sm.stage1.audit(self.repo, {"label": "x", "scope": "range", "base": self.base,
                                        "head": "0" * 40, "fallback": ""})

    # -- the cloud stage ----------------------------------------------------

    def test_each_run_is_a_fresh_conversation_and_a_fresh_directory(self):
        calls = []
        with patch.dict(os.environ, self.push_env):
            self.assertEqual(sm.run(self.repo, self.settings, spawn=self.stub_pi(calls)), 0)
            # A second operation over the same range reuses the verdict instead
            # of paying for the model twice.
            self.assertEqual(sm.run(self.repo, self.settings, spawn=self.stub_pi(calls)), 0)
        self.assertEqual(len(calls), 1)

    def test_audit_never_modifies_the_repository(self):
        before = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                  self.git("rev-parse", "HEAD^{tree}"))
        calls = []
        with patch.dict(os.environ, self.push_env):
            sm.run(self.repo, self.settings, spawn=self.stub_pi(calls))
        after = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                 self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(before, after)

    # -- tool surface and path policy --------------------------------------

    def test_plugin_exposes_only_two_readonly_tools(self):
        run_dir = self.root / "run"
        run_dir.mkdir()
        sm.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["leak.txt"], "kind": "push"})
        specs = sm.tool_plan(sm.Review(run_dir))
        self.assertEqual({spec[0] for spec in specs}, {"maintainer_context", "maintainer_submit_review"})

    def test_serve_tools_speaks_the_bridge_jsonl_contract(self):
        run_dir = self.root / "served"
        run_dir.mkdir()
        sm.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["leak.txt"], "kind": "push"})
        env = dict(os.environ, PYTHONPATH=str(SOURCE.parent / "agent-profiles"))
        proc = subprocess.Popen([sys.executable, str(SOURCE / "__init__.py"),
                                 "--serve-tools", "--run", str(run_dir)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, env=env)
        try:
            proc.stdin.write(json.dumps({"id": 3, "tool": "maintainer_context",
                                         "args": {"operation": "inventory"}}) + "\n")
            proc.stdin.flush()
            reply = json.loads(proc.stdout.readline())
            self.assertEqual(reply["id"], 3)
            self.assertIn("leak.txt", json.loads(reply["result"])["changed"])
        finally:
            proc.stdin.close()
            proc.stdout.close()
            proc.wait(15)

    def test_credential_containers_are_unreadable(self):
        for path in (".env", ".env.local", ".env.production", ".dev.vars", ".dev.vars.production",
                     "secrets/x.json", "credentials.json", "id_rsa.pem", "store.db", "notes.sqlite",
                     ".ssh/config", "../outside", "/etc/passwd"):
            with self.assertRaises(ValueError):
                sm.safe_path(path)
        self.assertEqual(sm.safe_path("src/app.js"), "src/app.js")

    def test_env_templates_stay_reviewable(self):
        for path in (".env.example", ".env.sample", ".env.template", ".env.dist",
                     ".dev.vars.example", "config/.env.example"):
            self.assertEqual(sm.safe_path(path), path)

    def test_submit_requires_every_domain(self):
        run_dir = self.root / "run2"
        run_dir.mkdir()
        sm.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["leak.txt"], "kind": "push"})
        review = sm.Review(run_dir)
        for missing in ("structure", "tests", "evolution"):
            partial = self.report()
            del partial["coverage"][missing]
            with self.assertRaises(ValueError):
                review.submit(partial)
        review.context({"operation": "diff", "path": "leak.txt"})
        unknown = self.report()
        unknown["coverage"]["duplication"] = {"status": "unknown", "reason": "unread"}
        with self.assertRaises(ValueError):
            review.submit(unknown)
        review.submit(self.report())

    def test_a_receipt_from_an_earlier_contract_is_not_reused(self):
        # The judged items are part of the reuse key. A range that passed before
        # `evolution` existed was never asked the question, so reusing that
        # receipt would report a pass for a review that did not happen.
        runs = Path(self.profile) / "sustainable-maintainer-runs" / "old"
        runs.mkdir(parents=True)
        runtime = sm.declared_runtime(self.settings)
        receipt = self.report() | {"gate_status": "passed", "provider": runtime["provider"],
                                   "model": runtime["model"], "reasoning": runtime["effort"],
                                   "review_base": self.base, "review_head": self.head}
        sm.write_json(runs / "report.json", receipt)
        self.assertFalse(sm.audited(self.settings, self.base, self.head, runtime),
                         "a receipt with no recorded items predates the contract and cannot answer for it")
        sm.write_json(runs / "report.json", receipt | {"review_items": [d for d in sm.DOMAINS if d != "evolution"]})
        self.assertFalse(sm.audited(self.settings, self.base, self.head, runtime),
                         "a receipt that never judged the new item cannot stand in for a review of it")
        sm.write_json(runs / "report.json", receipt | {"review_items": list(sm.DOMAINS)})
        self.assertTrue(sm.audited(self.settings, self.base, self.head, runtime))
        other = {**runtime, "model": "another/model"}
        self.assertFalse(sm.audited(self.settings, self.base, self.head, other),
                         "a pass on a different declared runtime cannot stand in for this one")


if __name__ == "__main__":
    unittest.main()
