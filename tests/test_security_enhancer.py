import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# The payload ships `profile_sync`; in the repository it lives once, in
# tools/agent-profiles, exactly as the installer copies it in.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "agent-profiles"))
SOURCE = Path(__file__).resolve().parents[1] / "tools/security-enhancer"
spec = importlib.util.spec_from_file_location("security_enhancer", SOURCE / "__init__.py")
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)


def completed(command, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, code, stdout, stderr)


class SecurityEnhancerTests(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "core.hooksPath", str(self.root / "no-hooks"))
        self.git("config", "user.name", "Synthetic Enhancer")
        self.git("config", "user.email", "enhancer@example.invalid")
        (self.repo / "app.js").write_text("export const value = 1\n")
        self.git("add", "app.js")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        (self.repo / "handler.js").write_text("export const handler = () => 2\n")
        self.git("add", "handler.js")
        self.git("commit", "-qm", "outgoing")
        self.git("branch", "-m", "work")  # the ref the fabricated push line names
        self.head = self.git("rev-parse", "HEAD")
        self.push_env = self.push_env_for(self.head)
        self.profile = self.root / "profile"
        credential_file = self.root / "credentials.env"
        credential_file.write_text("EXAMPLE_API_KEY=synthetic-fixture-only\nOTHER_SECRET=never-forward\n")
        self.settings = {"profile": str(self.profile), "pi": str(self.root / "pi"),
                         "credential_file": str(credential_file)}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       stderr=subprocess.DEVNULL).decode().strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message, "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def push_env_for(self, head, base=None):
        """The push line names the ref, its tip, and the published tip."""
        return {"GITVAULT_EVENT": "pre-push",
                "GITVAULT_PUSH_REFS": f"refs/heads/work {head} refs/heads/work {base or self.base}"}

    def report(self, verdict="pass", overrides=None):
        report = {"verdict": verdict, "summary": "Synthetic range reviewed", "findings": [], "unknowns": [],
                  "coverage": {k: {"status": "not-applicable", "reason": "Synthetic fixture"} for k in se.DOMAINS}}
        report.update(overrides or {})
        return report

    # -- range resolution ---------------------------------------------------

    def test_release_range_is_the_previous_release_to_this_one(self):
        # A release commit is normally already on the default branch, so a
        # merge-base against it would describe an empty range. The content a
        # release publishes is everything since the previous release.
        self.git("tag", "v1.0.0", self.base)
        head = self.commit("release two")
        self.git("tag", "v2.0.0", head)
        with patch.dict(os.environ, {"GITVAULT_EVENT": "release", "GITVAULT_RELEASE_TAG": "v2.0.0",
                                     "GITVAULT_RELEASE_COMMIT": head}):
            targets = se.review_ranges(self.repo)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["kind"], "release")
        self.assertEqual(targets[0]["scope"], "range")
        self.assertEqual(targets[0]["base"], self.base)
        self.assertEqual(targets[0]["head"], head)
        self.assertEqual(targets[0]["fallback"], "")

    def test_a_first_release_scans_the_whole_tree(self):
        head = self.commit("first release")
        self.git("tag", "v1.0.0", head)
        with patch.dict(os.environ, {"GITVAULT_EVENT": "release", "GITVAULT_RELEASE_TAG": "v1.0.0",
                                     "GITVAULT_RELEASE_COMMIT": head}):
            targets = se.review_ranges(self.repo)
        self.assertEqual(targets[0]["scope"], "snapshot")
        self.assertEqual(targets[0]["base"], "")
        self.assertEqual(targets[0]["fallback"], "snapshot-no-previous-release")

    def test_a_release_whose_commit_is_absent_is_refused(self):
        with patch.dict(os.environ, {"GITVAULT_EVENT": "release", "GITVAULT_RELEASE_TAG": "v9.9.9",
                                     "GITVAULT_RELEASE_COMMIT": ""}):
            with self.assertRaises(ValueError):
                se.review_ranges(self.repo)

    def test_range_resolution_never_uses_empty_tree(self):
        brand_new = {"GITVAULT_EVENT": "pre-push",
                     "GITVAULT_PUSH_REFS": f"refs/heads/work {self.head} refs/heads/work {'0' * 40}"}
        with patch.dict(os.environ, brand_new):
            targets = se.review_ranges(self.repo)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["scope"], "snapshot")
        self.assertEqual(targets[0]["base"], "")
        self.assertNotIn("4b825dc642cb6eb9a060e54bf8d69288fbee4904", json.dumps(targets))

    def test_published_tips_are_skipped(self):
        self.git("update-ref", "refs/remotes/origin/work", self.head)
        with patch.dict(os.environ, self.push_env):
            self.assertEqual(se.review_ranges(self.repo), [])

    # -- the static checklist decides before any cloud call -----------------

    def static_run(self, pi_calls, head=None):
        """Run the checker over the outgoing range that ends at `head`."""
        with patch.dict(os.environ, self.push_env_for(head or self.git("rev-parse", "HEAD"))):
            with self.assertRaises(ValueError):
                se.run(self.repo, self.settings, spawn=lambda *a, **kw: pi_calls.append(a))

    def test_tls_verification_disabled_in_ci_refuses_without_the_model(self):
        self.write(".github/workflows/deploy.yml",
                   "name: deploy\non: push\njobs:\n  x:\n    steps:\n"
                   "      - run: make\n        env:\n          NODE_TLS_REJECT_UNAUTHORIZED: 0\n")
        head = self.commit("ci")
        calls = []
        self.static_run(calls, head)
        self.assertEqual(calls, [])
        hits = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": self.base,
                                           "head": head, "fallback": ""})
        self.assertIn("ci/tls-verification-disabled",
                      {hit["rule"] for hit in hits["hits"]})
        self.assertEqual({hit["path"] for hit in hits["hits"]}, {".github/workflows/deploy.yml"})

    def test_a_manifest_moving_without_its_lockfile_refuses(self):
        # The lockfile must be in the tree (a repository that keeps locks) and
        # absent from the change (so the manifest moved alone).
        self.write("Cargo.toml", "[package]\nname = \"x\"\nversion = \"0.1.0\"\n")
        self.write("Cargo.lock", "# synthetic lock\n")
        crate = self.commit("crate")
        self.write("Cargo.toml", "[package]\nname = \"x\"\nversion = \"0.2.0\"\n")
        head = self.commit("bump without lockfile")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": crate,
                                              "head": head, "fallback": ""})
        self.assertEqual(summary["refused"], "static-security-regression")
        self.assertEqual([(h["rule"], h["path"]) for h in summary["hits"]],
                         [("dependency/lockfile-not-updated", "Cargo.toml")])

    def test_weakening_rules_read_removals_not_the_whole_file(self):
        # A .gitignore that keeps protecting secrets is fine; the refusal is the
        # removed rule, and only when it was protecting something key-shaped.
        self.write(".gitignore", "*.log\n.env\n")
        self.commit("ignore")
        self.write(".gitignore", ".env\n")
        head = self.commit("drop a log rule")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": self.base,
                                              "head": head, "fallback": ""})
        self.assertEqual(summary["status"], "clean")
        self.write(".gitignore", "*.log\n")
        head = self.commit("drop the secrets rule")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range",
                                              "base": self.git("rev-parse", "HEAD^"),
                                              "head": head, "fallback": ""})
        self.assertIn("hardening/ignore-rule-removed", {hit["rule"] for hit in summary["hits"]})

    def test_a_snapshot_scan_judges_the_whole_tree(self):
        # The first release has no previous release to diff against; a switch
        # that shipped long before the release commit is still judged.
        self.write("client.js", "const agent = new Agent({ rejectUnauthorized: " + "false })\n")
        head = self.commit("client")
        self.git("tag", "v1.0.0", head)
        summary = se.stage1.audit(self.repo, {"label": "release v1.0.0", "scope": "snapshot",
                                              "base": "", "head": head, "fallback": "snapshot-no-previous-release"})
        self.assertIn("runtime/tls-verification-disabled", {hit["rule"] for hit in summary["hits"]})

    def test_hits_never_carry_the_matched_text(self):
        self.write("deploy.sh", "curl --in" + "secure https://internal" + ".corp/api\n")
        self.write("net.js", "const host = '" + "10" + ".20.30.40" + "'\n")
        head = self.commit("planted")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": self.base,
                                              "head": head, "fallback": ""})
        printed = json.dumps(summary)
        self.assertIn("runtime/tls-verification-disabled", printed)
        self.assertIn("surface/private-address", printed)
        self.assertNotIn("10" + ".20.30.40", printed)
        self.assertNotIn("internal" + ".corp", printed)
        for hit in [*summary["hits"], *summary["surfaces"]]:
            self.assertEqual(set(hit), {"path", "line", "rule", "remedy"})

    def test_prose_is_not_judged_as_code(self):
        self.write("docs/hardening.md",
                   "Do not use --in" + "secure, never set DEBUG " + "= True, see http://internal" + ".corp/x\n")
        head = self.commit("docs")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": self.base,
                                              "head": head, "fallback": ""})
        self.assertEqual(summary["hits"], [])
        self.assertEqual(summary["surfaces"], [])

    # -- surfaces are recorded, not refused ---------------------------------

    def test_surfaces_are_recorded_and_reach_the_semantic_stage(self):
        self.write("package.json", json.dumps({
            "name": "app", "version": "1.0.0",
            "scripts": {"postinstall": "node ./scripts/setup.js"},
            "dependencies": {"lib": "git+https://github.com/example/lib.git"}}, indent=2) + "\n")
        head = self.commit("dependencies")
        summary = se.stage1.audit(self.repo, {"label": "push", "scope": "range", "base": self.base,
                                              "head": head, "fallback": ""})
        self.assertEqual(summary["refused"], "")
        self.assertEqual(summary["status"], "clean")
        self.assertEqual({surface["rule"] for surface in summary["surfaces"]},
                         {"surface/install-hook-added", "surface/dependency-url-source"})
        self.assertTrue(all(surface["remedy"].startswith("confirm")
                            for surface in summary["surfaces"]))

        # The surface list travels to the reviewer with the range it belongs to.
        run_dir = self.root / "run"
        run_dir.mkdir()
        se.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["package.json"],
                                               "kind": "push", "surfaces": summary["surfaces"]})
        review = se.Review(run_dir)
        self.assertEqual(len(review.context({"operation": "inventory"})["surfaces"]), 2)

    # -- the cloud stage ----------------------------------------------------

    def stub_pi(self, calls):
        def stub(command, **kwargs):
            # Every run is a fresh, unsaved session: nothing from an earlier
            # repository can leak into the judgement.
            self.assertIn("--no-session", command)
            self.assertNotIn("--continue", command)
            self.assertEqual(command[0], self.settings["pi"])
            self.assertEqual(command[command.index("--provider") + 1], "example")
            self.assertIn(str(SOURCE / "pi-bridge.ts"), command)
            self.assertNotIn("OTHER_SECRET", kwargs["env"])
            self.assertEqual(kwargs["env"]["EXAMPLE_API_KEY"], "synthetic-fixture-only")
            run_dir = Path(kwargs["env"]["GITVAULT_RUN_DIR"])
            calls.append(run_dir)
            review = se.Review(run_dir)
            review.context({"operation": "diff", "path": "handler.js"})
            review.submit(self.report())
            return completed(command, 0, json.dumps({"type": "agent_settled", "aborted": False}) + "\n")
        return stub

    def test_each_run_is_a_fresh_conversation_and_a_fresh_directory(self):
        calls = []
        with patch.dict(os.environ, self.push_env):
            self.assertEqual(se.run(self.repo, self.settings, spawn=self.stub_pi(calls)), 0)
            # A second operation over the same range reuses the verdict instead
            # of paying for the model twice.
            self.assertEqual(se.run(self.repo, self.settings, spawn=self.stub_pi(calls)), 0)
        self.assertEqual(len(calls), 1)

    def test_audit_never_modifies_the_repository(self):
        before = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                  self.git("rev-parse", "HEAD^{tree}"))
        with patch.dict(os.environ, self.push_env):
            self.assertEqual(se.run(self.repo, self.settings, spawn=self.stub_pi([])), 0)
        after = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                 self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(before, after)

    # -- tool surface and path policy --------------------------------------

    def test_plugin_exposes_only_two_readonly_tools(self):
        run_dir = self.root / "tools"
        run_dir.mkdir()
        se.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["handler.js"],
                                               "kind": "push", "surfaces": []})
        specs = se.tool_plan(se.Review(run_dir))
        self.assertEqual({spec[0] for spec in specs}, {"security_context", "security_submit_review"})

    def test_serve_tools_speaks_the_bridge_jsonl_contract(self):
        run_dir = self.root / "served"
        run_dir.mkdir()
        se.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["handler.js"],
                                               "kind": "push", "surfaces": []})
        env = dict(os.environ, PYTHONPATH=str(SOURCE.parent / "agent-profiles"))
        proc = subprocess.Popen([sys.executable, str(SOURCE / "__init__.py"),
                                 "--serve-tools", "--run", str(run_dir)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, env=env)
        try:
            proc.stdin.write(json.dumps({"id": 4, "tool": "security_context",
                                         "args": {"operation": "inventory"}}) + "\n")
            proc.stdin.flush()
            reply = json.loads(proc.stdout.readline())
            self.assertEqual(reply["id"], 4)
            self.assertIn("handler.js", json.loads(reply["result"])["changed"])
        finally:
            proc.stdin.close()
            proc.stdout.close()
            proc.wait(15)

    def test_credential_containers_are_unreadable(self):
        for path in (".env", ".env.example", ".dev.vars", "secrets/x.json", "credentials.json",
                     "id_rsa.pem", "store.db", "notes.sqlite", ".ssh/config", ".npmrc",
                     "../outside", "/etc/passwd"):
            with self.assertRaises(ValueError):
                se.safe_path(path)
        self.assertEqual(se.safe_path(".github/workflows/deploy.yml"), ".github/workflows/deploy.yml")

    def test_submit_requires_seven_domain_coverage(self):
        run_dir = self.root / "submit"
        run_dir.mkdir()
        se.write_json(run_dir / "scope.json", {"repo": str(self.repo), "tree": self.git("rev-parse", "HEAD^{tree}"),
                                               "base": self.base, "changed": ["handler.js"],
                                               "kind": "push", "surfaces": []})
        review = se.Review(run_dir)
        partial = self.report()
        del partial["coverage"]["release_artifacts"]
        with self.assertRaises(ValueError):
            review.submit(partial)
        review.context({"operation": "diff", "path": "handler.js"})
        unknown = self.report()
        unknown["coverage"]["transport_security"] = {"status": "unknown", "reason": "unread"}
        with self.assertRaises(ValueError):
            review.submit(unknown)
        blocked = self.report("block", {"findings": [{"file": "handler.js", "line": 1, "severity": "advisory",
                                                      "evidence": "e", "impact": "i", "remedy": "r",
                                                      "validation": "v"}]})
        with self.assertRaises(ValueError):
            review.submit(blocked)
        review.submit(self.report())

    def test_a_review_that_cannot_run_leaves_no_passing_receipt(self):
        with patch.dict(os.environ, self.push_env):
            with self.assertRaises(ValueError):
                se.run(self.repo, self.settings, spawn=lambda *a, **kw: completed(a, 1, "", "boom"))
        receipts = list((self.profile / "security-enhancer-runs").glob("*/report.json"))
        self.assertEqual(receipts, [], "a failed review leaves no passing receipt behind")


if __name__ == "__main__":
    unittest.main()
