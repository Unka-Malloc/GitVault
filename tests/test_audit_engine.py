"""Contract tests for the shared audit engine.

The engine exists so the four checkers cannot drift on the security-critical
machinery: the sensitive-path contract, sanitization, receipts and the review
orchestration. These tests pin the drift itself — each checker must resolve
the same implementation — and the installer's promise that the engine reaches
an installed payload.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROFILES = REPO / "tools" / "agent-profiles"
sys.path.insert(0, str(PROFILES))

import audit_engine  # noqa: E402


def load(name):
    directory = REPO / "tools" / name
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), directory / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AuditEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checkers = {name: load(name) for name in
                        ("clean-auditor", "security-enhancer", "sustainable-maintainer", "money-saver")}

    def test_every_checker_runs_the_same_engine_implementation(self):
        for name, module in self.checkers.items():
            with self.subTest(checker=name):
                for symbol in ("sanitize", "sanitize_source", "safe_path", "credential",
                               "declared_runtime", "write_json"):
                    self.assertIs(getattr(module, symbol), getattr(audit_engine, symbol),
                                  f"{name}.{symbol} drifted from the shared engine")

    def test_sensitive_path_contract_is_identical_everywhere(self):
        # The drift this pins: a same-named dotenv family must be refused the
        # same way by every checker - ".envrc" included - while the named
        # templates stay reviewable.
        for name, module in self.checkers.items():
            with self.subTest(checker=name):
                self.assertIs(module.SENSITIVE_PARTS, audit_engine.SENSITIVE_PARTS)
                self.assertIs(module.SENSITIVE_SUFFIXES, audit_engine.SENSITIVE_SUFFIXES)
                self.assertIs(module.SENSITIVE_PREFIXES, audit_engine.SENSITIVE_PREFIXES)
                self.assertIs(module.TEMPLATE_NAMES, audit_engine.TEMPLATE_NAMES)
                for path in (".env", ".env.local", ".envrc", ".dev.vars", ".dev.vars.production"):
                    with self.assertRaises(ValueError, msg=f"{name} must refuse {path}"):
                        module.safe_path(path)
                for path in (".env.example", ".env.template", ".dev.vars.example"):
                    self.assertEqual(module.safe_path(path), path)

    def test_installer_ships_the_engine_in_every_payload(self):
        text = (PROFILES / "installer.py").read_text()
        self.assertIn('"audit_engine.py"', text,
                      "the shared library list must carry the engine to installed payloads")

    def test_plugin_manifest_lists_the_tools_the_plan_serves(self):
        # plugin.yaml declares what the checker provides; tool_plan is what it
        # actually serves. The manifest is a second copy of that list, and the
        # drift the engine exists to prevent starts exactly here.
        import tempfile
        for name, module in self.checkers.items():
            with self.subTest(checker=name):
                manifest = (REPO / "tools" / name / "plugin.yaml").read_text()
                listed = [line.strip()[2:] for line in manifest.splitlines()
                          if line.strip().startswith("- ")]
                run_dir = Path(tempfile.mkdtemp(prefix="gv-plan-"))
                try:
                    tree = audit_engine.git(REPO, "rev-parse", "HEAD^{tree}").stdout.decode().strip()
                    audit_engine.write_json(
                        run_dir / "scope.json",
                        {"repo": str(REPO), "tree": tree, "base": "",
                         "changed": [], "kind": "push"})
                    served = [spec[0] for spec in
                              module.tool_plan(module.SPEC.make_review(run_dir))]
                finally:
                    import shutil
                    shutil.rmtree(run_dir, ignore_errors=True)
                self.assertEqual(listed, served)

    def test_receipt_reuse_contract_lives_in_one_place(self):
        # `audited` is the receipt contract: every checker's copy must be the
        # engine's, bound to its own spec.
        for name, module in self.checkers.items():
            with self.subTest(checker=name):
                self.assertIsNotNone(module.SPEC)
                self.assertEqual(module.SPEC.name, name)

    def test_review_runs_are_bounded_like_the_rust_store(self):
        # The convention both stores share: newest 200, nothing older than 90
        # days. Without it every gate run scans and grows an unbounded archive.
        import tempfile, time
        runs = Path(tempfile.mkdtemp(prefix="gv-prune-"))
        try:
            fresh = [runs / f"review-{i:03d}" for i in range(5)]
            for d in fresh:
                d.mkdir()
            old = runs / "review-ancient"
            old.mkdir()
            epoch = time.time() - audit_engine.MAX_AGE_SECS - 1
            import os
            os.utime(old, (epoch, epoch))
            audit_engine.prune_runs(runs, keep=3)
            survivors = sorted(p.name for p in runs.iterdir())
            self.assertEqual(survivors, ["review-002", "review-003", "review-004"])
        finally:
            import shutil
            shutil.rmtree(runs, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
