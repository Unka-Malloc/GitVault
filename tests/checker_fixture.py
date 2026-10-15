"""The shared synthetic fixture the checker test modules build on.

One copy of the engine's launch contract (environment names, --session-dir,
the credential key, the bridge path) is asserted here; a stub per checker
would silently stop checking the contract the first time a copy missed an
edit - the same drift the shared engine exists to prevent, in test form.
"""
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def load_checker(name):
    """Import a checker payload the way the installer lays it down: the
    checker directory and the shared agent-profiles library on sys.path."""
    for extra in (REPO / "tools" / "agent-profiles", REPO / "tools" / name):
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), REPO / "tools" / name / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def completed(command, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, code, stdout, stderr)


class CheckerFixture(unittest.TestCase):
    """A repository with one outgoing commit, the push environment and the
    Pi stub that asserts the engine's launch contract.

    Subclasses set ``module`` (the checker under test) and ``changed_file``
    (the outgoing path the stub's review diffs)."""

    module = None
    changed_file = "leak.txt"

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
        self.git("config", "user.name", "Synthetic Auditor")
        self.git("config", "user.email", "auditor@example.invalid")
        (self.repo / "app.js").write_text("export const value = 1\n")
        self.git("add", "app.js")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        (self.repo / self.changed_file).write_text("synthetic change\n")
        self.git("add", self.changed_file)
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

    def push_env_for(self, head, base=None):
        """The push line names the ref, its tip, and the published tip."""
        return {"GITVAULT_EVENT": "pre-push",
                "GITVAULT_PUSH_REFS": f"refs/heads/work {head} refs/heads/work {base or self.base}"}

    def report(self, verdict="pass", overrides=None):
        report = {"verdict": verdict, "summary": "Synthetic range reviewed",
                  "findings": [], "unknowns": [],
                  "coverage": {k: {"status": "not-applicable", "reason": "Synthetic fixture"}
                               for k in self.module.DOMAINS}}
        report.update(overrides or {})
        return report

    def stub_pi(self, calls):
        def stub(command, **kwargs):
            # Sessions resume within the same range key; nothing from an
            # earlier repository or range can leak into the judgement.
            self.assertIn("--session-dir", command)
            self.assertEqual(command[0], self.settings["pi"])
            self.assertEqual(command[command.index("--provider") + 1], "example")
            self.assertIn(str(Path(self.module.__file__).parent / "pi-bridge.ts"), command)
            self.assertNotIn("OTHER_SECRET", kwargs["env"])
            self.assertEqual(kwargs["env"]["EXAMPLE_API_KEY"], "synthetic-fixture-only")
            run_dir = Path(kwargs["env"]["GITVAULT_RUN_DIR"])
            calls.append(run_dir)
            review = self.module.Review(run_dir)
            review.context({"operation": "diff", "path": self.changed_file})
            review.submit(self.report())
            return completed(command, 0,
                             json.dumps({"type": "agent_settled", "aborted": False}) + "\n")
        return stub
