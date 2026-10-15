"""Contract tests for the shared installer.

The registry upsert decides whether an installed checker actually runs — a
mistake there is the failure mode the repository calls the worst: a gate that
looks installed while it silently is not. These tests pin the upsert, the
profile-config substitution and the legacy-record migration.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "agent-profiles"))

import installer  # noqa: E402

ENTRY = ('[[checkers]]\nname = "money-saver"\non = ["pre-push", "pr"]\nkind = "exec"\n'
         'severity = "blocking"\ntimeout_secs = 0\n'
         'command = ["/usr/bin/python3", "-I", "/x/__init__.py", "--repo", "{repo}"]\n')
OTHER = ('[[checkers]]\nname = "clean-auditor"\non = ["pre-push"]\nkind = "exec"\n'
         'severity = "blocking"\ntimeout_secs = 0\n'
         'command = ["/usr/bin/python3", "-I", "/y/__init__.py", "--repo", "{repo}"]\n')


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="gv-installer-"))
        self.file = self.dir / "config.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, text):
        self.file.write_text(text)

    def test_first_install_adds_then_replaces_in_place(self):
        self.write(OTHER)
        self.assertEqual(installer.register(self.file, "money-saver", ENTRY), "added")
        self.assertIn(OTHER.strip(), self.file.read_text())
        # A second install replaces rather than refusing or duplicating.
        newer = ENTRY.replace('"pre-push", "pr"', '"pre-push"')
        self.assertEqual(installer.register(self.file, "money-saver", newer), "replaced")
        text = self.file.read_text()
        self.assertEqual(text.count('name = "money-saver"'), 1)
        self.assertIn('on = ["pre-push"]', text)
        # The entry beside it is untouched, and the result is still TOML.
        self.assertIn(OTHER.strip(), text)
        import tomllib
        tomllib.loads(text)

    def test_replacement_does_not_swallow_neighbouring_entries(self):
        self.write(OTHER + "\n" + ENTRY)
        after = installer.register(self.file, "clean-auditor", OTHER.replace('"pre-push"', '"pr"'))
        self.assertEqual(after, "replaced")
        text = self.file.read_text()
        self.assertIn('name = "money-saver"', text)
        self.assertEqual(text.count('on = ["pr"]'), 1)


class ProfileConfigTests(unittest.TestCase):
    def test_template_substitution_names_only_the_checker(self):
        source = REPO / "tools" / "clean-auditor"
        rendered = installer._profile_config(source, "clean-auditor")
        self.assertIn("enabled: [clean-auditor]", rendered)
        self.assertIn("cli: [clean_auditor]", rendered)
        self.assertNotIn("@AGENT", rendered)
        # The shared policy is present: no review deadline, no memory.
        self.assertIn("timeout_s: 0", rendered)
        self.assertIn("memory_enabled: false", rendered)


class UpdateMigrationTests(unittest.TestCase):
    def test_update_drops_the_legacy_runtime_key(self):
        with tempfile.TemporaryDirectory(prefix="gv-update-") as tmp:
            home = Path(tmp)
            source = self.dir = home / "source"
            source.mkdir()
            (source / "__init__.py").write_text("")
            # install_payload expects the shared library beside the checker's
            # directory, under agent-profiles - the source-tree layout.
            library = home / "agent-profiles"
            library.mkdir()
            for name in ("profile_sync.py", "pi-bridge.ts", "audit_runtime.py",
                         "review_ranges.py", "audit_engine.py", "profile-config.yaml"):
                (library / name).write_text(
                    "enabled: [@AGENT@]\ncli: [@AGENT_CLI@]\n"
                    if name == "profile-config.yaml" else "")
            profile = home / ".hermes/profiles/agent-x"
            target = profile / "plugins/agent-x"
            target.mkdir(parents=True)
            (target / "installation.json").write_text(json.dumps({
                "pi": "/pi", "python": "/python3", "profile": str(profile),
                "hermes": "/legacy/runner", "synced": {"tag": "v1"}}))
            with patch.object(installer, "PROFILE_ROOT", home / ".hermes/profiles"), \
                 patch.object(installer, "SKILL_ROOT", home / ".agents/skills"), \
                 patch.object(Path, "home", return_value=home):
                installer.update(source, "agent-x", ("__init__.py",), "Agent X", ("SKILL.md",))
            settings = json.loads((target / "installation.json").read_text())
            self.assertNotIn("hermes", settings)
            self.assertEqual(settings["synced"], {"tag": "v1"})
            # The shared config template was regenerated with this agent's name.
            self.assertIn("enabled: [agent-x]", (profile / "config.yaml").read_text())


if __name__ == "__main__":
    unittest.main()
