import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tools/agent-profiles"
spec = importlib.util.spec_from_file_location("agent_profile_sync", SOURCE / "profile_sync.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

FILES = {"policy.md": "# Policy\n\nJudge everything.\n", "SKILL.md": "# Skill\n", "profile.json": "{}\n"}


def bundle_for(files, tag="profile/clean-auditor/v3"):
    return {"name": "clean-auditor", "tag": tag, "files": files,
            "hashes": {name: sync.sha256(text) for name, text in files.items()},
            "manifest": sync.manifest(files)}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *rest):
        return False

    def read(self):
        return json.dumps(self.payload).encode()

    def __iter__(self):
        return iter([])


class ProfileSyncTests(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.skill_dir = Path(self.tmp.name) / "skills" / "clean-auditor"

    def pull(self, payload, url="http://127.0.0.1:8891"):
        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)):
            return sync.pull("clean-auditor", self.skill_dir, url)

    # -- the manifest -------------------------------------------------------

    def test_the_manifest_is_order_independent_and_byte_sensitive(self):
        assert sync.manifest(FILES) == sync.manifest(dict(reversed(list(FILES.items()))))
        changed = {**FILES, "policy.md": FILES["policy.md"] + "x"}
        assert sync.manifest(changed) != sync.manifest(FILES)

    # -- pulling ------------------------------------------------------------

    def test_a_pull_writes_only_the_documents_and_records_their_hashes(self):
        result = self.pull(bundle_for(FILES))
        self.assertEqual(result["tag"], "profile/clean-auditor/v3")
        self.assertEqual(result["version"], 3)
        self.assertEqual(sorted(result["files"]), ["SKILL.md", "policy.md", "profile.json"])
        self.assertEqual(sorted(p.name for p in self.skill_dir.iterdir()),
                         ["SKILL.md", "policy.md", "profile.json"])
        self.assertEqual((self.skill_dir / "policy.md").read_text(), FILES["policy.md"])
        # profile.json carries the declared runtime: it is synced like the
        # prompt, so the configuration mapping is covered by the same hashes.
        self.assertEqual((self.skill_dir / "profile.json").read_text(), FILES["profile.json"])

    def test_a_tampered_bundle_writes_nothing(self):
        for mutate in (
            lambda payload: {**payload, "manifest": "0" * 64},
            lambda payload: {**payload, "hashes": {**payload["hashes"], "policy.md": "0" * 64}},
            lambda payload: {**payload, "hashes": {"policy.md": payload["hashes"]["policy.md"]}},
        ):
            payload = mutate(bundle_for(FILES))
            with self.assertRaises(ValueError):
                self.pull(payload)
            self.assertFalse(self.skill_dir.exists(), "a refused pull leaves nothing behind")

    def test_a_previous_version_survives_a_refused_pull(self):
        self.pull(bundle_for(FILES))
        before = (self.skill_dir / "policy.md").read_text()
        with self.assertRaises(ValueError):
            self.pull({**bundle_for({**FILES, "policy.md": "tampered"}), "manifest": "0" * 64})
        self.assertEqual((self.skill_dir / "policy.md").read_text(), before)

    def test_a_version_without_references_removes_a_stale_copy(self):
        self.pull(bundle_for({**FILES, "documents.json": '{"pricing": "https://example.invalid/x"}\n'}))
        self.assertTrue((self.skill_dir / "documents.json").exists())
        self.pull(bundle_for(FILES))
        self.assertFalse((self.skill_dir / "documents.json").exists())

    # -- drift --------------------------------------------------------------

    def test_drift_is_reported_only_against_a_recorded_version(self):
        # Nothing has been pulled yet: the local copy is the source, not a drift.
        self.assertEqual(sync.drift({"skill_dir": str(self.skill_dir)}), [])
        self.pull(bundle_for(FILES))
        installation = {"skill_dir": str(self.skill_dir), "synced": self.pull(bundle_for(FILES))}
        self.assertEqual(sync.drift(installation), [])
        sync.assert_synced(installation)

        (self.skill_dir / "policy.md").write_text("# Policy\n\nSomething else entirely.\n")
        self.assertEqual(sync.drift(installation), ["policy.md"])
        with self.assertRaises(ValueError) as caught:
            sync.assert_synced(installation)
        self.assertIn("install.py --pull", str(caught.exception))
        # The refusal names the document and never its content.
        self.assertNotIn("Something else", str(caught.exception))

        # A deleted document is a drift too, not a silent pass.
        (self.skill_dir / "policy.md").unlink()
        self.assertEqual(sync.drift(installation), ["policy.md"])

    def test_a_missing_skill_directory_is_a_drift_not_a_pass(self):
        self.pull(bundle_for(FILES))
        installation = {"skill_dir": str(Path(self.tmp.name) / "gone"), "synced": self.pull(bundle_for(FILES))}
        self.assertEqual(sorted(sync.drift(installation)), ["SKILL.md", "policy.md", "profile.json"])


if __name__ == "__main__":
    unittest.main()
