"""Install Money Saver outside working trees; never handles credential values."""
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
# The installer skeleton is shared by every agent: registry upsert, skill
# symlinking, payload copy and migrations live once in agent-profiles.
sys.path.insert(0, str(SOURCE.parent / "agent-profiles"))
import installer  # noqa: E402

if __name__ == "__main__":
    installer.main(
        source=SOURCE,
        agent="money-saver",
        payload=("__init__.py", "full_audit.py", "audit.py", "plugin.yaml"),
        events=("pre-push",),
        banner="Money Saver installed: Pi runtime, declared provider/model from the synced profile; "
               "blocking pre-push; no review deadline",
        title="Money Saver",
        skill_docs=("SKILL.md", "policy.md", "documents.json"),
    )
