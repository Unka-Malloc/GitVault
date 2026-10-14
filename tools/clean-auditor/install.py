"""Install Clean Auditor outside working trees; never handles credential values."""
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
        agent="clean-auditor",
        payload=("__init__.py", "clean_stage1.py", "plugin.yaml"),
        events=("pre-push", "pr"),
        banner="Clean Auditor installed: deterministic stage first, Pi semantic stage on pass; "
               "blocking pre-push and pr; no review deadline",
        title="Clean Auditor",
    )
