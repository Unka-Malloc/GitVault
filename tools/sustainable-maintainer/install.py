"""Install Sustainable Maintainer outside working trees; never handles credential values."""
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
        agent="sustainable-maintainer",
        payload=("__init__.py", "maintainer_stage1.py", "plugin.yaml"),
        events=("pre-push", "pr"),
        banner="Sustainable Maintainer installed: deterministic stage first, Pi semantic stage on pass; "
               "blocking pre-push and pr; no review deadline",
        title="Sustainable Maintainer",
    )
