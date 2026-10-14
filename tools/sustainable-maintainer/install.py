"""Install Sustainable Maintainer outside working trees; never handles credential values."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
import tomllib

SOURCE = Path(__file__).resolve().parent
# The machine's half of the profile contract is shared by every agent, so it is
# implemented once and copied into each payload.
LIBRARY = SOURCE.parent / "agent-profiles"
sys.path.insert(0, str(LIBRARY))
import profile_sync  # noqa: E402
AGENT = "sustainable-maintainer"
def register(config_file, name, block):
    """Add this checker's registry entry, or replace it in place.

    Replacing rather than refusing keeps an installed checker updatable: the
    command embeds absolute paths, so a machine that refused to touch an
    existing entry would be stranded on whatever was written first. The result
    is validated as TOML before it is written.
    """
    text = config_file.read_text()
    segments, current = [], []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("[") and current:
            segments.append("".join(current))
            current = []
        current.append(line)
    if current:
        segments.append("".join(current))
    pattern = re.compile(r'(?m)^\s*name\s*=\s*"%s"\s*$' % re.escape(name))
    for index, segment in enumerate(segments):
        if segment.lstrip().startswith("[[checkers]]") and pattern.search(segment):
            segments[index] = block
            action = "replaced"
            break
    else:
        segments.append(("\n" if not text.endswith("\n\n") else "") + block)
        action = "added"
    updated = "".join(segments)
    tomllib.loads(updated)
    config_file.write_text(updated)
    config_file.chmod(0o600)
    return action


def _synced(target):
    """True once a published profile version has been installed here."""
    settings = target / "installation.json"
    if not settings.is_file():
        return False
    try:
        return bool(json.loads(settings.read_text()).get("synced"))
    except ValueError:
        return False


def _installation(agent):
    target = Path.home() / f".hermes/profiles/{agent}/plugins/{agent}"
    settings = target / "installation.json"
    if not settings.is_file():
        raise SystemExit(f"{agent} is not installed")
    return settings, json.loads(settings.read_text())


def install_payload(target):
    home = Path.home()
    shared = home / f".agents/skills/{AGENT}"
    shared.mkdir(parents=True, exist_ok=True)
    # Documents are the dev site's to publish: this repository's copies are the
    # seed for a machine that has never pulled. Once a version is installed,
    # `--pull` is the only thing that overwrites them.
    if not _synced(target):
        for name in ("SKILL.md", "policy.md"):
            shutil.copyfile(SOURCE / name, shared / name)
    for directory in [*home.glob(".*/skills"), *home.glob(".config/*/skills"),
                      *home.glob(".hermes/profiles/*/skills")]:
        if not directory.is_dir() or directory.resolve() == shared.parent.resolve():
            continue
        link = directory / AGENT
        if link.is_symlink() and link.resolve() == shared.resolve():
            continue
        if link.exists() or link.is_symlink():
            raise ValueError(f"Conflicting {AGENT} skill entry requires inspection: {link}")
        link.symlink_to(shared, target_is_directory=True)
    for name in ("__init__.py", "maintainer_ranges.py", "maintainer_stage1.py", "plugin.yaml"):
        shutil.copyfile(SOURCE / name, target / name)
        (target / name).chmod(0o600)
    for name in ("profile_sync.py", "pi-bridge.ts"):
        shutil.copyfile(LIBRARY / name, target / name)
        (target / name).chmod(0o600)
    # The legacy embedded runner is gone from the payload entirely: an
    # update must not leave a second runtime beside the Pi bridge.
    (target / "runtime.py").unlink(missing_ok=True)
    destination = target / "policy.md"
    if destination.exists() or destination.is_symlink():
        destination.unlink()
    destination.symlink_to(shared / "policy.md")


def install():
    home = Path.home()
    pi = shutil.which("pi")
    python = shutil.which("python3")
    if not pi or not python:
        raise SystemExit("Pi and Python 3.11+ are required")
    profile = home / f".hermes/profiles/{AGENT}"
    target = profile / "plugins" / AGENT
    if not profile.exists():
        # The profile directory is just the checker's private home now; Pi
        # needs no profile scaffolding.
        profile.mkdir(parents=True, mode=0o700)
    elif not (target / "installation.json").is_file():
        raise SystemExit("Existing sustainable-maintainer profile requires inspection before installation")
    target.mkdir(parents=True, exist_ok=True)
    install_payload(target)
    (profile / "config.yaml").write_text((SOURCE / "config.yaml").read_text())
    (profile / "config.yaml").chmod(0o600)
    previous = json.loads((target / "installation.json").read_text()) if (target / "installation.json").is_file() else {}
    settings = {"pi": pi, "python": python, "profile": str(profile),
                "credential_file": str(home / ".hermes/.env"),
                "skill_dir": str(home / f".agents/skills/{AGENT}")}
    # Installing again does not un-sync anything: the profile the dev site
    # published is still what this machine runs on.
    if previous.get("synced"):
        settings["synced"] = previous["synced"]
    (target / "installation.json").write_text(json.dumps(settings, indent=2) + "\n")
    (target / "installation.json").chmod(0o600)
    # Registry entry is activated only after the implementation is installed.
    # Hook files belong to ~/.git-hooks/_dispatch and are never written here.
    block = ('[[checkers]]\nname = "sustainable-maintainer"\non = ["pre-push", "pr"]\nkind = "exec"\n'
             'severity = "blocking"\ntimeout_secs = 0\ncommand = '
             + json.dumps([python, "-I", str(target / "__init__.py"), "--repo", "{repo}"]) + '\n')
    action = register(home / ".config/gitvault/config.toml", AGENT, block)
    print("Sustainable Maintainer installed: deterministic stage first, Pi semantic stage on pass; "
          "blocking pre-push and pr; no review deadline")
    print(f"Registry entry {action} in ~/.config/gitvault/config.toml")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--pull"]:
        settings_path, settings = _installation(AGENT)
        skill_dir = settings.get("skill_dir") or str(Path.home() / f".agents/skills/{AGENT}")
        result = profile_sync.pull(
            AGENT, skill_dir,
            os.environ.get("GITVAULT_PROFILES_URL", profile_sync.DEFAULT_URL),
            sys.argv[2] if len(sys.argv) > 2 else None)
        # The drift check needs the directory it must re-hash, so the record
        # carries it: a version without its location is not a usable record.
        settings["skill_dir"] = skill_dir
        settings["synced"] = result
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
        settings_path.chmod(0o600)
        print(f"{AGENT} profile synced to {result['tag']} "
              f"({len(result['files'])} documents, manifest {result['manifest'][:12]})")
    elif sys.argv[1:] == ["--update"]:
        target = Path.home() / f".hermes/profiles/{AGENT}/plugins/{AGENT}"
        if not (target / "installation.json").is_file():
            raise SystemExit("Sustainable Maintainer is not installed")
        install_payload(target)
        # The legacy record predates the Pi runtime: migrate it in place so
        # the checker never consults a removed harness.
        settings_path = target / "installation.json"
        settings = json.loads(settings_path.read_text())
        settings.pop("hermes", None)
        settings["pi"] = shutil.which("pi")
        settings["python"] = sys.executable if sys.executable else shutil.which("python3")
        # The seeded config is the fallback for a machine that never pulled;
        # an update refreshes it so it cannot strand on the old runtime.
        config = Path(settings["profile"]) / "config.yaml"
        config.write_text((SOURCE / "config.yaml").read_text())
        config.chmod(0o600)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
        settings_path.chmod(0o600)
        print("Updated Sustainable Maintainer runtime and all existing Agent skill directories")
    elif sys.argv[1:]:
        raise SystemExit("Usage: install.py [--update | --pull [TAG]]")
    else:
        install()
