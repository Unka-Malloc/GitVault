"""The runtime a checker falls back to when nothing declares one.

This module is the single source for the fallback: it ships inside every
checker's payload (install.py copies it next to profile_sync.py), so the four
auditors cannot drift into different defaults. A synced profile.json overrides
it; config.yaml's model block overrides it for a machine that never pulled.
The constant itself must exist in exactly one place.
"""

DEFAULT_RUNTIME = {"provider": "example", "model": "deepseek/deepseek-v4.1-flash", "effort": "high"}
