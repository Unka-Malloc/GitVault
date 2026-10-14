"""The runtime a checker falls back to when nothing declares one.

This module is the single source for the fallback: it ships inside every
checker's payload (install.py copies it next to profile_sync.py), so the four
auditors cannot drift into different defaults. Resolution order is
profile.json's declared runtime first, this constant second — config.yaml
carries no model keys, because the review is spawned with explicit
--provider/--model/--thinking flags and a YAML copy would only look
authoritative without being read. The constant itself must exist in exactly
one place.
"""

DEFAULT_RUNTIME = {"provider": "example", "model": "deepseek/deepseek-v4.1-flash", "effort": "high"}
