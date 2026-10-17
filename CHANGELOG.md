# Changelog

## 0.2.0

- Run the four publication auditors through AwP profiles and bindings,
  A4AA's Codex adapter, and the native Codex runtime.
- Configure GPT-6.1 Sol with xhigh reasoning in the synced auditor profiles.
- Preserve each auditor's identity and profile revision in review receipts.
- Isolate model access to the declared audit tools and reuse the operator's
  Codex login without copying credential values into checker configuration.
- Preserve resumable conversations and require complete structured verdicts.
- Resume interrupted conversations even after report submission, and reuse
  validated completion evidence when only local receipt finalization failed.
  Retain unfinished review progress independently of completed-receipt cleanup.
- Remove the superseded Pi bridge and launcher configuration.
- Validate annotated release tags against their reviewed commit when checking
  that the published reference has not changed during an audit.
- Keep first-release reviews at whole-tree scope before and after push, so
  publishing a branch cannot change what the release gate judges.

The runtime now requires Codex and the `gitvault-audit-agent` binary. Update
the checker installation along with GitVault. Existing vault credentials,
identity routing, signed profile policy, and audit records remain user data.
