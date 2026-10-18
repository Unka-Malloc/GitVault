# Changelog

## 0.2.0

- Run the four publication auditors through AwP profiles and bindings over
  A4AA agent specs: the installer materializes each checker's registry
  document from the shared declarative template `tools/registry.json` —
  agent lane specs, the `audit` binding's fallback chain and the host's
  secret recipes are data, never code.
- The audit runtime is declared by the synced AwP profile — harness,
  provider, model chain, peak/off-peak windows, quota retry and effort. A
  profile without a `runtime` block refuses the audit; a model outside the
  declared provider's namespace refuses the declaration. No vendor or
  catalog is pinned by the framework.
- This machine's deployment binds an OpenCode serve lane on the free
  `opencode/`-namespaced chain with a `devin acp` fallback — a deployment
  choice recorded in the registry template, not a framework fact.
- Preserve each auditor's identity and profile revision in review receipts.
- Isolate model access to the declared audit tools; host credentials are
  resolved through the registry document's declared secret recipes, never
  copied into checker configuration.
- Preserve resumable conversations and require complete structured verdicts.
- Resume interrupted conversations even after report submission, and reuse
  validated completion evidence when only local receipt finalization failed.
  Retain unfinished review progress independently of completed-receipt cleanup.
- Remove the superseded Codex/Pi bridges and launcher configuration.
- Validate annotated release tags against their reviewed commit when checking
  that the published reference has not changed during an audit.
- Keep first-release reviews at whole-tree scope before and after push, so
  publishing a branch cannot change what the release gate judges.
- Split the audit policy into its own signed `checkers.toml`: policy
  signatures gate whether declared checker commands may execute at all,
  routing signatures gate verdicts and credentials, and audits always run
  before any signature is requested.
- Record the routing signature state in every audit run record.
- Close the local bypass surface: `gitvault api` refuses publication writes
  (contents, git objects and refs, merges, merge-upstream, pull-request
  create/merge/update-branch, releases, commit statuses); the pre-push gate
  rejects non-fast-forward updates, tag re-pointing and orphaning ref
  deletions; and the hook dispatcher pins its gateway binary instead of
  honouring `GITVAULT_BIN`.
- Attest reviewed heads server-side: a passed pre-push audit posts the
  `gitvault/audited` commit status for the exact reviewed commit, so a
  GitHub ruleset can require it and cover `--no-verify`, web edits and other
  machines. Tag objects peel to their commit; tips the remote already holds
  are never marked.
- Chain run records and review receipts with sha256 seals and add
  `gitvault records verify` to detect rewrites and gaps. Old records read as
  unsealed, never as tampered.
- Add `kind = "verify"` checkers: the signed policy's command runs in a
  detached worktree of the candidate revision, scoped by `repos`, giving the
  gate correctness evidence the repository cannot name itself.
- Give push and pull-request reviews a real base: stage-1 scans the blobs the
  range introduces (catching secrets added and removed mid-range) and the
  semantic stage diffs `base..head` instead of rereading the whole tree.
- Feed instruction-channel changes (agent rules, skills, MCP wiring) to the
  security auditor and published-interface diffs (proto, GraphQL, schemas,
  migrations, `.d.ts`, `*.schema.json`) to the maintainer as stage-1 surfaces
  for semantic adjudication. `gv-allow:<rule>` on a line demotes a blocking
  hit into a visible surface instead of hiding it.
- `gitvault check --event pre-push` outside a hook synthesizes the refs a
  push of the checkout would carry when stdin supplies none, instead of
  blocking on a terminal or vacuously passing on an empty list. A scheduled
  `gitvault check` thereby resumes provider-interrupted reviews in place -
  the audit keeps its session, and completed verdicts arrive as sealed
  receipts the next real push reuses.
- `gitvault api` learns comma branches in `--jq` and declares
  `Content-Type: application/json` for `--input` bodies automatically.

The runtime requires the agent programs the deployment's registry template
declares (this machine: OpenCode, with an optional Devin fallback), plus
the `gitvault-review` and `gitvault-audit-agent` binaries. Update the
checker installation along with GitVault. Existing vault credentials,
identity routing, signed profile policy, and audit records remain user
data.
