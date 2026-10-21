# Changelog

## 0.2.0

- `phase` on a checker row orchestrates the run into ordered pools: rows in
  one phase run concurrently, later phases start only while no blocking
  failure exists, and skipped rows are recorded without spending tokens.

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
- Preserve each auditor's identity and profile revision in review receipts.
- Isolate model access to the declared audit tools; host credentials are
  resolved through the registry document's declared secret recipes, never
  copied into checker configuration.
- Preserve resumable conversations and require complete structured verdicts.
- Resume interrupted conversations even after report submission, and reuse
  validated completion evidence when only local receipt finalization failed.
  Retain unfinished review progress independently of completed-receipt cleanup.
- Attest a first-time head inside the same push: when the `gitvault/audited`
  status post finds the commit unknown to the remote, the gate stages it
  under `refs/gitvault/incoming/<sha>` — a ref no branch ruleset watches —
  posts the mark, and deletes the staging ref, so the very first push of a
  commit lands attested instead of needing the manual second-push ritual.
  A staging failure still falls back to the deferred-attestation path.
- Bind each run's verdict to a one-shot credential: the run mints a random
  `verdict.key` before the reviewer starts, the review server signs its
  submitted receipt with `HMAC-SHA256(key, canonical receipt)` into
  `receipt_mac`, and the gate recomputes the signature before trusting the
  report — a hand-written, replayed or stale `report.json` no longer
  counts as a review. The key file dies with the verdict that sealed it;
  a spent or missing credential refuses submission outright.
- Conceal finished audit conversations from the harness's own session list:
  each run records every conversation it opens in `audit-session.json`
  (`session_ids` alongside the resume pointer), and when the run ends the
  engine marks those recorded sessions archived with the store's native
  flag — `hidden` on devin's sessions.db, `time_archived` on opencode's
  session_v2, and on the Devin desktop's globalStorage index both the
  `cognition.ai/isArchived` row flag and membership in the
  `archivedSessions` list its sidebar's Archived filter consults — so
  resumable transcripts stop filling the operator's visible session lists.
  The sweep covers every checker's runs root on each gate — a checker
  skipped by an earlier phase's refusal still gets its backlog concealed —
  and runs only after the audit finishes: flagging a conversation while
  its agent is still prompting breaks the turn. Each run directory carries
  a `live` pid marker so a sibling sweep can never archive a conversation
  mid-turn, and the store writes wait out transient database locks rather
  than refusing. Concealment is best-effort and never gates a run.
- Judge a push whose remote tip is not in the local object store as a whole
  snapshot: the remote's live tip sha cannot anchor a diff it never
  fetched, so the review object falls back to the same root-to-head
  snapshot a first push carries, the attribution scan widens the same way,
  and the history gate's refusal names the remedy — fetch the remote and
  rebase, or `git pull --rebase` — instead of a bare non-fast-forward
  refusal.
- Refuse sibling-repository references that run against the dependency
  direction: the Clean Auditor's deterministic stage reads a machine-local
  `repo-deps.txt` map and blocks a document in an upstream repository that
  names one of its downstreams — an upstream naming a downstream publishes
  that repository's plans before it has shipped anything on its own.
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
  are never marked. A status the remote cannot accept yet — the commit
  arrives with that very push — is recorded under the pending directory and
  reposted by the first later audited push, ruleset or not.
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
