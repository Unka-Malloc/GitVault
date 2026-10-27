# Changelog

## Unreleased

- `gitvault api` gains `--follow`/`-L` and `gitvault run` gains `logs JOB_ID`
  (job log text) and `logs --run RUN_ID` (run log archive). GitHub's log
  endpoints answer `302` to a signed download URL; the broker now follows the
  hop in-process: the signed URL reaches curl through a private stdin config
  (`-K -`), never argv or the environment, and the second hop carries no
  credential. The final response body streams to stdout with bounded memory,
  so zip archives pass through unchanged. `--follow` is limited to GET.
- `release create` accepts a repeatable `--asset PATH` and uploads each file
  onto the release it just created, naming the stored asset after the file's
  basename. Every asset path is checked before the create request so an
  unreadable file refuses before anything is published; the upload body
  streams from disk via `curl --data-binary @path` and never enters argv or
  memory. The token's origin set is now exactly two: `api.github.com` and
  `uploads.github.com`, the host GitHub assigns for asset uploads, while
  `gitvault api` still refuses the releases write surface on either origin.
- Publication coverage reads the hardening contract's declared domain set from
  the contract file the inspected row names instead of copying the
  `security-enhancer` domain list into GitVault. The contract identity stays a
  documented, versioned coupling and is named in the refusal text; engine-side
  domain additions are now required rather than silently rejected as missing
  coverage. Finding text also redacts bare endpoint URLs, keeping the scheme
  but not the host or path.
- Trust in an executable now judges the path itself: the biometric helper and
  the audit engine must be regular, non-symlink files that are root-owned or
  carry `schg`. Previously a symlink planted at the fixed helper path inherited
  the trust of a root-owned target such as `/usr/bin/true`, so the Touch ID
  prompt could be answered by an executable that never asked.
- An armed publication boundary now re-checks at every invocation that the
  audit engine is root-owned or carries the system immutable flag (`schg`), and
  `gitvault install` refuses to arm when no engine is present. An engine placed
  after the last install can no longer answer a `pre-push`, `pr` or `release`
  verdict with an empty findings array. The on-demand `working-tree` snapshot
  publishes nothing; it is the only event that may run an untrusted engine, and
  it warns.
- The biometric helper is resolved from the account database rather than
  `HOME`, and the fixed helper must be root-owned or `schg` before it runs.
  `gitvault install` immobilises an existing helper; one installed afterwards is
  refused until the install is re-run.
- The API broker re-checks the routing signature immediately before issuing a
  token. A merge's metadata read before the audit therefore cannot spend the
  vault on an unsigned or tampered routing table, while the publication verdict
  is still decided after the audit.
- The `--no-verify` documentation no longer instructs operators to remove a
  required `gitvault/audited` check before a replacement exists. GitVault still
  posts no commit status; the local boundary's residual is stated explicitly.
- `gitvault api` now matches publication routes on the percent-decoded path the
  server will see. An encoded route name, an encoded path separator, or a
  percent escape that survives one decode refuses anywhere in the relative
  path, including owner/repo, instead of slipping past as an unknown segment.
- `gitvault push` now resolves a deletion name against both `refs/heads` and
  `refs/tags`. A name present in both namespaces, or in neither, refuses and
  requires the full ref, so the audit line and the refspec git receives can
  never name different refs. `push.default=matching` reads the remote's
  advertised heads with a read-only `ls-remote` before the audit instead of
  trusting the local mirror; an unreadable remote refuses rather than
  selecting or omitting a ref git would move.
- The audit engine's fixed `PATH` now puts the root-owned system directories
  first, then the engine's own directory and `~/.local/bin` so the engine can
  find its agent. User-writable package-manager directories (`/usr/local/bin`,
  `/opt/homebrew/bin`) are omitted unless the engine itself resolves there,
  and are never placed before a root-owned helper. A same-user process can no
  longer substitute the `git` the audit spawns.
- `gitvault api` refuses a path containing a `.` or `..` segment, including a
  percent-encoded spelling, before the publication check and before the token
  is sent. `request_url` applies the same refusal, so a traversal cannot reach
  the API even when it does not match a publication surface.
- `hook` and `check` parse the event at the boundary. A misspelled event
  (`pre_pus`) now refuses instead of matching no gate and reporting success.
- An armed install migrates `withheld-names.txt` and `repo-deps.txt` to the
  engine's fixed configuration root, including lists the engine itself wrote
  under the unarmed XDG root, and pins the engine child's `XDG_CONFIG_HOME` to
  it, so a caller's environment cannot separate Clean Auditor's machine-local
  lists from the engine. Each target is read back before its source is removed.
- `pr create` fetches the base from the remote that owns the target
  repository, refreshes its tracking ref, and restores the checkout's own
  `origin` ref after the audit in a fork workflow. It re-reads the proposed
  head after the audit, refuses a moved head before the POST, and checks the
  created request's reported head against the audited commit (closing the
  request if it moved in that last window).
- Attribution at `pr merge` now scans the request's resolved target
  `base..head` instead of a range computed against the checkout's `HEAD`; a
  trailer in the PR head is blocking even when another branch is checked out.
  When `--base` is supplied it is verified against the request's own metadata
  after the audit and before the merge; a mismatch refuses.
- A valueless `remote.<name>.mirror` key is treated as the mirror git makes it,
  so the push plan refuses it instead of reading the empty value as "no
  mirror".
- `gitvault push` audits what a push carries before any credential is spent:
  git connects to the remote to learn the refs its `pre-push` hook reports,
  so a bare `git push` always spends the SSH credential before the audit.
  The wrapper synthesizes the same ref lines from the arguments and the
  local mirror, runs the audit, and hands a passing push to the real
  `git push`. That push's `pre-push` hook re-audits the refs git actually
  advertises; the hook run is the authoritative verdict and the wrapper's
  pre-audit is advisory (it exists so a failing audit is known before the
  credential is spent). Probator may reuse its sealed verdict for a head it
  has already judged. The wrapper hands git the exact refspecs it audited
  instead of forwarding the original argument vector, and forces
  `--no-follow-tags`, `--no-recurse-submodules` and `--no-prune` on the real
  push; it refuses a remote configured with `remote.<name>.mirror=true`. It
  resolves the remote with git's precedence
  (`branch.<name>.pushRemote`, `remote.pushDefault`, `branch.<name>.remote`,
  then `origin`) and uses one name for the mirror and the push. A bare push
  follows `push.default` instead of synthesizing a destination git would
  refuse: `simple` requires a same-named upstream on the pull remote,
  `upstream` requires the push remote to be that upstream, and `matching`
  selects only heads the remote advertises. A `HEAD` source resolves to
  the current branch's name, as git's own push does. It refuses `--no-verify`,
  `--stdin`, `--follow-tags`, `--prune`, `--mirror`, parameterised
  `--branches`, `--recurse-submodules` and any option it does not model, so no
  ref can be selected, added or deleted after the pre-audit has run. `--tags`
  is conservative: without the transport GitVault cannot know which tags the
  remote already has, so it audits every local tag; Probator then skips heads
  reachable from a remote-tracking ref and reuses its cursor for an
  already-judged head.
- A blocking built-in gate (identity, attribution, history) now ends the
  operation before the delegated audit starts: nothing could publish, so a
  refused push no longer pays for a semantic review that cannot inform a
  decision. The run record still carries every local gate that produced
  evidence, and a passing local boundary still runs the audit before any
  authorization request.
- Every vault-unlock prompt now announces itself on stderr with the
  credential being spent; the `pr merge` head fetch labels itself too. No
  audit path requests the vault, and a prompt can no longer read as one
  doing so.
- `pr merge` resolves the request's target base (or accepts `--base`) and
  fetches `pull/N/head` at the gate boundary, freezing the fetched SHA into
  the audit context. The same SHA is sent as the merge request's precondition,
  so a head that moves after the audit is a refusal. A private fetch ref is
  used instead of the shared `FETCH_HEAD`, so concurrent fetches cannot move
  the object the audit binds.
- `pr create` fetches the proposed head branch and audits that immutable
  commit; a base branch containing slashes keeps its full name after the
  remote prefix is removed. `release create` sends `target_commitish` with the
  audited commit and refuses an existing remote tag that points elsewhere.
- `config sign` and `config verify` resolve `audit_policy` from the routing
  table and certify or check that exact file, instead of always assuming the
  conventional `checkers.toml` sibling. The anchor, installed engine and
  engine ruling authority now share one account-home path, never `HOME`.
- An absent `checkers.toml` is classified by its signature state instead of
  being treated as inactive: an armed publication boundary refuses it before
  the engine runs, so the documented `config sign`-then-`install` bootstrap
  cannot reach a gate with no engine authorization.
- Audit consolidation: GitVault no longer ships a review engine. The two
  review binaries, the bundled checker contracts, the
  `docs/review-contract.schema.json` design schema and its design note, and
  the GitVault-owned audit policy are removed; Probator's contract schema is
  the replacement. A
  publication audit now hands the public
  [Probator](https://github.com/Unka-Malloc/Probator) engine one JSON action
  per review object and projects its findings; a missing engine, a failed run
  or an unreadable result is a blocking finding. `gitvault checkers` reads
  `probator inspect`, and `gitvault check` no longer accepts `--only`.
  The signed `checkers.toml` admits only rows naming the configured engine; a
  stale `gitvault-review` row refuses the boundary before the engine runs, and
  no row is executed. Boundary coverage requires a blocking hardening contract
  under the engine's profiles root with the full hardening domain set
  declared, a command that runs it against `{repo}`, and no `repos` scope
  excluding this repository. An
  armed installation resolves only the installed engine path; the
  engine child gets a cleared, minimal environment (no provider keys,
  `SSH_AUTH_SOCK`, `PROBATOR_*` or `GITVAULT_*` inheritance). GitVault
  serializes concurrent audits of one repository on an exclusive lock, so two
  invocations cannot enter the same review at the same time and one can lose
  its sealed report. A waiter blocks for a live owner
  with no internal elapsed-time cutoff; a slow audit is never rejected merely
  because it ran long, and only a dead lock owner (or an unreadable owner
  after a short grace) releases the lock. Finding text is re-rendered before
  display and storage: control characters are stripped, credential shapes and
  assignments, personal identifiers and private endpoints are redacted,
  absolute host paths become `[LOCAL_PATH]`, and an absolute or traversing
  finding path is omitted.
- Push audits name their scope with `push_refs` alone: the ref lines git
  supplied, preserving the exact remote-tip..local-head range a push publishes.
  A push is one action however many refs it moves, so one checker set answers
  for the whole push.
- `gitvault check --event working-tree` now delegates the uncommitted snapshot
  through the same `probator gate-audit` boundary with the action
  `{"kind":"working-tree","target":"...","detail":{"range":"working-tree"}}`.
  Policy coverage is checked against the engine's pre-push rows. A
  working-tree audit is not a publication boundary: it publishes nothing and
  spends no credential.
- `gitvault install` performs the one-time hand-off of the removed review
  engine's machine-local policy lists. `withheld-names.txt` and
  `repo-deps.txt` now belong to the engine's config root: a list it lacks is
  moved there, a byte-identical duplicate is deleted, and a conflicting pair
  refuses instead of silently choosing one. GitVault itself no longer reads
  either list.
- `gitvault install` deploys only `gitvault` and the `gitvault-sign` wrapper;
  the engine is installed and locked separately. The local identity,
  attribution and push-history gates are unchanged.
- Pull-request audits now send `head` and `base` in the engine's action
  vocabulary. The request number is not sent: GitVault already fetched and
  froze the head at the gate boundary, and the audit must not fetch it again.
- `gitvault check` gained `--pr-head`, `--pr-base` and `--pr-number` so a
  pull request can be audited outside `pr create`/`pr merge`.
- The old `~/.local/share/gitvault/profiles` receipts and cursors are left in
  place as history, not copied into the engine's data root. They were produced
  by the removed internal review engine and their cursor keys predate the
  engine's reviewer-bound key, so the engine cannot reuse them; rewriting the
  engine field or re-keying them would assert a provenance it never issued.

## 0.2.0

- Earlier 0.2.0 notes described the built-in review runtime and checker
  registry. Both were removed in the audit consolidation above; Probator now
  owns that surface.
