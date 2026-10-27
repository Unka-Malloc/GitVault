# GitVault

Holds the identity, intercepts the action, hands the audit to the configured
audit engine.

A repository cannot redefine the terms under which it is judged: identities and
ownership rules live outside every working tree, and the audit engine is a
separate tool with its own policy.

## Why

An audit gate that runs from inside the repository it inspects is not a gate. If
the checker, its rules, or its entry point can be reached through the work tree,
the repository can change the verdict. GitVault therefore never executes code
from the repository it inspects.

There used to be two audit engines: GitVault carried its own review runtime and
[Probator](https://github.com/Unka-Malloc/Probator) carried a fork of it. Two
implementations of the same policy drift, and two signed policies can disagree
about what an audit is. GitVault now owns only what only GitVault knows -
identity, routing and the local interception facts - and delegates every
publication audit to the public Probator engine through `probator gate-audit`.

## Model

`gitvault resolve` answers *who may act on this repository*, and says why:

1. `.gitvault-identity` in the repository root - an **assertion**, not a
   selector. It cannot grant an identity the owner rules do not allow; a
   mismatch is reported and the command exits non-zero. Because it is
   repository content, every credential-issuing path (API, SSH, signing)
   resolves with the assertion ignored - untrusted files never pick which
   account's credentials are used.
2. `rules.owners` matched against the **origin remote's owner**. Preferred over
   paths because it survives cloning elsewhere.
3. `rules.paths` for repositories with no remote yet.
4. `rules.default`. Absent means *refuse to act*, which is the correct default
   for a tool whose purpose is preventing mistakes.

`gitvault hook <event>` then runs GitVault's deterministic interception gates
and, at a publication boundary, the delegated Probator audit.

## Interception gates

These are local and built in. They answer questions a content review
cannot see, and they run before the delegated audit so a refusal costs no
audit work:

* **identity-actual** - compares the identity the routing rules resolved with
  the one git will actually stamp on the commit. `git -c user.email=...`, a
  repo-local override, or a stray `includeIf` can silently make git use a
  different address than the rules resolved to; attribution on GitHub follows
  the address, so the commit would land under the wrong account.
* **attribution-history** - refuses AI attribution trailers on outgoing
  commits and scrubs them from a message at the `commit-msg` and
  `prepare-commit-msg` hooks.
* **history-integrity** - reads the ref lines git supplies on a push: a
  non-fast-forward, a re-pointed tag, or a deletion that orphans a published
  tip is refused. A deletion whose commits remain reachable elsewhere is
  reported as advisory.

A blocking local gate ends the operation before the delegated audit: nothing
would publish, so the semantic review is not started.
When the local gates pass, the audit runs before authorization is requested.

## Audits run in Probator

At `pre-push`, `pr` and `release`, GitVault hands Probator one JSON action per
review object. `gitvault check --event working-tree` uses the same boundary for
an on-demand review of the uncommitted tree; it publishes nothing, so it is not
a publication boundary:

```json
{"kind":"pre-push","target":"/path/to/repo","detail":{"push_refs":"<ref lines>"}}
```

A push action names only `push_refs`, the ref lines as git supplied them,
preserving the exact `<remote-ref>..<local-head>` scope. A push stays one
action however many refs it moves; splitting it by head would start one full
checker set per head.

A working-tree check carries `{"kind":"working-tree","target":"/path/to/repo","detail":{"range":"working-tree"}}`.
It reviews the uncommitted snapshot, so the policy-coverage question is
answered against the engine's pre-push rows.

A pull request carries `head` and `base`; a release carries `tag` and
`commit`. Probator decides which policy checkers are bound to the event,
runs them, keeps the evidence in its own run directory, and returns a findings
array. GitVault projects those findings into its report and run record:

* `high` refuses the action;
* `warn` and `info` are reported but do not block;
* a finding the gate cannot classify refuses (an unknown label is never a pass);
* Probator missing, failing, exiting non-zero, or printing something that is
  not a findings array is a blocking finding.

Before running the gate, GitVault asks `probator inspect --json` whether the
installed policy binds a blocking hardening contract to the event, covers the
full hardening domain set, and names a command that runs that contract against
`{repo}` through the same resolved engine. An empty policy, an advisory-only or
unrelated row, a partial contract, or a contract outside the engine's own
profiles root cannot bless a publication boundary. GitVault pins one piece of
the engine's vocabulary deliberately: the hardening contract must be named
`security-enhancer`, a versioned coupling to Probator's installed policy. The
required domain set is not an admission constant - it is read from that
contract, and the row must cover every domain it declares. The current contract
declares `dependency_supply_chain`, `ci_workflow_authority`, `secret_handling`,
`transport_security`, `authz_defaults`, `container_runtime` and
`release_artifacts`; the rest of the contract vocabulary and profile layout are
the engine's own, and its published sources are the reference.

The engine child runs with a cleared, minimal environment: the account home, a
fixed search path and locale, plus the signed ruling ledger and anchor set by
GitVault. Provider keys, `SSH_AUTH_SOCK`, `PROBATOR_*` overrides and
`GITVAULT_*` are not inherited, so a caller cannot redirect the engine's policy
or lend it an ambient credential.

GitVault still keeps a signed `checkers.toml`. It no longer selects or executes
rows - that is Probator's policy - but its signature authorizes the external
engine, and an uncertified policy refuses a publication boundary before the
engine runs. `gitvault config sign` signs the routing table and this policy
together; only rows naming `probator` are admitted, a stale `gitvault-review`
row refuses the boundary, and no row is spawned.

GitVault passes its signed operator objection ledger
(`~/.config/gitvault/objections.toml`) and its public anchor to each invocation
as `PROBATOR_RULINGS_LEDGER` and `PROBATOR_RULINGS_ANCHOR`, so a ruling made
through `gitvault objection` applies to the engine's findings unchanged.

`gitvault checkers` is a read-through of `probator inspect`: the policy an
operator can see is the policy Probator actually enforces.

## Usage

```sh
gitvault resolve [DIR] [--json] [--ignore-assertion]
gitvault checkers [--json]                   # the policy Probator enforces
gitvault check --event pre-commit --directory DIR
gitvault check --event pre-push --directory DIR
gitvault check --event pr --pr-head BRANCH --pr-base BRANCH [--pr-number N]
gitvault check --event release --tag v1.2.0 --directory DIR
gitvault check --event working-tree --directory DIR  # uncommitted snapshot
gitvault records list [--json]               # what the gates did, newest first
gitvault records show RUN_ID [--json]
gitvault records verify                      # seal-chain integrity of the log
gitvault hook pre-commit                     # wired as core.hooksPath
gitvault push [git-push arguments]           # audit first, then push
gitvault api [--follow] <path> [...]         # read-only GitHub API proxy
gitvault run list [--json]                   # recent workflow runs
gitvault run view RUN_ID [--json]            # one run's metadata
gitvault run logs JOB_ID                     # a job's log text
gitvault run logs --run RUN_ID               # a run's logs archive (zip)
```

Log and download endpoints answer `302` rather than a body: GitHub hands the
log to a signed URL on a download host. `gitvault api --follow` (and `gitvault
run logs`, which follows by construction) performs that hop inside the
broker — the signed URL travels to curl through a private config pipe, never
argv or output, and the second hop carries no credential at all. `--follow`
is GET-only and streams the final response body straight to stdout, so a log
archive of any size moves with constant memory and zip bytes pass through
unmangled.

`gitvault push` exists because a bare `git push` connects to the remote
before it runs `pre-push` — the hook's ref lines are built from the remote's
advertised refs, which only the transport can supply — so the SSH credential
is spent before any audit runs. `gitvault push` synthesizes the same ref
lines locally (refspec arguments plus the remote's mirror refs), runs the
audit with no credential touched, and hands control to the real `git push`
only on a pass. That push's `pre-push` hook then re-audits the refs git
actually advertises; the hook's run, not the wrapper's pre-audit, is the
authoritative verdict. The pre-audit is advisory: it exists so a failing
audit is known before the credential is spent, and Probator may reuse its
sealed verdict for a head it has already judged. A stale mirror base is
re-audited at the hook, which can refuse mid-push. Audits never unlock the
vault anywhere: every biometric prompt is preceded by a `gitvault:` stderr
line naming the credential being spent.

The wrapper hands git the exact refspecs it audited instead of forwarding the
original argument vector, and forces `--no-follow-tags`, `--no-recurse-submodules`
and `--no-prune` on the real push; it also refuses a remote configured with
`remote.<name>.mirror=true`. Configuration therefore cannot add or delete a
ref. It resolves the push remote by git's own precedence
(`branch.<name>.pushRemote`, `remote.pushDefault`, `branch.<name>.remote`,
then `origin`) and uses that one name for both the mirror lookup and the push.
A bare push follows the configured `push.default` exactly: `simple` refuses a
missing or differently named upstream, `upstream` refuses a push remote that
is not the branch's upstream remote, and `matching` selects only heads the
remote advertises. Matching reads that advertised set with a read-only
`ls-remote` before the audit (a credential use, not a publication), and a
remote that cannot be read refuses instead of selecting from a stale mirror.
A deletion name is resolved against `refs/heads` and `refs/tags`; a name in
both namespaces, or in neither, refuses and asks for the full ref, so the
audit line and the refspec git receives name the same ref. `HEAD` as a source
resolves to the current branch, as git's own push does. It refuses
ref-selection options its pre-audit
cannot enumerate: `--no-verify` (which would skip the hook's authoritative
audit), `--stdin`, `--follow-tags`, `--prune`, `--mirror`, parameterised
`--branches`, `--recurse-submodules` and any option the plan does not model.
Push those refs explicitly, or use `--tags`, so every ref is in the reviewed
set. `--tags` is deliberately conservative: without the transport GitVault
cannot know which tags the remote already has, so it audits every local tag;
Probator then skips heads already reachable from a remote-tracking ref and
reuses its cursor for a head it has already judged, so already-published tips
do not start a new review.

`checkers.toml` sits beside `config.toml`; both are signed by
`gitvault config sign`. Rows must name `probator`; they are declarations, not
a command list GitVault executes.

Configuration defaults to `$XDG_CONFIG_HOME/gitvault/config.toml` (or
`~/.config/gitvault/config.toml` when `XDG_CONFIG_HOME` is unset); override
with `--config` or `GITVAULT_CONFIG`. The file is parsed strictly: an unknown key is
an error, not a silently ignored setting — a mistyped knob must not look like a
gate that is on. (Top-level keys must appear before the first `[table]` header,
as TOML requires.)

The removed in-tree review engine read `withheld-names.txt` and
`repo-deps.txt` from GitVault's config root. They are the engine's
machine-local lists now. `gitvault install` moves a list the engine lacks into
the account home's fixed configuration root when the install is armed, deletes
a byte-identical duplicate, and refuses a conflicting pair rather than silently
choosing one. When the install arms, lists the engine itself wrote under the
unarmed `$XDG_CONFIG_HOME` root move too, so arming does not silently change
which policy the engine reads; every target is read back before its source is
removed. GitVault itself never reads either file. The engine's
`XDG_CONFIG_HOME` is pinned to that same root so an operator's environment
cannot separate the lists from the engine that uses them.

## Publication boundaries

Two kinds of event exist. Hook events (`pre-commit`, `commit-msg`,
`prepare-commit-msg`, `pre-applypatch`, `pre-push`) are wired through
`core.hooksPath`; `pr` and `release` are not hooks at all — GitVault's own
operations run the audit before they reach GitHub:

| event | fires at | carries |
|---|---|---|
| `pre-push` | each pushed ref, via the hook | `push_refs` |
| `pr` | `pr create` and `pr merge` | `head`, `base` |
| `release` | `release create` | `tag`, `commit` |

`gitvault check --event working-tree` is also delegated, but it is not in this
table: it reviews the uncommitted tree on demand and publishes nothing, so it
neither spends a credential nor needs the routing table's blessing.

**`git push --no-verify` bypasses `pre-push`** — git offers no local counter to
it, so the hook alone is a convenience. `gitvault push` therefore refuses
`--no-verify` (and the unmodeled `--stdin`/`--follow-tags` selectors) instead of
forwarding them; a bare `git push --no-verify` remains outside the local
boundary. GitVault posts no commit status and asks no server to re-check the
audit, so a `--no-verify` push from any other checkout is outside the local
boundary too. It does not remove a server-side protection it cannot replace:
if an existing GitHub ruleset requires the removed `gitvault/audited` status,
keep it until you have an equivalent required check, then replace it
deliberately — do not drop the requirement first. `gitvault api` refuses
publication writes (contents, git refs, merges, `pulls`
create/merge/update-branch, releases, statuses) so the broker cannot move a
ref or publish around the gate either. The path is percent-decoded and matched
on the route the server will see; an encoded separator, an encoded route name,
or a percent escape that survives one decode refuses anywhere in the path,
including the owner/repo segments. A token is issued only after the routing
signature verifies, including a metadata read that happens before the audit.
The boundaries GitVault controls outright — `pr create`, `pr merge` and
`release create` — run the audit before the publishing request and refuse
without publishing. A merge fetches the request's head and reads its target
branch at that boundary when `--base` is omitted; a supplied `--base` is
verified against the request's own base after the audit and a mismatch refuses
before the merge. A create fetches the proposed head, fetches the base
from the remote that owns the target repository (refreshing that tracking
ref, and restoring the checkout's own `origin` ref afterwards in a fork
workflow), and reads the head again after the audit; a head that moved
refuses before the POST, and the request's reported head is checked against
the audited commit. Those read-only credential uses are not the publication.
An unknown `hook`/`check --event` spelling refuses rather than running no
gate and reporting success.

## Status

Implemented and tested: identity resolution, the local interception gates,
delegation to `probator gate-audit`, fail-closed engine handling, the
credential vault behind Touch ID, the SSH and signing proxies, the `pr` and
`release` publication gates, and run records.

Verified refusals include: no identity matches; an assertion conflicts with the
owner rule; the identity git would stamp differs from the routed one; an AI
attribution trailer; a rewritten or orphaned published ref; a Probator finding
at blocking severity; a missing or unreadable audit engine. The credential
model — what unlock grants, why the vault key is not the boundary, and where
credentials never go — is documented in
[`docs/security-model.md`](docs/security-model.md).

## Requirements

- **macOS** for the biometric gate: `gitvault unlock` and every credential use
  confirm through LocalAuthentication via the `gitvault-touchid` helper —
  build it with `swiftc tools/gitvault-touchid.swift -o ~/.local/bin/gitvault-touchid`.
  The helper path is fixed (`~/.local/bin/gitvault-touchid`), resolved from the
  account database rather than `HOME`, and not a `PATH` lookup: a path a caller
  could rewrite is a prompt the caller could self-answer. `gitvault install`
  immobilises an existing helper with `schg`; a helper installed afterwards is
  refused until the install is re-run, so a same-user process cannot replace it
  with `exit 0`. The trust check judges the helper path itself: a symlink
  planted there does not inherit the trust of a root-owned target.
- `git`, `curl`, `ssh-agent`/`ssh-add` for the SSH path.
- `probator` for publication audits, installed at the engine path
  `~/.local/bin/probator` documented by
  [that project](https://github.com/Unka-Malloc/Probator). An armed
  installation resolves only that path, and every publication boundary
  re-checks at run time that it is a regular, non-symlink file that is
  root-owned or carries the system immutable flag; a user-writable engine
  refuses even if it was installed after GitVault, and a link planted at the
  engine path is not judged by its target.
  `gitvault install` refuses to arm when no engine is present and immobilises
  one that is already there, so install order cannot silently leave an
  untrusted engine at the trusted path. The on-demand
  `check --event working-tree` snapshot is the one exception: it publishes and
  authorizes nothing, so an untrusted engine runs only there, with a warning.
  A debug build honours `GITVAULT_PROBATOR` with the `GITVAULT_ANCHOR` fixture;
  release builds compile the override out, and a sibling or `PATH` is consulted
  only while enforcement is unarmed.
  Probator is a separate tool with its own policy, profiles and evidence
  store; `gitvault install` never installs or copies it. Install or update the
  engine **before** running `gitvault install`: an engine placed afterwards is
  not immobilised and cannot carry a publication verdict until the next
  install. A boundary with no reachable engine refuses rather than passing.

## Run records

Every publication audit writes a record under
`$XDG_STATE_HOME/gitvault/runs` (or `~/.local/state/gitvault/runs`; override
with `record_dir`). The record holds the repository slug, the event, each
gate's verdict and seconds, and a bounded finding projection with control
characters stripped, credential shapes and assignments, personal identifiers
and private endpoints redacted, and absolute host paths replaced by
`[LOCAL_PATH]`. It never stores the work tree's path,
the raw engine message, or a finding's evidence. Concurrent audits of one
repository serialize on a lock under the same state root; a second invocation
waits for the first rather than entering the same audit.

The store is built to be read by something other than the person who ran the
gate. A record that cannot be written is reported on stderr and never refuses
an action: the run decided, and a diagnostic cannot un-decide it. The newest
200 runs (or 90 days) are kept. Runs that invoke no audit — a local commit with
only the identity gate — are not recorded.

`gitvault records list` shows the verdicts and what each gate cost in seconds;
`records show RUN_ID` adds what the gates printed. Both are read-only — no
vault, no network, no writes.

## License

Apache-2.0. See [LICENSE](LICENSE).
