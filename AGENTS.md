# Agent rules for GitVault

## Audit first, blessing after (hard rule)

Audits always precede authorization. At `pre-push`, `pr` and `release`, run
`probator gate-audit` and show its report before the operator is asked to
bless a verdict or release a credential — a blessing requested before the
evidence exists lets the audit be bypassed. Never reorder this. GitVault's
built-in identity, attribution and history gates are local and run first; when
one refuses, the operation ends there — nothing would publish, so the
delegated semantic audit is not started. Those local gates are never a
substitute for the audit when they pass. The one signature judged earlier is the
`checkers.toml` engine authorization: it must hold before the engine runs, and
it authorizes the executable rather than a verdict. `gitvault check
--event working-tree` runs the same engine over the uncommitted tree for an
on-demand look; it publishes nothing, so it is not a publication boundary.

GitVault runs no checker rows of its own. The checker set, contracts, reviewer
runs and receipts belong to the public
[Probator](https://github.com/Unka-Malloc/Probator) engine, which reads its own
installed configuration. GitVault does not parse that policy file or execute
its commands; it asks `probator inspect --json` whether a blocking hardening
contract under the engine's profiles root covers the event, declares the full
hardening domain set, and names a command that runs that contract against
`{repo}` through the same resolved engine. A row whose `repos` scope excludes
this repository or whose command names another tree is not coverage. The
engine still decides the findings. A policy that binds only a generic,
advisory or unrelated checker to the event cannot bless a publication
boundary. GitVault pins the hardening contract's name, `security-enhancer`,
as a documented versioned coupling; the required domain set is read from the
contract file the inspected row names, so the engine's added or renamed
domains are required rather than silently dropped. The refusal text names the
accepted contract and its documented domain set.

`checkers.toml` is a separate signed file: the authorization that this machine
may run the external audit engine. Only rows naming `probator` are admitted;
a stale `gitvault-review` row refuses the boundary. No row is executed. An
uncertified policy refuses a publication boundary **before** the engine runs,
because it authorizes the engine rather than blessing a verdict.
`gitvault check` obeys the same rule; there is no proposal exception.
`config sign` signs both files.

`gitvault check` runs the same interception and audit outside a hook, so a
gated event can be exercised before it happens.

## Trust boundary

`config.toml` is a signed routing table: which repository resolves to which
identity, backed by which account. The routing signature decides gated-event
verdicts and every credential-bearing surface. An uncertified routing table
never reaches a credential: the API broker re-checks the signature immediately
before issuing a token, so a metadata read inside a gate cannot spend the vault
while it waits for the audit report. The engine-authorization signature is
judged earlier, as the precondition that lets the audit run at all.

The audit engine is a separate executable with a separate policy and data
root. An armed installation trusts only the installed engine at
`~/.local/bin/probator`, and every publication boundary re-checks that the
path itself is a regular, non-symlink file that is root-owned or
system-immutable (`schg`); `gitvault install` immobilises an existing one and
refuses to arm without it. The on-demand working-tree
snapshot publishes nothing and is the only event allowed to warn and proceed
with an untrusted engine.
`PATH` and a build-tree sibling are consulted only while enforcement is
unarmed. `GITVAULT_PROBATOR` is a debug-build fixture seam, active only
together with the debug `GITVAULT_ANCHOR` fixture, and release binaries compile
it out. The engine child gets a cleared, minimal environment: the account
home, a fixed search path and locale, plus the signed ruling ledger and anchor
GitVault passes explicitly. The fixed search path puts the root-owned system
directories first, then the engine's own directory and `~/.local/bin` so the
engine can find its agent while a same-user process cannot shadow the `git`
helper the audit spawns. User-writable package-manager directories such as
`/usr/local/bin` and `/opt/homebrew/bin` are included only when the engine
itself resolves there, always after the system directories and never twice.
Provider keys, `SSH_AUTH_SOCK`, `PROBATOR_*` overrides and
`GITVAULT_*` are not inherited. GitVault reaches the
engine only through `probator gate-audit` and passes its signed
`objections.toml` and public anchor so operator rulings still apply. A missing
engine, a failing invocation, an unreadable findings array and an unknown
finding severity all refuse; none is a silent pass.

Concurrent GitVault audits of one repository are serialized by an exclusive
lock under the state root. Without it, two concurrent reviews can interfere
with the audit service's shared run state and one can end without a sealed
report. A live lock owner is waited for without an internal elapsed-time
cutoff: only its death (or an unreadable owner after a short grace) releases
the lock.

The removed in-tree review engine read `withheld-names.txt` and
`repo-deps.txt` from GitVault's config root. Those lists are Probator's now:
`gitvault install` moves a list Probator lacks into the engine's configuration
root (the account home's fixed configuration directory when the install is
armed), deletes a byte-identical duplicate, and refuses a conflicting pair
rather than silently choosing one. Arming also moves lists the engine wrote
under the unarmed XDG root, and reads each target back before removing its
source. GitVault never reads either file itself.

`gitvault push` audits the exact refs it will hand git, then passes those
refspecs explicitly instead of forwarding the original argument vector. It
refuses `--no-verify`, `--stdin`, `--follow-tags`, `--prune`, `--mirror`,
parameterised `--branches` selection, `--recurse-submodules` and any option the
plan does not model: each could select, add or delete a ref after the
pre-audit has run. It resolves the push remote by git's precedence
(`branch.<name>.pushRemote`, `remote.pushDefault`, `branch.<name>.remote`,
then `origin`) and uses that one name for both the mirror and the push, and it
follows `push.default` instead of synthesizing a destination git would refuse:
`simple` requires a same-named upstream on the pull remote, `upstream` requires
the push remote to be that upstream, and `matching` selects only heads the
remote advertises. Matching reads that advertised set with a read-only
`ls-remote` before the audit - a credential use, not a publication - and
refuses if the set cannot be read, rather than selecting from a stale mirror.
A deletion name is resolved against both `refs/heads` and `refs/tags`: a name
in both namespaces, or in neither, refuses and the operator must spell the
full ref, so the audit line and the refspec git receives always name the same
ref. A `HEAD` source resolves to the current branch's name, as git's own push
does. It also forces `--no-follow-tags`, `--no-recurse-submodules`
and `--no-prune` on the real push, and refuses a remote configured with
`remote.<name>.mirror=true`, so configuration cannot add or delete refs.

Local events the audit does not gate (`pre-commit`, `commit-msg`,
`prepare-commit-msg`, `pre-applypatch`) run only GitVault's deterministic
identity and attribution gates. They never spend a credential. `check` and
`hook` parse the event before anything else: an unknown spelling (for example
`pre_pus`) refuses instead of producing an empty pass at a boundary.

## Credential moments are labeled, never inside an audit

No audit code path unlocks the vault. Every biometric prompt is preceded by a
`gitvault:` stderr line naming the credential being spent; when one appears,
read it as the operation's own credential use, not as an auditor asking.

The known credential moments, in order: a bare `git push` prompts for SSH
before the hook because git connects to the remote (which supplies the hook's
ref lines) before hooks run — `gitvault push` audits first from the local
mirror, but the real `git push` then re-runs the audit against the refs the
remote advertises. That hook run is the authoritative verdict; the wrapper's
pre-audit is advisory and exists so a failing audit is known before the
credential is spent. A `push.default=matching` push is the exception: its ref
set is defined by the remote, so the wrapper reads the advertised heads
read-only before its audit. If the mirror base was stale, the hook audits the
actual advertised range and may refuse mid-push. Probator may reuse its sealed
verdict for a head it has already judged.
`pr merge` fetches `pull/N/head` and, when `--base` is omitted, reads the
request's target branch at the gate boundary before the audit; a supplied
`--base` is verified against the request's own base after the audit and a
mismatch refuses before the merge. `pr create` fetches the proposed head, fetches
the base from the remote that owns the target repository, and reads the head
again after the audit; a moved head refuses before the POST, and the created
request's reported head is checked against the audited commit. `release
create` likewise reads the remote tag it will publish. These are read-only
credential uses, not the publication itself. `api`/`ssh`/`config sign`/
`objection rule` prompt at use time. `ruleset create`/`set` and
`repo create`/`repo delete` ask for a fresh biometric naming the exact
object and outcome on every call (body-bearing requests also bind the
body's digest into the prompt); an open vault window never satisfies
them.

`gitvault update` runs the whole deploy as one command: it builds the
Probator checkout (`--probator`) and the GitVault checkout (`--self-src`,
defaulting to the running binary's own cargo checkout), rebuilds the Touch
ID helper when its source is newer, mints or replaces the signing anchor
(`--rekey`), then runs `install`'s privileged sequence with the engine and
helper as payloads, sets `core.hooksPath`, installs or refreshes the
checkers from `tools/*/contract.json`, and re-certifies the configuration
when a signature no longer verifies. It must run as the normal user - the
privileged steps escalate internally, and a whole-command sudo resolves the
account home to root's and deploys into the wrong tree.

## Verify

`cargo fmt && cargo clippy --all-targets && cargo test`
