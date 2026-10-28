# Security model

GitVault's guarantee is narrow and load-bearing: **an operation that needs a
credential cannot run without first passing the gates, and the credential itself
never reaches the caller.** Everything in the design serves one of those two
halves.

## What the vault is

`vault.enc` is a ChaCha20-Poly1305 blob holding API tokens and SSH key material,
keyed by account. The 32-byte vault key lives in the macOS login keychain as a
generic-password item (`gitvault-vault-key`, overridable via
`GITVAULT_KEYCHAIN_SERVICE` for tests). There is no credential file to copy.

## What unlock actually grants

`gitvault unlock` does not hand out anything. A biometric confirmation
(`gitvault-touchid`, a small Swift helper over LocalAuthentication) opens a
time-bounded window written to `$XDG_CONFIG_HOME/gitvault/unlock-until` (or
`~/.config/gitvault/unlock-until`) — a timestamp,
the machine's boot time (so a restored snapshot cannot resurrect an old
window), and an HMAC tag keyed on the vault key. The helper is the fixed
`~/.local/bin/gitvault-touchid`, resolved from the account database rather than
`HOME`; `gitvault install` gives it `schg`, and a helper path that is not a
regular, non-symlink file owned by root or carrying the system-immutable flag
is refused rather than executed. The default duration is
900 s; an operator wanting a longer window passes `gitvault unlock --ttl`,
an explicit act — the environment cannot size it, because a same-user process
must not stretch one confirmation indefinitely. `gitvault lock` closes the
window immediately.

During the window a caller may *ask* GitVault to perform an operation. The
window is a permission, not a possession:

- **The window does not identify the caller.** Any process running as this
  user can request operations while it is open. The gate bounds "how long
  after a human confirmed", not "who is asking"; who may act is decided per
  operation by the owner rules and the identity check, not by the window.
- **A window file cannot be fabricated.** The tag binds the record to the
  vault key, so minting a valid window requires the same capability as
  reading the vault directly — a process that could forge the record no
  longer needs the window. A process that cannot reach the vault key cannot
  stamp a record the gate accepts; missing or unverifiable state is locked,
  not assumed.
- **The vault keychain item has no biometric ACL.** macOS cannot put a
  per-read biometric requirement on a generic-password item created by a
  non-bundled CLI (the access-control variants are unavailable there). The
  temporal window is the gate; a process that reads the keychain item
  directly bypasses it, which is why the vault key alone is not treated as
  the security boundary — the boundary is that operations, not secrets, are
  what the credential holders receive.
- **The keychain write itself is an accepted limitation.** The vault key is
  stored with `security add-generic-password -w`, so the key bytes occupy the
  command's argv for the duration of that one call — observable by anything
  that can read the process table, on the same footing as reading the
  keychain item afterwards. The window is narrow (first `auth init`, or a
  later save where the item is missing), and the platform's argv-free write
  path (SecItemAdd) needs a bundled helper the CLI does not ship; it is
  recorded here so the "no credential in argv" claim below stays qualified:
  it holds for every credential the vault *hands out*, not for the one write
  that seeds it.

## Credentials never cross the process boundary

- **GitHub API** (`gitvault api`, `pr`, `release`, `repo`, `issue`): the token
  is decrypted inside the gitvault process and piped to `curl` on an anonymous
  stdin pipe as the `Authorization` header. It appears in no argv, no
  environment variable, no file. The caller receives the API response only.
  The header may reach exactly two origins: `api.github.com`, and
  `uploads.github.com` for the asset bodies `release create --asset` streams
  from disk after the audited release exists; every other absolute URL is
  refused before a credential is read, and the releases write surface stays
  refused to `gitvault api` on both origins.
- **SSH** (`gitvault ssh`, invoked by git via `core.sshCommand`): the private
  key is decrypted inside gitvault and fed to a throwaway `ssh-agent` on a
  private socket; the real `ssh` sees only `SSH_AUTH_SOCK`. The passphrase is
  handed to `ssh-add` through an `SSH_ASKPASS` script deleted after use — never
  argv, never the key bytes.
- **Biometric confirmation is requested at credential use, not before.**
  Semantic audits run before the publishing request and take the time they
  take; a window opened before an audit would expire during it. `ensure_open`
  is called at the moment a token or key is actually needed for the
  publication, so a refused publication never reaches the publishing
  credential. A merge's read-only head fetch and target-branch metadata read
  happen at the gate boundary before the audit and label themselves.
- **Reads are gated too.** A read of a private repository returns its
  contents, so an open window is required for reads as well as writes; there
  is no free path through the only egress.
- **Commit signing is deliberately not behind the window.** `gitvault sign`
  uses the stored signing key without biometric confirmation: a commit is
  local and reversible — amend, rebase and reset all discard it — so gating
  evidence would only tax the human while the decision that makes the commit
  permanent is the push, which is gated. The signing key still never leaves
  the process; the exclusion is about the window, not the boundary.

## The audit boundary

GitVault ships no audit engine. Semantic review - the policy, reviewer
contracts, agent prompts, run receipts and evidence - belongs to the public
[Probator](https://github.com/Unka-Malloc/Probator) engine and lives outside
every work tree. GitVault reaches it by executing `probator gate-audit` with
one JSON action per review object (`{kind, target, detail}`) and reading the
findings array it prints. `pre-push`, `pr` and `release` are publication
boundaries. A push action carries the hook's ref lines as `push_refs` and no
`range`, preserving the exact scope the push publishes. `gitvault check
--event working-tree` carries a `working-tree` action; it reviews the
uncommitted snapshot and publishes nothing, so it is an on-demand audit, not a
boundary.

The engine boundary is deliberately thin and fail-closed:

- GitVault never parses Probator's policy file or executes its checker rows;
  `probator inspect --json` is the machine form used to confirm that a
  blocking hardening contract lives under the engine's profiles root, covers
  the event, declares the full hardening domain set and runs that contract
  through the same resolved engine. The accepted contract identity is pinned
  to `security-enhancer` as a versioned coupling; the domain set itself is read
  from that contract, not copied into GitVault, so an engine-side addition is
  required rather than silently treated as missing coverage. A generic,
  advisory, decorative or partial row is not boundary coverage. The rest of
  the contract's vocabulary is the engine's published reference. Consumers
  migrating from GitVault's removed in-tree contract format should read the
  authoritative schema in the Probator repository at
  `docs/review-contract.schema.json` — the engine's document is the pinned
  replacement, versioned with the engine release this GitVault couples to.
- an armed installation finds the engine only at the installed path
  `~/.local/bin/probator`, which `gitvault install` immobilises with `schg`.
  `PATH` and a build-tree sibling are used only while enforcement is unarmed,
  and `GITVAULT_PROBATOR` is a debug-build fixture seam, active only together
  with the debug `GITVAULT_ANCHOR` fixture, and release binaries compile it
  out. The child's environment is cleared and rebuilt from the account
  home, a fixed search path and locale, plus the ruling ledger and anchor
  GitVault sets explicitly; provider keys, `SSH_AUTH_SOCK`, `PROBATOR_*` and
  `GITVAULT_*` are not inherited. The fixed search path puts the root-owned
  system directories first, then the engine's own directory and
  `~/.local/bin` so the engine can find its agent while a same-user process
  cannot shadow the `git` helper the audit spawns; user-writable
  package-manager directories (`/usr/local/bin`, `/opt/homebrew/bin`) are
  present only when the engine itself resolves there, always after the system
  directories and never twice. A missing binary is a refusal. In armed mode
  every publication boundary re-checks the resolved path: the engine must be a
  regular, non-symlink file that is root-owned or system-immutable (`schg`),
  not merely executable and not merely locked once at install time. `gitvault
  install` refuses to arm when
  no engine is present. The on-demand `working-tree` snapshot publishes and
  authorizes nothing; it is the only event that may run an untrusted engine,
  and it warns.
- a missing engine, a non-zero exit, an unreadable or empty output, a
  non-object finding or an unclassifiable finding severity is a blocking
  finding - the gate never reads silence as a pass;
- findings are re-rendered with terminal control characters removed,
  credential shapes and assignments, personal identifiers and private endpoints
  redacted, and home/temporary/absolute host paths replaced before they are
  printed or recorded. A finding's `path` must
  be repository-relative; an absolute path or one containing `..` is omitted.
  The engine's contract sends locations, not evidence, and GitVault does not
  preserve arbitrary engine bytes;
- the audit runs under the engine's own policy, not one a repository can edit;
- concurrent GitVault audits of one repository serialize on an exclusive lock
  under the state root (below);
- GitVault passes its signed operator objection ledger and public anchor to
  every invocation, so a ruling made through `gitvault objection` applies to
  the engine's findings unchanged;
- the machine-local `withheld-names.txt` and `repo-deps.txt` lists belong to
  the engine's config root. `gitvault install` moves a list Probator lacks into
  the account home's fixed configuration root when the install is armed,
  deletes a byte-identical duplicate, and refuses a conflicting pair. Arming
  also moves lists the engine itself wrote under the unarmed
  `$XDG_CONFIG_HOME` root, so the fixed-root hand-off does not silently drop
  them; each target is read back before its source is removed. The engine
  child's `XDG_CONFIG_HOME` is pinned to the same root, so an environment
  override cannot split the lists from the engine. GitVault never reads either
  file itself.

What remains in GitVault is the deterministic interception surface: the
identity-actual comparison, the AI-attribution gate and the push-history gate.
They run before the delegated audit, cost no audit work, and are built in
rather than registered. A blocking local gate ends the operation before the
delegated audit: nothing would publish, so there is no decision for the review
to inform. When they pass, the audit runs before any authorization request.

**Tracked repository hooks run.** The hook dispatcher also invokes a
checked-out `.githooks/<event>` when it is executable, so a repository's own
hooks keep working under GitVault. That is a declared exception to "nothing
is read from the repository": a cloned repo can ship executable hooks that
run as this user on commit and push. They cannot bypass the gate (the gate
runs first and a non-zero exit stops the chain), but the execution surface
exists — review `.githooks/` after cloning as you would `Makefile` or CI
scripts.

`git push --no-verify` bypasses the git `pre-push` hook — git offers no local
counter to it, so the hook alone is a convenience. `gitvault push` refuses
`--no-verify`, `--stdin`, `--follow-tags`, `--prune`, `--mirror`, parameterised
`--branches`, `--recurse-submodules` and any option it does not model, and it
passes git the exact refspecs the pre-audit saw. It resolves the remote with
git's own precedence and uses that same name for the mirror lookup and the
push, and it follows `push.default` exactly: `simple` refuses a missing or
differently named upstream, `upstream` refuses a push remote that is not the
branch's upstream remote, and `matching` selects only heads the remote
advertises. Matching reads that advertised set read-only before the audit and
refuses when it cannot, rather than selecting from the stale local mirror. A
deletion name is resolved against `refs/heads` and `refs/tags`; a name in both
namespaces, or in neither, refuses and requires the full ref, so the audited
ref and the refspec git receives are the same. It also forces
`--no-follow-tags`, `--no-recurse-submodules` and
`--no-prune`, and refuses a remote configured with
`remote.<name>.mirror=true`, so configuration cannot add or delete a ref after
the audit. The wrapper's pre-audit runs from the local mirror and is
advisory: the `pre-push` hook re-audits the refs git actually advertises, and
that hook run is authoritative. A stale mirror base is therefore re-audited at
the hook (which may refuse mid-push), and the engine may reuse its sealed
verdict for a head it has already judged. A bare `git push --no-verify` from
another checkout still leaves the local boundary.
GitVault publishes no commit status and asks no server to re-check the audit,
so that bypass is outside what this tool can observe. It does not remove a
server-side protection it cannot replace: if an existing GitHub ruleset
requires the removed `gitvault/audited` status, keep it until an equivalent
required check exists, then replace it deliberately; do not drop the
requirement first. A repository-local hook runs only after the gate, and it
cannot suppress a nested invocation: the dispatcher always calls the gate, so a
local hook that starts `git push` is audited like any other push. The boundaries
GitVault controls outright — `pr create`, `pr merge` and `release create` —
run the audit before the publishing request and refuse without publishing.
A merge fetches the request's head and, when `--base` is omitted, reads the
request's target branch from its metadata at that boundary before the audit.
That read spends the vault token, so the broker re-checks the routing
signature immediately before issuance; an unsigned or tampered table refuses
rather than reading private request data while it waits for the audit.
A supplied `--base` drives the audit as a cross-check and is then verified
against the request's own base after the audit, before the merge; a mismatch
refuses. A create fetches the
proposed head, fetches the base from the remote that owns the target
repository (refreshing it and restoring the checkout's own `origin` ref
afterwards in a fork workflow), reads the head again after the audit, and
checks the created request's reported head against the audited commit. These
are read-only credential uses, not the publication itself. An unknown
`hook`/`check --event` name refuses instead of producing an empty pass.

The remaining commands — `api`, `repo`, `issue` and `ssh` — do **not** reach
the audit engine, and `api` additionally *refuses* every request that
would publish: content writes (`contents`, `git/*`), ref-moving endpoints
(`merges`, `merge-upstream`, `pulls` create/merge/update-branch), releases,
commit statuses, and the GraphQL endpoint outright —
mutations there cannot be told from queries without parsing the body, so
`/graphql` is refused rather than classified. Every write under the CI
authority surface refuses as well: `dispatches`, and all of `actions/*`
(workflow dispatches, run reruns, approvals, cancellations and the rest) —
a privileged workflow can execute unreviewed code or publish artifacts on a
selected ref, so the whole subtree is closed to writes while reads such as
`GET /repos/o/r/actions/runs` stay open. The path is
percent-decoded and matched on the route the server will see; an encoded
separator, an encoded route name, or a percent escape that survives one decode
refuses anywhere in the path, including owner/repo. A token
is issued only after the routing signature verifies. Generic API access is
read-only: every mutating method refuses at the credential moment, because
any repository write - comments, labels, state flips included - emits
events that can trigger privileged workflows outside the audited path. The
only mutating requests the broker honors are marked by commands whose own
audit already ran (`pr create/merge`, `release create`) or by narrowly
justified removals of unaudited server-side state (draft-release and
moved-head pull-request cleanup).

## Concurrent audits

GitVault serializes audits of one repository on an exclusive lock under the
state root (a directory named from the origin slug, or the canonical git common
directory when there is no remote; reclaimed only when its recorded PID is
dead, with a short grace period for the creator to write it). A second
invocation waits for the first instead of entering the same audit, with no
internal elapsed-time cutoff: a live owner keeps the lock however long its
audit runs. Without that serialization two concurrent reviews can interfere
with the audit service's shared run state, and one can end without a sealed
report. The lock is the GitVault-side fix; serializing or resuming inside the
audit service is the service's own responsibility.

## Run records

Every publication audit writes a record under
`$XDG_STATE_HOME/gitvault/runs` (or `~/.local/state/gitvault/runs`): the
repository slug, each gate's verdict and seconds, and captured finding text with
any home or temporary path replaced by `[LOCAL_PATH]`. The store is built to
be read by someone other than the person who ran the gate; a record that
cannot be written is reported but never refuses an action.

## Configuration attestation

`config.toml` is a routing table, not a secret: which repository resolves to
which identity, backed by which account. What it requires is **integrity**, so
the control is a signature, not encryption. `checkers.toml` is a separate
signed policy: it authorizes the external audit engine. Only rows naming
`probator` are admitted at the gate; a stale `gitvault-review` row refuses the
boundary, and no row is executed. The checker set belongs to Probator.

- **Engine authorization.** The policy signature means *this machine may run
  the audit engine*. An uncertified policy refuses a publication boundary
  before the engine is invoked; it is a precondition on the executable, not a
  blessing of a verdict. `config sign` certifies both the routing table and
  this policy.
- **Audit first, blessing after.** The routing signature means *these
  identities may act*. Audits run under the audit engine before that signature
  is judged: a gated event whose routing signature does not hold refuses only
  after the audit report has been shown, so the operator always certifies
  evidence already produced, never a blind precondition. An uncertified
  routing table never reaches a credential.
- **Signing key in the vault.** `gitvault config keygen` creates an ed25519
  pair; the private half is stored in `vault.enc` beside the credentials, so
  producing a signature costs the same biometric-gated window as releasing a
  key. `gitvault config sign` re-blesses the routing table and the engine
  policy after an intended edit.
- **Public anchor, root-owned.** `config.pub` (an allowed-signers line, one
  `gitvault-config` principal) sits beside the configuration, but it only
  counts while root owns it. A same-user process can rewrite `config.toml`
  freely; it can neither re-sign it nor repoint the anchor. `gitvault install`
  performs the one privileged step: it transfers the anchor to `root:wheel`
  and sets the system-immutable flag on the binary and the hooks directory,
  which resists the same owner without changing how the kernel launches them
  (a user-built binary chowned to root is refused by AppleSystemPolicy).
  Probator is installed separately; GitVault does not ship it. `gitvault
  install` refuses to arm when no engine is present, and an engine already
  beside the binary is added to the locked enforcement surface. Every
  publication boundary then re-checks that the resolved engine is a regular,
  non-symlink file that is root-owned or system-immutable, so an engine
  installed after the last install cannot carry a verdict and a link planted at
  the engine path cannot borrow its target's authority. The on-demand working-tree snapshot publishes nothing and
  is the only event allowed to warn and proceed with an untrusted engine.
- **Reads stay free, writes are a ceremony.** Every credential-bearing load
  verifies the routing signature when enforcement is armed and fails closed
  on a missing or invalid sidecar; audit surfaces classify instead of
  refusing so the audit can precede the blessing. The API broker re-checks the
  signature immediately before it issues a token, so a metadata read inside a
  gate cannot spend the vault on an uncertified table. `gitvault config verify`
  reports both files' state for an operator.
- **Honest residual.** This does not change the keychain note above: a
  determined same-user process can read the vault key silently and could, in
  principle, decrypt the vault, extract the signing key, and forge a
  signature. The attestation removes casual and accidental mutation and makes
  tampering require a purpose-built attack rather than a text edit; it is not
  a Secure-Enclave-grade boundary. `gitvault config keygen` inside an open
  unlock window is, like every other gated operation, silent — the window is
  the unit of human confirmation.
