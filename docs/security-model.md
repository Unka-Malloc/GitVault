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
window), and an HMAC tag keyed on the vault key. The default duration is
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
- **SSH** (`gitvault ssh`, invoked by git via `core.sshCommand`): the private
  key is decrypted inside gitvault and fed to a throwaway `ssh-agent` on a
  private socket; the real `ssh` sees only `SSH_AUTH_SOCK`. The passphrase is
  handed to `ssh-add` through an `SSH_ASKPASS` script deleted after use — never
  argv, never the key bytes.
- **Biometric confirmation is requested at credential use, not before.**
  Checkers run first and take the time they take; a window opened before an
  audit would expire during it. `ensure_open` is called at the moment a token
  or key is actually needed — after every blocking checker has passed — so a
  refused publication never touches the vault at all.
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

Checkers are a list in `$XDG_CONFIG_HOME/gitvault/checkers.toml` (or
`~/.config/gitvault/checkers.toml`) — the audit policy the routing table's
`audit_policy` key binds — outside every work
tree, so a repository cannot edit the terms it is judged by. The engine:

- runs each checker from a **neutral working directory** with a **curated
  environment** (`PATH`, `HOME`, `LANG`, `TMPDIR`, `GITVAULT_*` only) — ambient
  credentials and steering variables cannot reach the check;
- passes the repository as an absolute argument, never as cwd;
- is **fail-closed**: a blocking checker that is missing, times out, or exits
  non-zero refuses the action;
- runs every checker for the event and reports all results — no short-circuit
  on the first refusal.

Checker rows default to `kind = "exec"`: the declared command runs as-is
under the curated environment above. A custom `kind = "python"` entry gets
the engine's portable floor — `-P` and `PYTHONSAFEPATH=1`, which stop
`sys.path` shadowing but leave user site-packages and `PYTHONPATH` alone;
register the command with `-I` itself when the stronger isolation is wanted.

**Tracked repository hooks run.** The hook dispatcher also invokes a
checked-out `.githooks/<event>` when it is executable, so a repository's own
hooks keep working under GitVault. That is a declared exception to "nothing
is read from the repository": a cloned repo can ship executable hooks that
run as this user on commit and push. They cannot bypass the gate (the gate
runs first and a non-zero exit stops the chain), but the execution surface
exists — review `.githooks/` after cloning as you would `Makefile` or CI
scripts.

`git push --no-verify` bypasses the git `pre-push` hook — git offers no counter
to it, so the push hook alone is a convenience. Two environment variables on
the hook chain are bypasses of the same class and are listed here so the list
is complete: `GITVAULT_BIN` substitutes the dispatcher's gateway binary, and
`GIT_IDENTITY_GUARD_CHAINED=1` skips the gateway call entirely (it exists as
the chain's own recursion guard). Neither reaches `pr`/`release`, whose
checker runs happen inside the `gitvault` process before any credential is
unlocked. The boundaries that cannot be
bypassed are the ones GitVault controls: `pr create`, `pr merge` and
`release create` run the checker registry before any credential is unlocked
and refuse without contacting GitHub.

The remaining commands — `api`, `repo`, `issue` and `ssh` — are gated by
identity routing and the unlock window only; they do **not** run registered
checkers. A direct `gitvault api` write therefore reaches GitHub after the
identity and unlock gates, not after an audit. Treat them as credential-broker
operations, not audited publication paths.

## Run records

Every run that invokes a checker writes a record under
`$XDG_STATE_HOME/gitvault/runs` (or `~/.local/state/gitvault/runs`): the
repository slug, each checker's verdict and seconds, and captured output with
any home or temporary path replaced by `[LOCAL_PATH]`. The store is built to
be read by someone other than the person who ran the gate; a record that
cannot be written is reported but never refuses an action.

## Profile integrity

Audit-agent prompts (`policy.md`, `SKILL.md`, `profile.json`) are synced from a
profile registry and hash-checked. A local edit to a synced document makes the
checker refuse to run until it is synced again — a prompt edited on this
machine is not the prompt that was reviewed.

## Configuration attestation

`config.toml` is a routing table, not a secret: which repository resolves to
which identity, backed by which account. `checkers.toml` is the audit policy:
the commands a gate may execute. What both require is **integrity**, so the
control is a signature, not encryption — one signature per file, because the
two files answer different questions and are blessed at different moments.

- **Audit first, blessing after.** The policy signature means *these commands
  may execute*; the routing signature means *these identities may act*.
  Audits run under the certified policy before the routing table's blessing
  is asked: a gated event whose routing signature does not hold refuses only
  after the audit report has been shown, so the operator always certifies
  evidence already produced, never a blind precondition. An uncertified
  policy is never executed — its declared commands are shown, then refused —
  and an uncertified routing table never reaches a credential. A routing
  table that declares `audit_policy` also binds the policy file's existence:
  deleting `checkers.toml` cannot silence the audit, it refuses.
- **Signing key in the vault.** `gitvault config keygen` creates an ed25519
  pair; the private half is stored in `vault.enc` beside the credentials, so
  producing a signature costs the same biometric-gated window as releasing a
  key. `gitvault config sign` re-blesses both files after an intended edit
  (and migrates any `[[checkers]]` rows still sitting in `config.toml` into
  the policy file).
- **Public anchor, root-owned.** `config.pub` (an allowed-signers line, one
  `gitvault-config` principal) sits beside the configuration, but it only
  counts while root owns it. A same-user process can rewrite `config.toml`
  freely; it can neither re-sign it nor repoint the anchor. `gitvault install`
  performs the one privileged step: it transfers the anchor to `root:wheel`
  and sets the system-immutable flag on the binaries and the hooks directory,
  which resists the same owner without changing how the kernel launches them
  (a user-built binary chowned to root is refused by AppleSystemPolicy).
- **Reads stay free, writes are a ceremony.** Every credential-bearing load
  verifies the routing signature when enforcement is armed and fails closed
  on a missing or invalid sidecar; audit surfaces classify instead of
  refusing so the audit can precede the blessing. `gitvault config verify`
  reports both files' state for an operator.
- **Honest residual.** This does not change the keychain note above: a
  determined same-user process can read the vault key silently and could, in
  principle, decrypt the vault, extract the signing key, and forge a
  signature. The attestation removes casual and accidental mutation and makes
  tampering require a purpose-built attack rather than a text edit; it is not
  a Secure-Enclave-grade boundary. `gitvault config keygen` inside an open
  unlock window is, like every other gated operation, silent — the window is
  the unit of human confirmation.
