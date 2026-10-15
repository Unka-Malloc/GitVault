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

Checkers are a list in `$XDG_CONFIG_HOME/gitvault/config.toml` (or
`~/.config/gitvault/config.toml`) — outside every work
tree, so a repository cannot edit the terms it is judged by. The engine:

- runs each checker from a **neutral working directory** with a **curated
  environment** (`PATH`, `HOME`, `LANG`, `TMPDIR`, `GITVAULT_*` only) — ambient
  credentials and steering variables cannot reach the check;
- passes the repository as an absolute argument, never as cwd;
- is **fail-closed**: a blocking checker that is missing, times out, or exits
  non-zero refuses the action;
- runs every checker for the event and reports all results — no short-circuit
  on the first refusal.

The Python checkers run under `-I` (isolated mode): no `sys.path` shadowing
from the work tree, no user site-packages, no environment `PYTHONPATH`.

`git push --no-verify` bypasses the git `pre-push` hook — git offers no counter
to it, so the push hook alone is a convenience. The boundaries that cannot be
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
