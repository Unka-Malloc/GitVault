# Agent rules for GitVault

## Audit first, blessing after (hard rule)

Audits always precede authorization. Run the certified audit policy and show
its report before the operator is asked for any signature, unlock or
credential — a blessing requested before the evidence exists lets the audit
be bypassed. Never reorder this, and never *enforce* checker rows from an
uncertified policy file: the rows declare arbitrary commands. `gitvault
check` is the exception by design — it audits a proposed policy so evidence
exists before its signature, marking the run uncertified — but the proposal
still cannot run arbitrary code: only rows invoking the trusted
`gitvault-review` runner execute — `baseline` or `run --contract` naming a
contract installed under the profiles root, with `--repo` bound to the
repository under review, no extra arguments, and no `GITVAULT_*` environment
overrides. At a publication boundary the proposal must also keep every
installed blocking reviewer contract covering the event. An empty policy
cannot bless a publication boundary at all.

## Trust boundary

`checkers.toml` (audit policy) and `config.toml` (routing table) are signed
independently. The policy signature decides whether checker commands may run;
the routing signature decides gated-event verdicts and every
credential-bearing surface. `audit_policy` in the routing table binds the
policy file's existence — deleting `checkers.toml` refuses rather than
silently running no audit.

Local events the policy does not gate (commits, messages) pass without a
blessing; gated events (`pre-push`, `pr`, `release`) run the audits, then
refuse an uncertified routing table — the refusal comes after the evidence is
on screen.

## Verify

`cargo fmt && cargo clippy --all-targets && cargo test`
