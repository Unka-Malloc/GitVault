# Money Saver

Money Saver is a blocking GitVault checker whose model runtime is Pi. The
provider, model and thinking effort come from the `runtime` block of the
synced `profile.json` — a published profile in the registry is the
configuration mapping, hash-checked like the policy, not a local guess.

Build/install GitVault with `pre-push` and `pr` event support and `timeout_secs=0` support,
then run `python3 tools/money-saver/install.py`. Installation copies policy and
tools outside repositories to the checker's private profile directory and
registers the checker. Each review launches `pi --mode json` with the
`pi-bridge.ts` extension; the bridge registers the checker's tools and
forwards each call to a long-lived Python `--serve-tools` process, so Python
keeps owning the evidence, the state and the receipt while Pi drives the
conversation. The system prompt is the synced `policy.md` plus the review
date — no HOME, scratch or profile paths. It reads only the declared
provider's `*_API_KEY` from the credential file at runtime; no keys are
copied or printed. GitVault retains its existing identity routing.

The maintained shared skill is installed at `$HOME/.agents/skills/money-saver`.
Existing local Agent skill directories link to this single installation. The
checker reads the same policy/catalog through symlinks. Use
`python3 tools/money-saver/install.py --update` to update an existing installation;
this preserves its credentials, profile configuration and GitVault registration.

The audit sits at the publication boundary, never on a local commit. The global
`pre-push` hook reviews the refs a push carries — the range each ref adds to what is
already published — once per push; a pull request is reviewed through GitVault's `pr`
path over its base..head range. A range whose push audit already passed is not paid
for again at pull-request time — and a receipt only counts when it was written by
the currently declared provider/model/effort. Beyond that range-identity reuse
there is no cached approval, extension-based Agent skip, repeated reviewer,
or wall-clock cancellation. An absent checker, provider error, incomplete review,
moved ref or blocking finding refuses the publication. An empty/delivery-only change
still receives a brief applicability review.

This guarantee applies to pushes and pull requests issued through the installed
hooks and GitVault commands. Git permits deliberate
`core.hooksPath` overrides and plumbing such as `commit-tree`; local hooks are not an
OS security boundary, and a remote pushed from another machine is out of a local
`pre-push` hook's reach — create its pull request through `gitvault pr`, which runs
the same checker. No server-side protection is installed.

The Agent has exactly three tools: immutable Git source context, catalogued official
public documents, and structured verdict submission. It has no shell, write, deployment,
production-query or delegation tools. Repository hooks/instructions are not loaded
by the Pi session. Source retrieval excludes credential containers/runtime data files and
redacts recognizable credentials and local identifiers; it is not a replacement for
a dedicated privacy audit. Do not stage private operational records as source code.

`policy.md` defines the six cost domains and blocking threshold. Findings require
file/line, trigger/evidence, impact, resource units before/after, a minimal remedy,
focused validation and successfully fetched official URLs. Cost estimates distinguish
inference from measurement, resource savings from invoice savings and allowances
from marginal charges. Unknown production volume uses formulas, not invented bills.
The checker reads no real operational usage or billing accounts.

`documents.json` is an operator-owned reference catalog. Fetch only relevant pages,
once per review, and page through the same response. Update this installed catalog
when adding a provider or when official URLs change. Missing material evidence means
incomplete. Pricing is retrieved at review time rather than embedded as fixed rates.

Sanitized reports, draft results and the Pi session are retained in the
profile's private run directory; review scope scratch files are removed.
Reports include review
usage so the review's own cost can be assessed. No report is committed to the project.

Verification: run `python3 -m unittest discover -s tests -p 'test_money_saver*.py'`
and `cargo test`. Python unit/integration tests use synthetic Git repositories, a stub
Pi transport and a real `--serve-tools` JSONL round-trip; GitVault tests exercise
actual hooks, refusal, `--no-verify`, partial
index scope and completion waits. A real model review is a separate live acceptance
operation, not an implementation test.

## Explicit full-service audit

`audit.py --manifest <manifest.json> --request <original-request.json> --output
<new-private-directory>` invokes the same Pi reviewer on selected
current source, including nonignored unstaged/untracked changes. The manifest maps
project labels to local source roots under `projects`. Optional `reuse` maps a
second selected project to its primary copy; byte-identical original source files share
evidence while distinct code remains independently inspectable. No Git index is
changed. Generated output, dependencies, runtime data and credential containers
are excluded; source endpoints and account identifiers are redacted before tools
can return them. The snapshot and report remain in the private output directory.

The request document carries the authorized conversation URL, exact original user
messages and the actual shared-page access result. The auditor must read these
originals and account for every project before submitting. Full-audit findings
must locate existing source lines that the auditor read. Each project and each cost
domain needs an explicit coverage decision. Unknown runtime coverage cannot pass.
Read-only source evidence is not a production measurement or a guarantee of future
bills. A full-audit report does not approve a later staged commit.

Full audits write compact tool progress and final status without a task deadline.
They do not deploy, mutate services, query production or automatically repeat a
failed audit. Resume a failed full audit with `audit.py --resume <run-directory>`:
the same snapshot, Pi session, read evidence, official document
cache and latest draft are retained. A successful report cannot be re-audited by
this command. Normal publication review continues to use only the operation's
resolved range. Report schemas specify coverage/status fields, project keys
and every finding field so the model can produce the correct format without
repeated guessing.

## Gate checks

| Check | Purpose and failure behavior |
| --- | --- |
| Range resolution | Review exactly what the operation publishes: each pushed ref's unpublished range, a pull request's base..head, deduplicated; an already-published tip is not re-reviewed. |
| Verdict reuse | A prior passing receipt for the same base..head, the same declared provider/model/effort and the same judged items stands; anything else is paid for again. |
| Source access | Only immutable Git objects; reject credential/runtime containers and traversal; never follow worktree symlinks. |
| Official catalog | Only operator-supplied public URLs; refuse cross-authority redirects; reuse one fetch per page. |
| Findings contract | Require concrete location, impact, before/after units, remedy, validation and retrieved sources. |
| Coverage | A pass requires all changed diffs and all six cost domains accounted for, with no blocker or unknown applicable coverage. |
| Single submission | Accept one verdict per run; no cached prior approvals. |
| Pi completion | Require successful engine exit and a structured verdict; provider errors/interruption refuse the publication. |
| Ref stability | A pushed ref that moved during review refuses the publication. |
| Report status | A model verdict is pending until the engine and snapshot checks pass; interrupted runs remain refused. |
| Full-audit originals and scope | Require original request read, every selected project accounted for and real inspected source locations; no unstated coverage pass. |

## Privacy verification

No live model request was sent during implementation verification. The default
agent runtime's system prompt was observed to inject machine identifiers
(profile, home and scratch paths); the dedicated review prompt omits them, and
the outbound prompt contract passes with no external transmission of local
paths. Source-sanitizer tests use synthetic placeholders — generated
credential, local-path and private-IP shapes — not genuine credentials or
customer records.

## Syncing a published profile

The prompt and skill this agent runs on are hosted in a profile registry (`GITVAULT_PROFILES_URL`; the default
points at a local development registry) and versioned by git tag. `install.py` seeds them once; after
that the registry is the source:

```sh
python3 tools/money-saver/install.py --pull                 # newest published version
python3 tools/money-saver/install.py --pull profile/money-saver/v2   # a pinned version
```

The download is checked file by file (and as a whole, by manifest) before
anything is written. A local edit to a synced document makes the checker refuse
the operation until it is synced again: a prompt that this machine edited is not
the prompt that was reviewed.
