# GitVault

Holds the identity, intercepts the action, runs the checkers.

A repository cannot redefine the terms under which it is judged: identities,
ownership rules and the checker list all live outside every working tree.

## Why

An audit gate that runs from inside the repository it inspects is not a gate. If
the checker, its rules, or its entry point can be reached through the work tree,
the repository can change the verdict. Two concrete failure modes this design
removes:

* **Import shadowing.** Python puts the process working directory on `sys.path`.
  Running a checker from a work tree lets a file named `token.py` or `json.py`
  shadow a standard library module and break or subvert the check. Verified:
  `python3 -c 'import token'` from a directory containing `token.py` loads the
  repository's file; with `-P` it loads the standard library.
* **Rule substitution.** A checker's rules and its withheld names are read from
  machine state outside every work tree, never from the repository, so a pull
  request cannot supply the policy it is measured against.

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

`gitvault hook <event>` then runs the registered checkers for that event.

## Checkers are a list

Adding capability means adding a registration, never editing the engine. An
audit is one entry; a formatter, a commit-message policy or a build check are
others.

```toml
[[checkers]]
name = "privacy-audit"
on = ["pre-commit", "pre-push"]
kind = "python"          # injects -P / PYTHONSAFEPATH=1
severity = "blocking"    # default; "advisory" reports without blocking
timeout_secs = 120       # 0 waits for completion without a wall-clock deadline
command = ["python3", "-m", "scanner", "scan", "--directory", "{repo}"]
```

The engine applies the hardening, so an entry cannot forget it:

* checkers run with a **neutral working directory**, never the repository
* `{repo}` arrives as an **absolute argument**; the checker is never *inside* the tree
* the environment is **curated** (PATH, HOME, LANG, TMPDIR plus `GITVAULT_*`), so
  ambient credentials or steering variables cannot reach a checker
* **fail-closed**: a blocking checker that is missing, times out, or exits
  non-zero refuses the action

Placeholders: `{repo}`, `{repo_slug}`, `{event}`, `{identity}`, `{account}`,
`{email}`, `{actual_email}`, `{pr_base}`, `{pr_head}`, `{pr_number}`,
`{release_tag}`, `{release_commit}`. A placeholder an event does not carry
substitutes to the empty string, never to a previous event's value.

## Usage

```sh
gitvault resolve [DIR] [--json] [--ignore-assertion]
gitvault checkers [--json]
gitvault check --event pre-commit --directory DIR [--only NAME]
gitvault check --event release --tag v1.2.0 --directory DIR
gitvault check --event release --tag COMMIT_SHA --directory DIR # preflight before creating a tag
gitvault records list [--json]               # what the gates did, newest first
gitvault records show RUN_ID [--json]
gitvault hook pre-commit                     # wired as core.hooksPath
```

Configuration defaults to `$XDG_CONFIG_HOME/gitvault/config.toml` (or
`~/.config/gitvault/config.toml` when `XDG_CONFIG_HOME` is unset); override
with `--config` or `GITVAULT_CONFIG`. The file is parsed strictly: an unknown key is
an error, not a silently ignored setting — a mistyped knob must not look like a
gate that is on. (Top-level keys must appear before the first `[table]` header,
as TOML requires.)

## Publication boundaries

Two kinds of event exist. Hook events (`pre-commit`, `commit-msg`,
`prepare-commit-msg`, `pre-applypatch`, `pre-push`) are wired through
`core.hooksPath`; `pr` and `release` are not hooks at all — GitVault's own
operations run the registry before they reach GitHub:

| event | fires at | carries |
|---|---|---|
| `pre-push` | each pushed ref, via the hook | `GITVAULT_PUSH_REFS`, `{pr_*}` empty |
| `pr` | `pr create` and `pr merge` | `{pr_base}`, `{pr_head}`, `{pr_number}` |
| `release` | `release create` | `{release_tag}`, `{release_commit}` |

**`git push --no-verify` bypasses `pre-push`** — git offers no counter to it, so
a push-only gate is a convenience, not a wall. The boundaries that cannot be
bypassed are the ones GitVault controls: `pr create`, `pr merge` and
`release create` run the registry before any credential is unlocked and refuse
without touching the API.

## Status

Implemented and tested: identity resolution, the checker registry, the assertion
contract, fail-closed semantics, safe checker launch, the credential vault behind
Touch ID, the SSH and signing proxies, the `pr` and `release` publication gates,
run records, and the hosted Agent profiles.

Verified refusals include: no identity matches; an assertion conflicts with the
owner rule; a checker is missing or exceeds its timeout; a checker refuses a
push, a pull request, a merge or a release. The credential model — what unlock
grants, why the vault key is not the boundary, and where credentials never go —
is documented in [`docs/security-model.md`](docs/security-model.md).

## Requirements

- **macOS** for the biometric gate: `gitvault unlock` and every credential use
  confirm through LocalAuthentication via the `gitvault-touchid` helper —
  build it with `swiftc tools/gitvault-touchid.swift -o ~/.local/bin/gitvault-touchid`.
  The helper path is fixed (`~/.local/bin/gitvault-touchid`), not a `PATH`
  lookup: a path a caller could rewrite is a prompt the caller could
  self-answer. The checker engine itself is platform-neutral; anything that
  touches the vault needs a Mac.
- `git`, `curl`, `ssh-agent`/`ssh-add` for the SSH path.
- `gitvault-review` and `gitvault-audit-agent` on PATH for the bundled
  checkers under `tools/`; the semantic review stage
  uses OpenCode (`opencode acp`) through A4AA with the runtime declared in the synced profile.
  Python 3 only when a registered checker uses `kind = "python"`.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Agent profiles

The four audit checkers invoke `gitvault-audit-agent`. Each checker is
materialized as an AwP `Profile` and selected through an AwP `Binding`:
`money-saver`, `clean-auditor`, `security-enhancer`, and
`sustainable-maintainer` are distinct `profile:<id>` principals. The profile
carries its policy, model, effort and explicit published revision; the
binding carries the current review context. AwP owns role resolution and
instruction composition. The existing signed registry documents remain
the source, projected into AwP's native types without a second persisted
card copy or another profile merge implementation.

The installer writes each checker's declared AwP registry document — the
`a4aa-opencode` agent spec and the `audit` binding — which the runner loads
through AwP's standard registry rather than wiring a specific agent itself.
The engine's role projection supplies the checker's review tools as the
role's one MCP server, materialized onto the ACP lane by AwP. The review
engine owns scope, evidence and verdicts; a
completed turn alone cannot pass a gate. Receipts record the AwP principal and revision;
receipt reuse and unfinished-run selection also match the role and version.

The declared runtime is OpenCode on a free model,
`opencode/deepseek-v4.1-flash-free`. Each checker has an isolated XDG home
with no host configuration, plugins, skills or shell tools; the per-run
config denies edits, shell, web and sub-agent calls and enables only the
`opencode` provider wall. Authentication links the operator's existing
OpenCode sign-in files; no API key is copied into the checker or passed
through the runner request. Durable session bindings resume unfinished
reviews of the same target and runtime. Agent failures
refuse publication; there is no fallback or review deadline.
Report submission alone does not finalize a review. Recovery resumes the same
conversation after transport failure, or reuses verified completion evidence
when only local receipt finalization failed. Unfinished reviews retain their
progress independently of completed-receipt cleanup.

Build both binaries with `cargo build --release`. Install the runner beside
`gitvault` on PATH, then run `gitvault-review update --source tools/<checker>`
for each checker and sync each published OpenCode profile with
`gitvault-review pull --source tools/<checker>`. The workspace
uses `a4aa` and `a4aa-opencode` from `../../Adapter-For-All-Agents`, and
`agents-with-profiles` from `../../Agents-With-Profiles` with default
features disabled (the OpenCode adapter is the only adapter needed).
The runner does not access GitHub credentials or the vault.

The prompt and skill each audit agent runs on are hosted in a profile
registry (`GITVAULT_PROFILES_URL`; the default points at a local development
registry) and versioned by git tag. A machine installs a version explicitly:

```sh
gitvault-review pull --source tools/clean-auditor                          # newest published version
gitvault-review pull --source tools/clean-auditor --tag profile/clean-auditor/v2
```

A profile carries a name, a summary, a tool list, prose and a runtime
declaration — harness, provider and model for the semantic review.
There is no field for a command or an argument, so an edit made in a browser
can change what an agent is *told* and its declared model and reasoning
settings, never the executable it launches. This implementation accepts only
OpenCode on a free `opencode/`-namespaced model. The registry remains part of
the machine's security boundary. The download is verified file by file and as
a whole before anything is written, and a local edit to a synced document
makes the checker refuse the operation until it is synced again: a prompt
this machine edited is not the prompt that was reviewed. `gitvault-review install` seeds
the documents only on a machine that has never pulled; after that the
registry is the source.

## Run records

Every run that invokes a registered checker writes a record under
`$XDG_STATE_HOME/gitvault/runs` (or `~/.local/state/gitvault/runs`; override
with `record_dir`). `gitvault records list` shows the verdicts and what each
checker cost in seconds; `records show RUN_ID` adds what each checker printed.
Both are read-only — no vault, no network, no writes.

The store is built to be read by something other than the person who ran the
gate, so it holds the repository slug and never the work tree's path, and any
home or temporary path in captured output is replaced with `[LOCAL_PATH]`. A
record that cannot be written is reported on stderr and never refuses an
action: the run decided, and a diagnostic cannot un-decide it. The newest 200
runs (or 90 days) are kept. Runs that invoke no registered checker — the
identity gate alone on a local commit — are not recorded at all.

## Money Saver

[Money Saver](tools/money-saver/README.md) is an operations-cost checker running
an isolated OpenCode review on the runtime its synced profile declares. It is registered for
`pre-push`: the whole tree at each pushed ref's head is reviewed once per push, and
the engine's `pr` event judges the same checker at a pull request's head commit, so
both publication boundaries are covered without auditing local commits. The engine also
accepts `timeout_secs = 0`
for reviewers that must be allowed to finish. Installation, evidence requirements,
checks and privacy verification are documented with the checker.

## Clean Auditor

[Clean Auditor](tools/clean-auditor/README.md) is a blocking privacy and
confidentiality checker on `pre-push` and `pr`. A local deterministic scan runs
first over the outgoing snapshot (a refusal there costs no token); only if it
passes does an isolated OpenCode conversation judge privacy, business secrets,
operational data, machine paths, personal information and credentials. It never
modifies the repository and never reads a skip switch.

## Security Enhancer

[Security Enhancer](tools/security-enhancer/README.md) is a blocking hardening
checker on `pre-push`, `pr` and `release`. A static checklist reads the outgoing
Git objects — no repository code is executed and no repository script is parsed
— and refuses on a proven regression (a disabled TLS check, a floating CI
action, a world-writable step, a manifest moving without its lockfile, an ignore
rule that was protecting a key file). New execution or egress surfaces (an added
install hook, a URL dependency source, a private address, a plaintext endpoint)
are recorded and handed to the semantic stage instead of refused. Only if the
static stage finds no regression does an isolated OpenCode conversation judge the
seven hardening domains. A release is judged as everything since the previous
tag, because a release commit is normally already on the default branch.

## Sustainable Maintainer

[Sustainable Maintainer](tools/sustainable-maintainer/README.md) is a blocking
maintainability checker on `pre-push` and `pr`. A local hygiene scan refuses
conflict markers, merge artifacts and editor/OS junk before any token is spent;
only if it passes does an isolated OpenCode conversation judge the six domains —
structure, contracts, craft, duplication, tests and evolution — and return
advisory findings with architecture advice for long-term maintainability. It
never modifies the repository and never reads a skip switch.
