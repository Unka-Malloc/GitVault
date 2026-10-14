# Security Enhancer

Security Enhancer is a blocking GitVault checker that reviews what a push, a
pull request, a merge or a release is about to publish, in two stages:

1. **Static checklist, entirely local** — rules evaluated on the immutable Git
   objects of the outgoing range. No repository code is executed and no
   repository script is parsed: a change never certifies itself. A regression
   refuses immediately and costs no tokens.
2. **Semantic, isolated Pi review** — only if stage one finds no regression: a
   fresh, unsaved Pi session over the same immutable range, on the
   provider/model/effort the synced `profile.json` declares, judging
   dependency_supply_chain / ci_workflow_authority /
   secret_handling / transport_security / authz_defaults / container_runtime /
   release_artifacts.

It only refuses. It never stages, edits, commits or fixes anything; the working
tree is byte-identical before and after a run. There is no skip flag and no
environment variable that widens the judgement.

## The two classes of static finding

**Regressions refuse the operation** — the shape is wrong on its own and the
repair is in the change: a manifest that moves without the lockfile kept beside
it; `pull_request_target`, `permissions: write-all`, a `uses:` pinned to a
branch (or a `docker://…:latest`), `curl … | sh`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
in CI; `USER root`, `--privileged`, `chmod 777`, a literal secret in
`ARG`/`ENV`, a `FROM` without a tag or with `:latest`; a removed `.gitignore`
rule that was protecting a key-shaped file, a removed `CODEOWNERS` line, a
changed registry source, a newly committed credential file; `verify=False` /
`InsecureSkipVerify` / `--insecure`, `DEBUG = True`, a CORS wildcard combined
with credentials.

**Surfaces are recorded, not refused** — a new install hook, a URL or git
dependency source, a private address, a plaintext endpoint. These are decisions
to be made rather than mistakes to be undone, and refusing them would block
ordinary work with no repair available. They are printed as `notice` lines,
listed in `security_context` inventory, and must be judged by the semantic
stage: an unjudged surface is an incomplete review, not a pass.

Neither class prints the matched text — a hit names the rule, the file and the
line, so an internal host name or a build-arg value never lands in a log.

## Install

```sh
python3 tools/security-enhancer/install.py            # first install
python3 tools/security-enhancer/install.py --update   # refresh payload and skill links
```

The installer creates the checker's private home
`~/.hermes/profiles/security-enhancer`, copies the payload (including the
`pi-bridge.ts` extension that forwards Pi tool calls into the Python
`--serve-tools` process), links the shared
skill directory `~/.agents/skills/security-enhancer` into every agent skill
directory it finds, and registers (or replaces in place) this entry in
`~/.config/gitvault/config.toml`:

```toml
[[checkers]]
name = "security-enhancer"
on = ["pre-push", "pr", "release"]
kind = "exec"
severity = "blocking"
timeout_secs = 0
```

Hook files are owned by `~/.git-hooks/_dispatch`; the installer never writes
them.

## Ranges

- `pre-push`: one range per pushed ref, against the published tip (or the
  merge-base with the default branch). A deletion publishes nothing; an
  already-published tip is skipped.
- `pr create`: base..head of the branch being proposed.
- `pr merge`: the merge request's head fetched into `FETCH_HEAD` (no ref is
  created), judged against its base.
- `release create`: **previous tag..release commit** — the content the release
  publishes. A release commit is normally already on the default branch, so a
  merge-base against the default branch would describe an empty range and the
  release would never be reviewed at all. With no previous release the tree is
  scanned whole (`fallback: snapshot-no-previous-release`).

## Boundaries an operator must know

- `git push --no-verify` skips the `pre-push` hook — git offers no counter to
  it. The boundaries that cannot be bypassed are the ones GitVault itself
  controls: `pr create`, `pr merge`, `release create`.
- `release delete` is not gated: destroying a release is a recovery action, not
  a publication.
- The semantic stage is not paid for twice: the static stage runs on every
  operation, but a range that already passed the semantic review is reused.

## Evidence and privacy

Credential containers (`.env`, `*.pem`, `*.key`, `secrets/`, `credentials*`,
`.ssh/**`, `.npmrc`, `*.db`) are judged by the static stage and never handed to
the semantic stage, because sending a key file to a cloud model is itself a
leak. Receipts are sanitized before they are written; reports live under
`~/.hermes/profiles/security-enhancer/security-enhancer-runs/` and the run
scope file is deleted when the run ends.

## Syncing a published profile

The prompt and skill this agent runs on are hosted in a profile registry (`GITVAULT_PROFILES_URL`; the default
points at a local development registry) and versioned by git tag. `install.py` seeds them once; after
that the registry is the source:

```sh
python3 tools/security-enhancer/install.py --pull                 # newest published version
python3 tools/security-enhancer/install.py --pull profile/security-enhancer/v2   # a pinned version
```

The download is checked file by file (and as a whole, by manifest) before
anything is written. A local edit to a synced document makes the checker refuse
the operation until it is synced again: a prompt that this machine edited is not
the prompt that was reviewed.
