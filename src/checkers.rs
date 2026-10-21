//! The checker registry: a list of external commands run before an action lands.
//!
//! Design constraints, all of which exist to keep repository content out of the
//! decision path:
//!
//! * **A neutral working directory.** Checkers run with cwd set to a temporary
//!   directory, never the repository. Python adds the process cwd to `sys.path`,
//!   so running from a work tree lets a file named `token.py` or `json.py` shadow
//!   the standard library and break - or subvert - the checker.
//! * **The repository arrives as an argument.** `{repo}` is substituted with an
//!   absolute path. The checker learns where the code is without ever being
//!   *inside* it.
//! * **Safe-path flags are injected, not requested.** For `kind = "python"` the
//!   launcher adds `-P` (or `PYTHONSAFEPATH=1` on older interpreters) so that even
//!   an accidental cwd cannot inject an import path.
//! * **A curated environment.** Nothing is inherited except PATH, HOME, TMPDIR
//!   and locale (LANG, LC_*); the GITVAULT_* run context is set explicitly, so
//!   ambient credentials or steering variables cannot reach a checker.
//! * **Fail-closed.** A blocking checker that is missing, times out, or exits
//!   non-zero stops the action.
//! * **Concurrent reads, serial writes.** Checkers run in parallel against the
//!   same repository snapshot - they only read it. Each still gets its own
//!   neutral directory, and outcomes are collected back in registry order so
//!   the report and run record stay deterministic and single-writer.
//!
//! Adding capability means adding a registry entry, not editing this file.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result};
use wait_timeout::ChildExt;

use crate::config::{Checker, Config, Event, Kind, Policy, Severity};
use crate::records;

#[derive(Debug, Clone)]
pub struct Context {
    pub event: String,
    pub repo_root: PathBuf,
    /// `Owner/Repo` from the origin remote, for tools that identify a repository
    /// by slug rather than by path.
    pub repo_slug: Option<String>,
    pub identity: String,
    pub account: Option<String>,
    /// The identity came from `rules.default` rather than a rule about this
    /// repository. Mirrored from the identity outcome for the same reason it is
    /// a field there: a display string is not a policy decision.
    pub via_default: bool,
    /// What the rules say should be used.
    pub expected_email: Option<String>,
    /// What git will actually stamp. Attribution follows this one.
    pub actual_email: Option<String>,
    /// For pre-push: the ref lines git supplies on stdin.
    pub stdin: Option<String>,
    /// For pre-push: the remote the push targets (the hook's argv), so a
    /// deletion is judged against that remote's mirror only - another
    /// remote's same-named mirror legitimately keeps the tip reachable.
    pub push_remote: Option<String>,
    /// For `pr`: the branch the request targets and the branch it proposes, as
    /// names the checker resolves in the local repository.
    pub pr_base: Option<String>,
    pub pr_head: Option<String>,
    /// For `pr merge`: the request number, so the checker can fetch its head
    /// when the branch is not checked out here.
    pub pr_number: Option<String>,
    /// For `release`: the tag being published and the commit it points at.
    pub release_tag: Option<String>,
    pub release_commit: Option<String>,
    /// For `commit-msg`/`prepare-commit-msg`: the message file git hands the
    /// hook (argv[0]) and its composition source (argv[1]: `message`,
    /// `template`, `merge`, `squash` or `commit` for `-c/-C` reuse).
    pub commit_message_file: Option<PathBuf>,
    pub commit_message_source: Option<String>,
}

impl Context {
    fn substitute(&self, raw: &str) -> String {
        raw.replace("{repo}", &self.repo_root.display().to_string())
            .replace("{repo_slug}", self.repo_slug.as_deref().unwrap_or(""))
            .replace("{event}", &self.event)
            .replace("{identity}", &self.identity)
            .replace("{account}", self.account.as_deref().unwrap_or(""))
            .replace("{email}", self.expected_email.as_deref().unwrap_or(""))
            .replace("{actual_email}", self.actual_email.as_deref().unwrap_or(""))
            .replace("{pr_base}", self.pr_base.as_deref().unwrap_or(""))
            .replace("{pr_head}", self.pr_head.as_deref().unwrap_or(""))
            .replace("{pr_number}", self.pr_number.as_deref().unwrap_or(""))
            .replace("{release_tag}", self.release_tag.as_deref().unwrap_or(""))
            .replace(
                "{release_commit}",
                self.release_commit.as_deref().unwrap_or(""),
            )
    }
}

#[derive(Debug)]
pub struct CheckerOutcome {
    pub name: String,
    pub severity: Severity,
    pub outcome: OutcomeKind,
    /// How long this checker took, for the run record and the operator's sense
    /// of what a gate costs.
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    Passed,
    Failed(i32),
    Timeout,
    CouldNotRun(String),
    /// A later-phase checker the gate short-circuited: not a failure - the
    /// refusal was already decided - and not a pass, just evidence it never
    /// spent its tokens.
    Skipped,
}

impl OutcomeKind {
    fn is_failure(&self) -> bool {
        !matches!(self, Self::Passed | Self::Skipped)
    }

    pub(crate) fn label(&self) -> String {
        match self {
            Self::Passed => "passed".into(),
            Self::Failed(code) => format!("failed (exit {code})"),
            Self::Timeout => "timed out".into(),
            Self::CouldNotRun(why) => format!("could not run: {why}"),
            Self::Skipped => "skipped: an earlier phase refused".into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub outcomes: Vec<CheckerOutcome>,
}

fn count_blocking(outcomes: &[CheckerOutcome]) -> usize {
    outcomes
        .iter()
        .filter(|o| o.severity == Severity::Blocking && o.outcome.is_failure())
        .count()
}

impl Report {
    pub fn blocking_failures(&self) -> usize {
        count_blocking(&self.outcomes)
    }

    pub fn exit_code(&self) -> std::process::ExitCode {
        if self.blocking_failures() > 0 {
            std::process::ExitCode::from(1)
        } else {
            std::process::ExitCode::SUCCESS
        }
    }

    pub fn print(&self, event: &str) {
        if self.outcomes.is_empty() {
            eprintln!("gitvault: no checkers registered for {event}");
            return;
        }
        for o in &self.outcomes {
            let mark = match (&o.outcome, o.severity) {
                (OutcomeKind::Passed, _) => "\x1b[32m✓\x1b[0m",
                (OutcomeKind::Skipped, _) => "\x1b[2m-\x1b[0m",
                (_, Severity::Advisory) => "\x1b[33m!\x1b[0m",
                _ => "\x1b[31m✗\x1b[0m",
            };
            eprintln!(
                "gitvault: {mark} {:<22} {} [{}]",
                o.name,
                o.outcome.label(),
                o.severity
            );
            // Forward the checker's own output. Checkers are required to keep
            // exact matched values out of stdout/stderr - evidence belongs in
            // their private local store - so this is safe to relay.
            for line in o.stdout.lines().filter(|l| !l.trim().is_empty()) {
                eprintln!("    {line}");
            }
            for line in o.stderr.lines().filter(|l| !l.trim().is_empty()) {
                eprintln!("    {line}");
            }
        }
        let failed = self.blocking_failures();
        if failed > 0 {
            eprintln!("gitvault: {failed} blocking checker(s) failed - action refused");
        }
    }
}

/// The built-in gate that no registry entry can replace or disable.
///
/// The rules answer "which identity SHOULD act here". This answers "which identity
/// WILL be stamped on the commit", and the two are not the same thing: `git -c
/// user.email=...`, a repo-local override, or a stray `includeIf` can silently make
/// git use a different address than the rules resolved to. Attribution on GitHub
/// follows the address, so a mismatch means the commit lands under the wrong
/// account even though every rule reported success.
///
/// Runs for pre-commit and pre-push, and is skipped by `--only` so an individual
/// checker can still be exercised in isolation.
///
/// `routing_certified` is false while the routing table's signature is broken
/// or missing under an armed anchor. The gate's expectation comes from that
/// table, so an uncertified expectation cannot hold a commit to anything - the
/// mismatch is still reported, as advisory, but nothing local is refused on an
/// uncertified word.
pub fn identity_gate(ctx: &Context, routing_certified: bool) -> Option<CheckerOutcome> {
    if !matches!(ctx.event.as_str(), "pre-commit" | "pre-push") {
        return None;
    }
    // A fallback route is not a decision about this repository, so there is nothing
    // here to hold a commit to.
    //
    // Without this the gate demanded the default identity's address from every
    // repository that matched no rule - a temporary fixture, a colleague's checkout,
    // any directory with a `git init` in it. That is not a guard against a wrong
    // identity; it is the invention of a requirement that no rule expressed. The API,
    // SSH and signing paths have always refused the fallback for the same reason.
    if ctx.via_default {
        return None;
    }

    let expected = ctx.expected_email.as_deref().unwrap_or("");
    let actual = ctx.actual_email.as_deref().unwrap_or("");
    if expected.is_empty() {
        return None;
    }

    let outcome = if actual.is_empty() {
        OutcomeKind::CouldNotRun(
            "git has no user.email configured; the commit would be unattributed".into(),
        )
    } else if actual.eq_ignore_ascii_case(expected) {
        OutcomeKind::Passed
    } else {
        OutcomeKind::Failed(-1)
    };

    Some(CheckerOutcome {
        name: "identity-actual".to_string(),
        severity: if routing_certified {
            Severity::Blocking
        } else {
            Severity::Advisory
        },
        outcome,
        duration_ms: 0,
        stdout: if actual.eq_ignore_ascii_case(expected) {
            format!("git will attribute this to {actual}")
        } else {
            format!(
                "git would attribute this to '{actual}' but identity '{}' expects '{expected}'\n\
                 fix: git config user.email {expected}   (or unset the override)",
                ctx.identity
            )
        },
        stderr: String::new(),
    })
}

/// The shared stage-1 evidence file for one check invocation. Every checker
/// the run spawns resolves and scans into the same document; keyed by the
/// check process so two operations never read each other's evidence.
fn stage1_evidence_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "gitvault-stage1-evidence-{}.json",
        std::process::id()
    ))
}

/// Run the certified policy against the snapshot. `policy` must come from
/// `Policy::load_certified` - this function executes its commands verbatim and
/// never re-checks the signature itself. `routing_sig` is the routing table's
/// signature state: uncertified routing downgrades the built-in identity gate
/// to advisory so nothing local is refused on an uncertified expectation, and
/// the state is stamped on the run record as evidence.
pub fn run_all(
    cfg: &Config,
    policy: &Policy,
    ctx: &Context,
    routing_sig: &crate::configsig::SigState,
    policy_sig: &crate::configsig::SigState,
    only: Option<&str>,
) -> Result<Report> {
    let routing_certified = !matches!(routing_sig, crate::configsig::SigState::Invalid(_));
    let event = Event::parse(&ctx.event)?;
    let selected: Vec<&Checker> = policy
        .checkers_for(event)
        .into_iter()
        .filter(|c| only.is_some() || c.applies_to(ctx.repo_slug.as_deref(), &ctx.repo_root))
        .filter(|c| only.is_none_or(|name| c.name == name))
        .collect();
    if let Some(name) = only {
        anyhow::ensure!(
            !selected.is_empty(),
            "no checker named '{name}' is registered for {}",
            event.name()
        );
    }
    // The record spans the whole run, so it starts before the first checker.
    let run = records::begin(cfg, selected.len());
    // Fresh shared evidence for this run: a stale file left by a crashed
    // check must not feed this one.
    let evidence = stage1_evidence_path();
    let _ = std::fs::remove_file(&evidence);
    let mut report = Report::default();

    if only.is_none()
        && let Some(gate) = identity_gate(ctx, routing_certified)
    {
        report.outcomes.push(gate);
    }
    if only.is_none()
        && let Some(gate) = crate::attribution::gate(ctx)
    {
        report.outcomes.push(gate);
    }
    if only.is_none() {
        report.outcomes.extend(crate::history::gates(ctx));
    }

    // Checkers run per phase: rows sharing a phase run concurrently, phases
    // ascend, and a blocking checker failure short-circuits every later
    // phase - a refusal that is decided never spends another checker's
    // tokens. Built-in gate outcomes deliberately do not short-circuit: a
    // refused push still wants its audits on the record, and they cost
    // nothing. Joining in declaration order keeps the report deterministic
    // and the run record single-writer. The safe-path probe runs once here
    // rather than once per thread.
    let safe_path = python_safe_path_flag();
    let mut phases: std::collections::BTreeMap<u32, Vec<&Checker>> =
        std::collections::BTreeMap::new();
    for checker in &selected {
        phases.entry(checker.phase).or_default().push(*checker);
    }
    let mut outcomes: Vec<CheckerOutcome> = Vec::with_capacity(selected.len());
    for group in phases.values() {
        if count_blocking(&outcomes) > 0 {
            outcomes.extend(group.iter().map(|checker| CheckerOutcome {
                name: checker.name.clone(),
                severity: checker.severity,
                outcome: OutcomeKind::Skipped,
                duration_ms: 0,
                stdout: String::new(),
                stderr: String::new(),
            }));
            continue;
        }
        let mut ran: Vec<CheckerOutcome> = std::thread::scope(|s| {
            group
                .iter()
                .map(|&checker| s.spawn(move || run_one(cfg, ctx, checker, safe_path)))
                .collect::<Vec<_>>()
                .into_iter()
                .zip(group.iter())
                .map(|(handle, checker)| {
                    handle.join().unwrap_or_else(|_| CheckerOutcome {
                        name: checker.name.clone(),
                        severity: checker.severity,
                        outcome: OutcomeKind::CouldNotRun("checker thread panicked".into()),
                        duration_ms: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                })
                .collect()
        });
        outcomes.append(&mut ran);
    }
    report.outcomes.append(&mut outcomes);
    if let Some(run) = run {
        records::finish(cfg, run, ctx, &report, routing_sig, policy_sig);
    }
    let _ = std::fs::remove_file(&evidence);
    Ok(report)
}

fn run_one(
    _cfg: &Config,
    ctx: &Context,
    checker: &Checker,
    safe_path: Option<&'static str>,
) -> CheckerOutcome {
    let started = std::time::Instant::now();
    let fail = |why: String| CheckerOutcome {
        name: checker.name.clone(),
        severity: checker.severity,
        outcome: OutcomeKind::CouldNotRun(why),
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
    };

    // A `verify` row first settles what it exercises: the publication
    // candidate, never the possibly-dirty working tree.
    let verify_ref = if checker.kind == Kind::Verify {
        match verify_ref(ctx) {
            Ok(None) => {
                return CheckerOutcome {
                    name: checker.name.clone(),
                    severity: checker.severity,
                    outcome: OutcomeKind::Passed,
                    duration_ms: started.elapsed().as_millis() as u64,
                    stdout: "no new revision publishes here; verification is vacuous".into(),
                    stderr: String::new(),
                };
            }
            Ok(Some(reference)) => Some(reference),
            Err(why) => return fail(why),
        }
    } else {
        None
    };
    let substitute = |raw: &str| {
        ctx.substitute(raw)
            .replace("{verify_head}", verify_ref.as_deref().unwrap_or(""))
    };

    let program = match checker.command.first() {
        Some(p) => substitute(p),
        None => return fail("empty command".into()),
    };
    let mut args: Vec<String> = checker.command[1..].iter().map(|a| substitute(a)).collect();

    // Language-specific hardening, applied by the engine so the registry entry
    // cannot forget it.
    if checker.kind == Kind::Python {
        match safe_path {
            Some(flag) => args.insert(0, flag.to_string()),
            None => { /* PYTHONSAFEPATH is set in the environment below */ }
        }
    }

    // Neutral cwd. This is the load-bearing line of the whole module - and with
    // checkers running concurrently it must be unique per checker, or the
    // cleanup below would remove a sibling's working directory mid-review.
    let neutral = match tempdir(&checker.name) {
        Ok(d) => d,
        Err(e) => return fail(format!("no neutral working directory: {e}")),
    };

    // The single exception: `verify` must exercise the candidate content
    // itself, so it gets a detached worktree of the resolved revision inside
    // its neutral directory. The command still comes from the signed policy;
    // the repository never names its own test.
    let mut worktree: Option<PathBuf> = None;
    if let Some(reference) = &verify_ref {
        let staged = neutral.join("candidate");
        match Command::new("git")
            .arg("-C")
            .arg(&ctx.repo_root)
            .args(["worktree", "add", "--detach"])
            .arg(&staged)
            .arg(reference)
            .output()
        {
            Ok(out) if out.status.success() => worktree = Some(staged),
            Ok(out) => {
                let _ = std::fs::remove_dir_all(&neutral);
                return fail(format!(
                    "cannot stage the candidate worktree: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&neutral);
                return fail(format!("cannot stage the candidate worktree: {e}"));
            }
        }
    }
    let run_dir = worktree.clone().unwrap_or_else(|| neutral.clone());

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .current_dir(&run_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A curated environment, as the module docs promise: the child starts
        // empty and regains only the whitelist below - ambient credentials,
        // PYTHONPATH, proxy and provider-steering variables cannot reach it.
        .env_clear();
    // The documented inheritance: PATH and locale, plus HOME and TMPDIR for
    // the child to find its own files. The GITVAULT_* context is contributed
    // explicitly underneath, never inherited - a same-named ambient variable
    // must not steer the checker.
    for (key, value) in std::env::vars_os() {
        if key.to_str().is_some_and(|k| {
            matches!(k, "PATH" | "HOME" | "TMPDIR" | "LANG")
                || k.starts_with("LC_")
                // A build or test legitimately reaches the network through the
                // machine's proxy; the command itself is already signed policy.
                || (checker.kind == Kind::Verify
                    && matches!(
                        k.to_ascii_uppercase().as_str(),
                        "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
                    ))
        }) {
            cmd.env(key, value);
        }
    }
    if let Some(reference) = &verify_ref {
        cmd.env("GITVAULT_VERIFY_HEAD", reference);
    }
    cmd.env("GITVAULT_EVENT", &ctx.event)
        // The shared deterministic evidence for this run: every checker the
        // run spawns gets the same file, so range resolution and the
        // withheld/credential sweep happen once per operation instead of once
        // per reviewer. Keyed by process, so concurrent checks never share.
        .env("GITVAULT_STAGE1_EVIDENCE", stage1_evidence_path())
        .env("GITVAULT_IDENTITY", &ctx.identity)
        .env("GITVAULT_REPO", ctx.repo_root.display().to_string())
        .env(
            "GITVAULT_REPO_SLUG",
            ctx.repo_slug.clone().unwrap_or_default(),
        )
        .env("GITVAULT_ACCOUNT", ctx.account.clone().unwrap_or_default())
        .env(
            "GITVAULT_EMAIL",
            ctx.expected_email.clone().unwrap_or_default(),
        )
        .env(
            "GITVAULT_ACTUAL_EMAIL",
            ctx.actual_email.clone().unwrap_or_default(),
        )
        .env("PYTHONSAFEPATH", "1");

    // Partial commits use a temporary index. Preserve that exact review scope
    // when changing to the neutral checker directory.
    if let Some(index) = std::env::var_os("GIT_INDEX_FILE") {
        let index = PathBuf::from(index);
        cmd.env(
            "GIT_INDEX_FILE",
            if index.is_absolute() {
                index
            } else {
                ctx.repo_root.join(index)
            },
        );
    }
    if let Some(refs) = &ctx.stdin {
        cmd.env("GITVAULT_PUSH_REFS", refs);
    }
    if let Some(base) = &ctx.pr_base {
        cmd.env("GITVAULT_PR_BASE", base);
    }
    if let Some(head) = &ctx.pr_head {
        cmd.env("GITVAULT_PR_HEAD", head);
    }
    if let Some(number) = &ctx.pr_number {
        cmd.env("GITVAULT_PR_NUMBER", number);
    }
    if let Some(tag) = &ctx.release_tag {
        cmd.env("GITVAULT_RELEASE_TAG", tag);
    }
    if let Some(commit) = &ctx.release_commit {
        cmd.env("GITVAULT_RELEASE_COMMIT", commit);
    }
    for (k, v) in &checker.env {
        cmd.env(k, substitute(v));
    }

    // A staged worktree must leave through `git worktree remove`, not just
    // directory deletion, or it leaks its administrative entry under .git.
    let cleanup = |worktree: &Option<PathBuf>| {
        if let Some(path) = worktree {
            let _ = Command::new("git")
                .arg("-C")
                .arg(&ctx.repo_root)
                .args(["worktree", "remove", "--force"])
                .arg(path)
                .output();
        }
        let _ = std::fs::remove_dir_all(&neutral);
    };

    eprintln!("gitvault: running {}…", checker.name);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            cleanup(&worktree);
            return fail(format!("{program}: {e}"));
        }
    };

    if let Some(mut stdin) = child.stdin.take()
        && let Some(data) = &ctx.stdin
    {
        let _ = stdin.write_all(data.as_bytes());
    }
    // Dropping closes the pipe; a checker that reads stdin sees EOF.

    // Drain both pipes on separate threads. Reading them after the wait would
    // deadlock as soon as a checker writes more than a pipe buffer holds.
    let mut out_pipe: Option<Box<dyn std::io::Read + Send>> =
        child.stdout.take().map(|p| Box::new(p) as _);
    let mut err_pipe: Option<Box<dyn std::io::Read + Send>> =
        child.stderr.take().map(|p| Box::new(p) as _);
    let out_reader = std::thread::spawn(move || read_all(&mut out_pipe));
    let err_reader = std::thread::spawn(move || read_all(&mut err_pipe));

    let waited = if checker.timeout_secs == 0 {
        child.wait().map(Some)
    } else {
        child.wait_timeout(Duration::from_secs(checker.timeout_secs))
    };
    let status = match waited {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            cleanup(&worktree);
            return CheckerOutcome {
                name: checker.name.clone(),
                severity: checker.severity,
                outcome: OutcomeKind::Timeout,
                duration_ms: started.elapsed().as_millis() as u64,
                stdout: String::new(),
                stderr: format!("exceeded {}s", checker.timeout_secs),
            };
        }
        Err(e) => {
            cleanup(&worktree);
            return fail(format!("wait failed: {e}"));
        }
    };

    // Killing or exiting closes the pipes, so the readers terminate.
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    cleanup(&worktree);

    let outcome = if status.success() {
        OutcomeKind::Passed
    } else {
        OutcomeKind::Failed(status.code().unwrap_or(-1))
    };

    CheckerOutcome {
        name: checker.name.clone(),
        severity: checker.severity,
        outcome,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
    }
}

/// The revision a `verify` checker must exercise: the publication candidate,
/// never the possibly-dirty working tree. A push takes its pushed head
/// (preferring the checked-out branch), a request its proposed head, a
/// release its tagged commit; anything else verifies `HEAD`.
///
/// `Ok(None)` is vacuous - nothing on this event publishes a new revision, so
/// there is no candidate to test. `Err` means a candidate should exist but
/// cannot be resolved, which fails closed like any unverifiable evidence.
fn verify_ref(ctx: &Context) -> Result<Option<String>, String> {
    let rev = |r: &str| -> Option<String> { crate::git::commit_at(&ctx.repo_root, r) };
    match ctx.event.as_str() {
        "pre-push" => {
            let heads: Vec<String> = ctx
                .stdin
                .as_deref()
                .unwrap_or("")
                .lines()
                .filter_map(|line| line.split_whitespace().nth(1))
                .filter(|sha| !sha.trim_matches('0').is_empty())
                .map(str::to_string)
                .collect();
            if heads.is_empty() {
                return Ok(None);
            }
            let current = rev("HEAD");
            Ok(Some(
                heads
                    .iter()
                    .find(|h| Some(h.as_str()) == current.as_deref())
                    .unwrap_or(&heads[0])
                    .clone(),
            ))
        }
        "pr" => {
            if let Some(head) = ctx.pr_head.as_deref().and_then(&rev) {
                return Ok(Some(head));
            }
            // A merge names only a request number: fetch its head the same
            // way the review range does, so the row verifies the merge head
            // rather than whatever stale FETCH_HEAD or checkout happens to
            // be. Falling back to HEAD would attest unreviewed content -
            // unresolvable is a refusal, matching the release arm.
            if let Some(number) = ctx.pr_number.as_deref().filter(|n| !n.is_empty()) {
                let fetched = Command::new("git")
                    .arg("-C")
                    .arg(&ctx.repo_root)
                    .args([
                        "fetch",
                        "--no-tags",
                        "--quiet",
                        "origin",
                        &format!("refs/pull/{number}/head"),
                    ])
                    .output()
                    .map(|out| out.status.success())
                    .unwrap_or(false);
                if fetched && let Some(head) = rev("FETCH_HEAD") {
                    return Ok(Some(head));
                }
            }
            Err("the pull request head is not available locally".to_string())
        }
        "release" => match ctx.release_commit.as_deref() {
            Some(commit) if !commit.is_empty() => Ok(Some(commit.to_string())),
            _ => Err("no release commit declared for verification".to_string()),
        },
        _ => Ok(rev("HEAD")),
    }
}

fn read_all(pipe: &mut Option<Box<dyn std::io::Read + Send>>) -> String {
    let Some(p) = pipe.as_mut() else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = std::io::Read::read_to_end(p, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// `-P` exists from CPython 3.11. On anything older, `PYTHONSAFEPATH=1` is set
/// in the environment instead, which has the same effect.
fn python_safe_path_flag() -> Option<&'static str> {
    let out = Command::new("python3")
        .args(["-c", "import sys; print(sys.version_info[:2] >= (3, 11))"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim() == "True" {
        Some("-P")
    } else {
        None
    }
}

fn tempdir(tag: &str) -> Result<PathBuf> {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let tag: String = tag
        .chars()
        .map(|c| if c == '/' || c == '\\' { '-' } else { c })
        .collect();
    let dir = PathBuf::from(base).join(format!("gitvault-checker-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::{Context, OutcomeKind, run_all, run_one, verify_ref};
    use crate::config::{Checker, Config, Kind, Severity};
    use std::path::{Path, PathBuf};

    fn context() -> Context {
        Context {
            event: "pr".into(),
            repo_root: PathBuf::from("/synthetic/repo"),
            repo_slug: Some("Owner/Repo".into()),
            identity: "personal".into(),
            account: None,
            via_default: false,
            expected_email: Some("maintainer@example.invalid".into()),
            actual_email: Some("maintainer@example.invalid".into()),
            stdin: None,
            push_remote: None,
            pr_base: Some("main".into()),
            pr_head: Some("feature".into()),
            pr_number: Some("7".into()),
            release_tag: Some("v1.0.0".into()),
            release_commit: Some("c0ffee".into()),
            commit_message_file: None,
            commit_message_source: None,
        }
    }

    #[test]
    fn substitutes_the_pull_request_range() {
        let ctx = context();
        assert_eq!(ctx.substitute("{pr_base}..{pr_head}"), "main..feature");
        assert_eq!(ctx.substitute("{repo_slug} {event}"), "Owner/Repo pr");
        assert_eq!(
            ctx.substitute("{pr_number}/{release_tag}/{release_commit}"),
            "7/v1.0.0/c0ffee"
        );
        // An event without a range substitutes empty, never the last range.
        let mut hook = context();
        hook.pr_base = None;
        hook.pr_head = None;
        hook.pr_number = None;
        hook.release_tag = None;
        hook.release_commit = None;
        assert_eq!(hook.substitute(":{pr_base}:{pr_head}:"), ":::");
        assert_eq!(hook.substitute("{release_tag}/{pr_number}"), "/");
    }

    /// A scratch repository so `verify_ref` has real objects to resolve.
    struct Repo(PathBuf);
    impl Repo {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "gv-verify-{}-{:04x}",
                std::process::id(),
                rand::random::<u16>()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            git(&dir, &["init", "-b", "main"]);
            Self(dir)
        }
        fn commit(&self, file: &str) -> String {
            std::fs::write(self.0.join(file), file).unwrap();
            git(&self.0, &["add", file]);
            git(&self.0, &["commit", "-m", file]);
            git(&self.0, &["rev-parse", "HEAD"])
        }
    }
    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Synthetic")
            .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
            .env("GIT_COMMITTER_NAME", "Synthetic")
            .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn ctx_at(repo: &Repo, event: &str) -> Context {
        Context {
            event: event.into(),
            repo_root: repo.0.clone(),
            repo_slug: None,
            identity: "synthetic".into(),
            account: None,
            via_default: false,
            expected_email: None,
            actual_email: None,
            stdin: None,
            push_remote: None,
            pr_base: None,
            pr_head: None,
            pr_number: None,
            release_tag: None,
            release_commit: None,
            commit_message_file: None,
            commit_message_source: None,
        }
    }

    /// The verify row exercises the publication candidate, resolved per event:
    /// the pushed head for pre-push, the request's head for pr, the declared
    /// commit for release - and a deletion-only push is vacuously verified.
    #[test]
    fn verify_head_is_the_candidate_each_event_publishes() {
        let repo = Repo::new();
        let a = repo.commit("a");
        let zero = "0".repeat(40);

        // pre-push: the pushed local sha is the candidate.
        let mut c = ctx_at(&repo, "pre-push");
        c.stdin = Some(format!("refs/heads/main {a} refs/heads/main {zero}"));
        assert_eq!(verify_ref(&c).unwrap().as_deref(), Some(a.as_str()));

        // A deletion-only push publishes nothing to verify.
        c.stdin = Some(format!("refs/heads/gone {zero} refs/heads/gone {a}"));
        assert_eq!(verify_ref(&c).unwrap(), None);

        // pr: the request's head ref resolves.
        let mut c = ctx_at(&repo, "pr");
        c.pr_head = Some("main".into());
        assert_eq!(verify_ref(&c).unwrap().as_deref(), Some(a.as_str()));

        // release: the declared commit, and none declared is an error - a
        // verify row must never silently exercise whatever HEAD happens to be.
        let mut c = ctx_at(&repo, "release");
        c.release_commit = Some(a.clone());
        assert_eq!(verify_ref(&c).unwrap().as_deref(), Some(a.as_str()));
        c.release_commit = None;
        assert!(verify_ref(&c).is_err());
    }

    /// A `verify` row must see the candidate revision, not the dirty working
    /// tree it shares, and the staged worktree must leave no administrative
    /// residue in the repository when the run ends.
    #[test]
    fn a_verify_checker_runs_the_candidate_and_leaves_no_worktree() {
        let repo = Repo::new();
        let head = repo.commit("a");
        // An uncommitted file proves the run did NOT happen in the checkout.
        std::fs::write(repo.0.join("dirty"), "uncommitted").unwrap();
        let mut ctx = ctx_at(&repo, "pre-push");
        ctx.stdin = Some(format!(
            "refs/heads/main {head} refs/heads/main {}",
            "0".repeat(40)
        ));
        let checker = Checker {
            name: "verify-head".into(),
            kind: Kind::Verify,
            on: vec!["pre-push".into()],
            severity: Severity::Blocking,
            timeout_secs: 60,
            repos: Vec::new(),
            // The detached worktree carries the candidate, not the checkout:
            // the dirty file is absent and HEAD is the pushed sha.
            command: vec![
                "sh".into(),
                "-c".into(),
                "test ! -f dirty && git rev-parse HEAD".into(),
            ],
            env: Default::default(),
            phase: 0,
        };
        let outcome = run_one(&Config::default(), &ctx, &checker, None);
        assert!(
            matches!(outcome.outcome, OutcomeKind::Passed),
            "{:?} {}",
            outcome.outcome,
            outcome.stderr
        );
        assert_eq!(outcome.stdout.trim(), head);
        let worktrees = git(&repo.0, &["worktree", "list", "--porcelain"]);
        assert_eq!(worktrees.matches("worktree ").count(), 1, "{worktrees}");
        assert!(!repo.0.join(".git/worktrees").exists());
    }

    /// A blocking refusal in phase 0 short-circuits phase 1: the later
    /// checker never runs (its marker file proves it) and is reported as
    /// skipped, which neither passes nor counts as another failure.
    #[test]
    fn an_earlier_phase_refusal_skips_later_phases() {
        let repo = Repo::new();
        let ctx = ctx_at(&repo, "pre-push");
        let marker = repo.0.join("later-ran");
        let row = |name: &str, phase: u32, cmd: &str| Checker {
            name: name.into(),
            kind: Kind::Exec,
            on: vec!["pre-push".into()],
            severity: Severity::Blocking,
            timeout_secs: 60,
            repos: Vec::new(),
            command: vec!["sh".into(), "-c".into(), cmd.into()],
            env: Default::default(),
            phase,
        };
        let policy = crate::config::Policy {
            checkers: vec![
                row("gate", 0, "exit 3"),
                row("later", 1, &format!("touch {}", marker.display())),
            ],
        };
        let report = run_all(
            &Config::default(),
            &policy,
            &ctx,
            &crate::configsig::SigState::Inactive,
            &crate::configsig::SigState::Inactive,
            None,
        )
        .unwrap();
        let later = report
            .outcomes
            .iter()
            .find(|o| o.name == "later")
            .expect("later outcome");
        assert!(matches!(later.outcome, OutcomeKind::Skipped));
        assert!(!marker.exists());
        assert_eq!(report.blocking_failures(), 1);

        // Same rows, one pool: phase defaults to 0 and both run.
        let policy = crate::config::Policy {
            checkers: vec![row("gate", 0, "exit 3"), {
                let mut later = row("later", 0, &format!("touch {}", marker.display()));
                later.severity = Severity::Advisory;
                later
            }],
        };
        let report = run_all(
            &Config::default(),
            &policy,
            &ctx,
            &crate::configsig::SigState::Inactive,
            &crate::configsig::SigState::Inactive,
            None,
        )
        .unwrap();
        assert!(marker.exists());
        assert!(
            report
                .outcomes
                .iter()
                .all(|o| !matches!(o.outcome, OutcomeKind::Skipped))
        );
    }
}
