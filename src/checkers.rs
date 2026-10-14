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
//! * **A curated environment.** Nothing is inherited except PATH and locale, so
//!   ambient credentials or steering variables cannot reach a checker.
//! * **Fail-closed.** A blocking checker that is missing, times out, or exits
//!   non-zero stops the action.
//!
//! Adding capability means adding a registry entry, not editing this file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result};
use wait_timeout::ChildExt;

use crate::config::{Checker, Config, Event, Kind, Severity};
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
    /// Why this identity was chosen, e.g. `rules.owners['acme']` or
    /// `rules.default`. Carried so the gate can tell a deliberate rule from a
    /// fallback; the API, SSH and signing paths already make that distinction.
    pub reason: String,
    /// The identity came from `rules.default` rather than a rule about this
    /// repository. Mirrored from the identity outcome for the same reason it is
    /// a field there: a display string is not a policy decision.
    pub via_default: bool,
    /// What the rules say should be used.
    pub expected_email: Option<String>,
    /// What git will actually stamp. Attribution follows this one.
    pub actual_email: Option<String>,
    /// Arguments git passed to the hook.
    pub args: Vec<String>,
    /// For pre-push: the ref lines git supplies on stdin.
    pub stdin: Option<String>,
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
            .replace("{release_commit}", self.release_commit.as_deref().unwrap_or(""))
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
}

impl OutcomeKind {
    fn is_failure(&self) -> bool {
        !matches!(self, Self::Passed)
    }

    fn label(&self) -> String {
        match self {
            Self::Passed => "passed".into(),
            Self::Failed(code) => format!("failed (exit {code})"),
            Self::Timeout => "timed out".into(),
            Self::CouldNotRun(why) => format!("could not run: {why}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub outcomes: Vec<CheckerOutcome>,
}

impl Report {
    pub fn blocking_failures(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.severity == Severity::Blocking && o.outcome.is_failure())
            .count()
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
pub fn identity_gate(ctx: &Context) -> Option<CheckerOutcome> {
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
        severity: Severity::Blocking,
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

pub fn run_all(cfg: &Config, ctx: &Context, only: Option<&str>) -> Result<Report> {
    let event = Event::parse(&ctx.event)?;
    let selected: Vec<&Checker> = cfg
        .checkers_for(event)
        .into_iter()
        .filter(|c| only.is_none_or(|name| c.name == name))
        .collect();
    // The record spans the whole run, so it starts before the first checker.
    let run = records::begin(cfg, selected.len());
    let mut report = Report::default();

    if only.is_none() {
        if let Some(gate) = identity_gate(ctx) {
            report.outcomes.push(gate);
        }
    }

    for checker in selected {
        report.outcomes.push(run_one(cfg, ctx, checker));
    }
    if let Some(run) = run {
        records::finish(cfg, run, ctx, &report);
    }
    Ok(report)
}

fn run_one(cfg: &Config, ctx: &Context, checker: &Checker) -> CheckerOutcome {
    let started = std::time::Instant::now();
    let fail = |why: String| CheckerOutcome {
        name: checker.name.clone(),
        severity: checker.severity,
        outcome: OutcomeKind::CouldNotRun(why),
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
    };

    let program = match checker.command.first() {
        Some(p) => ctx.substitute(p),
        None => return fail("empty command".into()),
    };
    let mut args: Vec<String> = checker.command[1..]
        .iter()
        .map(|a| ctx.substitute(a))
        .collect();

    // Language-specific hardening, applied by the engine so the registry entry
    // cannot forget it.
    if checker.kind == Kind::Python {
        match python_safe_path_flag() {
            Some(flag) => args.insert(0, flag.to_string()),
            None => { /* PYTHONSAFEPATH is set in the environment below */ }
        }
    }

    // Neutral cwd. This is the load-bearing line of the whole module.
    let neutral = match tempdir() {
        Ok(d) => d,
        Err(e) => return fail(format!("no neutral working directory: {e}")),
    };

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .current_dir(&neutral)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("LANG", std::env::var("LANG").unwrap_or_else(|_| "C".into()))
        .env("TMPDIR", std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()))
        .env("GITVAULT_EVENT", &ctx.event)
        .env("GITVAULT_IDENTITY", &ctx.identity)
        .env("GITVAULT_REPO", ctx.repo_root.display().to_string())
        .env(
            "GITVAULT_REPO_SLUG",
            ctx.repo_slug.clone().unwrap_or_default(),
        )
        .env(
            "GITVAULT_ACCOUNT",
            ctx.account.clone().unwrap_or_default(),
        )
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
        cmd.env(k, ctx.substitute(v));
    }

    eprintln!("gitvault: running {}…", checker.name);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("{program}: {e}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Some(data) = &ctx.stdin {
            let _ = stdin.write_all(data.as_bytes());
        }
        // Dropping closes the pipe; a checker that reads stdin sees EOF.
    }

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
            let _ = std::fs::remove_dir_all(&neutral);
            return CheckerOutcome {
                name: checker.name.clone(),
                severity: checker.severity,
                outcome: OutcomeKind::Timeout,
                duration_ms: started.elapsed().as_millis() as u64,
                stdout: String::new(),
                stderr: format!("exceeded {}s", checker.timeout_secs),
            };
        }
        Err(e) => return fail(format!("wait failed: {e}")),
    };

    // Killing or exiting closes the pipes, so the readers terminate.
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    let _ = std::fs::remove_dir_all(&neutral);

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
    if text.trim() == "True" { Some("-P") } else { None }
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(base).join(format!("gitvault-checker-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir)
}

/// Environment variables a checker is allowed to see, for documentation and tests.
pub fn inherited_env_allowlist() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("PATH", "locate the checker binary"),
        ("HOME", "checkers may need their own config"),
        ("LANG", "stable encoding"),
        ("TMPDIR", "scratch space"),
    ])
}

#[cfg(test)]
mod tests {
    use super::Context;
    use std::path::PathBuf;

    fn context() -> Context {
        Context {
            event: "pr".into(),
            repo_root: PathBuf::from("/synthetic/repo"),
            repo_slug: Some("Owner/Repo".into()),
            identity: "personal".into(),
            account: None,
            reason: "rules.owners[Owner]".into(),
            via_default: false,
            expected_email: Some("maintainer@example.invalid".into()),
            actual_email: Some("maintainer@example.invalid".into()),
            args: Vec::new(),
            stdin: None,
            pr_base: Some("main".into()),
            pr_head: Some("feature".into()),
            pr_number: Some("7".into()),
            release_tag: Some("v1.0.0".into()),
            release_commit: Some("c0ffee".into()),
        }
    }

    #[test]
    fn substitutes_the_pull_request_range() {
        let ctx = context();
        assert_eq!(ctx.substitute("{pr_base}..{pr_head}"), "main..feature");
        assert_eq!(ctx.substitute("{repo_slug} {event}"), "Owner/Repo pr");
        assert_eq!(ctx.substitute("{pr_number}/{release_tag}/{release_commit}"), "7/v1.0.0/c0ffee");
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
}
