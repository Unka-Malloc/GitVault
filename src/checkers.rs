//! The audit report and GitVault's built-in interception gates.
//!
//! GitVault does not own an audit engine. Semantic review - the checkers, their
//! contracts, ranges, receipts and operator waivers - belongs to Probator and
//! is reached only through `probator gate-audit` (see `crate::probator`). What
//! remains here is the part only GitVault knows:
//!
//! * the **identity gate** compares the identity the routing rules resolved
//!   with the one git will actually stamp on the commit;
//! * the **attribution gate** refuses AI attribution trailers and scrubs them
//!   from a commit message at the message hooks;
//! * the **history gate** refuses non-fast-forward pushes, tag re-points and
//!   orphaning deletions, facts about the refs that no content review sees.
//!
//! All three are deterministic, local and free. They run first, and a
//! blocking one ends the operation: nothing would publish, so the delegated
//! semantic audit is not started and spends no tokens. The record still
//! carries every local gate that produced evidence. When they pass, the
//! delegated audit runs before any authorization is requested.
//!
//! Fail-closed is the rule everywhere. A gate that cannot decide is a refusal,
//! and the delegated engine's absence or unreadable output is a blocking
//! finding rather than a silent pass.

use std::path::PathBuf;

use anyhow::Result;

use crate::config::{Config, Severity};
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
    /// names the checker resolves in the local repository. `pr_base_sha` is
    /// the commit the target branch resolved to at the gate boundary: the
    /// attribution range uses it, never the checkout's `HEAD`, because a
    /// merge publishes the request's base..head, not whatever branch happens
    /// to be checked out.
    pub pr_base: Option<String>,
    pub pr_base_sha: Option<String>,
    pub pr_head: Option<String>,
    /// For `pr merge`: the request number. The gate fetched its head at the
    /// boundary and put it in `pr_head`; the number is carried as evidence.
    pub pr_number: Option<String>,
    /// For `release`: the tag being published and the commit it points at.
    pub release_tag: Option<String>,
    pub release_commit: Option<String>,
    /// For `release`: the assets bound to this release as
    /// `(name, size, sha256, staged_ref)` tuples, snapshotted privately and
    /// hashed before the audit so the evidence names the exact bytes the
    /// publish may carry. The staged ref is a `/dev/fd/N` descriptor path
    /// inherited into the audit child, not a filesystem name a same-user
    /// process could swap.
    pub release_assets: Vec<(String, u64, String, String, bool)>,
    /// Descriptors the audit child must inherit (numbers already reserved in
    /// this process with the share flag cleared at exec): how staged asset
    /// bytes reach the scanner without trusting a replaceable path.
    pub inherited_fds: Vec<i32>,
    /// For `commit-msg`/`prepare-commit-msg`: the message file git hands the
    /// hook (argv[0]) and its composition source (argv[1]: `message`,
    /// `template`, `merge`, `squash` or `commit` for `-c/-C` reuse).
    pub commit_message_file: Option<PathBuf>,
    pub commit_message_source: Option<String>,
}

#[derive(Debug)]
pub struct CheckerOutcome {
    pub name: String,
    pub severity: Severity,
    pub outcome: OutcomeKind,
    /// How long this gate took, for the run record and the operator's sense
    /// of what a gate costs.
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
// Timeout/Skipped are retained for the report/record vocabulary even though
// the delegated engine decides short-circuiting and deadlines itself.
#[allow(dead_code)]
pub enum OutcomeKind {
    Passed,
    Failed(i32),
    Timeout,
    CouldNotRun(String),
    /// A later-phase checker the gate short-circuited: not a failure - the
    /// refusal was already decided - and not a pass, just evidence it never
    /// spent its tokens. Retained for the report/record shape; the delegated
    /// engine decides its own short-circuiting now.
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
            // Findings carry locations, never evidence: Probator keeps the
            // matched value inside its run directory, so relaying the finding
            // text is safe.
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

/// The built-in gate that no registration can replace or disable.
///
/// The rules answer "which identity SHOULD act here". This answers "which identity
/// WILL be stamped on the commit", and the two are not the same thing: `git -c
/// user.email=...`, a repo-local override, or a stray `includeIf` can silently make
/// git use a different address than the rules resolved to. Attribution on GitHub
/// follows the address, so a mismatch means the commit lands under the wrong
/// account even though every rule reported success.
///
/// Runs for pre-commit and pre-push.
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
        // The outcome text is persisted into engine.json records that can be
        // shared or copied, so addresses are masked to a categorical form -
        // the exact value lives in the signed routing table already.
        stdout: if actual.eq_ignore_ascii_case(expected) {
            format!("git will attribute this to {}", mask_email(actual))
        } else {
            format!(
                "git would attribute this to '{}' but identity '{}' expects '{}'\n\
                 fix: set user.email to that identity's configured address   (or unset the override)",
                mask_email(actual),
                ctx.identity,
                mask_email(expected)
            )
        },
        stderr: String::new(),
    })
}

/// `name@host` reduced to `n…@host`: enough to recognise which address was
/// compared, not enough to carry a personal address into a stored record.
/// The mask takes the first Unicode scalar - a non-ASCII local part must not
/// slice mid-encoding and panic the gate.
fn mask_email(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) if !local.is_empty() => {
            format!("{}…@{domain}", local.chars().next().unwrap_or('?'))
        }
        _ => "(unparseable address)".to_string(),
    }
}

/// Run the interception gates and the delegated audit, then record the run.
///
/// The record is written whenever a publication audit is due, so evidence
/// exists even when every gate passed. Local events that run only a built-in
/// gate are not recorded: there was no audit to observe.
pub fn audit(
    cfg: &Config,
    ctx: &Context,
    routing_sig: &crate::configsig::SigState,
    policy_sig: &crate::configsig::SigState,
) -> Result<Report> {
    let routing_certified = !matches!(routing_sig, crate::configsig::SigState::Invalid(_));
    let mut report = Report::default();

    if let Some(gate) = identity_gate(ctx, routing_certified) {
        report.outcomes.push(gate);
    }
    if let Some(gate) = crate::attribution::gate(ctx) {
        report.outcomes.push(gate);
    }
    report.outcomes.extend(crate::history::gates(ctx));

    let audited = crate::probator::applies(&ctx.event);
    if audited {
        // The record store's location is part of the boundary: refuse before
        // the engine runs when it would write inside the reviewed tree.
        records::check_store_location(cfg, &ctx.repo_root)?;
    }
    let run = if audited {
        records::begin(cfg, 1)
    } else {
        None
    };
    if audited && report.blocking_failures() == 0 {
        eprintln!(
            "gitvault: delegating the {} audit to probator gate-audit…",
            ctx.event
        );
        report.outcomes.extend(crate::probator::gates(ctx));
    } else if audited {
        // Nothing can publish past a local refusal, so a semantic review
        // could not inform any decision. Starting it anyway would buy
        // evidence for a boundary that is already closed.
        eprintln!(
            "gitvault: a local gate refused the {} action; the paid semantic audit is not started",
            ctx.event
        );
    }
    if let Some(run) = run {
        records::finish(cfg, run, ctx, &report, routing_sig, policy_sig);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{Context, OutcomeKind, identity_gate};
    use crate::config::Severity;
    use std::path::PathBuf;

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
            pr_base_sha: Some("c0ffee".into()),
            pr_head: Some("feature".into()),
            pr_number: Some("7".into()),
            release_tag: Some("v1.0.0".into()),
            release_commit: Some("c0ffee".into()),
            release_assets: Vec::new(),
            inherited_fds: Vec::new(),
            commit_message_file: None,
            commit_message_source: None,
        }
    }

    /// The identity gate compares the routing decision with what git would
    /// actually stamp, and an uncertified routing table cannot block anything.
    #[test]
    fn the_identity_gate_reports_a_mismatch_and_downgrades_uncertified() {
        let mut ctx = context();
        ctx.event = "pre-commit".into();
        let passing = identity_gate(&ctx, true).expect("a gate outcome");
        assert!(matches!(passing.outcome, OutcomeKind::Passed));

        ctx.actual_email = Some("wrong@example.invalid".into());
        let failing = identity_gate(&ctx, true).expect("a gate outcome");
        assert_eq!(failing.severity, Severity::Blocking);
        assert!(matches!(failing.outcome, OutcomeKind::Failed(_)));

        let advisory = identity_gate(&ctx, false).expect("a gate outcome");
        assert_eq!(advisory.severity, Severity::Advisory);
    }

    /// A repository that fell through to `rules.default` has no decision to
    /// hold a commit to, and events without a commit carry no identity gate.
    #[test]
    fn the_identity_gate_only_judges_ruled_commits() {
        let mut ctx = context();
        ctx.event = "pre-commit".into();
        ctx.via_default = true;
        assert!(identity_gate(&ctx, true).is_none());
        ctx.via_default = false;
        ctx.event = "pr".into();
        assert!(identity_gate(&ctx, true).is_none());
    }

    /// A non-ASCII local part masks on the first scalar, never mid-encoding:
    /// slicing bytes would panic the gate on a valid address.
    #[test]
    fn the_email_mask_handles_multibyte_local_parts() {
        assert_eq!(
            super::mask_email("üser@example.invalid"),
            "ü…@example.invalid"
        );
        assert_eq!(super::mask_email("a@example.invalid"), "a…@example.invalid");
        assert_eq!(super::mask_email("not-an-address"), "(unparseable address)");
    }
}
