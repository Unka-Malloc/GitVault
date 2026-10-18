//! Configuration: identities, ownership rules, and the checker registry.
//!
//! The registry is a *list*, deliberately. An audit is one entry; a formatter, a
//! commit-message policy, a secret scanner or a build check are others. New
//! capability is added by registering an entry, never by editing the engine.
//!
//! Note what is NOT here: nothing in this file is read from the repository being
//! inspected. Ownership rules and the checker list live outside any work tree so
//! that a repository cannot redefine the terms under which it is judged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Which git hook an entry answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Event {
    #[serde(rename = "pre-commit")]
    PreCommit,
    #[serde(rename = "pre-push")]
    PrePush,
    #[serde(rename = "commit-msg")]
    CommitMsg,
    #[serde(rename = "prepare-commit-msg")]
    PrepareCommitMsg,
    #[serde(rename = "pre-applypatch")]
    PreApplyPatch,
    /// Not a git hook: GitVault's own pull request operations run the registry
    /// before they reach GitHub, so content that entered the remote outside this
    /// machine's pre-push gate is still reviewed before a request proposes it.
    #[serde(rename = "pr")]
    Pr,
    /// Not a git hook either: creating a release publishes a tag and its notes,
    /// and the registry runs before GitHub is asked to do it.
    #[serde(rename = "release")]
    Release,
}

impl Event {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "pre-commit" => Ok(Self::PreCommit),
            "pre-push" => Ok(Self::PrePush),
            "commit-msg" => Ok(Self::CommitMsg),
            "prepare-commit-msg" => Ok(Self::PrepareCommitMsg),
            "pre-applypatch" => Ok(Self::PreApplyPatch),
            "pr" => Ok(Self::Pr),
            "release" => Ok(Self::Release),
            other => bail!(
                "unknown hook event '{other}' (expected pre-commit, prepare-commit-msg, pre-applypatch, pre-push, commit-msg, pr or release)"
            ),
        }
    }

    /// The hook name this event is registered and invoked under.
    pub fn name(self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PrePush => "pre-push",
            Self::CommitMsg => "commit-msg",
            Self::PrepareCommitMsg => "prepare-commit-msg",
            Self::PreApplyPatch => "pre-applypatch",
            Self::Pr => "pr",
            Self::Release => "release",
        }
    }
}

/// A stable name for an identity. Contracts in `.gitvault-identity` and in test
/// fixtures refer to identities by this key, so it is the one thing that must not
/// drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub email: String,
    /// GitHub account this identity authenticates as, when applicable.
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub ssh_key: Option<PathBuf>,
    #[serde(default)]
    pub signing_key: Option<PathBuf>,
}

/// How an identity is chosen for a repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Preferred: match on the remote's owning account -> the identities key
    /// that may act on it. It survives being cloned to a different path and
    /// does not depend on local directory layout.
    #[serde(default)]
    pub owners: BTreeMap<String, String>,
    /// Fallback: match on a path prefix, for repositories with no remote yet.
    #[serde(default)]
    pub paths: Vec<PathRule>,
    /// Identity used when nothing else matches. Absent means "refuse to act",
    /// which is the safe default for a tool whose job is preventing mistakes.
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub prefix: PathBuf,
    pub identity: String,
}

/// Fail-closed is the default. A checker that cannot run must block, because a
/// gate that silently passes is worse than no gate: it creates false confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A non-zero exit, a missing command or a timeout ALL block.
    #[default]
    Blocking,
    /// Failures are reported but never block. For advisory checks.
    Advisory,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocking => write!(f, "blocking"),
            Self::Advisory => write!(f, "advisory"),
        }
    }
}

/// One entry in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checker {
    pub name: String,
    /// `python` injects safe-path flags; `exec` runs the command verbatim;
    /// `verify` runs it inside a detached worktree of the publication
    /// candidate. Declaring the kind is what lets the engine apply
    /// language-specific hardening without the user having to remember it.
    #[serde(default = "default_kind")]
    pub kind: Kind,
    #[serde(default = "default_event")]
    pub on: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_timeout")]
    /// Zero waits for completion without a wall-clock deadline.
    pub timeout_secs: u64,
    /// Repositories the row applies to, as origin slugs (`owner/repo`) or
    /// work-tree path prefixes. An empty list applies everywhere. Scoping is
    /// what lets a signed policy declare `cargo test` for Rust repositories
    /// without demanding it of every other tree the machine touches.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Command and arguments. Placeholders are substituted from the run context:
    /// `{repo}`, `{event}`, `{identity}`, `{account}`, `{email}`, and for a
    /// `verify` row `{verify_head}` (the candidate revision it exercises).
    pub command: Vec<String>,
    /// Extra environment for the checker. `{identity}`-style placeholders apply.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Orchestration phase: rows sharing a phase run concurrently, phases run
    /// in ascending order, and a blocking failure in an earlier phase skips
    /// every later phase so a refusal that is already decided never spends
    /// another checker's tokens. The default 0 keeps every row in one pool.
    #[serde(default)]
    pub phase: u32,
}

impl Checker {
    /// Whether the row is scoped to this repository: an empty `repos` applies
    /// everywhere, otherwise any entry equal to the origin slug or a path
    /// prefix of the repository root selects it.
    pub fn applies_to(&self, slug: Option<&str>, root: &Path) -> bool {
        self.repos.is_empty()
            || self
                .repos
                .iter()
                .any(|r| Some(r.as_str()) == slug || root.starts_with(r))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Exec,
    Python,
    /// Runs inside a worktree of the candidate revision: the signed policy -
    /// never the repository - declares the command, and its exit status is
    /// the correctness evidence for what is about to publish. This is the one
    /// kind allowed a repository working directory, because a build or test
    /// cannot run from a neutral one.
    Verify,
}

fn default_kind() -> Kind {
    Kind::Exec
}

fn default_severity() -> Severity {
    Severity::Blocking
}

fn default_timeout() -> u64 {
    // No wall-clock deadline unless the operator asks for one: a deadline that
    // fires mid-review discards work that was already paid for, and the default
    // should never silently buy that outcome.
    0
}

fn default_event() -> Vec<String> {
    vec!["pre-commit".to_string()]
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub identities: BTreeMap<String, Identity>,
    #[serde(default)]
    pub rules: Rules,
    /// Path of the signed audit policy file, relative to the configuration
    /// directory when not absolute. Declaring it here binds the policy's
    /// existence into the routing table's signature, so an audit cannot be
    /// skipped by deleting the policy file: a declared policy that is absent
    /// or uncertified refuses to run.
    #[serde(default)]
    pub audit_policy: Option<PathBuf>,
    /// Where run records are written. Defaults to
    /// `$XDG_STATE_HOME/gitvault/runs` (or `~/.local/state/...`).
    #[serde(default)]
    pub record_dir: Option<PathBuf>,
}

/// The single authority for GitVault's configuration directory:
/// `$XDG_CONFIG_HOME/gitvault` when set, `~/.config/gitvault` otherwise.
/// Everything under it — config.toml, vault.enc, the unlock window record —
/// derives from this one root so the on-disk layout cannot split across two
/// conventions.
pub fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home).join(".config")
        })
        .join("gitvault")
}

impl Config {
    /// Default location, overridable by `--config` / `GITVAULT_CONFIG`.
    pub fn default_path() -> PathBuf {
        if let Ok(explicit) = std::env::var("GITVAULT_CONFIG") {
            return PathBuf::from(explicit);
        }
        config_dir().join("config.toml")
    }

    /// The gate every credential-bearing surface funnels through: once
    /// `config.pub` is root-owned, the routing table is attested or refused - a
    /// table anyone can silently rewrite is no table at all.
    ///
    /// Audit surfaces must NOT use this: they run before the blessing, so they
    /// take [`load_unverified`] and decide the signature question themselves.
    pub fn load(explicit: Option<&PathBuf>) -> Result<Self> {
        let path = match explicit {
            Some(p) => p.clone(),
            None => Self::default_path(),
        };
        if !path.exists() {
            bail!(
                "no configuration at {} - create it or pass --config",
                path.display()
            );
        }
        crate::configsig::verify(&path)?;
        Self::load_path(&path)
    }

    /// Parse and classify without consulting the signature anchor. Audit
    /// surfaces take this so the audits can run and be shown BEFORE the
    /// operator is asked to bless the file; the returned signature state is
    /// checked after the report is produced, at the point a verdict or a
    /// credential would otherwise depend on the routing table.
    pub fn load_unverified(
        explicit: Option<&PathBuf>,
    ) -> Result<(Self, PathBuf, crate::configsig::SigState)> {
        let path = match explicit {
            Some(p) => p.clone(),
            None => Self::default_path(),
        };
        if !path.exists() {
            bail!(
                "no configuration at {} - create it or pass --config",
                path.display()
            );
        }
        let signature = crate::configsig::signature_state(&path);
        let cfg = Self::load_path(&path)?;
        Ok((cfg, path, signature))
    }

    /// Parse and validate a file without consulting the signature anchor. The
    /// parser's own tests exercise this; every command path must use `load`
    /// or `load_unverified`.
    fn load_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        // Checker rows declare executable commands, so they live in
        // checkers.toml - signed independently so audits can run before the
        // routing table's blessing. Rows left here are stale, not policy.
        // Line-anchored so a comment that merely mentions the header cannot
        // trip the refusal.
        if raw
            .lines()
            .any(|l| l.trim_start().starts_with("[[checkers]]"))
        {
            bail!(
                "{} still contains [[checkers]] entries - the audit policy lives in checkers.toml now\n  \
                 migrate and certify both files: gitvault config sign",
                path.display()
            );
        }
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("invalid configuration in {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Move `[[checkers]]` sections out of `config_path` into the policy file.
    /// A same-named row in the policy wins over a stale row being migrated,
    /// so certifying newer policy can never resurrect an old command.
    /// Returns true when the file changed.
    pub fn migrate_checkers(config_path: &Path) -> Result<bool> {
        let text = std::fs::read_to_string(config_path)
            .with_context(|| format!("cannot read {}", config_path.display()))?;
        if !text
            .lines()
            .any(|l| l.trim_start().starts_with("[[checkers]]"))
        {
            return Ok(false);
        }
        // Split on table headers; a [[checkers]] segment runs until the next
        // header line, comments ahead of it staying with the previous section.
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        for line in text.split_inclusive('\n') {
            if line.trim_start().starts_with('[') && !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            current.push_str(line);
        }
        if !current.is_empty() {
            segments.push(current);
        }
        let mut kept = String::new();
        let mut moved: Vec<String> = Vec::new();
        for segment in segments {
            if segment.trim_start().starts_with("[[checkers]]") {
                moved.push(segment);
            } else {
                kept.push_str(&segment);
            }
        }
        let policy_path = Policy::path_for(config_path);
        let existing = std::fs::read_to_string(&policy_path).unwrap_or_default();
        let mut policy = Policy::load_str(&existing)
            .with_context(|| format!("invalid audit policy in {}", policy_path.display()))?;
        #[derive(Deserialize)]
        struct Row {
            checkers: Vec<Checker>,
        }
        for block in &moved {
            let parsed: Row = toml::from_str(block).context("cannot parse migrated checker row")?;
            for row in parsed.checkers {
                policy.checkers.retain(|c| c.name != row.name);
                policy.checkers.push(row);
            }
        }
        policy.validate()?;
        let mut policy_text = String::from(
            "# Audit policy: the commands GitVault may execute as checks.\n\
             # Signed independently of config.toml (checkers.toml.sig) so audits\n\
             # run BEFORE the routing table is asked for a blessing.\n\n",
        );
        for row in &policy.checkers {
            policy_text.push_str(&toml::to_string(&Policy {
                checkers: vec![row.clone()],
            })?);
            policy_text.push('\n');
        }
        toml::from_str::<toml::Value>(&policy_text).context("generated policy is invalid TOML")?;
        // The moved rows only count as policy once the routing table declares
        // the file: without the signed declaration, deleting checkers.toml
        // would silently run no audit at all.
        let declared = kept
            .lines()
            .take_while(|l| !l.trim_start().starts_with('['))
            .any(|l| l.trim_start().starts_with("audit_policy"));
        if !declared {
            let declaration = "audit_policy = \"checkers.toml\"\n\n";
            let offset = kept
                .char_indices()
                .scan(true, |bol, (i, c)| {
                    let at_bol = *bol;
                    *bol = c == '\n';
                    Some((i, at_bol))
                })
                .find(|(i, at_bol)| *at_bol && kept[*i..].trim_start().starts_with('['))
                .map(|(i, _)| i)
                .unwrap_or(kept.len());
            kept.insert_str(offset, declaration);
        }
        toml::from_str::<toml::Value>(&kept).context("config without checkers is invalid TOML")?;
        std::fs::write(&policy_path, policy_text)
            .with_context(|| format!("cannot write {}", policy_path.display()))?;
        std::fs::write(config_path, kept)
            .with_context(|| format!("cannot write {}", config_path.display()))?;
        Ok(true)
    }

    fn validate(&self) -> Result<()> {
        for (key, id) in &self.identities {
            if id.name.is_empty() || id.email.is_empty() {
                bail!("identity '{key}' must set both name and email");
            }
            if !id.email.contains('@') {
                bail!("identity '{key}' has a malformed email: {}", id.email);
            }
        }
        for (owner, target) in &self.rules.owners {
            if !self.identities.contains_key(target) {
                bail!("rules.owners maps '{owner}' to unknown identity '{target}'");
            }
        }
        for rule in &self.rules.paths {
            if !self.identities.contains_key(&rule.identity) {
                bail!(
                    "rules.paths entry {} maps to unknown identity '{}'",
                    rule.prefix.display(),
                    rule.identity
                );
            }
        }
        if let Some(default) = &self.rules.default
            && !self.identities.contains_key(default)
        {
            bail!("rules.default names unknown identity '{default}'");
        }
        Ok(())
    }
}

/// The audit policy: the checker registry, kept in its own signed file
/// (`checkers.toml` beside `config.toml`) so the audit can run BEFORE the
/// operator is asked to bless the routing table.
///
/// The split is what makes "audit first, sign after" sound. A signature on
/// checkers.toml means "these are the commands audits may execute"; a
/// signature on config.toml means "these identities may act". Audits never
/// execute an uncertified command, and an uncertified routing table never
/// reaches a credential - the two blessings are independent and each is asked
/// only after the evidence it certifies has been produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub checkers: Vec<Checker>,
}

impl Policy {
    /// The policy file conventionally sits beside the routing table.
    pub fn path_for(config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("checkers.toml")
    }

    /// Where this routing table keeps its audit policy: the declared
    /// `audit_policy` path, else the conventional `checkers.toml` sibling.
    pub fn resolve(config_path: &Path, cfg: &Config) -> PathBuf {
        match &cfg.audit_policy {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(p),
            None => Self::path_for(config_path),
        }
    }

    /// Load the policy and its signature state WITHOUT gating on it. The
    /// caller decides: a surface that is about to execute rows must refuse an
    /// `Invalid` state (checker commands are arbitrary code), while an event
    /// the policy says nothing about executes nothing and may proceed. The
    /// declared rows are still readable for the refusal preview - showing a
    /// command is not running it.
    pub fn load_state(
        config_path: &Path,
        cfg: &Config,
    ) -> Result<(Self, PathBuf, crate::configsig::SigState)> {
        let path = Self::resolve(config_path, cfg);
        if !path.exists() {
            if cfg.audit_policy.is_some() {
                bail!(
                    "the routing table declares an audit policy at {} but the file is absent\n  \
                     the declaration is signed, so its file cannot simply disappear\n  \
                     restore it or amend and re-certify: gitvault config sign",
                    path.display()
                );
            }
            return Ok((Self::default(), path, crate::configsig::SigState::Inactive));
        }
        let policy = Self::load_path(&path)?;
        let state = crate::configsig::signature_state(&path);
        Ok((policy, path, state))
    }

    fn load_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Self::load_str(&raw).with_context(|| format!("invalid audit policy in {}", path.display()))
    }

    fn load_str(raw: &str) -> Result<Self> {
        let policy: Policy = toml::from_str(raw).context("expected [[checkers]] entries")?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for checker in &self.checkers {
            if !seen.insert(checker.name.clone()) {
                bail!("duplicate checker name '{}'", checker.name);
            }
            if checker.command.is_empty() {
                bail!("checker '{}' has an empty command", checker.name);
            }
            for event in &checker.on {
                Event::parse(event).with_context(|| format!("checker '{}'", checker.name))?;
            }
        }
        Ok(())
    }

    /// Checkers registered for an event, in declaration order.
    pub fn checkers_for(&self, event: Event) -> Vec<&Checker> {
        self.checkers
            .iter()
            .filter(|c| c.on.iter().any(|e| Event::parse(e).ok() == Some(event)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Event, Policy, Severity};

    const BASE: &str = r#"
[identities.acme]
name = "acme Maintainer"
email = "acme@example.invalid"
account = "acme-dev"

[identities.personal]
name = "A. User"
email = "personal@example.invalid"

[rules.owners]
acme = "acme"

[rules]
default = "personal"
"#;

    const POLICY: &str = r#"
[[checkers]]
name = "audit"
on = ["pre-commit", "pre-push"]
kind = "python"
command = ["python3", "-m", "scanner", "scan", "--directory", "{repo}"]

[[checkers]]
name = "advisory"
on = ["pre-commit"]
severity = "advisory"
command = ["/bin/true"]
"#;

    /// `validate()` is private, so exercise the real checks by round-tripping
    /// through a temp file. Each call gets a UNIQUE path: tests run in parallel
    /// and a shared path makes them overwrite each other's config.
    fn parse(s: &str) -> anyhow::Result<Config> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gv-cfg-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, s).unwrap();
        let loaded = Config::load_path(&path);
        let _ = std::fs::remove_dir_all(&dir);
        loaded
    }

    fn parse_policy(s: &str) -> anyhow::Result<Policy> {
        Policy::load_str(s)
    }

    #[test]
    fn accepts_a_well_formed_registry() {
        let policy = parse_policy(POLICY).expect("valid policy");
        assert_eq!(policy.checkers.len(), 2);
        assert_eq!(policy.checkers_for(Event::PreCommit).len(), 2);
        assert_eq!(policy.checkers_for(Event::PrePush).len(), 1);
        assert_eq!(policy.checkers_for(Event::CommitMsg).len(), 0);
        assert_eq!(policy.checkers_for(Event::Pr).len(), 0);
        assert_eq!(policy.checkers[0].severity, Severity::Blocking);
        assert_eq!(policy.checkers[1].severity, Severity::Advisory);
    }

    #[test]
    fn accepts_the_publication_boundary_events() {
        // `pre-push` and `pr` are the boundaries content crosses to become
        // public; a checker registered on `pr` is selected for that event only.
        let with_pr = POLICY.replace("on = [\"pre-commit\"]", "on = [\"pre-commit\", \"pr\"]");
        let policy = parse_policy(&with_pr).expect("valid policy");
        assert_eq!(policy.checkers_for(Event::Pr).len(), 1);
        assert_eq!(policy.checkers_for(Event::Pr)[0].name, "advisory");
        assert_eq!(policy.checkers_for(Event::PrePush).len(), 1);
    }

    /// A `verify` row is the only kind that runs in a repository worktree, so
    /// `repos` is what keeps a signed `cargo test` from firing on trees that
    /// are not Rust. Scoping must match on slug or path prefix and refuse
    /// everywhere else.
    #[test]
    fn a_verify_row_scopes_to_named_repositories() {
        let policy = parse_policy(
            r#"
[[checkers]]
name = "verify-cargo"
kind = "verify"
on = ["pre-push"]
repos = ["Owner/Repo", "/opt/rusty"]
command = ["cargo", "test"]

[[checkers]]
name = "verify-any"
kind = "verify"
on = ["pre-push"]
command = ["/bin/true"]
"#,
        )
        .expect("valid policy");
        let scoped = &policy.checkers[0];
        assert_eq!(scoped.kind, super::Kind::Verify);
        assert!(scoped.applies_to(Some("Owner/Repo"), std::path::Path::new("/x")));
        assert!(scoped.applies_to(Some("Other/Repo"), std::path::Path::new("/opt/rusty/sub")));
        assert!(!scoped.applies_to(Some("Other/Repo"), std::path::Path::new("/x")));
        // An empty repos list applies everywhere - it is the default, not an
        // opt-out the row has to spell.
        assert!(policy.checkers[1].applies_to(Some("Any/Repo"), std::path::Path::new("/x")));
    }

    #[test]
    fn rejects_checker_rows_left_in_the_routing_table() {
        // A [[checkers]] row in config.toml is executable code smuggled past
        // the policy's own signature: stale rows must refuse, not silently run
        // under the routing table's blessing.
        let stale = format!("{BASE}\n{POLICY}");
        let err = parse(&stale).expect_err("checker rows in config.toml must refuse");
        assert!(
            err.to_string().contains("checkers.toml"),
            "the refusal points at the policy file: {err}"
        );
        // A comment that merely mentions the header is not a row.
        let commented = format!("# policy rows live in [[checkers]] now\n{BASE}");
        assert!(
            parse(&commented).is_ok(),
            "comments must not trip the refusal"
        );
    }

    #[test]
    fn migrate_moves_checker_rows_to_the_policy_file() {
        let dir = std::env::temp_dir().join(format!("gv-mig-{}-{}", std::process::id(), 1));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        std::fs::write(&config, format!("{BASE}\n{POLICY}")).unwrap();

        assert!(Config::migrate_checkers(&config).expect("migration runs"));
        let kept = std::fs::read_to_string(&config).unwrap();
        assert!(!kept.contains("[[checkers]]"), "rows left behind: {kept}");
        // The declaration binds the policy file's existence into the routing
        // signature: without it, deleting checkers.toml would run no audit.
        let reloaded = Config::load_path(&config).expect("kept config parses");
        assert_eq!(
            reloaded.audit_policy.as_deref(),
            Some(std::path::Path::new("checkers.toml")),
            "migrated config must declare its policy: {kept}"
        );
        let policy = Policy::load_str(&std::fs::read_to_string(dir.join("checkers.toml")).unwrap())
            .expect("migrated policy parses");
        assert_eq!(policy.checkers.len(), 2);
        assert_eq!(policy.checkers[0].name, "audit");
        // Idempotent: nothing left to move.
        assert!(!Config::migrate_checkers(&config).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_an_owner_rule_pointing_at_an_undefined_identity() {
        let bad = BASE.replace("acme = \"acme\"", "acme = \"nobody\"");
        assert!(
            parse(&bad).is_err(),
            "must reject an unknown identity target"
        );
    }

    #[test]
    fn rejects_a_default_pointing_at_an_undefined_identity() {
        let bad = BASE.replace("default = \"personal\"", "default = \"ghost\"");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_checker_names() {
        let bad = format!("{POLICY}\n[[checkers]]\nname = \"audit\"\ncommand = [\"/bin/true\"]\n");
        assert!(
            parse_policy(&bad).is_err(),
            "duplicate names would make --only ambiguous"
        );
    }

    #[test]
    fn rejects_a_malformed_email() {
        let bad = BASE.replace("acme@example.invalid", "not-an-email");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_an_unknown_key_instead_of_ignoring_it() {
        // A mistyped knob that silently does nothing is the worst kind of gate
        // configuration: the operator believes it is on.
        for bad in [
            BASE.replace("[rules]", "[rules]\nunknown_knob = true"),
            BASE.replace(
                "email = \"acme@example.invalid\"",
                "email = \"acme@example.invalid\"\nworkspace = \"/tmp\"",
            ),
        ] {
            assert!(
                parse(&bad).is_err(),
                "an unknown key must be refused: {bad}"
            );
        }
        let bad_policy = POLICY.replace(
            "severity = \"advisory\"",
            "severity = \"advisory\"\nsevverity = \"blocking\"",
        );
        assert!(
            parse_policy(&bad_policy).is_err(),
            "an unknown policy key must be refused"
        );
    }

    #[test]
    fn a_key_after_a_table_header_belongs_to_that_table() {
        // The trap this guards against: a top-level knob written below a table
        // header is parsed as part of that table, and without unknown-key
        // rejection it is dropped without a word.
        let misplaced = BASE.replace("[rules]", "[rules]\nrecord_dir = \"/tmp/runs\"");
        assert!(
            parse(&misplaced).is_err(),
            "a misplaced top-level key must be refused"
        );
        let placed = format!("record_dir = \"/tmp/runs\"\n{BASE}");
        let cfg = parse(&placed).expect("a top-level key before every header parses");
        assert_eq!(
            cfg.record_dir.as_deref(),
            Some(std::path::Path::new("/tmp/runs"))
        );
    }

    #[test]
    fn rejects_an_unknown_hook_event() {
        let bad = POLICY.replace(
            "on = [\"pre-commit\", \"pre-push\"]",
            "on = [\"post-commit\"]",
        );
        assert!(parse_policy(&bad).is_err());
    }

    #[test]
    fn a_declared_policy_cannot_disappear() {
        // `audit_policy` is signed into the routing table: the file it names
        // being absent refuses the audit outright, so removing checkers.toml
        // is detected rather than silently running no checks.
        let dir = std::env::temp_dir().join(format!("gv-decl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        std::fs::write(&config, format!("audit_policy = \"checkers.toml\"\n{BASE}")).unwrap();
        let cfg = Config::load_path(&config).unwrap();
        let err = Policy::load_state(&config, &cfg).expect_err("a declared policy file must exist");
        assert!(
            err.to_string().contains("absent"),
            "the refusal names the disappearance: {err}"
        );
        // Without the declaration, an absent policy file is simply no registry.
        let mut plain = cfg;
        plain.audit_policy = None;
        let (policy, _, _) = Policy::load_state(&config, &plain).unwrap();
        assert!(policy.checkers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
