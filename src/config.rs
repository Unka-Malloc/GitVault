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
    /// `python` injects safe-path flags; `exec` runs the command verbatim.
    /// Declaring the kind is what lets the engine apply language-specific
    /// hardening without the user having to remember it.
    #[serde(default = "default_kind")]
    pub kind: Kind,
    #[serde(default = "default_event")]
    pub on: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_timeout")]
    /// Zero waits for completion without a wall-clock deadline.
    pub timeout_secs: u64,
    /// Command and arguments. Placeholders are substituted from the run context:
    /// `{repo}`, `{event}`, `{identity}`, `{account}`, `{email}`.
    pub command: Vec<String>,
    /// Extra environment for the checker. `{identity}`-style placeholders apply.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Exec,
    Python,
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
    #[serde(default)]
    pub checkers: Vec<Checker>,
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
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("invalid configuration in {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
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
        if let Some(default) = &self.rules.default {
            if !self.identities.contains_key(default) {
                bail!("rules.default names unknown identity '{default}'");
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for checker in &self.checkers {
            if !seen.insert(checker.name.clone()) {
                bail!("duplicate checker name '{}'", checker.name);
            }
            if checker.command.is_empty() {
                bail!("checker '{}' has an empty command", checker.name);
            }
            for event in &checker.on {
                Event::parse(event)
                    .with_context(|| format!("checker '{}'", checker.name))?;
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
    use super::{Config, Event, Severity};

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
        let dir = std::env::temp_dir().join(format!(
            "gv-cfg-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, s).unwrap();
        let loaded = Config::load(Some(&path));
        let _ = std::fs::remove_dir_all(&dir);
        loaded
    }

    #[test]
    fn accepts_a_well_formed_registry() {
        let cfg = parse(BASE).expect("valid config");
        assert_eq!(cfg.checkers.len(), 2);
        assert_eq!(cfg.checkers_for(Event::PreCommit).len(), 2);
        assert_eq!(cfg.checkers_for(Event::PrePush).len(), 1);
        assert_eq!(cfg.checkers_for(Event::CommitMsg).len(), 0);
        assert_eq!(cfg.checkers_for(Event::Pr).len(), 0);
        assert_eq!(cfg.checkers[0].severity, Severity::Blocking);
        assert_eq!(cfg.checkers[1].severity, Severity::Advisory);
    }

    #[test]
    fn accepts_the_publication_boundary_events() {
        // `pre-push` and `pr` are the boundaries content crosses to become
        // public; a checker registered on `pr` is selected for that event only.
        let with_pr = BASE.replace("on = [\"pre-commit\"]", "on = [\"pre-commit\", \"pr\"]");
        let cfg = parse(&with_pr).expect("valid config");
        assert_eq!(cfg.checkers_for(Event::Pr).len(), 1);
        assert_eq!(cfg.checkers_for(Event::Pr)[0].name, "advisory");
        assert_eq!(cfg.checkers_for(Event::PrePush).len(), 1);
    }

    #[test]
    fn rejects_an_owner_rule_pointing_at_an_undefined_identity() {
        let bad = BASE.replace("acme = \"acme\"", "acme = \"nobody\"");
        assert!(parse(&bad).is_err(), "must reject an unknown identity target");
    }

    #[test]
    fn rejects_a_default_pointing_at_an_undefined_identity() {
        let bad = BASE.replace("default = \"personal\"", "default = \"ghost\"");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_checker_names() {
        let bad = format!("{BASE}\n[[checkers]]\nname = \"audit\"\ncommand = [\"/bin/true\"]\n");
        assert!(parse(&bad).is_err(), "duplicate names would make --only ambiguous");
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
            BASE.replace("severity = \"advisory\"", "severity = \"advisory\"\nsevverity = \"blocking\""),
            BASE.replace("email = \"acme@example.invalid\"", "email = \"acme@example.invalid\"\nworkspace = \"/tmp\""),
        ] {
            assert!(parse(&bad).is_err(), "an unknown key must be refused: {bad}");
        }
    }

    #[test]
    fn a_key_after_a_table_header_belongs_to_that_table() {
        // The trap this guards against: a top-level knob written below a table
        // header is parsed as part of that table, and without unknown-key
        // rejection it is dropped without a word.
        let misplaced = BASE.replace("[rules]", "[rules]\nrecord_dir = \"/tmp/runs\"");
        assert!(parse(&misplaced).is_err(), "a misplaced top-level key must be refused");
        let placed = format!("record_dir = \"/tmp/runs\"\n{BASE}");
        let cfg = parse(&placed).expect("a top-level key before every header parses");
        assert_eq!(cfg.record_dir.as_deref(), Some(std::path::Path::new("/tmp/runs")));
    }

    #[test]
    fn rejects_an_unknown_hook_event() {
        let bad = BASE.replace("on = [\"pre-commit\", \"pre-push\"]", "on = [\"post-commit\"]");
        assert!(parse(&bad).is_err());
    }
}
