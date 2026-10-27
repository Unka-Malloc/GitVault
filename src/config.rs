//! Configuration: identities, ownership rules, and the signed engine policy.
//!
//! `config.toml` is the routing table. `checkers.toml` is a signed policy that
//! authorizes the external audit engine; only rows naming probator are
//! admitted at the gate, and GitVault never executes them. The
//! event-to-checker selection belongs to Probator's own policy.
//!
//! Note what is NOT here: nothing in this file is read from the repository being
//! inspected. Ownership rules and the policy live outside any work tree so that
//! a repository cannot redefine the terms under which it is judged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Which gate event an entry answers to. Hook events, GitVault's `pr` and
/// `release` operations, and the on-demand `working-tree` check share this
/// vocabulary.
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
    /// Not a git hook: an on-demand review of the uncommitted working tree.
    /// `gitvault check --event working-tree` runs it through the same engine
    /// boundary for a pre-publication look. It publishes nothing and spends no
    /// credential, so it is not itself a publication boundary.
    #[serde(rename = "working-tree")]
    WorkingTree,
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
            "working-tree" => Ok(Self::WorkingTree),
            other => bail!(
                "unknown event '{other}' (expected pre-commit, prepare-commit-msg, pre-applypatch, pre-push, commit-msg, pr, release or working-tree)"
            ),
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
    /// Aggregate byte ceiling for one release's assets. Staging refuses once
    /// the running total would exceed it - an accidentally giant asset set
    /// stops before any byte is read or sent, and a deliberate large release
    /// raises it here explicitly. Being signed into the routing table, the
    /// budget is policy, not a flag a caller can widen unilaterally.
    #[serde(default)]
    pub release_asset_budget: Option<u64>,
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

/// One row of the signed engine policy.
///
/// Rows are declarations, not commands: GitVault does not execute them -
/// Probator owns the checker set, contracts and commands. The gate admits
/// only rows naming probator; a stale review-engine row refuses the boundary.
/// The fields are kept so the file can be displayed and migrated.
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
    /// prefix of the repository root selects it. Used by the policy parser's
    /// tests; selection itself belongs to Probator now.
    #[cfg(test)]
    pub fn applies_to(&self, slug: Option<&str>, root: &Path) -> bool {
        self.repos.is_empty()
            || self
                .repos
                .iter()
                .any(|r| Some(r.as_str()) == slug || root.starts_with(r))
    }
}

/// Legacy row kind, retained so the file can be displayed and migrated.
/// GitVault never spawns a row; Probator owns checker execution.
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
    /// The file this routing table was parsed from. Kept out of the
    /// serialized shape: it is process state used by the credential broker to
    /// re-check the signature immediately before a token is read. A `Config`
    /// built directly in a test has no path and skips that check.
    #[serde(skip)]
    pub(crate) path: Option<PathBuf>,
    /// The SHA-256 of the bytes this table was parsed from. The credential
    /// broker verifies the signature against a buffer whose digest matches
    /// this value, so a file swapped between parse and credential issuance
    /// can never launder stale routing data through a fresh signature check.
    #[serde(skip)]
    pub(crate) source_digest: Option<[u8; 32]>,
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

/// The two machine-local lists the removed in-tree review engine read from
/// GitVault's own config root. The configured engine reads the same lists from
/// its config root; a second copy under GitVault is a stale policy source
/// nobody reads.
pub const LEGACY_POLICY_FILES: [&str; 2] = ["withheld-names.txt", "repo-deps.txt"];

/// What the one-time hand-off did with a legacy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyPolicyMove {
    /// The engine had no copy, so the file was moved into its config root.
    Moved,
    /// The engine's copy was byte-identical, so the redundant file was deleted.
    DuplicateRemoved,
}

/// One-time hand-off of machine-local policy data to the engine's config
/// root. `fixed_config_root` names the root the engine will use after this
/// install: true for the account home's fixed configuration directory (an
/// armed installation), false for the caller's XDG root (an unarmed
/// development tree). The caller passes the post-install state because install
/// migrates the lists before it hands the anchor to root.
///
/// Two sources can hold a list the engine is about to stop reading:
/// GitVault's old config root, and - when this install arms - the engine's own
/// unarmed root under `$XDG_CONFIG_HOME`. The second one matters because the
/// engine itself may have written there while unarmed; moving only the GitVault
/// copy would silently drop an operator's withheld names or dependency list at
/// the moment the fixed root takes over.
///
/// A file the engine lacks is moved; a byte-identical duplicate is deleted; a
/// conflicting pair refuses, because silently choosing one would discard a
/// list the operator may still need. Every target is read back and compared
/// with the source bytes before the source is removed. Idempotent: a second
/// call finds nothing.
pub fn migrate_legacy_policy_data(
    fixed_config_root: bool,
) -> Result<Vec<(PathBuf, LegacyPolicyMove)>> {
    let probator_root = crate::probator::config_root_for(fixed_config_root);
    let mut handled = migrate_policy_files(&config_dir(), &probator_root)?;
    if fixed_config_root {
        let unarmed_root = crate::probator::config_root_for(false);
        if unarmed_root != probator_root {
            handled.extend(migrate_policy_files(&unarmed_root, &probator_root)?);
        }
    }
    Ok(handled)
}

fn migrate_policy_files(
    source_root: &Path,
    target_root: &Path,
) -> Result<Vec<(PathBuf, LegacyPolicyMove)>> {
    let mut handled = Vec::new();
    for name in LEGACY_POLICY_FILES {
        let source = source_root.join(name);
        let target = target_root.join(name);
        if let Some(action) = migrate_legacy_policy_file(&source, &target)? {
            handled.push((source, action));
        }
    }
    Ok(handled)
}

fn migrate_legacy_policy_file(legacy: &Path, target: &Path) -> Result<Option<LegacyPolicyMove>> {
    let bytes = match std::fs::read(legacy) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", legacy.display()));
        }
    };
    match std::fs::read(target) {
        Ok(existing) => {
            if existing != bytes {
                bail!(
                    "policy data {} differs from Probator's {}; \
                     reconcile the two lists and remove the stale copy, then reinstall",
                    legacy.display(),
                    target.display()
                );
            }
            protect_policy_target(target)?;
            verify_policy_target(target, &bytes)?;
            std::fs::remove_file(legacy)
                .with_context(|| format!("cannot remove {}", legacy.display()))?;
            return Ok(Some(LegacyPolicyMove::DuplicateRemoved));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", target.display()));
        }
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    // The destination is claimed, never replaced: a same-user process could
    // drop a file at the path between the absence check and the move, and a
    // rename or write would silently take it over. A same-device move claims
    // the name with a hard link - AlreadyExists, never a clobber - and any
    // other failure (cross-device roots, filesystems without links) falls
    // back to an exclusive create.
    match std::fs::hard_link(legacy, target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "policy data destination {} appeared during migration - refusing",
                target.display()
            );
        }
        Err(_) => {
            // The exclusive create must also carry the private mode: under a
            // permissive umask a plain create leaves the window between open
            // and chmod world-readable while the policy bytes are written.
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let staged = options.open(target);
            let mut staged = match staged {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    bail!(
                        "policy data destination {} appeared during migration - refusing",
                        target.display()
                    );
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("cannot write {}", target.display()));
                }
            };
            use std::io::Write as _;
            if let Err(error) = staged.write_all(&bytes) {
                let _ = std::fs::remove_file(target);
                return Err(error).with_context(|| format!("cannot write {}", target.display()));
            }
        }
    }
    protect_policy_target(target)?;
    verify_policy_target(target, &bytes)?;
    std::fs::remove_file(legacy).with_context(|| format!("cannot remove {}", legacy.display()))?;
    Ok(Some(LegacyPolicyMove::Moved))
}

/// A policy list is private data: 0600 wherever it lands, enforced on moved
/// and duplicate targets alike before the legacy source is removed.
fn protect_policy_target(target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot protect {}", target.display()))?;
    }
    #[cfg(not(unix))]
    let _ = target;
    Ok(())
}

fn verify_policy_target(target: &Path, expected: &[u8]) -> Result<()> {
    let actual =
        std::fs::read(target).with_context(|| format!("cannot read back {}", target.display()))?;
    if actual != expected {
        bail!(
            "policy data at {} did not arrive intact; the source was not removed",
            target.display()
        );
    }
    Ok(())
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
        let mut cfg = Self::load_path(&path)?;
        cfg.path = Some(path);
        Ok(cfg)
    }

    /// The digest of the buffer `load_path` parsed, bound onto the config.
    fn bind_digest(cfg: &mut Self, raw: &str) {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(raw.as_bytes());
        cfg.source_digest = Some(hasher.finalize().into());
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
        let mut cfg = Self::load_path(&path)?;
        cfg.path = Some(path.clone());
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
        let mut cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("invalid configuration in {}", path.display()))?;
        cfg.validate()?;
        Self::bind_digest(&mut cfg, &raw);
        Ok(cfg)
    }

    /// Move `[[checkers]]` sections out of `config_path` into the policy file.
    /// A same-named row in the policy wins over a stale row being migrated,
    /// so certifying newer policy can never resurrect an old command.
    /// Returns the policy path that changed, or `None` when there was nothing
    /// to move.
    pub fn migrate_checkers(config_path: &Path) -> Result<Option<PathBuf>> {
        let text = std::fs::read_to_string(config_path)
            .with_context(|| format!("cannot read {}", config_path.display()))?;
        if !text
            .lines()
            .any(|l| l.trim_start().starts_with("[[checkers]]"))
        {
            return Ok(None);
        }
        // The routing table cannot be parsed as `Config` while the stale rows
        // are present, but its top-level declaration is still ordinary TOML.
        // Respect it: signing or migrating into a different file would leave
        // the declared policy unsigned and the gate reading the wrong file.
        let declared_policy = match toml::from_str::<toml::Value>(&text) {
            Ok(value) => match value.get("audit_policy") {
                Some(toml::Value::String(path)) => Some(PathBuf::from(path)),
                Some(_) => bail!("audit_policy must be a path string"),
                None => None,
            },
            // The final parse below reports a malformed routing table.
            Err(_) => None,
        };
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
        let policy_path = Policy::resolve_declared(config_path, declared_policy.as_deref());
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
            "# Signed engine authorization. The checker set belongs to Probator;\n\
             # these rows are declarations and are never executed by GitVault.\n\
             # Only rows naming probator are admitted at the gate.\n\n",
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
        let declared = declared_policy.is_some()
            || kept
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
        if let Some(parent) = policy_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        std::fs::write(&policy_path, policy_text)
            .with_context(|| format!("cannot write {}", policy_path.display()))?;
        std::fs::write(config_path, kept)
            .with_context(|| format!("cannot write {}", config_path.display()))?;
        Ok(Some(policy_path))
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

/// The signed engine policy, kept in its own file (`checkers.toml` beside
/// `config.toml`).
///
/// The signature is now the authorization that this machine may run the
/// external audit engine. The rows no longer select or execute checkers -
/// Probator's own policy does that - but an uncertified policy still refuses a
/// publication boundary, and the two signatures remain independent so the
/// routing table's blessing is judged separately from the engine's authority.
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

    /// Resolve an explicitly declared `audit_policy` value against the
    /// routing table's directory. `None` means the conventional sibling.
    pub fn resolve_declared(config_path: &Path, declared: Option<&Path>) -> PathBuf {
        match declared {
            Some(p) if p.is_absolute() => p.to_path_buf(),
            Some(p) => config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(p),
            None => Self::path_for(config_path),
        }
    }

    /// Where this routing table keeps its audit policy: the declared
    /// `audit_policy` path, else the conventional `checkers.toml` sibling.
    pub fn resolve(config_path: &Path, cfg: &Config) -> PathBuf {
        Self::resolve_declared(config_path, cfg.audit_policy.as_deref())
    }

    /// Load the policy and its signature state WITHOUT gating on it. The
    /// caller decides: a publication boundary refuses an `Invalid` state
    /// before the engine runs, because the policy is the authorization for
    /// that engine. The rows are still readable for display and migration;
    /// GitVault does not execute them.
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
            // No declaration: the conventional sibling is simply absent.
            // Its signature state still decides an armed boundary. Returning
            // `Inactive` unconditionally would let the documented bootstrap
            // (`config sign` with no `[[checkers]]` rows, then `install`)
            // reach a publication boundary with no engine authorization.
            let state = crate::configsig::signature_state(&path);
            return Ok((Self::default(), path, state));
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

    /// The gate boundary's admission rule for the signed policy.
    ///
    /// GitVault executes no row, but a signed row that names another executor
    /// is still a statement that some other program is the audit engine. The
    /// only trusted executor is `probator`; a stale `gitvault-review` row -
    /// or any other command - refuses the boundary rather than being ignored
    /// as if it had never been signed.
    pub fn admit_engine_rows(&self) -> Result<()> {
        for checker in &self.checkers {
            let declared = checker.command.first().map(String::as_str).unwrap_or("");
            let name = Path::new(declared)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(declared);
            if !name.eq_ignore_ascii_case("probator") && !name.eq_ignore_ascii_case("probator.exe")
            {
                bail!(
                    "checker '{}' invokes '{declared}': the only trusted audit executor is \
                     probator, so this signed row is refused",
                    checker.name
                );
            }
        }
        Ok(())
    }

    /// Checkers registered for an event, in declaration order. Used by the
    /// parser's tests; the running gate does not select rows.
    #[cfg(test)]
    pub fn checkers_for(&self, event: Event) -> Vec<&Checker> {
        self.checkers
            .iter()
            .filter(|c| c.on.iter().any(|e| Event::parse(e).ok() == Some(event)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Event, LegacyPolicyMove, Policy, Severity, migrate_legacy_policy_file,
        migrate_policy_files,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scratch(tag: &str) -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gv-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

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

    /// Rows are inert, but the signed file still names the audit executor.
    /// Only probator may appear; a stale gitvault-review row is refused at
    /// the gate boundary instead of being silently ignored.
    #[test]
    fn the_gate_admits_only_probator_policy_rows() {
        let probator = r#"
[[checkers]]
name = "audit"
on = ["pre-push"]
command = ["/opt/probator", "baseline", "--repo", "{repo}"]
"#;
        parse_policy(probator)
            .expect("a probator row parses")
            .admit_engine_rows()
            .expect("a probator row is admitted");

        let legacy = r#"
[[checkers]]
name = "legacy"
on = ["pre-push"]
command = ["/opt/gitvault-review", "baseline", "--repo", "{repo}"]
"#;
        let err = parse_policy(legacy)
            .expect("the stale row still parses")
            .admit_engine_rows()
            .expect_err("the removed review engine must not be admitted");
        assert!(
            err.to_string().contains("gitvault-review"),
            "the refusal names the removed engine: {err}"
        );

        let foreign = r#"
[[checkers]]
name = "foreign"
on = ["pre-push"]
command = ["/bin/true"]
"#;
        assert!(
            parse_policy(foreign).unwrap().admit_engine_rows().is_err(),
            "a non-probator executor is not admitted"
        );
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

        assert!(
            Config::migrate_checkers(&config)
                .expect("migration runs")
                .is_some()
        );
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
        assert!(
            Config::migrate_checkers(&config)
                .expect("second migration")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_honours_a_declared_non_default_policy_path() {
        let dir = scratch("mig-custom");
        let config = dir.join("config.toml");
        std::fs::write(
            &config,
            format!("audit_policy = \"policy/audit.toml\"\n{BASE}\n{POLICY}"),
        )
        .unwrap();

        let moved = Config::migrate_checkers(&config)
            .expect("migration runs")
            .expect("rows moved");
        assert_eq!(moved, dir.join("policy").join("audit.toml"));
        assert!(
            !dir.join("checkers.toml").exists(),
            "the conventional sibling must not be written when the table declares another path"
        );
        let kept = std::fs::read_to_string(&config).unwrap();
        assert_eq!(
            kept.matches("audit_policy").count(),
            1,
            "the declaration must not be duplicated: {kept}"
        );
        let reloaded = Config::load_path(&config).expect("kept config parses");
        assert_eq!(
            Policy::resolve(&config, &reloaded),
            dir.join("policy").join("audit.toml")
        );
        let policy =
            Policy::load_str(&std::fs::read_to_string(dir.join("policy/audit.toml")).unwrap())
                .expect("migrated policy parses");
        assert_eq!(policy.checkers.len(), 2);
        assert_eq!(policy.checkers[0].name, "audit");
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
            "duplicate names would make the policy ambiguous"
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
    fn accepts_the_on_demand_working_tree_event() {
        // `check --event working-tree` reviews the uncommitted tree through
        // the same engine boundary; it is a check event, not a git hook.
        assert_eq!(Event::parse("working-tree").unwrap(), Event::WorkingTree);
    }

    #[test]
    fn legacy_policy_data_moves_or_removes_duplicates_once() {
        let dir = scratch("legacy-data");
        let legacy_root = dir.join("gitvault");
        let probator_root = dir.join("probator");
        std::fs::create_dir_all(&legacy_root).unwrap();

        // Probator has no copy: the list moves into its config root.
        let names = legacy_root.join("withheld-names.txt");
        let names_target = probator_root.join("withheld-names.txt");
        std::fs::write(&names, "Acme\n").unwrap();
        assert_eq!(
            migrate_legacy_policy_file(&names, &names_target).unwrap(),
            Some(LegacyPolicyMove::Moved)
        );
        assert!(!names.exists());
        assert_eq!(std::fs::read_to_string(&names_target).unwrap(), "Acme\n");

        // Probator's copy is identical: the redundant GitVault copy goes.
        let deps = legacy_root.join("repo-deps.txt");
        let deps_target = probator_root.join("repo-deps.txt");
        std::fs::write(&deps, "Repo <- Upstream\n").unwrap();
        std::fs::write(&deps_target, "Repo <- Upstream\n").unwrap();
        assert_eq!(
            migrate_legacy_policy_file(&deps, &deps_target).unwrap(),
            Some(LegacyPolicyMove::DuplicateRemoved)
        );
        assert!(!deps.exists());
        assert!(deps_target.exists());

        // A conflicting pair refuses and deletes nothing: silently choosing
        // one list would discard names the operator still needs withheld.
        let conflict = legacy_root.join("withheld-names.txt");
        std::fs::write(&conflict, "Other\n").unwrap();
        let err = migrate_legacy_policy_file(&conflict, &names_target).unwrap_err();
        assert!(err.to_string().contains("differs"), "{err}");
        assert!(conflict.exists() && names_target.exists());

        // Idempotent: nothing left to migrate is not an error.
        assert_eq!(
            migrate_legacy_policy_file(
                &legacy_root.join("absent.txt"),
                &probator_root.join("absent.txt")
            )
            .unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An engine installed before GitVault was armed reads its lists from the
    /// caller's XDG root. Arming moves the engine to the account home's fixed
    /// root; both files must follow it, or the privacy and dependency checks
    /// silently lose their local inputs at the moment the install arms.
    #[test]
    fn arming_moves_engine_side_policy_data_from_the_unarmed_root() {
        let dir = scratch("engine-policy");
        let unarmed = dir.join("xdg").join("probator");
        let fixed = dir.join("home").join(".config").join("probator");
        std::fs::create_dir_all(&unarmed).unwrap();
        std::fs::write(unarmed.join("withheld-names.txt"), "Acme\n").unwrap();
        std::fs::write(unarmed.join("repo-deps.txt"), "Repo <- Upstream\n").unwrap();

        let handled = migrate_policy_files(&unarmed, &fixed).unwrap();
        assert_eq!(handled.len(), 2, "both lists must move: {handled:?}");
        assert!(!unarmed.join("withheld-names.txt").exists());
        assert!(!unarmed.join("repo-deps.txt").exists());
        assert_eq!(
            std::fs::read_to_string(fixed.join("withheld-names.txt")).unwrap(),
            "Acme\n"
        );
        assert_eq!(
            std::fs::read_to_string(fixed.join("repo-deps.txt")).unwrap(),
            "Repo <- Upstream\n"
        );

        // Idempotent: the next install finds nothing left to move.
        assert!(
            migrate_policy_files(&unarmed, &fixed).unwrap().is_empty(),
            "a second migration must be a no-op"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_an_unknown_hook_event() {
        let bad = POLICY.replace(
            "on = [\"pre-commit\", \"pre-push\"]",
            "on = [\"post-commit\"]",
        );
        assert!(parse_policy(&bad).is_err());
    }

    /// The credential broker re-checks the signature on the file the table
    /// came from. A parsed table that forgot its path would silently skip that
    /// check, so `load` and `load_unverified` both record it.
    #[test]
    fn loading_records_the_path_for_credential_time_checks() {
        let dir = scratch("config-path");
        let path = dir.join("config.toml");
        std::fs::write(&path, BASE).unwrap();
        let (cfg, returned, _) = Config::load_unverified(Some(&path)).unwrap();
        assert_eq!(returned, path);
        assert_eq!(cfg.path.as_deref(), Some(path.as_path()));
        let _ = std::fs::remove_dir_all(&dir);
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
