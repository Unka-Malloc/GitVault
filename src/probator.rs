//! The audit engine boundary: GitVault asks the configured engine, and nothing
//! else.
//!
//! GitVault used to carry a second audit implementation: it executed checker
//! rows from its own signed policy, resolved ranges, ran reviewer agents and
//! sealed receipts. That made two implementations of the same audit and two
//! places for a policy to drift. The engine is now the only audit
//! implementation. This module is the whole integration surface:
//!
//! * one JSON action per review object goes to `probator gate-audit` on stdin,
//!   in the engine's `{kind, target, detail}` vocabulary;
//! * the JSON findings array comes back on stdout and is projected onto
//!   GitVault's report/record shape;
//! * any failure to start, finish or parse the engine is a blocking finding -
//!   an audit that cannot answer refuses instead of passing silently.
//!
//! GitVault contributes only what it alone knows: the event, the repository,
//! the pushed heads, the pull-request range and the release commit. It does
//! not read the engine's policy file or execute its checker rows; `probator
//! inspect --json` is the machine-readable policy the engine itself enforces.
//!
//! The signed operator objection ledger stays GitVault's: every invocation
//! points the engine at GitVault's ledger and public anchor, so a signed ruling
//! made with `gitvault objection` applies to the engine's findings unchanged.
//!
//! The engine is the public [Probator](https://github.com/Unka-Malloc/Probator)
//! project; its contract vocabulary and profile layout are documented there.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::checkers::{CheckerOutcome, Context, OutcomeKind};
use crate::config::Severity;

/// The contract that carries publication hardening. The name is a deliberate,
/// documented coupling to Probator's installed policy: the engine exposes no
/// "this row is the hardening gate" marker, so a name is the only identity it
/// publishes. The required *domain* set is not copied here; it is read from
/// the contract file the row names, so a domain the engine adds or renames is
/// required rather than silently rejected as missing coverage. The accepted
/// name and current domain set are documented in README, AGENTS and
/// `docs/security-model.md`, and named in the refusal text.
const HARDENING_CONTRACT: &str = "security-enhancer";

/// A second audit waits for the repository's audit lock for as long as its
/// live owner runs. There is deliberately no internal elapsed-time cutoff: a
/// slow audit is spending work that is already paid for, and rejecting a
/// still-valid concurrent request merely because time passed would turn a
/// queue into a failure. Only a dead or unreadable owner releases the lock.
const AUDIT_LOCK_POLL: Duration = Duration::from_millis(250);
/// Finding text is rendered and recorded. A bounded, sanitized projection is
/// enough to act on and cannot become an evidence dump.
const MAX_FINDING_TEXT: usize = 4 * 1024;

/// Whether the signature anchor is armed. In that state the routing table and
/// engine policy are root-anchored, so the engine must come from the fixed
/// installed path rather than an environment or PATH override.
fn enforcement_armed() -> bool {
    matches!(
        crate::configsig::anchor_state(&crate::configsig::anchor_path()),
        crate::configsig::Anchor::Anchored
    )
}

/// The integration-test anchor escape is itself a debug-only fixture. When it
/// is set, the test may point the engine and state roots at its own fixtures;
/// a release binary never compiles this branch.
fn fixture_armed() -> bool {
    cfg!(debug_assertions) && std::env::var_os("GITVAULT_ANCHOR").is_some()
}

/// The fixture seam. `GITVAULT_PROBATOR` lets the integration tests and a
/// development build point at a deterministic stub; a release binary compiles
/// the override out, and an armed installation never consults it. The code is
/// conditional rather than a runtime check so the release binary contains no
/// such resolution path at all.
#[cfg(debug_assertions)]
fn explicit_engine() -> Option<PathBuf> {
    std::env::var("GITVAULT_PROBATOR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(not(debug_assertions))]
fn explicit_engine() -> Option<PathBuf> {
    None
}

fn sibling_engine() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let sibling = exe.parent()?.join("probator");
    is_executable(&sibling).then_some(sibling)
}

fn installed_engine() -> Option<PathBuf> {
    let installed = crate::configsig::home_dir()
        .join(".local")
        .join("bin")
        .join("probator");
    is_executable(&installed).then_some(installed)
}

/// Whether `gitvault install` has an installed engine to immobilise. The
/// installer uses this instead of [`engine`] so a reinstall can find the
/// binary it is about to re-lock, while the runtime gate judges the lock.
pub(crate) fn installed_engine_path() -> Option<PathBuf> {
    installed_engine()
}

/// Resolve the audit engine's path. An armed installation trusts only the
/// installed path (`~/.local/bin/probator`, which `gitvault install`
/// immobilises with `schg`); no environment variable, `PATH` entry or
/// build-tree sibling can substitute for it. An unarmed development tree may
/// use the debug fixture seam, a sibling or `PATH`.
///
/// This function answers "where is the engine", not "may its verdict carry a
/// publication". Callers that authorize something use [`engine_for`], which
/// re-checks the trusted property on every invocation.
pub fn engine() -> Result<PathBuf, String> {
    if !enforcement_armed() {
        // The environment seam is active only with the debug fixture anchor;
        // a bare GITVAULT_PROBATOR in a developer shell is not enough.
        if fixture_armed()
            && let Some(explicit) = explicit_engine()
        {
            return Ok(explicit);
        }
        if let Some(sibling) = sibling_engine() {
            return Ok(sibling);
        }
        if let Some(found) = find_on_path("probator") {
            return Ok(found);
        }
        return Err(
            "probator is not installed beside gitvault or on PATH - publication audits \
             cannot run"
                .to_string(),
        );
    }
    if fixture_armed()
        && let Some(explicit) = explicit_engine()
    {
        return Ok(explicit);
    }
    if let Some(installed) = installed_engine() {
        return Ok(installed);
    }
    Err(
        "probator is not installed at the immobilized enforcement path \
         (~/.local/bin/probator) - publication audits cannot run"
            .to_string(),
    )
}

/// The trust decision for one engine invocation. Split from [`engine_for`] so
/// the policy is testable without an armed anchor on the test machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineTrust {
    Allow,
    Warn,
    Refuse,
}

fn engine_trust(event: &str, armed: bool, fixture: bool, trusted: bool) -> EngineTrust {
    if !armed || fixture || trusted {
        return EngineTrust::Allow;
    }
    if event == "working-tree" {
        EngineTrust::Warn
    } else {
        EngineTrust::Refuse
    }
}

/// Resolve the engine for an event that may authorize a publication.
///
/// In an armed installation the installed engine must be root-owned or carry
/// the system immutable flag. That property is checked here, at every
/// invocation, rather than inferred from install order: Probator is a separate
/// tool, and a user-writable binary at the trusted path could answer
/// `gate-audit` with an empty findings array.
///
/// `working-tree` is the one event that publishes nothing. It still gets the
/// real engine, but a failed trust check only warns instead of refusing: the
/// snapshot authorizes no credential or ref. Every hook, `pr` and `release`
/// boundary refuses.
pub fn engine_for(event: &str) -> Result<PathBuf, String> {
    let binary = engine()?;
    let trust = engine_trust(
        event,
        enforcement_armed(),
        fixture_armed(),
        crate::configsig::executable_is_trusted(&binary),
    );
    match trust {
        EngineTrust::Allow => Ok(binary),
        EngineTrust::Warn => {
            eprintln!(
                "gitvault: warning: the audit engine at {} is not locked against this user\n  \
                 this on-demand working-tree snapshot authorizes nothing; run `gitvault install` \
                 to immobilise the engine before a publication boundary",
                binary.display()
            );
            Ok(binary)
        }
        EngineTrust::Refuse => Err(format!(
            "the audit engine at {} is user-writable; a same-user process could replace it \
             and answer with an empty findings array\n  run `gitvault install` to immobilise \
             the engine before a publication boundary",
            binary.display()
        )),
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

/// The fixed `PATH` the engine and its runner see. The root-owned system
/// directories come first, so an attacker-controlled `git` placed in a
/// user-writable directory cannot be the helper the audit executes. The
/// engine's own directory and `~/.local/bin` follow: that is where the
/// engine's agent lives, but system helpers still win the lookup. The
/// caller's `PATH` is never inherited.
///
/// User-writable package-manager directories (`/usr/local/bin`,
/// `/opt/homebrew/bin`) are absent unless the engine itself resolves there:
/// its parent is then appended after the system directories, never first and
/// never twice. Resolving the engine binary from configuration while running
/// helpers from a fixed root-owned path keeps the two trust decisions
/// separate.
fn engine_path(binary: &Path) -> OsString {
    engine_path_for(binary, &crate::configsig::home_dir())
}

/// The same rule with the account home supplied, so a test can place a fake
/// helper in the exact user-writable directory the resolver appends without
/// touching the machine's real home.
fn engine_path_for(binary: &Path, home: &Path) -> OsString {
    let home_bin = home.join(".local").join("bin");
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let dir = PathBuf::from(dir);
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    if let Some(parent) = binary.parent() {
        let parent = parent.to_path_buf();
        if !dirs.contains(&parent) {
            dirs.push(parent);
        }
    }
    if !dirs.contains(&home_bin) {
        dirs.push(home_bin);
    }
    std::env::join_paths(dirs).unwrap_or_else(|_| OsString::from("/usr/bin:/bin"))
}

/// The engine's configuration root, resolved once for both `gitvault
/// install`'s policy-list hand-off and the engine's child environment.
///
/// An armed installation gets the account home's fixed layout, matching the
/// fixed `HOME` the engine is given. While unarmed, the caller's
/// `XDG_CONFIG_HOME` is honoured so fixtures and a development tree can point
/// both sides at the same directory. The two behaviours must not drift: if
/// install moved the withheld-name and dependency-direction lists into one
/// root and the armed engine read another, the engine would silently lose its
/// machine-local privacy checks.
pub(crate) fn config_root() -> PathBuf {
    config_root_for(enforcement_armed() && !fixture_armed())
}

/// The same resolver with the armed state supplied by the caller. `gitvault
/// install` migrates the policy lists *before* it hands the anchor to root, so
/// it must resolve the root the engine will use after that hand-off rather
/// than the (still unarmed) state of this process.
pub(crate) fn config_root_for(fixed: bool) -> PathBuf {
    let config_home = config_home(
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        &crate::configsig::home_dir(),
        fixed,
    );
    config_home.join("probator")
}

/// The XDG configuration base directory this engine will read. Split out so
/// the armed/unarmed decision is testable without touching the environment.
fn config_home(xdg: Option<&std::ffi::OsStr>, home: &Path, fixed: bool) -> PathBuf {
    if fixed {
        return home.join(".config");
    }
    xdg.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

/// A command for the engine with an explicit environment. Provider keys,
/// `SSH_AUTH_SOCK`, `PROBATOR_*` overrides and `GITVAULT_*` are not inherited:
/// the engine gets the account home, a fixed search path and locale, and
/// nothing a caller could use to redirect its policy or borrow a credential.
/// The engine's configuration root is pinned to the same resolver `gitvault
/// install` uses; other XDG roots are honoured only while enforcement is
/// unarmed (fixtures and a development tree).
pub fn command(binary: &Path) -> Command {
    let armed = enforcement_armed();
    let mut command = Command::new(binary);
    command.env_clear();
    command.env("HOME", crate::configsig::home_dir());
    command.env("PATH", engine_path(binary));
    // Pin the engine's configuration root explicitly. In armed mode this is
    // the account home's fixed `~/.config`, so the withheld-name and
    // dependency-direction lists moved by install are the ones it reads.
    if let Some(parent) = config_root().parent() {
        command.env("XDG_CONFIG_HOME", parent);
    }
    if let Some(value) = std::env::var_os("TMPDIR") {
        command.env("TMPDIR", value);
    }
    for key in [
        "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "LOGNAME", "SHELL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if !armed || fixture_armed() {
        for key in [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
    }
    command
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The events Probator's gate surface understands. Local events (`pre-commit`,
/// the message hooks) never reach Probator: GitVault's own identity and
/// attribution gates intercept those, and Probator has no vocabulary for them.
/// `working-tree` is the on-demand snapshot `gitvault check --event
/// working-tree` asks for; Probator binds it to the pre-push boundary and
/// reviews the uncommitted tree.
pub fn applies(event: &str) -> bool {
    matches!(event, "pre-push" | "pr" | "release" | "working-tree")
}

/// The review objects one GitVault event carries, as gate actions.
///
/// A push is one review object even when it moves several refs, so it yields
/// one action carrying every new ref line. A pull request has exactly one
/// head, and a release exactly one commit. A deletion-only push publishes
/// nothing and yields no actions. A working-tree check has exactly one review
/// object: the uncommitted snapshot.
fn actions(ctx: &Context) -> Result<Vec<Value>, String> {
    let target = ctx.repo_root.display().to_string();
    match ctx.event.as_str() {
        "pre-push" => {
            let refs = ctx.stdin.as_deref().unwrap_or_default();
            // One action carries the whole push. Probator reads each line's
            // remote sha as the review base and its local sha as the head, so
            // the action keeps the exact `<remote-ref>..<local-head>` scope
            // for every ref. Splitting by head would start one full checker
            // set per head for the same push.
            let mut lines: Vec<String> = Vec::new();
            for line in refs.lines().filter(|line| !line.trim().is_empty()) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() != 4 {
                    return Err(
                        "a pre-push ref line is malformed: expected four whitespace-separated fields"
                            .to_string(),
                    );
                }
                let (local_sha, remote_sha) = (fields[1], fields[3]);
                if local_sha.trim_matches('0').is_empty() {
                    continue; // a deletion publishes nothing
                }
                if local_sha == remote_sha {
                    continue; // already published at this ref
                }
                let line = line.trim().to_string();
                if !lines.contains(&line) {
                    lines.push(line);
                }
            }
            if lines.is_empty() {
                return Ok(Vec::new());
            }
            Ok(vec![json!({
                "kind": "pre-push",
                "target": target,
                "detail": {
                    // `range` must stay absent. Probator gives any range
                    // precedence over `push_refs`, resolving it as a bare
                    // snapshot of one commit with no base — which drops the
                    // remote-tip..local-head scope the ref lines carry. The
                    // local head is already the local sha of each line.
                    "push_refs": lines.join("\n"),
                },
            })])
        }
        "pr" => {
            // Probator reads `head` and `base`, not GitVault's internal
            // `pr_*` spellings: its range environment maps those two names
            // onto PROBATOR_PR_HEAD/PROBATOR_PR_BASE and the `pr` event then
            // resolves the already-fetched commit locally. `range` must stay
            // absent: it wins over the event scope and turns the review into
            // a bare snapshot, losing the base. `number` stays absent too:
            // Probator reacts to it by fetching `pull/<n>/head` again inside
            // the audit, while GitVault spent that one credential moment
            // before the engine started and froze the resolved head here.
            let mut detail = Map::new();
            let head = ctx
                .pr_head
                .as_deref()
                .filter(|h| !h.trim().is_empty())
                .ok_or("the pull request audit has no head commit")?;
            detail.insert("head".into(), json!(head));
            if let Some(base) = ctx.pr_base.as_deref().filter(|b| !b.is_empty()) {
                detail.insert("base".into(), json!(base));
            }
            Ok(vec![json!({
                "kind": "pr",
                "target": target,
                "detail": Value::Object(detail),
            })])
        }
        "release" => {
            let mut detail = Map::new();
            if let Some(tag) = ctx.release_tag.as_deref().filter(|t| !t.is_empty()) {
                detail.insert("tag".into(), json!(tag));
            }
            if let Some(commit) = ctx.release_commit.as_deref().filter(|c| !c.is_empty()) {
                detail.insert("commit".into(), json!(commit));
            }
            if detail.is_empty() {
                return Err("the release audit names neither a tag nor a commit".into());
            }
            // The assets publish alongside the commit, so the evidence names
            // their exact bytes and where the scan can read them: name, size,
            // digest and the private immutable snapshot path per file. The
            // upload streams that same snapshot to GitHub.
            if !ctx.release_assets.is_empty() {
                detail.insert(
                    "assets".into(),
                    Value::Array(
                        ctx.release_assets
                            .iter()
                            .map(|(name, size, sha256, staged)| {
                                json!({"name": name, "size": size, "sha256": sha256, "staged": staged})
                            })
                            .collect(),
                    ),
                );
            }
            Ok(vec![json!({
                "kind": "release",
                "target": target,
                "detail": Value::Object(detail),
            })])
        }
        "working-tree" => Ok(vec![json!({
            "kind": "working-tree",
            "target": target,
            // Probator's `range` spelling for the uncommitted state. Its
            // event mapping binds a working-tree action to the pre-push
            // checker set, so the snapshot is reviewed by the same rows.
            "detail": { "range": "working-tree" },
        })]),
        other => Err(format!("'{other}' is not a Probator audit event")),
    }
}

/// The engine's data root: `$XDG_DATA_HOME` while unarmed, the account
/// home's fixed `~/.local/share` when the anchor is armed. Split out so the
/// armed/unarmed decision is testable without mutating the environment.
fn data_home(xdg: Option<&std::ffi::OsStr>, home: &Path, fixed: bool) -> PathBuf {
    if fixed {
        return home.join(".local").join("share");
    }
    xdg.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local").join("share"))
}

/// The engine's profile root. An armed install uses the fixed account layout;
/// while unarmed (fixtures, development), the XDG root is honoured so both
/// sides point at the same tree. This is the one resolver behind the engine
/// child's data root and `gitvault objection file`'s report lookup: an
/// objection must bind the report the engine actually wrote, not a second
/// copy under a caller's redirected home.
pub(crate) fn profiles_root() -> PathBuf {
    profiles_root_for(enforcement_armed() && !fixture_armed())
}

/// The same resolver with the armed state supplied by the caller, for the
/// install and fixture paths that must reason about the post-install state.
pub(crate) fn profiles_root_for(fixed: bool) -> PathBuf {
    let data = data_home(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        &crate::configsig::home_dir(),
        fixed,
    );
    data.join("probator").join("profiles")
}

/// Whether a policy row is the reviewed engine shape: a contract under
/// Probator's profiles root, or the contract-free deterministic `baseline`
/// entry point. An out-of-tree contract, an advisory row, or a command that
/// merely mentions an event does not count.
fn row_is_contract_bound(row: &Value, profiles: &Path) -> bool {
    if let Some(contract) = row.get("contract").and_then(Value::as_str) {
        return Path::new(contract)
            .canonicalize()
            .ok()
            .zip(profiles.canonicalize().ok())
            .is_some_and(|(contract, root)| contract.starts_with(root));
    }
    let command = row.get("command").and_then(Value::as_array);
    let Some(command) = command else {
        return false;
    };
    let runner = command
        .first()
        .and_then(Value::as_str)
        .and_then(|program| Path::new(program).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "probator" || name == "probator.exe");
    let baseline = command
        .iter()
        .filter_map(Value::as_str)
        .nth(1)
        .is_some_and(|subcommand| subcommand == "baseline");
    runner && baseline
}

/// Whether a policy row would audit *this* repository. GitVault's signed
/// policy schema scopes rows with `repos` (origin slug or work-tree path
/// prefix, matching `Checker::applies_to`); an empty or absent list applies
/// everywhere. A row scoped entirely elsewhere is not coverage, however many
/// domains it declares.
fn row_applies(row: &Value, ctx: &Context) -> bool {
    let Some(repos) = row.get("repos") else {
        return true;
    };
    let Some(repos) = repos.as_array() else {
        // A malformed scope is not an unconditional grant.
        return false;
    };
    repos.is_empty()
        || repos.iter().filter_map(Value::as_str).any(|scope| {
            Some(scope) == ctx.repo_slug.as_deref() || ctx.repo_root.starts_with(scope)
        })
}

/// Whether a policy row is the hardening contract publication requires: the
/// blocking contract-bound row, declaring the full domain set. A generic
/// blocking row, an advisory row or a policy that merely names the event
/// cannot stand in for that review.
fn row_runs_contract(row: &Value, binary: &Path, contract: &str) -> bool {
    let Some(command) = row.get("command").and_then(Value::as_array) else {
        return false;
    };
    let args: Vec<&str> = command.iter().filter_map(Value::as_str).collect();
    // The row must resolve the review target to the repository the gate is
    // auditing. `gate-audit` substitutes `{repo}` and runs the command from
    // its own working directory, so a fixed `--repo /somewhere/else` would
    // audit another tree and return its empty findings here.
    let mut repo_arg = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--repo" {
            repo_arg = args.get(i + 1).copied();
            i += 2;
            continue;
        }
        if let Some(value) = args[i].strip_prefix("--repo=") {
            repo_arg = Some(value);
        }
        i += 1;
    }
    if repo_arg != Some("{repo}") {
        return false;
    }
    let runner = args
        .first()
        .and_then(|program| Path::new(program).canonicalize().ok())
        .zip(binary.canonicalize().ok())
        .is_some_and(|(declared, actual)| declared == actual);
    let runs_contract = args.contains(&"run")
        && args.windows(2).any(|pair| {
            pair[0] == "--contract"
                && Path::new(pair[1])
                    .canonicalize()
                    .ok()
                    .zip(Path::new(contract).canonicalize().ok())
                    .is_some_and(|(declared, actual)| declared == actual)
        });
    runner && runs_contract
}

/// The domains a hardening contract declares. The contract file named by the
/// policy row is the authority, not a copy in this source tree. A malformed
/// declaration, a non-blocking contract or a contract for another checker is
/// not coverage; none of those may silently shrink the reviewed set.
fn hardening_contract_domains(contract: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(contract).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    if value.get("name").and_then(Value::as_str) != Some(HARDENING_CONTRACT)
        || value.get("severity").and_then(Value::as_str) != Some("blocking")
    {
        return None;
    }
    let declared = value.get("domains")?.as_array()?;
    let keys: Option<Vec<&str>> = declared.iter().map(Value::as_str).collect();
    let keys = keys?;
    (!keys.is_empty()).then(|| keys.into_iter().map(str::to_string).collect())
}

fn hardening_row(row: &Value, profiles: &Path, binary: &Path) -> bool {
    if row.get("name").and_then(Value::as_str) != Some(HARDENING_CONTRACT) {
        return false;
    }
    if row.get("severity").and_then(Value::as_str) != Some("blocking") {
        return false;
    }
    if !row_is_contract_bound(row, profiles) {
        return false;
    }
    let Some(contract) = row.get("contract").and_then(Value::as_str) else {
        return false;
    };
    if !row_runs_contract(row, binary, contract) {
        return false;
    }
    let Some(required) = hardening_contract_domains(contract) else {
        return false;
    };
    let Some(domains) = row.get("domains").and_then(Value::as_array) else {
        return false;
    };
    required.iter().all(|required| {
        domains
            .iter()
            .any(|domain| domain.get("key").and_then(Value::as_str) == Some(required.as_str()))
    })
}

/// The policy event a GitVault event maps onto. The engine treats a
/// `working-tree` action as a snapshot of the pre-push boundary, so the
/// completeness check must read the same rows the engine will run.
fn policy_event(event: &str) -> &str {
    match event {
        "working-tree" => "pre-push",
        other => other,
    }
}

/// Whether the engine's inspected rows bind the hardening review to this
/// event and this repository. A row counts only when it is the blocking
/// contract-bound row under the engine's profiles root whose contract declares
/// the full hardening domain set, whose row covers every one of those domains,
/// names a command that runs that contract against `{repo}`, and has no
/// `repos` scope excluding this tree.
fn covers_hardening(rows: &Value, ctx: &Context, profiles: &Path, binary: &Path) -> bool {
    let event = policy_event(&ctx.event);
    rows.as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            let on_event = row
                .get("on")
                .and_then(Value::as_array)
                .is_some_and(|on| on.iter().any(|candidate| candidate.as_str() == Some(event)));
            on_event && row_applies(row, ctx) && hardening_row(row, profiles, binary)
        })
    })
}

/// Ask Probator's enforced policy whether the hardening review covers this
/// event.
///
/// This is the gate-completeness check: gate-audit prints `[]` both when
/// every checker passed and when no checker was bound to the event, and an
/// empty policy must not bless a gate. Reading Probator's own machine
/// form keeps GitVault from parsing the policy file itself.
fn policy_covers(binary: &Path, ctx: &Context) -> Result<(), String> {
    let output = command(binary)
        .args(["inspect", "--json"])
        .output()
        .map_err(|error| format!("probator inspect could not run: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let first = detail
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no diagnostic");
        return Err(format!(
            "probator's enforced policy could not be read ({}): {first}",
            output.status
        ));
    }
    let rows: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("probator inspect --json is not valid JSON: {error}"))?;
    let profiles = profiles_root();
    let event = policy_event(&ctx.event);
    if covers_hardening(&rows, ctx, &profiles, binary) {
        Ok(())
    } else {
        let scope = if event == ctx.event {
            event.to_string()
        } else {
            format!("{event} (the boundary Probator applies to {})", ctx.event)
        };
        Err(format!(
            "the configured engine's audit policy has no blocking {HARDENING_CONTRACT} hardening \
             checker covering {scope} with a contract under {} - GitVault accepts that contract \
             identity and requires every domain it declares (this build documents \
             dependency_supply_chain, ci_workflow_authority, secret_handling, transport_security, \
             authz_defaults, container_runtime, release_artifacts) to be covered by a row that \
             runs the contract against {{repo}}; the gate needs audit evidence, not a vacuous pass",
            profiles.display()
        ))
    }
}

/// One repository's audit mutex. Two concurrent gate invocations can enter the
/// same review, and a review ending can remove state the other invocation is
/// still using, so one can finish without a sealed report. Serializing
/// GitVault's engine calls is the fix on this side of the boundary. A stale
/// lock (a dead owner, or an unreadable owner after a short grace) is
/// reclaimed; a live owner is waited for without an internal elapsed-time
/// cutoff.
struct AuditLock {
    path: PathBuf,
}

/// The identity a lock is keyed by. Probator names a repository by its origin
/// slug when there is one, so two clones of that repository serialize on the
/// same key; otherwise the common git directory keeps linked worktrees
/// together. The canonical work-tree path is the last fallback.
fn lock_identity(repo: &Path, slug: Option<&str>) -> String {
    if let Some(slug) = slug.filter(|slug| !slug.trim().is_empty()) {
        return format!("repo:{}", slug.trim().to_ascii_lowercase());
    }
    let common = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            let path = Path::new(&value);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo.join(path)
            }
        });
    common
        .and_then(|path| path.canonicalize().ok())
        .or_else(|| repo.canonicalize().ok())
        .unwrap_or_else(|| repo.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

impl AuditLock {
    fn acquire(repo: &Path, slug: Option<&str>) -> Result<Self, String> {
        let key = {
            let mut hasher = Sha256::new();
            hasher.update(lock_identity(repo, slug).as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let base = if enforcement_armed() && !fixture_armed() {
            crate::configsig::home_dir().join(".local").join("state")
        } else {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| crate::configsig::home_dir().join(".local").join("state"))
        };
        let root = base.join("gitvault").join("locks");
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("cannot create the audit lock root: {error}"))?;
        let path = root.join(format!("audit-{}", &key[..32]));
        let mut announced = false;
        loop {
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(error) =
                        std::fs::write(path.join("pid"), std::process::id().to_string())
                    {
                        let _ = std::fs::remove_dir_all(&path);
                        return Err(format!("cannot record the audit lock owner: {error}"));
                    }
                    // The boot session is recorded alongside the pid: a lock
                    // surviving a reboot can name a pid the new session has
                    // already reused, which a liveness probe alone reads as
                    // alive forever.
                    if let Some(boot) = boot_session() {
                        let _ = std::fs::write(path.join("boot"), boot);
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        reclaim_stale(&path);
                        continue;
                    }
                    // The owner is alive, so the review is still in progress.
                    // Wait for it without an internal deadline: it may be
                    // spending tokens already paid for, and a valid request
                    // must not be rejected just because the queue is slow.
                    if !announced {
                        eprintln!(
                            "gitvault: another audit holds this repository's lock; \
                             waiting for it to finish"
                        );
                        announced = true;
                    }
                    std::thread::sleep(AUDIT_LOCK_POLL);
                }
                Err(error) => return Err(format!("cannot take the audit lock: {error}")),
            }
        }
    }
}

impl Drop for AuditLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // Signal 0 only probes existence; it sends nothing. `EPERM` still means
    // the process exists, so treat any non-`ESRCH` result as alive.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // Without a liveness probe, assume the owner is alive. Reclaiming a live
    // lock would reintroduce the concurrent-resume race; a stale lock on a
    // non-Unix host waits rather than corrupts a run.
    true
}

/// How long a lock directory may exist without a readable owner PID before a
/// waiter may reclaim it. `create_dir` and the owner's `pid` write are two
/// operations; the gap is normally microscopic, but a waiter that read the
/// directory in that gap must not steal a lock the creator is about to own.
const LOCK_PID_GRACE: Duration = Duration::from_secs(5);

/// Move a stale lock aside before deleting it. Two waiters can both decide the
/// same lock is stale; an atomic rename is what makes exactly one of them the
/// reclaimer. The loser's rename fails with `ENOENT` and it retries the
/// `create_dir`, while the winner deletes only the directory it moved. A
/// plain "remove then create" would let both believe they hold the lock.
fn reclaim_stale(path: &Path) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "audit-lock".to_string());
    let aside = path.with_file_name(format!("{name}.stale-{}-{stamp}", std::process::id()));
    if std::fs::rename(path, &aside).is_ok() {
        let _ = std::fs::remove_dir_all(&aside);
    }
}

/// The current boot session, from `kern.boottime`. A pid recorded under a
/// different boot cannot name a process in this session: the number may have
/// been reused, so the lock is reclaimable rather than waited on.
#[cfg(target_os = "macos")]
fn boot_session() -> Option<String> {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>();
    let name = std::ffi::CString::new("kern.boottime").ok()?;
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut tv as *mut _ as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (ok == 0).then(|| format!("{}:{}", tv.tv_sec, tv.tv_usec))
}

#[cfg(not(target_os = "macos"))]
fn boot_session() -> Option<String> {
    // /proc uptime resets each boot and needs no platform API.
    std::fs::read_to_string("/proc/stat").ok().and_then(|stat| {
        stat.lines()
            .find_map(|line| line.strip_prefix("btime ").map(str::to_string))
    })
}

fn lock_is_stale(path: &Path) -> bool {
    // A live PID keeps its lock no matter how long the audit runs. Only a
    // dead or unreadable owner is reclaimable; a missing or half-written PID
    // gets a short grace period for the creator to write it.
    let age = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok());
    // A lock recorded under a different boot session can never own a live
    // process now; its pid number may already belong to an unrelated program.
    if let (Some(current), Ok(recorded)) =
        (boot_session(), std::fs::read_to_string(path.join("boot")))
        && recorded.trim() != current
    {
        return true;
    }
    match std::fs::read_to_string(path.join("pid")) {
        Ok(raw) => match raw.trim().parse::<u32>() {
            // A pid outside the signed pid_t range cannot name a process; do
            // not let it wrap to a negative process-group probe.
            Ok(pid) if pid > 0 && pid <= i32::MAX as u32 => !process_alive(pid),
            Ok(_) => true,
            Err(_) => age.is_some_and(|age| age > LOCK_PID_GRACE),
        },
        Err(_) => age.is_some_and(|age| age > LOCK_PID_GRACE),
    }
}

fn blocking(name: &str, why: String, started: Instant) -> CheckerOutcome {
    // The refusal text can quote the engine's stderr; that is untrusted input
    // and goes through the same projection as a finding.
    let why = safe_text(&why);
    CheckerOutcome {
        name: name.to_string(),
        severity: Severity::Blocking,
        outcome: OutcomeKind::CouldNotRun(why),
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn passed(started: Instant) -> CheckerOutcome {
    CheckerOutcome {
        name: "probator".to_string(),
        severity: Severity::Blocking,
        outcome: OutcomeKind::Passed,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: String::new(),
        stderr: String::new(),
    }
}

/// The checker name a gate finding names, kept for the operator's report and
/// the run record. Probator prefixes translated findings with the policy row's
/// name; a message without one is the engine itself.
fn finding_name(message: &str) -> &str {
    message
        .split_once(": ")
        .map(|(name, _)| name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("probator")
}

/// Credential-looking strings and assignments. Engine messages are written by
/// a reviewer and may quote the very value a finding is about; neither the
/// terminal nor the run record may receive it.
fn secret_shapes() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(sk-[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-z0-9-]{10,}|bearer\s+[a-z0-9._-]{10,}|-----begin [a-z ]*private key-----)",
        )
        .expect("the credential redaction pattern is valid")
    })
}

fn private_key_blocks() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?is)-----begin [a-z ]*private key-----.*?(?:-----end [a-z ]*private key-----|$)",
        )
        .expect("the private-key block pattern is valid")
    })
}

fn secret_assignments() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+")
            .expect("the credential assignment pattern is valid")
    })
}

fn identifying_tokens() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(?:https?://)[^/\s@]+@|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){3}\b",
        )
        .expect("the identifying-token pattern is valid")
    })
}

/// Endpoint URLs. A finding may quote the private endpoint it is about; the
/// scheme stays readable, the host, path and query do not.
fn endpoint_urls() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r#"(?i)(https?|wss?)://[^\s"'<>`]+"#)
            .expect("the endpoint-url pattern is valid")
    })
}

fn sensitive_paths() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r#"(?:/Users/|/home/|/var/|/tmp/|/private/|/etc/|/opt/|/root/|/usr/|/Library/|/Applications/|/System/|/Volumes/|/srv/|/mnt/|/media/|/nix/store/)[^\s"'`<>]+"#,
        )
        .expect("the path redaction pattern is valid")
    })
}

/// Engine text is printed and persisted in the run record. Drop terminal
/// control characters, redact the machine's home/temporary prefixes, and
/// scrub credential shapes, assignments and absolute host paths. The engine's
/// contract sends locations rather than evidence; this is defense in depth
/// against a reviewer that drifts from it.
fn safe_text(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    let text = crate::records::redact(&filtered);
    let text = private_key_blocks()
        .replace_all(&text, "[REDACTED]")
        .into_owned();
    let text = secret_shapes()
        .replace_all(&text, "[REDACTED]")
        .into_owned();
    let text = secret_assignments()
        .replace_all(&text, "$1=[REDACTED]")
        .into_owned();
    let text = identifying_tokens()
        .replace_all(&text, "[REDACTED]")
        .into_owned();
    let text = endpoint_urls()
        .replace_all(&text, "$1://[ENDPOINT]")
        .into_owned();
    let text = sensitive_paths()
        .replace_all(&text, "[LOCAL_PATH]")
        .into_owned();
    if text.len() <= MAX_FINDING_TEXT {
        return text;
    }
    let mut end = MAX_FINDING_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated]", &text[..end])
}

/// A finding's location is a repository-relative path. An absolute path or
/// one with a parent traversal names this machine or leaves the reviewed
/// tree, so it is omitted rather than rendered.
fn safe_relative_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || Path::new(raw).is_absolute() || raw.chars().any(char::is_control) {
        return None;
    }
    if raw.starts_with('\\') || raw.chars().nth(1) == Some(':') {
        return None;
    }
    if raw.split(['/', '\\']).any(|part| part == "..") {
        return None;
    }
    Some(safe_text(raw))
}

fn finding_outcome(finding: &Value, started: Instant) -> CheckerOutcome {
    if !finding.is_object() {
        return blocking(
            "probator",
            "probator returned a finding that is not an object".to_string(),
            started,
        );
    }
    let message = finding["message"]
        .as_str()
        .map(safe_text)
        .filter(|message| !message.trim().is_empty())
        .unwrap_or_else(|| "gate finding".to_string());
    let name = finding_name(&message).to_string();
    let mut text = message;
    if let Some(path) = finding["path"].as_str().and_then(safe_relative_path) {
        match finding["line"].as_u64().filter(|line| *line > 0) {
            Some(line) => text.push_str(&format!("\n{path}:{line}")),
            None => text.push_str(&format!("\n{path}")),
        }
    }
    // High refuses. Anything the engine labels less severe is reported but
    // does not block; an unrecognized label is treated as high, because a
    // finding the gate cannot classify must not be laundered into a pass.
    let (severity, outcome) = match finding["severity"]
        .as_str()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("high") => (Severity::Blocking, OutcomeKind::Failed(1)),
        Some("warn" | "warning" | "info") => (Severity::Advisory, OutcomeKind::Failed(1)),
        _ => (Severity::Blocking, OutcomeKind::Failed(-1)),
    };
    CheckerOutcome {
        name,
        severity,
        outcome,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: text,
        stderr: String::new(),
    }
}

/// Run one gate action and return the findings array. A non-zero exit, absent
/// binary, absent output or an output that is not a JSON array is an error:
/// the caller turns it into a blocking finding.
fn run_gate(
    binary: &Path,
    action: &Value,
    ledger: Option<&Path>,
    anchor: Option<&Path>,
    shared: &[i32],
) -> Result<Vec<Value>, String> {
    let mut engine = command(binary);
    engine
        .arg("gate-audit")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Staged asset bytes reach the scanner through these descriptors, not
    // through a filesystem path. The parent reserved each number with
    // F_DUPFD_CLOEXEC; clearing the flag here, after fork and before exec,
    // is what lets the descriptor ride the spawn boundary and every exec
    // beneath it to the checker agent.
    #[cfg(unix)]
    if !shared.is_empty() {
        use std::os::unix::process::CommandExt as _;
        let shared = shared.to_vec();
        unsafe {
            engine.pre_exec(move || {
                for fd in &shared {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    // The rulings are GitVault's signed operator authority; Probator verifies
    // them against the same anchor the routing table uses. An absent ledger or
    // unarmed anchor simply waives nothing. They are set after the minimal
    // environment, so they are the only PROBATOR_* variables the engine sees.
    if let Some(ledger) = ledger {
        engine.env("PROBATOR_RULINGS_LEDGER", ledger);
    }
    if let Some(anchor) = anchor {
        engine.env("PROBATOR_RULINGS_ANCHOR", anchor);
    }
    let mut child = engine
        .spawn()
        .map_err(|error| format!("probator gate-audit could not start: {error}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(action.to_string().as_bytes())
            .map_err(|error| format!("could not hand the action to probator: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("probator gate-audit could not finish: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no diagnostic");
        return Err(format!(
            "probator gate-audit refused the operation ({}): {first}",
            output.status
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("probator gate-audit output is not JSON: {error}"))?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| "probator gate-audit output is not a findings array".to_string())
}

/// Project one gate run onto GitVault's outcomes. Findings are reported in
/// engine order; an empty array is the pass this audit produced.
fn outcomes(findings: &[Value], started: Instant) -> Vec<CheckerOutcome> {
    if findings.is_empty() {
        return vec![passed(started)];
    }
    findings
        .iter()
        .map(|finding| finding_outcome(finding, started))
        .collect()
}

/// Run Probator's gate for this context. Never returns `Err`: a failure to
/// obtain a verdict is itself a blocking finding, so no caller can mistake
/// "the engine did not answer" for a pass.
pub fn gates(ctx: &Context) -> Vec<CheckerOutcome> {
    let started = Instant::now();
    // Two GitVault audits of the same repository must not enter that shared
    // review machinery together. The lock is per repository and reclaimed if
    // its owner died.
    let _lock = match AuditLock::acquire(&ctx.repo_root, ctx.repo_slug.as_deref()) {
        Ok(lock) => lock,
        Err(why) => return vec![blocking("probator", why, started)],
    };
    let actions = match actions(ctx) {
        Ok(actions) => actions,
        Err(why) => return vec![blocking("probator", why, started)],
    };
    let binary = match engine_for(&ctx.event) {
        Ok(binary) => binary,
        Err(why) => return vec![blocking("probator", why, started)],
    };
    // The policy check runs even when the operation publishes nothing: an
    // empty policy must not make a publication boundary look audited.
    if let Err(why) = policy_covers(&binary, ctx) {
        return vec![blocking("probator", why, started)];
    }
    if actions.is_empty() {
        // A deletion-only or already-published push publishes nothing new.
        return vec![passed(started)];
    }

    let ledger = crate::objection::ledger_path();
    let anchor = crate::configsig::anchor_path();
    let mut findings = Vec::new();
    for action in actions {
        match run_gate(
            &binary,
            &action,
            Some(&ledger),
            Some(&anchor),
            &ctx.inherited_fds,
        ) {
            Ok(mut batch) => findings.append(&mut batch),
            Err(why) => return vec![blocking("probator", why, started)],
        }
    }
    let mut outcomes = outcomes(&findings, started);
    // The engine's sealed runs are the verifiable record of what the audit
    // actually spent - invocations, retries, usage and kept receipts live in
    // those report directories. Naming them in the outcome makes that cost
    // evidence reachable instead of leaving it unverifiable.
    let sealed = sealed_runs_since(&profiles_root(), started, ctx.repo_slug.as_deref());
    if !sealed.is_empty() {
        let note = format!(
            "audit evidence sealed under {}: {}",
            profiles_root().display(),
            sealed.join(", ")
        );
        for outcome in &mut outcomes {
            if outcome.stdout.is_empty() {
                outcome.stdout = note.clone();
            } else {
                outcome.stdout = format!("{}\n{note}", outcome.stdout);
            }
        }
    }
    outcomes
}

/// The engine runs sealed since `started`, as `<checker>/<run>` names. These
/// are the receipts a cost review verifies the external audit against. A run
/// is only claimed when its sealed report names this repository - mtime
/// alone cannot tell this gate's runs from a concurrent audit elsewhere,
/// though the repository lock already serializes two audits of one repo.
fn sealed_runs_since(profiles: &Path, started: Instant, slug: Option<&str>) -> Vec<String> {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(started.elapsed())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let mut sealed = Vec::new();
    let Ok(profiles_dir) = std::fs::read_dir(profiles) else {
        return sealed;
    };
    for profile in profiles_dir.flatten() {
        let checker = profile.file_name().to_string_lossy().into_owned();
        let Ok(runs) = std::fs::read_dir(profile.path().join(format!("{checker}-runs"))) else {
            continue;
        };
        for run in runs.flatten() {
            // Only a sealed report counts, and only one fresh since this
            // gate began.
            let report = run.path().join("report.json");
            let fresh = std::fs::metadata(&report)
                .and_then(|meta| meta.modified())
                .map(|modified| modified >= cutoff)
                .unwrap_or(false);
            if !fresh {
                continue;
            }
            if let Some(slug) = slug {
                let repo = std::fs::read_to_string(&report)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .and_then(|value| {
                        value
                            .get("repo")
                            .and_then(|repo| repo.as_str())
                            .map(str::to_owned)
                    });
                if repo.as_deref() != Some(slug) {
                    continue;
                }
            }
            sealed.push(format!("{checker}/{}", run.file_name().to_string_lossy()));
        }
    }
    sealed.sort();
    sealed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::Context;
    use std::path::PathBuf;

    fn context(event: &str) -> Context {
        Context {
            event: event.into(),
            repo_root: PathBuf::from("/synthetic/repo"),
            repo_slug: Some("Owner/Repo".into()),
            identity: "personal".into(),
            account: None,
            via_default: false,
            expected_email: None,
            actual_email: None,
            stdin: None,
            push_remote: None,
            pr_base: None,
            pr_base_sha: None,
            pr_head: None,
            pr_number: None,
            release_tag: None,
            release_commit: None,
            release_assets: Vec::new(),
            inherited_fds: Vec::new(),
            commit_message_file: None,
            commit_message_source: None,
        }
    }

    /// The engine's fixed PATH never falls back to a user-writable
    /// package-manager directory, except when the engine itself lives there
    /// (then it is already first as the engine's own directory).
    #[test]
    fn the_engine_path_puts_root_owned_helpers_before_user_writable_dirs() {
        let system: Vec<PathBuf> = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let home = std::env::temp_dir().join(format!(
            "gv-engine-path-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let home_bin = home.join(".local").join("bin");
        std::fs::create_dir_all(&home_bin).unwrap();
        let fake_git = home_bin.join("git");
        std::fs::write(&fake_git, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&fake_git, std::fs::Permissions::from_mode(0o700)).unwrap();

        // A Homebrew engine's own directory is user-writable. It stays on the
        // path (it is where the agent lives) but after every root-owned
        // directory, so it cannot shadow `git`.
        let engine = Path::new("/opt/homebrew/bin/probator");
        let dirs: Vec<PathBuf> = std::env::split_paths(&engine_path_for(engine, &home)).collect();
        assert_eq!(
            &dirs[..system.len()],
            system.as_slice(),
            "root-owned system dirs come first: {dirs:?}"
        );
        // The engine child resolves `git` from this PATH. With a fake git in
        // the account's user-writable bin directory, the first executable
        // `git` must still be the root-owned one.
        let resolved = dirs
            .iter()
            .map(|dir| dir.join("git"))
            .find(|candidate| is_executable(candidate));
        assert_ne!(
            resolved.as_deref(),
            Some(fake_git.as_path()),
            "a fake ~/.local/bin/git must not shadow the audit helper: {dirs:?}"
        );
        let system_git = ["/usr/bin/git", "/bin/git"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| is_executable(candidate));
        assert_eq!(
            resolved, system_git,
            "the helper comes from a root-owned dir"
        );
        let homebrew = dirs
            .iter()
            .position(|dir| dir.as_path() == Path::new("/opt/homebrew/bin"))
            .expect("the engine's directory stays available for its agent");
        assert!(
            homebrew >= system.len(),
            "a user-writable engine directory must not precede /usr/bin: {dirs:?}"
        );
        assert_eq!(
            dirs.iter()
                .filter(|dir| dir.as_path() == Path::new("/opt/homebrew/bin"))
                .count(),
            1,
            "the engine's directory is never duplicated"
        );
        assert!(
            !dirs
                .iter()
                .any(|dir| dir.as_path() == Path::new("/usr/local/bin")),
            "a user-writable Homebrew prefix must not shadow helpers: {dirs:?}"
        );
        let installed_bin = dirs
            .iter()
            .position(|dir| dir == &home_bin)
            .expect("the installed bin dir remains reachable for the agent");
        assert!(
            installed_bin >= system.len(),
            "~/.local/bin must not precede a root-owned helper: {dirs:?}"
        );

        // The installed engine lives under ~/.local/bin: that directory is
        // present once, after the system dirs, and no package-manager
        // directory is added at all.
        let installed = home_bin.join("probator");
        let dirs: Vec<PathBuf> =
            std::env::split_paths(&engine_path_for(&installed, &home)).collect();
        assert_eq!(&dirs[..system.len()], system.as_slice());
        assert_eq!(
            dirs.iter().filter(|dir| *dir == &home_bin).count(),
            1,
            "the engine's own directory is never duplicated: {dirs:?}"
        );
        assert_eq!(dirs.last(), Some(&home_bin));
        for untrusted in ["/usr/local/bin", "/opt/homebrew/bin"] {
            assert!(
                !dirs.iter().any(|dir| dir.as_path() == Path::new(untrusted)),
                "{untrusted} must not be trusted: {dirs:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// An armed engine reads the account home's fixed config root, never a
    /// caller's XDG override; the same resolver drives the install hand-off.
    #[test]
    fn the_engine_config_root_ignores_xdg_when_armed() {
        let home = Path::new("/Users/someone");
        let xdg = std::ffi::OsStr::new("/tmp/redirected-xdg");
        assert_eq!(
            config_home(Some(xdg), home, true),
            home.join(".config"),
            "armed mode fixes the config root to the account home"
        );
        assert_eq!(
            config_home(Some(xdg), home, false),
            PathBuf::from("/tmp/redirected-xdg"),
            "unarmed fixtures may redirect the root"
        );
        assert_eq!(config_home(None, home, false), home.join(".config"));
        assert_eq!(
            config_home(Some(std::ffi::OsStr::new("")), home, false),
            home.join(".config"),
            "an empty XDG_CONFIG_HOME is not a directory"
        );
        assert_eq!(
            config_root_for(true),
            crate::configsig::home_dir()
                .join(".config")
                .join("probator"),
            "install and the armed engine resolve the same fixed root"
        );
    }

    /// The objection report lookup follows the engine's data root, not the
    /// caller's HOME/XDG once the anchor is armed.
    #[test]
    fn the_objection_report_root_follows_the_engine_data_root() {
        let home = Path::new("/Users/someone");
        let xdg = std::ffi::OsStr::new("/tmp/redirected-xdg");
        assert_eq!(
            data_home(Some(xdg), home, true),
            home.join(".local").join("share"),
            "armed mode fixes the data root to the account home"
        );
        assert_eq!(
            data_home(Some(xdg), home, false),
            PathBuf::from("/tmp/redirected-xdg"),
            "unarmed fixtures may redirect the data root"
        );
        assert_eq!(
            data_home(None, home, false),
            home.join(".local").join("share")
        );
        assert_eq!(
            profiles_root_for(true),
            crate::configsig::home_dir()
                .join(".local")
                .join("share")
                .join("probator")
                .join("profiles"),
            "the armed objection lookup and the engine child agree"
        );
    }

    #[test]
    fn only_the_audited_events_reach_the_engine() {
        for event in ["pre-push", "pr", "release", "working-tree"] {
            assert!(applies(event), "{event}");
        }
        for event in [
            "pre-commit",
            "commit-msg",
            "prepare-commit-msg",
            "pre-applypatch",
        ] {
            assert!(!applies(event), "{event}");
        }
        // Probator binds a working-tree snapshot to the pre-push checker set.
        assert_eq!(policy_event("working-tree"), "pre-push");
        assert_eq!(policy_event("pre-push"), "pre-push");
        assert_eq!(policy_event("pr"), "pr");
    }

    /// A user-writable engine can answer with an empty findings array. It must
    /// never carry a publication verdict. The one exception is the on-demand
    /// working-tree snapshot, which publishes and authorizes nothing; it warns
    /// so nobody mistakes that output for a boundary.
    #[test]
    fn an_untrusted_engine_authorizes_no_publication_boundary() {
        for event in ["pre-push", "pr", "release"] {
            assert_eq!(
                engine_trust(event, true, false, false),
                EngineTrust::Refuse,
                "{event} must refuse"
            );
        }
        assert_eq!(
            engine_trust("working-tree", true, false, false),
            EngineTrust::Warn,
            "the on-demand snapshot is not a publication boundary"
        );
        assert_eq!(
            engine_trust("pre-push", true, false, true),
            EngineTrust::Allow,
            "root-owned or schg is trusted"
        );
        assert_eq!(
            engine_trust("pre-push", false, false, false),
            EngineTrust::Allow,
            "an unarmed development tree has no enforcement to protect"
        );
        assert_eq!(
            engine_trust("pre-push", true, true, false),
            EngineTrust::Allow,
            "the debug fixture is not an armed installation"
        );
    }

    #[test]
    fn a_working_tree_check_yields_the_snapshot_action() {
        let ctx = context("working-tree");
        let actions = actions(&ctx).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "working-tree");
        assert_eq!(actions[0]["target"], "/synthetic/repo");
        assert_eq!(actions[0]["detail"]["range"], "working-tree");
        assert!(
            actions[0]["detail"].get("push_refs").is_none(),
            "{actions:?}"
        );
    }

    #[test]
    fn a_push_carries_all_new_heads_in_one_action() {
        let mut ctx = context("pre-push");
        let zero = "0".repeat(40);
        ctx.stdin = Some(format!(
            "refs/heads/main aaaa refs/heads/main {zero}\n\
             refs/heads/dev aaaa refs/heads/dev {zero}\n\
             refs/heads/old {zero} refs/heads/old bbbb\n\
             refs/heads/same cccc refs/heads/same cccc\n"
        ));
        let actions = actions(&ctx).unwrap();
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert_eq!(actions[0]["kind"], "pre-push");
        assert_eq!(actions[0]["target"], "/synthetic/repo");
        // A range would preempt `push_refs` in Probator and collapse the
        // review to a base-less snapshot. The ref lines are the only scope.
        assert!(actions[0]["detail"].get("range").is_none(), "{actions:?}");
        let refs = actions[0]["detail"]["push_refs"].as_str().unwrap();
        assert!(refs.contains("refs/heads/main"), "{refs}");
        assert!(refs.contains("refs/heads/dev"), "{refs}");
        assert!(!refs.contains("refs/heads/old"), "{refs}");
        assert!(!refs.contains("refs/heads/same"), "{refs}");
    }

    #[test]
    fn a_multi_head_push_keeps_each_lines_remote_base() {
        let mut ctx = context("pre-push");
        ctx.stdin = Some(
            "refs/heads/main aaaa refs/heads/main 1111\n\
             refs/heads/dev bbbb refs/heads/dev 2222\n"
                .into(),
        );
        let actions = actions(&ctx).unwrap();
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert!(actions[0]["detail"].get("range").is_none(), "{actions:?}");
        let refs = actions[0]["detail"]["push_refs"].as_str().unwrap();
        let lines: Vec<&str> = refs.lines().collect();
        assert_eq!(lines.len(), 2, "{refs}");
        // Each line keeps its own remote tip as the review base; one action
        // must not flatten the two heads onto a single base.
        assert!(
            lines.contains(&"refs/heads/main aaaa refs/heads/main 1111"),
            "{refs}"
        );
        assert!(
            lines.contains(&"refs/heads/dev bbbb refs/heads/dev 2222"),
            "{refs}"
        );
    }

    #[test]
    fn a_deletion_only_push_has_no_review_object() {
        let mut ctx = context("pre-push");
        let zero = "0".repeat(40);
        ctx.stdin = Some(format!("refs/heads/gone {zero} refs/heads/gone aaaa\n"));
        assert!(actions(&ctx).unwrap().is_empty());
    }

    #[test]
    fn a_malformed_ref_line_refuses_instead_of_disappearing() {
        let mut ctx = context("pre-push");
        ctx.stdin = Some("refs/heads/main not-a-full-ref-line\n".into());
        assert!(actions(&ctx).is_err());
    }

    #[test]
    fn a_pull_request_action_carries_the_probator_field_names() {
        let mut ctx = context("pr");
        ctx.pr_head = Some("deadbeef".into());
        ctx.pr_base = Some("main".into());
        ctx.pr_number = Some("7".into());
        let built = actions(&ctx).unwrap();
        assert_eq!(built.len(), 1);
        // Probator's range_env only maps `head`/`base`; `range` would
        // override the PR scope and `number` would make the engine fetch
        // pull/7/head again. Neither may be on the wire.
        assert_eq!(built[0]["detail"]["head"], "deadbeef");
        assert_eq!(built[0]["detail"]["base"], "main");
        assert!(built[0]["detail"].get("range").is_none(), "{built:?}");
        assert!(built[0]["detail"].get("number").is_none(), "{built:?}");
        assert!(built[0]["detail"].get("pr_head").is_none(), "{built:?}");
        assert!(built[0]["detail"].get("pr_base").is_none(), "{built:?}");
        assert!(built[0]["detail"].get("pr_number").is_none(), "{built:?}");

        // A merge whose fetch never resolved a head must refuse, never let
        // the engine re-fetch inside the audit (a credential moment).
        ctx.pr_head = None;
        assert!(actions(&ctx).is_err());
    }

    #[test]
    fn a_release_action_names_the_tag_and_commit() {
        let mut ctx = context("release");
        ctx.release_tag = Some("v1.0.0".into());
        ctx.release_commit = Some("c0ffee".into());
        let actions = actions(&ctx).unwrap();
        assert_eq!(actions[0]["kind"], "release");
        assert_eq!(actions[0]["detail"]["tag"], "v1.0.0");
        assert_eq!(actions[0]["detail"]["commit"], "c0ffee");
    }

    #[cfg(unix)]
    #[test]
    fn a_live_lock_owner_keeps_the_lock() {
        let dir = std::env::temp_dir().join(format!(
            "gv-audit-lock-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pid"), std::process::id().to_string()).unwrap();
        assert!(!lock_is_stale(&dir));
        // The age of a live owner's lock is not a reason to reject the
        // waiter: an audit may legitimately run for hours.
        let old = std::time::SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        std::fs::File::open(&dir)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(
            !lock_is_stale(&dir),
            "a live owner keeps the lock no matter how long it has run"
        );

        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        std::fs::write(dir.join("pid"), dead.to_string()).unwrap();
        assert!(lock_is_stale(&dir), "an exited owner must be reclaimable");

        // A creator can be observed between `create_dir` and its PID write.
        // A half-written owner file is not proof of death until the grace
        // period has passed; stealing it there would let two audits run.
        std::fs::File::open(&dir)
            .unwrap()
            .set_modified(std::time::SystemTime::now())
            .unwrap();
        std::fs::write(dir.join("pid"), "").unwrap();
        assert!(!lock_is_stale(&dir), "a fresh incomplete owner gets grace");

        reclaim_stale(&dir);
        assert!(!dir.exists(), "the stale lock was moved aside and deleted");
    }

    /// The contract-free deterministic entry point still counts as review
    /// coverage, but only when the row really invokes Probator's `baseline`.
    #[test]
    fn a_baseline_row_is_reviewed_engine_coverage() {
        let profiles = Path::new("/synthetic/probator/profiles");
        assert!(row_is_contract_bound(
            &json!({"command": ["/opt/probator", "baseline", "--repo", "{repo}"]}),
            profiles
        ));
        assert!(row_is_contract_bound(
            &json!({"command": ["/opt/probator.exe", "baseline"]}),
            profiles
        ));
        assert!(!row_is_contract_bound(
            &json!({"command": ["/bin/true", "baseline"]}),
            profiles
        ));
        assert!(!row_is_contract_bound(
            &json!({"command": ["/opt/probator", "run"]}),
            profiles
        ));
        assert!(!row_is_contract_bound(
            &json!({"contract": "/outside/contract.json"}),
            profiles
        ));
    }

    /// Publication coverage is the hardening review itself, not just any
    /// blocking row: the contract, its declared domain set and the blocking
    /// severity all have to be present. The accepted contract identity is a
    /// documented coupling, and the domains are read from that contract so an
    /// engine-side addition cannot be silently dropped.
    #[test]
    fn hardening_coverage_requires_the_blocking_contract() {
        const DOMAINS: [&str; 7] = [
            "dependency_supply_chain",
            "ci_workflow_authority",
            "secret_handling",
            "transport_security",
            "authz_defaults",
            "container_runtime",
            "release_artifacts",
        ];
        let dir = std::env::temp_dir().join(format!(
            "gv-hardening-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let contract = hardening_contract(&dir, &DOMAINS);
        let binary = dir.join("probator");
        std::fs::write(&binary, "").unwrap();
        let row = hardening_policy_row(&binary, &contract, &DOMAINS);
        assert!(hardening_row(&row, &dir, &binary));

        let mut advisory = row.clone();
        advisory["severity"] = json!("advisory");
        assert!(!hardening_row(&advisory, &dir, &binary));

        let mut unrelated = row.clone();
        unrelated["name"] = json!("some-auditor");
        assert!(!hardening_row(&unrelated, &dir, &binary));

        // The accepted identity is pinned deliberately and documented. A row
        // that otherwise covers everything under another name is refused, not
        // silently treated as the hardening gate.
        let mut renamed = row.clone();
        renamed["name"] = json!("hardening");
        assert!(!hardening_row(&renamed, &dir, &binary));

        let mut partial = row.clone();
        partial["domains"] = json!([{"key": "secret_handling"}]);
        assert!(!hardening_row(&partial, &dir, &binary));

        // A row that names a contract but does not run it is not coverage.
        let mut decorative = row.clone();
        decorative["command"] = json!([
            "/bin/true",
            "run",
            "--contract",
            contract.display().to_string()
        ]);
        assert!(!hardening_row(&decorative, &dir, &binary));

        let outside = dir.join("..").join("outside-contract.json");
        std::fs::write(&outside, "{}").unwrap();
        let mut out_of_tree = row.clone();
        out_of_tree["contract"] = json!(outside.display().to_string());
        assert!(!hardening_row(&out_of_tree, &dir, &binary));

        // The required set is the contract's own declaration. A domain the
        // engine adds is required, not ignored because this source predates it.
        let extended = dir.join("extended-contract.json");
        let extended_domains: Vec<&str> = DOMAINS.iter().copied().chain(["new_domain"]).collect();
        std::fs::write(
            &extended,
            json!({
                "name": "security-enhancer",
                "severity": "blocking",
                "domains": extended_domains,
            })
            .to_string(),
        )
        .unwrap();
        let stale = hardening_policy_row(&binary, &extended, &DOMAINS);
        assert!(!hardening_row(&stale, &dir, &binary));
        let mut complete = stale.clone();
        complete["domains"] = json!(
            DOMAINS
                .iter()
                .chain(["new_domain"].iter())
                .map(|key| json!({"key": key}))
                .collect::<Vec<_>>()
        );
        assert!(hardening_row(&complete, &dir, &binary));

        // A contract that is not itself the named blocking hardening review is
        // not coverage, whatever its row says.
        let mild = dir.join("mild-contract.json");
        std::fs::write(
            &mild,
            json!({
                "name": "security-enhancer",
                "severity": "advisory",
                "domains": DOMAINS,
            })
            .to_string(),
        )
        .unwrap();
        let mild_row = hardening_policy_row(&binary, &mild, &DOMAINS);
        assert!(!hardening_row(&mild_row, &dir, &binary));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hardening_contract(dir: &Path, domains: &[&str]) -> PathBuf {
        let contract = dir.join("contract.json");
        std::fs::write(
            &contract,
            json!({
                "name": "security-enhancer",
                "severity": "blocking",
                "domains": domains,
            })
            .to_string(),
        )
        .unwrap();
        contract
    }

    fn hardening_policy_row(binary: &Path, contract: &Path, domains: &[&str]) -> Value {
        json!({
            "name": "security-enhancer",
            "severity": "blocking",
            "contract": contract.display().to_string(),
            "command": [
                binary.display().to_string(),
                "run",
                "--contract",
                contract.display().to_string(),
                "--repo",
                "{repo}",
            ],
            "domains": domains
                .iter()
                .map(|key| json!({"key": key}))
                .collect::<Vec<_>>(),
        })
    }

    /// Coverage is scoped to the repository the gate is auditing. An
    /// inspector row that is otherwise perfect for another repository (or
    /// that runs the engine against a fixed other tree) must not count: the
    /// engine would not review this publication and could return `[]`.
    #[test]
    fn hardening_coverage_is_scoped_to_this_repository() {
        const DOMAINS: [&str; 7] = [
            "dependency_supply_chain",
            "ci_workflow_authority",
            "secret_handling",
            "transport_security",
            "authz_defaults",
            "container_runtime",
            "release_artifacts",
        ];
        let dir = std::env::temp_dir().join(format!(
            "gv-hardening-scope-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let contract = hardening_contract(&dir, &DOMAINS);
        let binary = dir.join("probator");
        std::fs::write(&binary, "").unwrap();
        let mut row = hardening_policy_row(&binary, &contract, &DOMAINS);
        row["on"] = json!(["pre-push"]);
        let ctx = context("pre-push");
        assert!(covers_hardening(&json!([row.clone()]), &ctx, &dir, &binary));

        // Scope matches by origin slug or work-tree path prefix.
        for scope in ["Owner/Repo", "/synthetic/repo", "/synthetic"] {
            let mut scoped = row.clone();
            scoped["repos"] = json!([scope]);
            assert!(
                covers_hardening(&json!([scoped]), &ctx, &dir, &binary),
                "{scope} should select this repository"
            );
        }
        // The regression the completeness check exists to prevent: a row
        // scoped entirely to another repository is not coverage here.
        for scope in ["other/repo", "/elsewhere"] {
            let mut elsewhere = row.clone();
            elsewhere["repos"] = json!([scope]);
            assert!(
                !covers_hardening(&json!([elsewhere]), &ctx, &dir, &binary),
                "{scope} must not bless this repository"
            );
        }
        let mut malformed = row.clone();
        malformed["repos"] = json!("Owner/Repo");
        assert!(!covers_hardening(&json!([malformed]), &ctx, &dir, &binary));

        // The command must resolve the gate's target. A fixed other repo (or
        // no repo argument, which inherits the gate's cwd) is not evidence
        // about this tree, even when the row's scope matches.
        let mut other_tree = row.clone();
        other_tree["command"] = json!([
            binary.display().to_string(),
            "run",
            "--contract",
            contract.display().to_string(),
            "--repo",
            "/some/other/repo",
        ]);
        assert!(!covers_hardening(&json!([other_tree]), &ctx, &dir, &binary));
        let mut no_repo = row.clone();
        no_repo["command"] = json!([
            binary.display().to_string(),
            "run",
            "--contract",
            contract.display().to_string(),
        ]);
        assert!(!covers_hardening(&json!([no_repo]), &ctx, &dir, &binary));

        // The event still has to match the boundary Probator will run.
        let mut wrong_event = row.clone();
        wrong_event["on"] = json!(["pr"]);
        assert!(!covers_hardening(
            &json!([wrong_event]),
            &ctx,
            &dir,
            &binary
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A finding can quote the secret or the private endpoint it is about.
    /// The projection keeps the judgement and location, never the value.
    #[test]
    fn finding_text_drops_credentials_and_absolute_paths() {
        // Keep the credential shapes out of this source file: Probator's own
        // deterministic stage scans the working tree for them, and a fixture
        // that spells a token or private-key header literally would make the
        // publication gate refuse the very test that proves redaction.
        let token = concat!("ghp", "_abcdefghijklmnopqrstuvwxyz0123456789");
        let key_begin = concat!("-----BEGIN ", "OPENSSH PRIVATE KEY-----");
        let key_end = concat!("-----END ", "OPENSSH PRIVATE KEY-----");
        let message = format!(
            "clean-auditor: token {token} under /etc/private/key\n{key_begin}\nsecret block\n{key_end}\nmail someone@example.invalid endpoint http://user:pass@10.0.0.1/admin and https://internal.example.invalid/private"
        );
        let outcome = finding_outcome(
            &json!({
                "severity": "high",
                "message": message,
                "path": "/Users/someone/private.txt",
                "line": 4,
            }),
            Instant::now(),
        );
        assert!(!outcome.stdout.contains("ghp_"), "{}", outcome.stdout);
        assert!(
            !outcome.stdout.contains("/etc/private"),
            "{}",
            outcome.stdout
        );
        assert!(!outcome.stdout.contains("/Users/"), "{}", outcome.stdout);
        assert!(
            !outcome.stdout.contains("secret block"),
            "{}",
            outcome.stdout
        );
        assert!(outcome.stdout.contains("[REDACTED]"), "{}", outcome.stdout);
        // A bare private endpoint must keep only its scheme; the old report
        // sanitizer redacted the URL and a finding that quotes one must not
        // leak it to the terminal or the run record.
        assert!(
            !outcome.stdout.contains("internal.example.invalid"),
            "{}",
            outcome.stdout
        );
        assert!(outcome.stdout.contains("[ENDPOINT]"), "{}", outcome.stdout);
        // An absolute finding location is omitted, not rendered.
        assert!(
            !outcome.stdout.contains("private.txt:4"),
            "{}",
            outcome.stdout
        );

        let malformed = finding_outcome(&json!(["not", "an", "object"]), Instant::now());
        assert_eq!(malformed.severity, Severity::Blocking);
        assert!(matches!(malformed.outcome, OutcomeKind::CouldNotRun(_)));
    }

    #[test]
    fn findings_map_to_named_outcomes_and_keep_locations() {
        let started = Instant::now();
        let high = finding_outcome(
            &json!({
                "source": "probator",
                "severity": "high",
                "message": "clean-auditor: a private name would publish",
                "path": "src/lib.rs",
                "line": 12,
            }),
            started,
        );
        assert_eq!(high.name, "clean-auditor");
        assert_eq!(high.severity, Severity::Blocking);
        assert!(matches!(high.outcome, OutcomeKind::Failed(1)));
        assert!(high.stdout.contains("src/lib.rs:12"));

        let warn = finding_outcome(
            &json!({"severity": "warn", "message": "money-saver: advisory"}),
            started,
        );
        assert_eq!(warn.severity, Severity::Advisory);
        assert!(matches!(warn.outcome, OutcomeKind::Failed(1)));

        // An unknown label is not a pass.
        let unknown = finding_outcome(
            &json!({"severity": "notice", "message": "probator: odd"}),
            started,
        );
        assert_eq!(unknown.severity, Severity::Blocking);
    }

    /// Findings are rendered and recorded, so terminal control characters in
    /// engine text must not reach either. The location still survives.
    #[test]
    fn finding_text_cannot_carry_terminal_controls() {
        let outcome = finding_outcome(
            &json!({
                "severity": "high",
                "message": "clean-auditor: \u{1b}[31mred\u{1b}[0m\u{7}bell",
                "path": "src/\u{1b}hidden.rs",
                "line": 3,
            }),
            Instant::now(),
        );
        assert!(!outcome.stdout.contains('\u{1b}'));
        assert!(!outcome.stdout.contains('\u{7}'));
        assert!(outcome.stdout.contains("[31mred[0m"));
        // A path containing a control character is not a safe location.
        assert!(!outcome.stdout.contains("hidden"));

        // A finding that names this machine's home path is rendered with the
        // same redaction the run record uses.
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/someone".into());
        let located = finding_outcome(
            &json!({
                "severity": "high",
                "message": format!("clean-auditor: receipt under {home}/private/run.json"),
                "path": format!("{home}/private/report.json"),
            }),
            Instant::now(),
        );
        assert!(!located.stdout.contains(&home), "{}", located.stdout);
        assert!(
            located.stdout.contains("[LOCAL_PATH]"),
            "{}",
            located.stdout
        );
    }

    #[test]
    fn an_empty_findings_array_is_a_pass() {
        let outcomes = outcomes(&[], Instant::now());
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].name, "probator");
        assert!(matches!(outcomes[0].outcome, OutcomeKind::Passed));
    }

    fn stub(body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-gate-stub-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probator");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    #[test]
    fn a_gate_that_answers_with_json_is_parsed() {
        let bin = stub("cat >/dev/null; printf '[{\"severity\":\"high\",\"message\":\"x: y\"}]'");
        let findings = run_gate(&bin, &json!({}), None, None, &[]).unwrap();
        assert_eq!(findings.len(), 1);
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }

    #[test]
    fn a_missing_or_failing_gate_is_an_error_not_a_pass() {
        assert!(
            run_gate(
                Path::new("/nonexistent/probator"),
                &json!({}),
                None,
                None,
                &[]
            )
            .is_err()
        );
        let bin = stub("cat >/dev/null; echo 'gate exploded' >&2; exit 1");
        let err = run_gate(&bin, &json!({}), None, None, &[]).unwrap_err();
        assert!(err.contains("gate exploded"), "{err}");
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }

    #[test]
    fn a_non_array_answer_is_an_error() {
        let bin = stub("cat >/dev/null; printf '{\"not\":\"an array\"}'");
        let err = run_gate(&bin, &json!({}), None, None, &[]).unwrap_err();
        assert!(err.contains("not a findings array"), "{err}");
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }

    #[test]
    fn empty_output_is_an_error_not_an_empty_pass() {
        // A gate that exits 0 but prints nothing has not produced evidence.
        let bin = stub("cat >/dev/null");
        let err = run_gate(&bin, &json!({}), None, None, &[]).unwrap_err();
        assert!(err.contains("not JSON"), "{err}");
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }
}
