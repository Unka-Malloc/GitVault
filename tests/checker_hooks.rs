//! Integration coverage for GitVault's interception surface.
//!
//! GitVault no longer runs checker rows: publication audits are delegated to
//! `probator gate-audit`. These tests install a deterministic `probator` stub
//! (debug builds honour `GITVAULT_PROBATOR`) and assert the action GitVault
//! hands the engine, the gate's projection back into the report/record, and
//! that the local identity/attribution gates still intercept.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap()
}
fn checked(repo: &Path, args: &[&str]) {
    let result = git(repo, args);
    assert!(
        result.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn temp(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "gitvault-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn base_repo(tag: &str) -> PathBuf {
    let root = temp(tag);
    checked(&root, &["init", "-q", "-b", "main"]);
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("no-hooks").to_str().unwrap(),
        ],
    );
    checked(&root, &["config", "commit.gpgsign", "false"]);
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    // Git reports the canonical `/private/var/...` path on macOS; the path
    // rule must match what discovery returns, not the `/var` symlink.
    root.canonicalize().unwrap_or(root)
}

/// The routing table: a path rule makes this a ruled repository (not a
/// fallback), so the identity gate has an expectation to compare against.
fn write_config(root: &Path, expected_email: &str) {
    std::fs::write(
        root.join("config.toml"),
        format!(
            "record_dir = '{}'\n\
             [identities.fixture]\nname = 'Synthetic'\nemail = '{expected_email}'\n\
             [[rules.paths]]\nprefix = '{}'\nidentity = 'fixture'\n",
            root.join("runs").display(),
            root.display()
        ),
    )
    .unwrap();
}

/// The deterministic engine double: `inspect` describes the policy,
/// `gate-audit` records the action and returns the configured findings.
fn install_probator(root: &Path, events: &[&str], findings: &str) {
    let quoted: Vec<String> = events.iter().map(|e| format!("\"{e}\"")).collect();
    // `inspect` must name a blocking contract under Probator's profiles root:
    // that is the policy completeness GitVault checks before spending a gate.
    let profiles = root.join("data").join("probator").join("profiles");
    let contract = profiles.join("security-enhancer").join("contract.json");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    let domain_keys = [
        "dependency_supply_chain",
        "ci_workflow_authority",
        "secret_handling",
        "transport_security",
        "authz_defaults",
        "container_runtime",
        "release_artifacts",
    ];
    // The contract is the authority for the required domain set; the inspect
    // row declares the same set without descriptions.
    std::fs::write(
        &contract,
        format!(
            "{{\"name\":\"security-enhancer\",\"severity\":\"blocking\",\"domains\":[{}]}}",
            domain_keys
                .iter()
                .map(|key| format!("\"{key}\""))
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
    .unwrap();
    let domains = domain_keys
        .iter()
        .map(|key| format!("{{\"key\":\"{key}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        root.join("inspect.json"),
        format!(
            "[{{\"name\":\"security-enhancer\",\"title\":\"Security Enhancer\",\"on\":[{}],\"severity\":\"blocking\",\"contract\":{},\"command\":[{},\"run\",\"--contract\",{},\"--repo\",\"{{repo}}\"],\"domains\":[{}]}}]",
            quoted.join(","),
            serde_json::to_string(&contract.display().to_string()).unwrap(),
            serde_json::to_string(&root.join("probator").display().to_string()).unwrap(),
            serde_json::to_string(&contract.display().to_string()).unwrap(),
            domains
        ),
    )
    .unwrap();
    std::fs::write(root.join("findings.json"), findings).unwrap();
    let script = format!(
        "#!/bin/sh\n\
         ROOT='{root}'\n\
         case \"$1\" in\n\
           inspect) cat \"$ROOT/inspect.json\" ;;\n\
           gate-audit)\n\
             cat > \"$ROOT/action.json\"\n\
             printf '%s' \"$PROBATOR_RULINGS_LEDGER\" > \"$ROOT/ledger.txt\"\n\
             printf '%s' \"$PROBATOR_RULINGS_ANCHOR\" > \"$ROOT/anchor.txt\"\n\
             env > \"$ROOT/engine-env.txt\"\n\
             cat \"$ROOT/findings.json\"\n\
             ;;\n\
           *) echo \"unexpected probator invocation: $*\" >&2; exit 2 ;;\n\
         esac\n",
        root = root.display()
    );
    std::fs::write(root.join("probator"), script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("probator"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

/// Run GitVault with the fixture engine and an absent enforcement anchor, so
/// the developer machine's real anchor cannot classify the fixture as armed.
fn run(root: &Path, args: &[&str]) -> Output {
    run_with(root, &[], args)
}

fn run_with(root: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitvault"));
    command
        .env("GITVAULT_PROBATOR", root.join("probator"))
        .env("GITVAULT_ANCHOR", root.join("no-anchor"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_STATE_HOME", root.join("state"))
        .current_dir(root)
        .arg("--config")
        .arg(root.join("config.toml"))
        .args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn publication(events: &[&str], findings: &str) -> Fixture {
    let root = base_repo("pub");
    write_config(&root, "synthetic@example.invalid");
    install_probator(&root, events, findings);
    Fixture(root)
}

const PASS: &str = "[]";
const BLOCK: &str = r#"[{"source":"probator","severity":"high","message":"fixture-audit: blocked by the fixture"}]"#;

/// The separate signed policy that authorizes the engine. It carries no
/// executed rows; only its signature gates a publication boundary.
fn declare_engine_policy(root: &Path) {
    std::fs::write(root.join("checkers.toml"), "# engine authorization\n").unwrap();
    let config = std::fs::read_to_string(root.join("config.toml")).unwrap();
    std::fs::write(
        root.join("config.toml"),
        format!("audit_policy = \"checkers.toml\"\n{config}"),
    )
    .unwrap();
}

/// An allowed-signers anchor plus the key that can sign for it. Returns the
/// private key path, or None when ssh-keygen cannot sign on this host.
fn signing_anchor(root: &Path) -> Option<PathBuf> {
    let key = root.join("anchor-key");
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "gitvault-config", "-f"])
        .arg(&key)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let public = std::fs::read_to_string(key.with_extension("pub")).ok()?;
    let mut fields = public.split_whitespace();
    std::fs::write(
        root.join("config.pub"),
        format!("gitvault-config {} {}\n", fields.next()?, fields.next()?),
    )
    .ok()?;
    Some(key)
}

fn sign_with(key: &Path, file: &Path) -> bool {
    Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "gitvault-config", "-f"])
        .arg(key)
        .arg(file)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[test]
fn pull_request_event_delegates_the_range_to_probator() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--pr-base",
            "main",
            "--pr-number",
            "7",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "pr check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "pr");
    assert_eq!(action["target"], root.display().to_string());
    // Probator's PR scope is named by `head`/`base`; `range` would override
    // it and `number` would trigger a second pull/N/head fetch inside the
    // audit. GitVault's already-fetched head is what crosses the boundary.
    assert_eq!(action["detail"]["head"], "main");
    assert_eq!(action["detail"]["base"], "main");
    assert!(action["detail"].get("range").is_none(), "{action}");
    assert!(action["detail"].get("number").is_none(), "{action}");
    assert!(action["detail"].get("pr_number").is_none(), "{action}");
}

#[test]
fn a_misspelled_event_refuses_instead_of_passing() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let directory = root.to_str().unwrap().to_string();
    // `check` and `hook` both take the event from an argument. An unknown
    // spelling matches no gate and reaches no engine, so an empty pass would
    // be a typo at a publication boundary, not a clean result.
    for args in [
        vec![
            "check",
            "--event",
            "pre_pus",
            "--directory",
            directory.as_str(),
        ],
        vec!["hook", "pre_pus"],
    ] {
        let result = run(&root, &args);
        assert!(
            !result.status.success(),
            "{args:?} exited successfully: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("unknown event 'pre_pus'"),
            "{args:?}: {stderr}"
        );
    }
    assert!(
        !root.join("action.json").exists(),
        "a misspelled event must not reach the engine"
    );
}

#[test]
fn working_tree_event_delegates_the_snapshot_to_probator() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    std::fs::write(root.join("one"), "uncommitted change\n").unwrap();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "working-tree",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "working-tree check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "working-tree");
    assert_eq!(action["target"], root.display().to_string());
    // Probator's `range` spelling for the uncommitted state; the event name
    // is its own, not a bare snapshot of some arbitrary revision.
    assert_eq!(action["detail"]["range"], "working-tree");
    assert!(action["detail"].get("push_refs").is_none(), "{action}");
}

#[test]
fn a_working_tree_audit_reads_the_pre_push_checker_set() {
    // Probator binds `working-tree` to the pre-push boundary. A policy with
    // only a `pr` row therefore cannot bless the snapshot, and the engine must
    // not run to produce a vacuous pass.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "working-tree",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        !result.status.success(),
        "a pr-only policy blessed a snapshot"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("pre-push"), "{stderr}");
    assert!(
        !root.join("action.json").exists(),
        "the engine ran without pre-push coverage"
    );
}

#[test]
fn a_contract_outside_the_engine_profile_root_cannot_bless_the_event() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let outside = root.join("outside-contract.json");
    std::fs::write(&outside, "{}").unwrap();
    std::fs::write(
        root.join("inspect.json"),
        format!(
            "[{{\"name\":\"fixture\",\"on\":[\"pr\"],\"severity\":\"blocking\",\"contract\":{}}}]",
            serde_json::to_string(&outside.display().to_string()).unwrap()
        ),
    )
    .unwrap();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--pr-base",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(!result.status.success(), "an out-of-tree contract passed");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("contract under"), "{stderr}");
    assert!(
        !root.join("action.json").exists(),
        "the engine ran for an unauthorized contract"
    );
}

#[test]
fn an_advisory_row_is_not_boundary_coverage() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let contract = root
        .join("data/probator/profiles/security-enhancer/contract.json")
        .display()
        .to_string();
    std::fs::write(
        root.join("inspect.json"),
        format!(
            "[{{\"name\":\"fixture\",\"on\":[\"pr\"],\"severity\":\"advisory\",\"contract\":{}}}]",
            serde_json::to_string(&contract).unwrap()
        ),
    )
    .unwrap();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--pr-base",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(!result.status.success(), "an advisory-only policy passed");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("no blocking security-enhancer"), "{stderr}");
    assert!(
        !root.join("action.json").exists(),
        "the engine ran without blocking coverage"
    );
}

/// The engine child is a credential boundary: provider keys, the SSH agent,
/// and every `GITVAULT_*`/`PROBATOR_*` steering variable must be absent. The
/// allowlist is the account home, a fixed search path, locale/terminal, and
/// the two ruling paths GitVault sets itself.
#[test]
fn the_engine_child_receives_only_the_curated_environment() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let sentinels = [
        ("GH_TOKEN", "sentinel-github-token"),
        ("AWS_SECRET_ACCESS_KEY", "sentinel-aws-secret"),
        ("SSH_AUTH_SOCK", "/tmp/sentinel-agent.sock"),
        ("PROBATOR_EVENT", "sentinel-event"),
        ("GITVAULT_UNLOCK_TTL", "999999"),
        ("PROBATOR_RULINGS_LEDGER", "/tmp/sentinel-ledger"),
        ("PROBATOR_RULINGS_ANCHOR", "/tmp/sentinel-anchor"),
        ("LANG", "sentinel-locale"),
        ("TERM", "sentinel-term"),
    ];
    // Pin the caller's configuration root so the assertion below proves the
    // engine receives the resolver's answer, not an ambient user directory.
    let config_home = root.join("data");
    let config_home_text = config_home.display().to_string();
    let mut envs = sentinels.to_vec();
    envs.push(("XDG_CONFIG_HOME", config_home_text.as_str()));
    let result = run_with(
        &root,
        &envs,
        &[
            "check",
            "--event",
            "working-tree",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let engine = std::fs::read_to_string(root.join("engine-env.txt"))
        .expect("the fake engine records the environment it received");
    let has = |line: &str| engine.lines().any(|candidate| candidate == line);
    for (key, value) in sentinels {
        match key {
            // The documented allowlist reaches the child unchanged.
            "LANG" | "TERM" => assert!(
                has(&format!("{key}={value}")),
                "{key} should be inherited: {engine}"
            ),
            // GitVault sets these itself; the caller's value must not win.
            "PROBATOR_RULINGS_LEDGER" | "PROBATOR_RULINGS_ANCHOR" => {
                assert!(
                    engine
                        .lines()
                        .any(|line| line.starts_with(&format!("{key}="))),
                    "{key} should be set by GitVault: {engine}"
                );
                assert!(
                    !has(&format!("{key}={value}")),
                    "{key} kept the caller's value: {engine}"
                );
            }
            _ => assert!(
                !has(&format!("{key}={value}")),
                "{key} reached the engine: {engine}"
            ),
        }
    }
    assert!(
        !engine.lines().any(|line| line.starts_with("GITVAULT_")),
        "a GITVAULT_* variable reached the engine: {engine}"
    );
    for key in ["HOME", "PATH", "XDG_CONFIG_HOME"] {
        assert!(
            engine
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))),
            "{key} is missing from the curated environment: {engine}"
        );
    }
    assert!(
        engine.contains(&format!("XDG_CONFIG_HOME={config_home_text}")),
        "the engine's configuration root is not pinned: {engine}"
    );
}

#[test]
fn release_event_delegates_the_tag_and_commit() {
    let fixture = publication(&["release"], PASS);
    let root = fixture.0.clone();
    checked(&root, &["tag", "v1.0.0"]);
    let commit = String::from_utf8(git(&root, &["rev-parse", "v1.0.0"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "release",
            "--tag",
            "v1.0.0",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "release check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "release");
    assert_eq!(action["detail"]["tag"], "v1.0.0");
    assert_eq!(action["detail"]["commit"], commit);
}

#[test]
fn release_create_is_refused_before_any_credential_is_touched() {
    // The gate sits ahead of the vault, so this holds with no vault at all --
    // and the absence of an authentication error proves nothing reached the API.
    let fixture = publication(&["release"], BLOCK);
    let root = fixture.0.clone();
    checked(&root, &["tag", "v1.0.0"]);
    let result = run(
        &root,
        &["release", "create", "v1.0.0", "--repo", "Owner/Name"],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a blocked release must fail");
    assert!(stderr.contains("refused this release"), "stderr: {stderr}");
    assert!(stderr.contains("fixture-audit"), "stderr: {stderr}");
    for credential_error in ["unlock", "authentication", "credential"] {
        assert!(
            !stderr.to_lowercase().contains(credential_error),
            "the gate must run before any credential is touched: {stderr}"
        );
    }
}

#[test]
fn merge_is_refused_before_the_api_call() {
    let fixture = publication(&["pr"], BLOCK);
    let root = fixture.0.clone();
    // The merge review fetches pull/7/head at the gate boundary, before any
    // audit runs: give it a local origin carrying that ref so the fetch
    // succeeds without a network. Run from the PR head, not its base: the
    // audit must carry the request's target, not this checkout's HEAD.
    let main = String::from_utf8_lossy(&git(&root, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string();
    checked(&root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("two"), "feature\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "feature"]);
    let feature = String::from_utf8_lossy(&git(&root, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_string();
    checked(&root, &["init", "-q", "--bare", "origin.git"]);
    checked(
        &root,
        &[
            "push",
            "-q",
            "origin.git",
            "main:refs/heads/main",
            "HEAD:refs/pull/7/head",
        ],
    );
    checked(&root, &["update-ref", "refs/remotes/origin/main", &main]);
    let origin = root.join("origin.git");
    checked(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/Owner/Name.git",
        ],
    );
    checked(
        &root,
        &[
            "config",
            &format!("url.{}.insteadOf", origin.to_str().unwrap()),
            "https://github.com/Owner/Name.git",
        ],
    );
    let result = run(
        &root,
        &["pr", "merge", "7", "--repo", "Owner/Name", "--base", "main"],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a blocked merge must fail");
    assert!(stderr.contains("refused this merge"), "stderr: {stderr}");
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(
        action["detail"]["base"], "main",
        "the audit base is the request's target, not the checked-out head: {action}"
    );
    assert_eq!(
        action["detail"]["head"], feature,
        "the fetched PR head is the review object: {action}"
    );
    assert_ne!(action["detail"]["head"], main);
    // The number is not sent: Probator would fetch pull/7/head again inside
    // the audit, while this merge already spent that credential moment.
    assert!(action["detail"].get("number").is_none(), "{action}");
    assert!(action["detail"].get("range").is_none(), "{action}");
}

#[test]
fn a_run_is_recorded_without_this_machines_paths() {
    // The record is built for a reader other than the person who ran the gate,
    // so it must describe the work and not the machine: a finding that names a
    // path under HOME gets it replaced before anything is stored.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let findings = format!(
        r#"[{{"source":"probator","severity":"warn","message":"publication: receipt under {home}/receipts/run.json"}}]"#
    );
    let fixture = publication(&["pr"], &findings);
    let root = fixture.0.clone();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "an advisory finding does not block: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let runs: Vec<_> = std::fs::read_dir(root.join("runs"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(runs.len(), 1, "exactly one run was recorded");
    let record = std::fs::read_to_string(runs[0].path().join("engine.json")).unwrap();
    for leaked in ["/Users", "/var/folders", "/home/"] {
        assert!(
            !record.contains(leaked),
            "the record describes this machine: {record}"
        );
    }
    assert!(record.contains("[LOCAL_PATH]"), "{record}");
    assert!(record.contains("\"event\": \"pr\""), "{record}");
    assert!(record.contains("\"name\": \"publication\""), "{record}");

    // `records` reads the same store without opening the vault or the network.
    let listed = run(&root, &["records", "list", "--json"]);
    let json = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(json.contains("\"outcomes\""), "{json}");
    assert!(
        !json.contains("stdout"),
        "the list projection leaves the transcript out: {json}"
    );
}

#[test]
fn pre_push_refuses_commits_with_ai_attribution() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    checked(
        &root,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "feat: a thing",
            "-m",
            "Co-Authored-By: Devin <devin-ai-integration[bot]@users.noreply.github.com>",
        ],
    );
    let local = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let remote = String::from_utf8(git(&root, &["rev-parse", "HEAD^"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(
        !root.join("action.json").exists(),
        "the fixture starts with no gate action"
    );
    let result = check_pre_push(
        &root,
        &format!("refs/heads/main {local} refs/heads/main {remote}\n"),
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a tainted range must fail: {stderr}"
    );
    assert!(
        stderr.contains(&local[..12]),
        "the refused commit's sha must be named: {stderr}"
    );
    assert!(stderr.contains("AI attribution"), "stderr: {stderr}");
    // A local refusal closes the boundary before the paid semantic audit:
    // the stub never received a gate action.
    assert!(
        !root.join("action.json").exists(),
        "a locally refused push must not start the delegated audit: {stderr}"
    );
}

#[test]
fn pre_push_passes_a_clean_range() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    checked(&root, &["commit", "--allow-empty", "-qm", "feat: clean"]);
    let local = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let remote = String::from_utf8(git(&root, &["rev-parse", "HEAD^"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let result = check_pre_push(
        &root,
        &format!("refs/heads/main {local} refs/heads/main {remote}\n"),
    );
    assert!(
        result.status.success(),
        "a clean range must pass: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "pre-push");
    assert_eq!(action["target"], root.display().to_string());
    // `range` would take precedence over `push_refs` and drop the remote-tip
    // base; the ref lines alone carry the remote..local scope.
    assert!(action["detail"].get("range").is_none(), "{action}");
    let refs = action["detail"]["push_refs"].as_str().unwrap();
    assert!(refs.contains(&local), "{refs}");
    assert!(refs.contains(&remote), "{refs}");
    assert!(refs.contains("refs/heads/main"), "{refs}");
}

#[test]
fn the_pre_push_hook_audits_the_refs_git_advertises() {
    // The wrapper's pre-audit is advisory: git always runs the hook, and the
    // hook sees the remote tip the transport actually advertised. The fixture
    // installs the real hook shim in front of the built binary so the test
    // observes that second, authoritative run rather than only `check`.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let remote = root.join("remote.git");
    // A bare clone carries the base commit and refs, so the remote can
    // advertise a real tip without a second hooked push.
    checked(&root, &["clone", "-q", "--bare", ".", "remote.git"]);
    let base = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    checked(
        &root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    checked(
        &root,
        &["commit", "--allow-empty", "-qm", "feat: hook audit"],
    );
    let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    let hooks = root.join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-push");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\n\
             export GITVAULT_PROBATOR='{}'\n\
             export GITVAULT_ANCHOR='{}'\n\
             export XDG_DATA_HOME='{}'\n\
             export XDG_STATE_HOME='{}'\n\
             exec '{}' --config '{}' hook pre-push \"$@\"\n",
            root.join("probator").display(),
            root.join("no-anchor").display(),
            root.join("data").display(),
            root.join("state").display(),
            env!("CARGO_BIN_EXE_gitvault"),
            root.join("config.toml").display(),
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    checked(
        &root,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    );

    let result = git(&root, &["push", "-q", "origin", "main"]);
    assert!(
        result.status.success(),
        "the hooked push failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "pre-push");
    assert_eq!(action["target"], root.display().to_string());
    assert!(action["detail"].get("range").is_none(), "{action}");
    let refs = action["detail"]["push_refs"].as_str().unwrap();
    assert!(refs.contains(&head), "{refs}");
    // The hook's base is the remote's advertised tip, not a mirror guess.
    assert!(refs.contains(&base), "{refs}");
    let moved = String::from_utf8(git(&remote, &["rev-parse", "refs/heads/main"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(moved, head, "the push did not move the remote branch");
}

#[test]
fn pre_push_passes_when_nothing_is_outgoing() {
    // A deletion ref line (local sha all zeros) and an up-to-date line both
    // publish nothing: the engine must not be asked to review an empty range.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    for refs_line in [
        format!(
            "refs/heads/main {} refs/heads/main {head}\n",
            "0".repeat(40)
        ),
        format!("refs/heads/main {head} refs/heads/main {head}\n"),
    ] {
        let result = check_pre_push(&root, &refs_line);
        assert!(
            result.status.success(),
            "range '{refs_line}' must pass: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(
        !root.join("action.json").exists(),
        "an empty push must not invoke gate-audit"
    );
}

#[test]
fn gitvault_push_refuses_what_it_cannot_pre_audit() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    for option in ["--no-verify", "--stdin", "--follow-tags", "--prune"] {
        let result = run(&root, &["push", option, "origin", "main"]);
        assert!(!result.status.success(), "{option} was forwarded");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("refuses this option"),
            "{option} did not explain the refusal: {stderr}"
        );
        assert!(
            !root.join("action.json").exists(),
            "{option} reached the audit engine"
        );
    }
}

#[test]
fn a_mirror_configured_remote_is_refused_before_the_audit() {
    // `remote.<name>.mirror=true` makes git push the whole ref namespace, and
    // `--no-mirror` does not override it. The plan cannot enumerate that set,
    // so the push must refuse before spending the audit.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    checked(
        &root,
        &["remote", "add", "origin", "git@github.com:Owner/Repo.git"],
    );
    checked(&root, &["config", "remote.origin.mirror", "true"]);
    let result = run(&root, &["push", "origin", "main"]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a mirror-configured remote must refuse: {stderr}"
    );
    assert!(
        stderr.contains("mirror=true"),
        "the refusal must name the configuration: {stderr}"
    );
    assert!(
        !root.join("action.json").exists(),
        "the refusal must happen before the audit"
    );
}

#[test]
fn a_configured_remote_push_refspec_is_refused_before_the_audit() {
    // `remote.<name>.push` outranks push.default for a bare push. Its
    // refspecs can rename, force or delete refs, so following push.default
    // would audit a different set than git would publish. The push must
    // refuse before spending the audit; an explicit refspec overrides it.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    checked(
        &root,
        &["remote", "add", "origin", "git@github.com:Owner/Repo.git"],
    );
    checked(
        &root,
        &[
            "config",
            "remote.origin.push",
            "refs/heads/main:refs/heads/release",
        ],
    );
    let result = run(&root, &["push", "origin"]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a configured push refspec must refuse: {stderr}"
    );
    assert!(
        stderr.contains("remote.origin.push"),
        "the refusal must name the configuration: {stderr}"
    );
    assert!(
        !root.join("action.json").exists(),
        "the refusal must happen before the audit"
    );
}

#[test]
fn a_tag_push_with_no_tags_moves_nothing() {
    // An explicit selector that matched nothing is a no-op. Falling back to
    // push.default here would push the current branch, and handing git an
    // empty refspec list would let it re-select refs the plan never audited.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let result = run(&root, &["push", "origin", "--tags"]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "a no-op tag push must succeed: {stderr}"
    );
    assert!(
        stderr.contains("nothing to push"),
        "the no-op must be explained: {stderr}"
    );
    assert!(
        !root.join("action.json").exists(),
        "no ref was selected, so no gate action may be sent"
    );
}

#[test]
fn release_refuses_ai_attribution_in_the_tag_range() {
    let fixture = publication(&["release"], PASS);
    let root = fixture.0.clone();
    checked(&root, &["tag", "v1.0.0"]);
    checked(
        &root,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "chore: notes",
            "-m",
            "Generated with [Claude Code](https://claude.com/claude-code)",
        ],
    );
    let sha = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    checked(&root, &["tag", "v2.0.0"]);
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "release",
            "--tag",
            "v2.0.0",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a tainted release must fail: {stderr}"
    );
    assert!(
        stderr.contains(&sha[..12]),
        "the refused commit's sha must be named: {stderr}"
    );
}

#[test]
fn prepare_commit_msg_hook_blocks_even_no_verify() {
    // `--no-verify` bypasses pre-commit and commit-msg, but the message hooks
    // still run: the attribution gate refuses the AI trailer before the commit
    // object exists.
    let root = base_repo("hook");
    write_config(&root, "synthetic@example.invalid");
    install_probator(&root, &["pr"], PASS);
    std::fs::create_dir_all(root.join("hooks")).unwrap();
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("hooks").to_str().unwrap(),
        ],
    );
    let hook = root.join("hooks/prepare-commit-msg");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nGITVAULT_PROBATOR='{}' GITVAULT_ANCHOR='{}' exec '{}' --config '{}' hook prepare-commit-msg \"$@\"\n",
            root.join("probator").display(),
            root.join("no-anchor").display(),
            env!("CARGO_BIN_EXE_gitvault"),
            root.join("config.toml").display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let before = git(&root, &["rev-parse", "HEAD"]).stdout;
    let result = git(
        &root,
        &[
            "commit",
            "--no-verify",
            "--allow-empty",
            "-m",
            "feat: notes",
            "-m",
            "Generated with [Claude Code](https://claude.com/claude-code)",
        ],
    );
    assert!(!result.status.success(), "the message hook must refuse");
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).stdout, before);
}

#[test]
fn an_unsigned_routing_table_cannot_disarm_the_publication_boundary() {
    // The audit runs first and its report is shown; only then does the routing
    // signature refuse. The marker proves the engine was consulted before the
    // refusal, so an unsigned table cannot suppress the audit either.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    // The engine authorization is a precondition, so it must be certified
    // here: this test is about the routing table being judged *after* the
    // audit, not about an absent policy.
    let Some(key) = signing_anchor(&root) else {
        return;
    };
    declare_engine_policy(&root);
    assert!(sign_with(&key, &root.join("checkers.toml")));
    assert!(
        !root.join("config.toml.sig").exists(),
        "the routing table must stay unsigned"
    );
    let result = run_with(
        &root,
        &[("GITVAULT_ANCHOR", root.join("config.pub").to_str().unwrap())],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "the boundary must refuse: {stderr}"
    );
    assert!(
        stderr.contains("routing table") && stderr.contains("uncertified"),
        "stderr: {stderr}"
    );
    assert!(
        root.join("action.json").exists(),
        "the audit must run before the routing signature is judged"
    );
}

#[test]
fn the_engine_receives_the_signed_ruling_authority() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let xdg = root.join("xdg");
    // Point GitVault's trust root at a fixture path: the engine must receive
    // exactly that path, proving it is GitVault's anchor and not a guess.
    let anchor_path = root.join("fixture-config.pub");
    let result = run_with(
        &root,
        &[
            ("XDG_CONFIG_HOME", xdg.to_str().unwrap()),
            ("GITVAULT_ANCHOR", anchor_path.to_str().unwrap()),
        ],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let ledger = std::fs::read_to_string(root.join("ledger.txt")).unwrap();
    let anchor = std::fs::read_to_string(root.join("anchor.txt")).unwrap();
    assert_eq!(
        ledger,
        xdg.join("gitvault/objections.toml").display().to_string()
    );
    assert_eq!(
        anchor,
        anchor_path.display().to_string(),
        "the engine verifies against GitVault's anchor"
    );
    let action: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("action.json")).unwrap()).unwrap();
    assert_eq!(action["kind"], "pr");
}

#[test]
fn checkers_reports_the_policy_probator_enforces() {
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let result = run(&root, &["checkers", "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let policy: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("inspect JSON is relayed");
    assert_eq!(policy[0]["name"], "security-enhancer");
    assert_eq!(policy[0]["on"][0], "pre-push");
}

#[test]
fn a_missing_engine_fails_closed() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let result = run_with(
        &root,
        &[("GITVAULT_PROBATOR", "/nonexistent/probator")],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a missing engine must refuse");
    assert!(
        stderr.contains("probator") && stderr.contains("No such file"),
        "stderr: {stderr}"
    );
}

#[test]
fn a_blocking_engine_finding_refuses_the_check() {
    let fixture = publication(&["pr"], BLOCK);
    let root = fixture.0.clone();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a high finding must refuse");
    assert!(stderr.contains("blocking checker"), "stderr: {stderr}");
}

#[test]
fn an_uncertified_engine_policy_refuses_before_the_audit_runs() {
    // The policy is the authorization for the engine. An armed anchor with no
    // valid signature must refuse the boundary before gate-audit is invoked;
    // the missing action marker proves the engine never ran.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    declare_engine_policy(&root);
    std::fs::write(
        root.join("config.pub"),
        "gitvault-config ssh-ed25519 AAAAFixtureOnly\n",
    )
    .unwrap();
    let result = run_with(
        &root,
        &[("GITVAULT_ANCHOR", root.join("config.pub").to_str().unwrap())],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "an unsigned policy must refuse");
    assert!(
        stderr.contains("uncertified audit policy"),
        "stderr: {stderr}"
    );
    assert!(
        !root.join("action.json").exists(),
        "the engine must not run under an uncertified policy"
    );
}

#[test]
fn an_absent_engine_policy_refuses_an_armed_boundary_before_the_audit() {
    // The documented bootstrap signs config.toml before any checkers.toml
    // exists. An armed install in that state must refuse the boundary like an
    // unsigned policy; an absent file is not an implicit activation.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    let Some(key) = signing_anchor(&root) else {
        return;
    };
    assert!(sign_with(&key, &root.join("config.toml")));
    assert!(
        !root.join("checkers.toml").exists(),
        "the fixture starts without a policy file"
    );
    let result = run_with(
        &root,
        &[("GITVAULT_ANCHOR", root.join("config.pub").to_str().unwrap())],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "an armed boundary with no policy must refuse: {stderr}"
    );
    assert!(
        stderr.contains("uncertified audit policy"),
        "stderr: {stderr}"
    );
    assert!(
        !root.join("action.json").exists(),
        "the engine must not run without a policy"
    );
}

#[test]
fn a_certified_engine_policy_lets_the_audit_run() {
    let Some(key) = ({
        let fixture = publication(&["pr"], PASS);
        let root = fixture.0.clone();
        let key = signing_anchor(&root);
        key.map(|key| (fixture, key))
    }) else {
        return;
    };
    let (fixture, key) = key;
    let root = fixture.0.clone();
    declare_engine_policy(&root);
    assert!(sign_with(&key, &root.join("config.toml")));
    assert!(sign_with(&key, &root.join("checkers.toml")));
    let result = run_with(
        &root,
        &[("GITVAULT_ANCHOR", root.join("config.pub").to_str().unwrap())],
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "a certified policy must let the audit run: {stderr}"
    );
    assert!(
        root.join("action.json").exists(),
        "the engine ran under the certified policy"
    );
}

#[test]
fn config_verify_reads_the_declared_policy_and_ignores_a_redirected_home() {
    // `audit_policy` is signed into the routing table. Verification and
    // signing must follow that declaration, not the conventional sibling,
    // and the anchor must come from the account home (here the debug fixture
    // that stands in for a root-owned file), never from HOME.
    let Some(key) = ({
        let fixture = publication(&["pr"], PASS);
        let root = fixture.0.clone();
        let key = signing_anchor(&root);
        key.map(|key| (fixture, key))
    }) else {
        return;
    };
    let (fixture, key) = key;
    let root = fixture.0.clone();
    let config = root.join("config.toml");
    let current = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!("audit_policy = \"policy/audit.toml\"\n{current}"),
    )
    .unwrap();
    let policy = root.join("policy/audit.toml");
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::write(&policy, "# engine authorization\n").unwrap();
    // A different HOME that contains its own (junk) anchor: using HOME would
    // classify enforcement as inactive and accept the unsigned table.
    let redirected = root.join("redirected-home");
    std::fs::create_dir_all(redirected.join(".config/gitvault")).unwrap();
    std::fs::write(
        redirected.join(".config/gitvault/config.pub"),
        "gitvault-config ssh-ed25519 AAAAFixtureOnly\n",
    )
    .unwrap();
    let home = redirected.to_str().unwrap();
    let anchor = root.join("config.pub");
    let run_verify = |root: &Path| {
        run_with(
            root,
            &[
                ("HOME", home),
                ("GITVAULT_ANCHOR", anchor.to_str().unwrap()),
            ],
            &["config", "verify"],
        )
    };

    let unsigned = run_verify(&root);
    assert!(
        !unsigned.status.success(),
        "an unsigned routing table must be refused while the fixture anchor is armed: {}",
        String::from_utf8_lossy(&unsigned.stderr)
    );

    assert!(sign_with(&key, &config), "config signs");
    assert!(sign_with(&key, &policy), "declared policy signs");
    let verified = run_verify(&root);
    let stdout = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success(),
        "the declared policy must verify: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        stdout.contains(&policy.display().to_string()),
        "verification must name the declared policy, not the sibling: {stdout}"
    );
    assert!(
        !stdout.contains("checkers.toml"),
        "verification must not consult the conventional sibling: {stdout}"
    );

    // Tampering with the declared policy must fail and name that file. If
    // verification still read checkers.toml, this would spuriously pass.
    std::fs::write(&policy, "# engine authorization\n# tampered\n").unwrap();
    let tampered = run_verify(&root);
    assert!(
        !tampered.status.success(),
        "a tampered declared policy must be refused: {}",
        String::from_utf8_lossy(&tampered.stdout)
    );
    assert!(
        String::from_utf8_lossy(&tampered.stderr).contains(&policy.display().to_string()),
        "the refusal names the declared policy: {}",
        String::from_utf8_lossy(&tampered.stderr)
    );
}

#[test]
fn legacy_gitvault_review_policy_rows_are_refused_before_the_audit() {
    // checkers.toml is a signed engine authorization. GitVault executes no
    // rows, but a row naming the removed engine must not be silently ignored:
    // the gate refuses before Probator runs, and the stale binary is never
    // spawned.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    declare_engine_policy(&root);
    let marker = root.join("legacy-ran");
    let legacy = root.join("gitvault-review");
    std::fs::write(
        &legacy,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        root.join("checkers.toml"),
        format!(
            "[[checkers]]\nname = \"legacy\"\non = [\"pr\"]\ncommand = [\"{}\", \"baseline\", \"--repo\", \"{{repo}}\"]\n",
            legacy.display()
        ),
    )
    .unwrap();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a gitvault-review row must refuse the gate: {stderr}"
    );
    assert!(
        stderr.contains("gitvault-review") && stderr.contains("probator"),
        "the refusal names the removed executor and the trusted one: {stderr}"
    );
    assert!(!marker.exists(), "the stale review binary was executed");
    assert!(
        !root.join("action.json").exists(),
        "the engine must not run under a refused policy"
    );
}

#[test]
fn probator_policy_rows_are_admitted_but_never_executed() {
    // A row that names the trusted runner is admitted by the gate, yet it is
    // still inert: the delegated audit runs and the row's own binary never
    // does.
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    declare_engine_policy(&root);
    let marker = root.join("row-ran");
    let row_bin = root.join("policy-bin");
    std::fs::create_dir_all(&row_bin).unwrap();
    let row = row_bin.join("probator");
    std::fs::write(&row, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&row, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        root.join("checkers.toml"),
        format!(
            "[[checkers]]\nname = \"delegated\"\non = [\"pr\"]\ncommand = [\"{}\", \"baseline\", \"--repo\", \"{{repo}}\"]\n",
            row.display()
        ),
    )
    .unwrap();
    let result = run(
        &root,
        &[
            "check",
            "--event",
            "pr",
            "--pr-head",
            "main",
            "--directory",
            root.to_str().unwrap(),
        ],
    );
    assert!(
        result.status.success(),
        "the delegated audit should pass: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!marker.exists(), "a policy row was executed as a checker");
    assert!(root.join("action.json").exists(), "the delegation ran");
}

/// `gitvault check --event pre-push` reading the ref line git would put on the
/// hook's stdin.
fn check_pre_push(root: &Path, refs_line: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_PROBATOR", root.join("probator"))
        .env("GITVAULT_ANCHOR", root.join("no-anchor"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_STATE_HOME", root.join("state"))
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "pre-push",
            "--directory",
            root.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(refs_line.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn gitvault_push_hands_git_only_the_audited_refspecs() {
    // A local bare remote keeps the test offline. The tag plus
    // `push.followTags=true` is the trap: the wrapper must disable that
    // configuration, and it must pass the audited branch refspec rather than
    // the original argument vector.
    let fixture = publication(&["pre-push"], PASS);
    let root = fixture.0.clone();
    let remote = root.join("remote.git");
    checked(&root, &["init", "-q", "--bare", "remote.git"]);
    checked(
        &root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    checked(&root, &["config", "push.followTags", "true"]);
    checked(&root, &["tag", "-a", "v1", "-m", "release"]);
    checked(&root, &["checkout", "-q", "-b", "side"]);
    checked(&root, &["commit", "--allow-empty", "-qm", "side"]);
    checked(&root, &["checkout", "-q", "main"]);

    let result = run(&root, &["push", "origin", "main"]);
    assert!(
        result.status.success(),
        "the audited push failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let pushed = String::from_utf8(
        git(
            &root,
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "rev-parse",
                "--verify",
                "refs/heads/main",
            ],
        )
        .stdout,
    )
    .unwrap_or_default();
    assert!(!pushed.trim().is_empty(), "main did not reach the remote");
    let tag = git(
        &root,
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "rev-parse",
            "--verify",
            "refs/tags/v1",
        ],
    );
    assert!(
        !tag.status.success(),
        "push.followTags published an unaudited tag"
    );
    let side = git(
        &root,
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "rev-parse",
            "--verify",
            "refs/heads/side",
        ],
    );
    assert!(
        !side.status.success(),
        "a ref outside the refspec was pushed"
    );
}

#[test]
fn a_blocking_engine_finding_refuses_the_push_before_git_runs() {
    // The push path must both execute Probator and act on the report it reads:
    // a high finding refuses the push, and git is never reached.
    let fixture = publication(&["pre-push"], BLOCK);
    let root = fixture.0.clone();
    let remote = root.join("remote.git");
    checked(&root, &["init", "-q", "--bare", "remote.git"]);
    checked(
        &root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );

    let result = run(&root, &["push", "origin", "main"]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success(),
        "a blocking finding must refuse the push: {stderr}"
    );
    assert!(
        stderr.contains("fixture-audit"),
        "the engine report is read and shown: {stderr}"
    );
    assert!(
        root.join("action.json").exists(),
        "the push action never reached the stub engine"
    );
    let pushed = git(
        &root,
        &[
            "--git-dir",
            remote.to_str().unwrap(),
            "rev-parse",
            "--verify",
            "refs/heads/main",
        ],
    );
    assert!(
        !pushed.status.success(),
        "a refused push published a ref to the remote"
    );
}

#[test]
fn concurrent_audits_serialize_on_the_repository_lock() {
    let fixture = publication(&["pr"], PASS);
    let root = fixture.0.clone();
    // Replace the instant stub with one that holds the first gate-audit open
    // until the test releases it, and records entry/exit. Without the lock,
    // both GitVault processes enter the engine and the log interleaves.
    let script = format!(
        "#!/bin/sh\n\
         ROOT='{root}'\n\
         case \"$1\" in\n\
           inspect) cat \"$ROOT/inspect.json\" ;;\n\
           gate-audit)\n\
             cat >/dev/null\n\
             printf 'start\\n' >> \"$ROOT/serial.log\"\n\
             if [ ! -f \"$ROOT/release\" ]; then\n\
               while [ ! -f \"$ROOT/release\" ]; do sleep 0.05; done\n\
             fi\n\
             printf 'end\\n' >> \"$ROOT/serial.log\"\n\
             cat \"$ROOT/findings.json\"\n\
             ;;\n\
           *) echo \"unexpected probator invocation: $*\" >&2; exit 2 ;;\n\
         esac\n",
        root = root.display()
    );
    std::fs::write(root.join("probator"), &script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("probator"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_gitvault"))
            .env("GITVAULT_PROBATOR", root.join("probator"))
            .env("GITVAULT_ANCHOR", root.join("no-anchor"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_STATE_HOME", root.join("state"))
            .current_dir(&root)
            .arg("--config")
            .arg(root.join("config.toml"))
            .args([
                "check",
                "--event",
                "pr",
                "--pr-head",
                "main",
                "--directory",
                root.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn();
    let log = root.join("serial.log");
    for _ in 0..800 {
        if std::fs::read_to_string(&log)
            .map(|text| text.contains("start"))
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if !std::fs::read_to_string(&log)
        .map(|text| text.contains("start"))
        .unwrap_or(false)
    {
        // Let the child finish before collecting its stderr; otherwise this
        // failure path waits forever on the release file the test never wrote.
        let _ = std::fs::write(root.join("release"), "go");
        let output = first.wait_with_output().unwrap();
        panic!(
            "the first audit never reached the engine: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let second = spawn();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let held = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        held.lines().filter(|line| *line == "start").count(),
        1,
        "a second audit entered the engine while the first held the lock: {held:?}"
    );
    std::fs::write(root.join("release"), "go").unwrap();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(
        first.status.success(),
        "first audit failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "second audit failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        ["start", "end", "start", "end"],
        "{log:?}"
    );
}
