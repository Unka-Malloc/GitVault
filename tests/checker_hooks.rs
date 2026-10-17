use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
    assert!(result.status.success(), "fixture Git command failed");
}
fn fixture(checker: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "gitvault-hook-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(root.join("hooks")).unwrap();
    checked(&root, &["init", "-q"]);
    checked(&root, &["config", "commit.gpgsign", "false"]);
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("hooks").to_str().unwrap(),
        ],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    std::fs::write(root.join("two"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    std::fs::write(root.join("checker.sh"), checker).unwrap();
    // The audit policy is its own file beside the routing table: checker rows
    // declare executable commands, so they are certified (and refused) on
    // their own signature, not the routing table's.
    let cfg = format!(
        "record_dir = '{}'\n[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
        root.join("runs").display()
    );
    std::fs::write(root.join("config.toml"), cfg).unwrap();
    let policy = format!(
        "[[checkers]]\nname = 'money-saver-fixture'\non = ['prepare-commit-msg', 'pre-applypatch']\ntimeout_secs = 0\ncommand = ['/bin/sh', '{}', '{{repo}}']\n",
        root.join("checker.sh").display()
    );
    std::fs::write(root.join("checkers.toml"), policy).unwrap();
    let hook = root.join("hooks/prepare-commit-msg");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nGITVAULT_UNSIGNED_OK=1 exec '{}' --config '{}' hook prepare-commit-msg\n",
            env!("CARGO_BIN_EXE_gitvault"),
            root.join("config.toml").display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(
        root.join("hooks/prepare-commit-msg"),
        root.join("hooks/pre-applypatch"),
    )
    .unwrap();
    let patch_hook = root.join("hooks/pre-applypatch");
    let text = std::fs::read_to_string(&patch_hook)
        .unwrap()
        .replace("hook prepare-commit-msg", "hook pre-applypatch");
    std::fs::write(patch_hook, text).unwrap();
    Fixture(root)
}

#[test]
fn pull_request_event_runs_registered_checkers() {
    // `pr` is the publication boundary that is not a git hook: GitVault's own
    // pull-request operations run the same registry, so a checker registered for
    // the event is selected and sees GITVAULT_EVENT=pr.
    let root = std::env::temp_dir().join(format!(
        "gitvault-pr-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _cleanup = Fixture(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    checked(&root, &["init", "-q"]);
    // Neutral hooks: this fixture must not run the machine's real hook chain,
    // and its own commit must not reach the installed gates.
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("no-hooks").to_str().unwrap(),
        ],
    );
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    let marker = root.join("reviewed");
    let checker = root.join("checker.sh");
    std::fs::write(
        &checker,
        format!(
            "#!/bin/sh\nprintf '%s|%s' \"$GITVAULT_EVENT\" \"$GITVAULT_PR_HEAD\" > '{}'\n",
            marker.display()
        ),
    )
    .unwrap();
    let cfg = format!(
        "record_dir = '{}'\n[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
        root.join("runs").display()
    );
    std::fs::write(root.join("config.toml"), cfg).unwrap();
    let policy = format!(
        "[[checkers]]\nname = 'publication'\non = ['pr']\ncommand = ['/bin/sh', '{}', '{{repo}}']\n",
        checker.display()
    );
    std::fs::write(root.join("checkers.toml"), policy).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "pr",
            "--directory",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "pr check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let recorded = std::fs::read_to_string(&marker).unwrap();
    assert!(recorded.starts_with("pr|"), "checker saw '{recorded}'");
}

/// A throwaway repository with its own config; `checkers` is the checker block
/// and `event` the registry events it covers.
fn publication_fixture(events: &str, blocking: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "gitvault-pub-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    checked(&root, &["init", "-q"]);
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("no-hooks").to_str().unwrap(),
        ],
    );
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    checked(&root, &["tag", "v1.0.0"]);
    let marker = root.join("ran");
    let checker = root.join("checker.sh");
    std::fs::write(
        &checker,
        format!(
            "#!/bin/sh\nprintf '%s|%s|%s' \"$GITVAULT_EVENT\" \"$GITVAULT_RELEASE_TAG\" \"$GITVAULT_PR_NUMBER\" > '{}'\nprintf 'receipt: %s\\n' \"$HOME/receipts/run.json\"\n{}",
            marker.display(),
            if blocking { "exit 1\n" } else { "exit 0\n" }
        ),
    )
    .unwrap();
    let cfg = format!(
        "record_dir = '{}'\n[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
        root.join("runs").display()
    );
    std::fs::write(root.join("config.toml"), cfg).unwrap();
    let policy = format!(
        "[[checkers]]\nname = 'publication'\non = [{events}]\ncommand = ['/bin/sh', '{}', '{{repo}}']\n",
        checker.display()
    );
    std::fs::write(root.join("checkers.toml"), policy).unwrap();
    Fixture(root)
}

#[test]
fn release_event_runs_registered_checkers_with_the_tag() {
    let fixture = publication_fixture("'release'", false);
    let root = fixture.0.clone();
    let marker = root.join("ran");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "release",
            "--tag",
            "v1.0.0",
            "--directory",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "release check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let recorded = std::fs::read_to_string(&marker).unwrap();
    assert!(
        recorded.starts_with("release|v1.0.0|"),
        "checker saw '{recorded}'"
    );
}

#[test]
fn release_create_is_refused_before_any_credential_is_touched() {
    // The gate sits ahead of the vault, so this holds with no vault at all --
    // and the absence of an authentication error proves nothing reached the API.
    let fixture = publication_fixture("'release'", true);
    let root = fixture.0.clone();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "release",
            "create",
            "v1.0.0",
            "--repo",
            "Owner/Name",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a blocked release must fail");
    assert!(stderr.contains("refused this release"), "stderr: {stderr}");
    for credential_error in ["unlock", "authentication", "credential"] {
        assert!(
            !stderr.to_lowercase().contains(credential_error),
            "the gate must run before any credential is touched: {stderr}"
        );
    }
}

#[test]
fn merge_is_refused_before_the_api_call() {
    let fixture = publication_fixture("'pr'", true);
    let root = fixture.0.clone();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "pr",
            "merge",
            "7",
            "--repo",
            "Owner/Name",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "a blocked merge must fail");
    assert!(stderr.contains("refused this merge"), "stderr: {stderr}");
    let recorded = std::fs::read_to_string(root.join("ran")).unwrap();
    assert!(recorded.starts_with("pr||7"), "checker saw '{recorded}'");
}

#[test]
fn a_run_is_recorded_without_this_machines_paths() {
    // The record is built for a reader other than the person who ran the gate,
    // so it must describe the work and not the machine: a checker that prints a
    // path under HOME gets it replaced before anything is stored.
    let fixture = publication_fixture("'pr'", false);
    let root = fixture.0.clone();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "pr",
            "--directory",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
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
    assert!(
        record.contains("[LOCAL_PATH]"),
        "the printed path is marked: {record}"
    );
    assert!(record.contains("\"event\": \"pr\""), "{record}");
    assert!(record.contains("\"name\": \"publication\""), "{record}");

    // `records` reads the same store without opening the vault or the network.
    let listed = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "records",
            "list",
            "--json",
        ])
        .output()
        .unwrap();
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

/// A repository wired for `check --event pre-push|release`: the built-in
/// attribution gate runs regardless of which checkers the policy registers,
/// so the fixture keeps a single passing one.
fn attribution_fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "gitvault-attr-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    checked(&root, &["init", "-q"]);
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
    let checker = root.join("checker.sh");
    std::fs::write(&checker, "#!/bin/sh\nexit 0\n").unwrap();
    let cfg = format!(
        "record_dir = '{}'\n[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
        root.join("runs").display()
    );
    std::fs::write(root.join("config.toml"), cfg).unwrap();
    let policy = format!(
        "[[checkers]]\nname = 'publication'\non = ['pre-push', 'pr', 'release']\ncommand = ['/bin/sh', '{}', '{{repo}}']\n",
        checker.display()
    );
    std::fs::write(root.join("checkers.toml"), policy).unwrap();
    Fixture(root)
}

/// `gitvault check --event pre-push` reading the ref line git would put on the
/// hook's stdin.
fn check_pre_push(root: &Path, refs_line: &str) -> Output {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "pre-push",
            "--directory",
            root.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(refs_line.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

#[test]
fn pre_push_refuses_commits_with_ai_attribution() {
    let fixture = attribution_fixture();
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
}

#[test]
fn pre_push_passes_a_clean_range() {
    let fixture = attribution_fixture();
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
}

#[test]
fn pre_push_passes_when_nothing_is_outgoing() {
    // A deletion ref line (local sha all zeros) and an up-to-date line both
    // contribute no outgoing commits - the gate must not invent a refusal.
    let fixture = attribution_fixture();
    let root = fixture.0.clone();
    let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    for refs_line in [
        format!("refs/heads/main {ZERO_SHA} refs/heads/main {head}\n"),
        format!("refs/heads/main {head} refs/heads/main {head}\n"),
    ] {
        let result = check_pre_push(&root, &refs_line);
        assert!(
            result.status.success(),
            "range '{refs_line}' must pass: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn release_refuses_ai_attribution_in_the_tag_range() {
    let fixture = attribution_fixture();
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
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "release",
            "--tag",
            "v2.0.0",
            "--directory",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
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
fn mandatory_hook_blocks_even_no_verify() {
    let f = fixture("exit 1\n");
    let before = git(&f.0, &["rev-parse", "HEAD"]).stdout;
    let result = git(
        &f.0,
        &["commit", "--no-verify", "--allow-empty", "-m", "refused"],
    );
    assert!(!result.status.success());
    assert_eq!(git(&f.0, &["rev-parse", "HEAD"]).stdout, before);
}

#[test]
fn completion_wait_and_partial_commit_use_actual_index() {
    let f = fixture("sleep 1.1\ngit -C \"$1\" diff --cached --name-only > \"$1/observed\"\n");
    std::fs::write(f.0.join("one"), "changed one\n").unwrap();
    std::fs::write(f.0.join("two"), "changed two\n").unwrap();
    checked(&f.0, &["add", "two"]);
    checked(&f.0, &["commit", "--only", "one", "-qm", "partial"]);
    assert_eq!(
        std::fs::read_to_string(f.0.join("observed")).unwrap(),
        "one\n"
    );
    assert_eq!(
        String::from_utf8(git(&f.0, &["diff", "--cached", "--name-only"]).stdout).unwrap(),
        "two\n"
    );
}

#[test]
fn patch_application_cannot_create_an_unreviewed_commit() {
    let f = fixture("exit 0\n");
    std::fs::write(f.0.join("one"), "patch change\n").unwrap();
    checked(&f.0, &["add", "one"]);
    checked(&f.0, &["commit", "-qm", "patch source"]);
    let patch = git(&f.0, &["format-patch", "-1", "--stdout"]).stdout;
    checked(&f.0, &["reset", "--hard", "HEAD^"]);
    let before = git(&f.0, &["rev-parse", "HEAD"]).stdout;
    std::fs::write(f.0.join("change.patch"), patch).unwrap();
    std::fs::write(f.0.join("checker.sh"), "exit 1\n").unwrap();
    assert!(!git(&f.0, &["am", "change.patch"]).status.success());
    assert_eq!(git(&f.0, &["rev-parse", "HEAD"]).stdout, before);
}

/// A repository under armed signature enforcement: the debug-only
/// `GITVAULT_ANCHOR` escape points the trust root at the fixture's own
/// `config.pub`, so unsigned policy and routing files classify as `Invalid`.
/// The policy file exists but declares no `[[checkers]]` - the emptied state
/// a local write can produce.
fn anchored_fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "gitvault-anchor-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    checked(&root, &["init", "-q"]);
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("no-hooks").to_str().unwrap(),
        ],
    );
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    std::fs::write(
        root.join("config.toml"),
        "[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
    )
    .unwrap();
    std::fs::write(root.join("checkers.toml"), "# audit policy: emptied\n").unwrap();
    Fixture(root)
}

/// `gitvault check --event pr` and `gitvault hook pr` over the fixture, under
/// the armed anchor.
fn pr_gate_runs(root: &Path) -> Vec<Output> {
    let anchor = root.join("config.pub");
    let config = root.join("config.toml");
    [
        vec![
            "--config".into(),
            config.display().to_string(),
            "check".into(),
            "--event".into(),
            "pr".into(),
            "--directory".into(),
            root.display().to_string(),
        ],
        vec![
            "--config".into(),
            config.display().to_string(),
            "hook".into(),
            "pr".into(),
        ],
    ]
    .into_iter()
    .map(|args| {
        Command::new(env!("CARGO_BIN_EXE_gitvault"))
            .env("GITVAULT_ANCHOR", &anchor)
            .env_remove("GITVAULT_UNSIGNED_OK")
            .env_remove("GITVAULT_CONFIG")
            .args(&args)
            .current_dir(root)
            .output()
            .unwrap()
    })
    .collect()
}

#[test]
fn an_emptied_policy_cannot_disarm_the_publication_boundary() {
    // The emptied policy declares no checkers, which used to skip the
    // signature refusal entirely: one local write ran zero audits at the
    // boundary and credentials still flowed. Anchored, the refusal is
    // unconditional at events that publish or spend credentials.
    let fixture = anchored_fixture();
    let root = fixture.0.clone();
    // Any existing file arms the fixture anchor; its content is only read
    // when a signature sidecar exists.
    std::fs::write(
        root.join("config.pub"),
        "gitvault-config ssh-ed25519 AAAAFixtureOnly\n",
    )
    .unwrap();
    for result in pr_gate_runs(&root) {
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            !result.status.success(),
            "the boundary must refuse: {stderr}"
        );
        assert!(
            stderr.contains("uncertified audit policy"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn an_emptied_policy_still_holds_the_routing_table_to_its_signature() {
    // ssh-keygen does the signing, the same plumbing `gitvault config sign`
    // uses; skip where it cannot sign.
    if Command::new("ssh-keygen")
        .args(["-Y", "sign"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
    {
        return;
    }
    let fixture = anchored_fixture();
    let root = fixture.0.clone();
    // Certify the emptied policy; leave the routing table unsigned.
    let key = root.join("anchor-key");
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "gitvault-config", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success(), "anchor keygen failed");
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let mut fields = public.split_whitespace();
    std::fs::write(
        root.join("config.pub"),
        format!(
            "gitvault-config {} {}\n",
            fields.next().unwrap(),
            fields.next().unwrap()
        ),
    )
    .unwrap();
    let out = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "gitvault-config", "-f"])
        .arg(&key)
        .arg(root.join("checkers.toml"))
        .output()
        .unwrap();
    assert!(out.status.success(), "policy signing failed");

    for result in pr_gate_runs(&root) {
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            !result.status.success(),
            "the boundary must refuse: {stderr}"
        );
        assert!(
            stderr.contains("routing table") && stderr.contains("uncertified"),
            "stderr: {stderr}"
        );
    }
}

#[test]
fn checkers_run_with_a_curated_environment() {
    // The documented guarantee: nothing is inherited except PATH and locale.
    // Sentinel variables in the parent environment - credentials, steering
    // knobs - must not reach a checker; PATH and the GITVAULT_* context must.
    let root = std::env::temp_dir().join(format!(
        "gitvault-env-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _cleanup = Fixture(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    checked(&root, &["init", "-q"]);
    checked(
        &root,
        &[
            "config",
            "core.hooksPath",
            root.join("no-hooks").to_str().unwrap(),
        ],
    );
    checked(&root, &["config", "user.name", "Synthetic"]);
    checked(
        &root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    std::fs::write(root.join("one"), "base\n").unwrap();
    checked(&root, &["add", "."]);
    checked(&root, &["commit", "-qm", "base"]);
    let marker = root.join("env-report");
    let checker = root.join("checker.sh");
    std::fs::write(
        &checker,
        format!(
            "#!/bin/sh\n\
             if [ -n \"${{CHECKER_SENTINEL:+x}}\" ] || [ -n \"${{GH_TOKEN:+x}}\" ] || [ -n \"${{PYTHONPATH:+x}}\" ]; then\n  \
               printf 'leaked' > '{0}'; exit 1\n\
             fi\n\
             if [ -z \"$PATH\" ] || [ -z \"$GITVAULT_EVENT\" ]; then\n  \
               printf 'missing' > '{0}'; exit 1\n\
             fi\n\
             printf 'clean:%s' \"$GITVAULT_EVENT\" > '{0}'\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("config.toml"),
        format!(
            "record_dir = '{}'\n[identities.fixture]\nname = 'Synthetic'\nemail = 'synthetic@example.invalid'\n[rules]\ndefault = 'fixture'\n",
            root.join("runs").display()
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("checkers.toml"),
        format!(
            "[[checkers]]\nname = 'env-probe'\non = ['pr']\ncommand = ['/bin/sh', '{}', '{{repo}}']\n",
            checker.display()
        ),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_gitvault"))
        .env("GITVAULT_UNSIGNED_OK", "1")
        .env("CHECKER_SENTINEL", "must-not-leak")
        .env("GH_TOKEN", "must-not-leak")
        .env("PYTHONPATH", "/attacker/modules")
        .args([
            "--config",
            root.join("config.toml").to_str().unwrap(),
            "check",
            "--event",
            "pr",
            "--directory",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "clean:pr",
        "the checker's view of its environment"
    );
}
