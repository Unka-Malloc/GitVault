//! GitVault - hold the identity, intercept the action, delegate the audit.
//!
//! The binary is the only component that decides *who* is acting. It never
//! executes code from the repository it inspects and it does not own an audit
//! engine: publication audits are handed to `probator gate-audit`, which keeps
//! the policy, the reviewer contracts, the receipts and the operator waivers.

mod api;
mod attribution;
mod auth;
mod checkers;
mod config;
mod configsig;
mod git;
mod history;
mod identity;
mod objection;
mod probator;
mod records;
mod seal;
mod sign;
mod ssh;
mod tempsecret;
mod unlock;
mod vault;

use std::io::{IsTerminal, Read};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gitvault", version, about)]
struct Cli {
    /// Override the configuration file location.
    #[arg(long, global = true, env = "GITVAULT_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolve the identity that applies to a repository, and say why.
    Resolve {
        #[arg(default_value = ".")]
        directory: PathBuf,
        /// Ignore `.gitvault-identity` and resolve from the remote owner only.
        #[arg(long)]
        ignore_assertion: bool,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Intercept a git hook event: local gates, then the delegated audit.
    ///
    /// Wired as `core.hooksPath` entries. git passes the event name and, for
    /// pre-push, the ref list on stdin.
    Hook {
        /// pre-commit | prepare-commit-msg | pre-applypatch | pre-push | commit-msg
        event: String,
        /// Arguments git passed to the hook.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Run the same interception outside a hook, for testing and for CI.
    /// For `--event pre-push` the refs git would hand the hook are derived
    /// from the checkout's outgoing branches when stdin supplies none.
    Check {
        #[arg(long, default_value = "pre-commit")]
        event: String,
        #[arg(long, default_value = ".")]
        directory: PathBuf,
        /// The release tag or exact commit, for `--event release`.
        #[arg(long)]
        tag: Option<String>,
        /// The proposed head (branch or sha) for `--event pr`.
        #[arg(long)]
        pr_head: Option<String>,
        /// The base branch for `--event pr`.
        #[arg(long)]
        pr_base: Option<String>,
        /// The request number for `--event pr`.
        #[arg(long)]
        pr_number: Option<String>,
    },

    /// Audit what this push would carry, then run it.
    ///
    /// A bare `git push` connects to the remote before it runs the pre-push
    /// hook - the hook's stdin is built from the remote's advertised refs,
    /// which only the transport can supply - so the SSH credential is spent
    /// before the audit has run. This entry restores the intended order: the
    /// same ref lines are synthesized locally from the arguments and the
    /// remote's mirror refs, the audit runs with no credential touched, and
    /// only a passing audit hands control to the real `git push`. That push's
    /// hook then re-audits the refs git actually advertises; the hook's run is
    /// the authoritative verdict, so this pre-audit is advisory. It exists to
    /// avoid spending the SSH credential before a failing audit is known.
    /// Arguments are not forwarded unchanged: git receives the exact refspecs
    /// the pre-audit examined.
    Push {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Inspect recorded audit runs.
    ///
    /// Read-only: no vault, no network, no writes. Records are built to be
    /// read by someone other than the person who ran the gate, so nothing
    /// here may describe this machine's paths.
    Records {
        #[command(subcommand)]
        command: RecordsCommand,
    },

    /// Show the audit policy Probator enforces.
    Checkers {
        #[arg(long)]
        json: bool,
    },

    /// Manage stored GitHub credentials (replaces `gh auth`).
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Open the vault for a bounded window.
    ///
    /// Reading the vault key is the human-presence event. Without an open window,
    /// write operations are refused, so an idle machine cannot be driven silently.
    Unlock {
        /// Window length in seconds.
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Close the vault immediately.
    Lock,

    /// Report whether the vault is open.
    Status {
        #[arg(long)]
        json: bool,
    },

    /// File and adjudicate objections to checker findings.
    ///
    /// A blocking verdict is evidence, not law: the operator may rule that a
    /// finding does not apply. Filing is a plain record; ruling requires the
    /// biometric vault confirmation and signs the rulings ledger — a waiver
    /// only counts while that signature verifies.
    Objection {
        #[command(subcommand)]
        command: ObjectionCommand,
    },

    /// Inspect or bless the configuration itself.
    ///
    /// Once `config.pub` is root-owned, every GitVault surface refuses an
    /// unsigned configuration. Editing the file stays a plain edit; blessing it
    /// is the gated step.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Deploy GitVault on this machine and hand its enforcement surface to root.
    ///
    /// Lays down the binary, the hook dispatchers and - when a configuration
    /// signing anchor exists - transfers the binaries, the hooks directory and
    /// the anchor to root ownership. The configuration file itself stays
    /// user-writable: editing it is allowed, but only a signed version loads.
    Install,

    /// Make an authenticated GitHub API request.
    ///
    /// The token is used inside GitVault and is never returned, so there is no
    /// interface here that yields a credential.
    Api {
        /// Endpoint, e.g. /repos/OWNER/REPO or a full URL.
        path: String,
        /// HTTP method (default GET).
        #[arg(long, short = 'X', default_value = "GET")]
        method: String,
        /// A string field, repeatable.
        #[arg(long = "field", short = 'f')]
        fields: Vec<String>,
        /// A raw field, repeatable.
        #[arg(long = "raw-field", short = 'F')]
        raw_fields: Vec<String>,
        /// An extra header, repeatable.
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,
        /// A request body, or @file.
        #[arg(long)]
        input: Option<String>,
        /// Restrict output to a dotted path (a small subset of jq).
        #[arg(long, short = 'q')]
        jq: Option<String>,
        /// Act for this OWNER/NAME instead of the current working tree.
        #[arg(long, short = 'R')]
        repo: Option<String>,
        /// Act as this configured identity instead of resolving from a repository.
        /// Mutually exclusive with --repo: two selectors must never silently
        /// disagree about whose credentials are used.
        #[arg(long, conflicts_with = "repo")]
        identity: Option<String>,
        /// Follow a redirect hop on a read request (Actions logs, archive
        /// downloads): the signed download URL is fetched inside GitVault -
        /// the token never leaves the first request, and the redirect
        /// target is never printed. Read verbs only.
        #[arg(long = "follow", short = 'L')]
        follow: bool,
        /// Print nothing on success.
        #[arg(long)]
        silent: bool,
    },

    /// Print the public half of an account's signing key, for
    /// `gpg.ssh.defaultKeyCommand`.
    ///
    /// Git requires either `user.signingkey` or this command to be configured, even
    /// when `gpg.ssh.program` supplies the signature itself. Pointing it here keeps
    /// that requirement satisfied without a placeholder file on disk or a path that
    /// does not exist.
    SigningKey {
        /// Account to read the signing key for. Defaults to the one the current
        /// repository resolves to.
        account: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },

    /// Commit-signing proxy. Configured as gpg.ssh.program; invoked by git.
    Sign {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// SSH transport proxy. Configured as core.sshCommand; invoked by git.
    ///
    /// Declared as trailing arguments so git's own ssh arguments reach it intact.
    Ssh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Issues.
    Issue {
        #[command(subcommand)]
        command: IssueCommand,
        #[arg(long, short = 'R', global = true)]
        repo: Option<String>,
    },

    /// Repositories.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },

    /// Releases.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
        #[arg(long, short = 'R', global = true)]
        repo: Option<String>,
    },

    /// Workflow runs.
    Run {
        #[command(subcommand)]
        command: RunCommand,
        #[arg(long, short = 'R', global = true)]
        repo: Option<String>,
    },

    /// Pull requests.
    Pr {
        #[command(subcommand)]
        command: PrCommand,
        /// Act for this OWNER/NAME instead of the current working tree.
        #[arg(long, short = 'R', global = true)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
enum ObjectionCommand {
    /// File an objection against a finding (or a whole non-pass verdict).
    ///
    /// For a finding objection, `--finding FILE[:LINE]` locates the newest
    /// blocking finding in the checker's latest report and pins its evidence
    /// fingerprint. `--verdict` instead objects to a non-pass outcome (for
    /// example an `incomplete`) and binds the ruling to the current head.
    File {
        /// Checker contract name, e.g. money-saver.
        #[arg(long)]
        checker: String,
        /// Finding location in `FILE[:LINE]` form.
        #[arg(long, conflicts_with = "verdict")]
        finding: Option<String>,
        /// Object to the checker's whole non-pass verdict for this head.
        #[arg(long)]
        verdict: bool,
        /// Why the finding does not apply.
        #[arg(long)]
        reason: String,
        /// Repository under review (defaults to the current working tree).
        #[arg(long, short = 'd', default_value = ".")]
        directory: PathBuf,
    },
    /// List pending objections and signed rulings.
    List,
    /// Rule on a pending objection: sustain (finding stands) or overrule
    /// (waived while the ledger signature verifies).
    ///
    /// Requires the biometric vault confirmation, then re-signs the ledger.
    Rule {
        id: String,
        /// The adjudication.
        #[arg(long, conflicts_with = "sustain")]
        overrule: bool,
        #[arg(long)]
        sustain: bool,
        /// The operator's adjudication note.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Rescind a ruling (the finding blocks again from the next run).
    Rescind { id: String },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Create the configuration signing key and publish the verification anchor.
    ///
    /// The private key goes into the vault; its public half lands in
    /// `config.pub` beside the configuration, where `gitvault install` later
    /// transfers it to root ownership - that ownership is what arms
    /// verification.
    Keygen,

    /// Sign the configuration and the engine-authorization policy.
    ///
    /// Editing `config.toml` or `checkers.toml` stays a plain file edit; this
    /// command is the ceremony that certifies both, gated by the same human
    /// confirmation as releasing a credential. The policy's signature is what
    /// lets the audit engine run.
    Sign,

    /// Report the configuration's signature state. Fails when enforcement is
    /// armed and the signature is missing or wrong.
    Verify,
}

#[derive(Subcommand)]
enum IssueCommand {
    /// Open an issue.
    Create {
        #[arg(long)]
        title: String,
        #[arg(long)]
        body: Option<String>,
    },
    /// List issues.
    List {
        #[arg(long, default_value = "open")]
        state: String,
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// View one issue.
    View {
        number: u64,
        #[arg(long)]
        json: bool,
    },
    /// Comment on an issue.
    Comment {
        number: u64,
        #[arg(long)]
        body: String,
    },
    /// Close an issue.
    Close { number: u64 },
    /// Reopen an issue.
    Reopen { number: u64 },
}

#[derive(Subcommand)]
enum RepoCommand {
    /// View a repository.
    View {
        /// OWNER/NAME, or omitted for the current working tree.
        slug: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List repositories for an owner.
    ///
    /// Works for both organisations and personal accounts: the endpoint differs and
    /// picking the wrong one fails with a 404 that looks like the owner does not
    /// exist.
    List {
        owner: String,
        #[arg(long, default_value_t = 30)]
        limit: u32,
        /// Filter by visibility: all, public, private.
        #[arg(long, default_value = "all")]
        visibility: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the default branch.
    DefaultBranch { slug: Option<String> },
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// List releases.
    List {
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// View one release by tag.
    View {
        tag: String,
        #[arg(long)]
        json: bool,
    },
    /// Create a release for an existing tag.
    Create {
        tag: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        draft: bool,
        #[arg(long)]
        prerelease: bool,
        /// Upload a file as a release asset (repeatable). The stored asset
        /// name is the file's basename.
        #[arg(long = "asset")]
        assets: Vec<PathBuf>,
    },
    /// Delete a release by tag.
    Delete { tag: String },
}

#[derive(Subcommand)]
enum RunCommand {
    /// List recent workflow runs.
    List {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// View one workflow run.
    View {
        id: u64,
        #[arg(long)]
        json: bool,
    },
    /// Fetch a workflow job's log text. The logs endpoint answers a
    /// redirect to a signed download URL, which the broker follows inside
    /// the vault: the token never leaves the first request and the signed
    /// URL is never printed. `--run` reads a whole run's zipped archive
    /// instead - binary output, so pipe it somewhere useful.
    Logs {
        /// Workflow job id (or a workflow run id with `--run`).
        id: u64,
        /// Treat `id` as a workflow run and fetch the zipped log archive.
        #[arg(long)]
        run: bool,
    },
}

#[derive(Subcommand)]
enum PrCommand {
    /// Open a pull request.
    Create {
        #[arg(long)]
        title: String,
        #[arg(long)]
        body: Option<String>,
        /// Source branch (defaults to the current branch).
        #[arg(long)]
        head: Option<String>,
        /// Target branch (defaults to the repository default).
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        draft: bool,
    },
    /// List pull requests.
    List {
        #[arg(long, default_value = "open")]
        state: String,
        #[arg(long, default_value_t = 30)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// View one pull request.
    View {
        number: u64,
        #[arg(long)]
        json: bool,
    },
    /// Merge a pull request.
    Merge {
        number: u64,
        #[arg(long, default_value = "merge")]
        method: String,
        #[arg(long)]
        subject: Option<String>,
        /// Target branch; read from the pull request when omitted.
        #[arg(long)]
        base: Option<String>,
    },
    /// Close a pull request without merging.
    Close { number: u64 },
    /// Comment on a pull request.
    Comment {
        number: u64,
        #[arg(long)]
        body: String,
    },
}

#[derive(Subcommand)]
enum RecordsCommand {
    /// Every recorded run, newest first.
    List {
        #[arg(long)]
        json: bool,
    },
    /// One recorded run, including what each gate printed.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Re-walk the seal chain over every record and report gaps or rewrites.
    Verify,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Create the vault key. Run once per machine.
    Init,
    /// Store a token for an account. Reads the token from stdin.
    Add { account: String },
    /// Remove stored material for an account.
    ///
    /// Scoped by default: removing a key does not touch the token. Pass --all to
    /// clear the account entirely.
    Remove {
        account: String,
        /// Remove only the tokens.
        #[arg(long)]
        token: bool,
        /// Remove only the keys (authentication, signing and their passphrase).
        #[arg(long)]
        keys: bool,
        /// Remove everything held for this account.
        #[arg(long)]
        all: bool,
    },
    /// Remove one specific key, leaving everything else in place.
    RemoveKey {
        account: String,
        /// Target the commit-signing key rather than the authentication key.
        #[arg(long)]
        signing: bool,
    },
    /// List stored accounts and which identities reference them.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Import a private key from a file into the vault.
    ///
    /// After this the file is redundant, and deleting it is the point: a key on
    /// disk can be read and used by any process as that identity.
    ImportKey {
        account: String,
        /// Path to the private key.
        file: PathBuf,
        /// Import it as the commit-signing key rather than the authentication key.
        #[arg(long)]
        signing: bool,
    },
    /// Report whether a specific account has a token, without revealing it.
    Status {
        /// Account to check; omit to check every account an identity references.
        account: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Resolve {
            directory,
            ignore_assertion,
            json,
        } => cmd_resolve(cli.config.as_ref(), &directory, ignore_assertion, json),
        Command::Hook { event, args } => cmd_hook(cli.config.as_ref(), &event, &args),
        Command::Check {
            event,
            directory,
            tag,
            pr_head,
            pr_base,
            pr_number,
        } => cmd_check(
            cli.config.as_ref(),
            &event,
            &directory,
            tag.as_deref(),
            pr_head.as_deref(),
            pr_base.as_deref(),
            pr_number.as_deref(),
        ),
        Command::Push { args } => cmd_push(cli.config.as_ref(), &args),
        Command::Records { command } => cmd_records(cli.config.as_ref(), command),
        Command::Checkers { json } => cmd_checkers(cli.config.as_ref(), json),
        Command::Auth { command } => cmd_auth(cli.config.as_ref(), command),
        Command::Unlock { ttl } => cmd_unlock(ttl),
        Command::Lock => cmd_lock(),
        Command::Status { json } => cmd_status(json),
        Command::Config { command } => cmd_config(cli.config.as_ref(), command),
        Command::Objection { command } => cmd_objection(command),
        Command::Install => cmd_install(),
        Command::Api {
            path,
            method,
            fields,
            raw_fields,
            headers,
            input,
            jq,
            repo,
            identity,
            follow,
            silent,
        } => cmd_api(
            cli.config.as_ref(),
            path,
            method,
            fields,
            raw_fields,
            headers,
            input,
            jq,
            repo,
            identity,
            follow,
            silent,
        ),
        Command::Pr { command, repo } => cmd_pr(cli.config.as_ref(), command, repo),
        Command::Ssh { args } => cmd_ssh(cli.config.as_ref(), &args),
        Command::Sign { args } => cmd_sign(cli.config.as_ref(), &args),
        Command::SigningKey { account, repo } => {
            cmd_signing_key(cli.config.as_ref(), account, repo)
        }
        Command::Issue { command, repo } => cmd_issue(cli.config.as_ref(), command, repo),
        Command::Repo { command } => cmd_repo(cli.config.as_ref(), command),
        Command::Release { command, repo } => cmd_release(cli.config.as_ref(), command, repo),
        Command::Run { command, repo } => cmd_run(cli.config.as_ref(), command, repo),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            // Configuration or environment failure. A gate that cannot decide
            // must not look like a gate that passed.
            eprintln!("gitvault: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn cmd_resolve(
    config: Option<&PathBuf>,
    directory: &Path,
    ignore_assertion: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let repo = git::Repo::discover(directory)?;
    let outcome = identity::resolve(&cfg, &repo, ignore_assertion)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&outcome.to_json())?);
    } else {
        println!("repository : {}", repo.root.display());
        println!(
            "remote     : {}",
            repo.remote_display().unwrap_or("(none)".to_string())
        );
        println!(
            "owner      : {}",
            repo.owner().unwrap_or_else(|| "(unparsed)".into())
        );
        println!("identity   : {}", outcome.identity);
        println!(
            "account    : {}",
            outcome.account.as_deref().unwrap_or("(none)")
        );
        println!(
            "expected   : {}",
            outcome.expected_email.as_deref().unwrap_or("(none)")
        );
        println!(
            "git actual : {}",
            outcome.actual_email.as_deref().unwrap_or("(unset)")
        );
        println!("decided by : {}", outcome.reason);
        if let Some(c) = &outcome.conflict {
            println!("\n\x1b[31mconflict   : {c}\x1b[0m");
        }
    }

    // A declared conflict is a failure even outside a hook, so `gitvault resolve`
    // is usable as a plain health check.
    if outcome.conflict.is_some() {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_checkers(config: Option<&PathBuf>, json: bool) -> anyhow::Result<ExitCode> {
    // The checker set belongs to Probator; the signed GitVault policy only
    // authorizes the engine. Show the former and report the latter's state.
    let (cfg, cfg_path, _) = config::Config::load_unverified(config)?;
    let (_policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    if let configsig::SigState::Invalid(reason) = policy_sig {
        eprintln!("warning: audit policy is uncertified - {reason}");
    }
    let bin = probator::engine().map_err(anyhow::Error::msg)?;
    let (mut command, scratch) = probator::command(&bin, None)?;
    command.arg("inspect");
    if json {
        command.arg("--json");
    }
    let output = command.output().with_context(|| {
        format!(
            "cannot run {} - Probator is the audit engine and must be installed",
            bin.display()
        )
    })?;
    if let Some(share) = &scratch {
        share
            .reassert()
            .context("the scratch root moved during the inspect run")?;
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "probator inspect failed ({}): {}",
            output.status,
            stderr.trim()
        );
    }
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(ExitCode::SUCCESS)
}

/// Build the run context shared by `hook` and `check`.
fn context_for(
    cfg: &config::Config,
    event: &str,
    directory: &Path,
    release_tag: Option<String>,
    hook_args: &[String],
    stdin_override: Option<String>,
) -> anyhow::Result<checkers::Context> {
    // Both `hook` and `check` take the event from an argument. An unknown
    // spelling would match no gate and reach no engine, so the report would be
    // an empty pass - a typo at a publication boundary must refuse instead.
    // `working-tree` is part of the accepted vocabulary.
    config::Event::parse(event)?;
    let repo = git::Repo::discover(directory)?;
    let outcome = identity::resolve(cfg, &repo, false)?;

    // git hands pre-push its refs on stdin:
    //   <local ref> <local sha> <remote ref> <remote sha>
    // Outside a hook nobody supplies them: a terminal would only block on
    // input nobody intends to type, and an empty list reads as "nothing to
    // review" - a vacuous pass at a publication boundary. `check` then
    // synthesizes the refs a push of this checkout would carry, which is also
    // what a scheduled resume of unfinished reviews needs to drive the gate.
    // An explicit override (`gitvault push` derives its lines from argv, not
    // a pipe) skips the read entirely.
    let stdin = if let Some(lines) = stdin_override {
        Some(lines)
    } else if event == "pre-push" {
        let mut buf = String::new();
        if !std::io::stdin().is_terminal() {
            std::io::stdin().read_to_string(&mut buf)?;
        }
        if buf.trim().is_empty() {
            Some(outgoing_push_stdin(&repo))
        } else {
            Some(buf)
        }
    } else {
        None
    };

    // A release is reviewed at the commit its tag points at; a tag that is not
    // in this checkout cannot be reviewed from here, and saying so beats
    // reviewing nothing.
    let release_commit = match &release_tag {
        Some(tag) => Some(repo.resolve_commit(tag).map_err(|_| {
            anyhow::anyhow!(
                "release tag '{tag}' is not in this checkout; run this from the tagged working tree"
            )
        })?),
        None => None,
    };

    // The remote a push targets: the hook passes it on argv; `check` falls
    // back to the checkout's first configured remote, the usual case.
    let push_remote = if event == "pre-push" {
        hook_args.first().cloned().or_else(|| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&repo.root)
                .args(["remote"])
                .output()
                .ok()
                .and_then(|out| {
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .next()
                        .map(str::to_string)
                })
        })
    } else {
        None
    };

    Ok(checkers::Context {
        event: event.to_string(),
        repo_root: repo.root.clone(),
        repo_slug: repo.slug(),
        identity: outcome.identity.clone(),
        account: outcome.account.clone(),
        via_default: outcome.via_default,
        expected_email: outcome.expected_email.clone(),
        actual_email: outcome.actual_email.clone(),
        stdin,
        push_remote,
        pr_base: None,
        pr_base_sha: None,
        pr_head: None,
        pr_number: None,
        release_tag,
        release_commit,
        release_assets: Vec::new(),
        inherited_fds: Vec::new(),
        commit_message_file: matches!(event, "commit-msg" | "prepare-commit-msg")
            .then(|| hook_args.first().map(PathBuf::from))
            .flatten(),
        commit_message_source: matches!(event, "commit-msg" | "prepare-commit-msg")
            .then(|| hook_args.get(1).cloned())
            .flatten(),
    })
}

/// The stdin a `git push` of this checkout's outgoing branches would carry:
/// `<local ref> <local sha> <remote ref> <remote sha>` per line. The upstream
/// tracking ref stands in for the remote's value - stale by at most a fetch,
/// and the gate refuses non-fast-forwards on its own evidence anyway. Heads
/// already published are filtered downstream exactly as a real push's would
/// be, so an up-to-date checkout still yields zero targets honestly.
fn outgoing_push_stdin(repo: &git::Repo) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo.root)
        .args([
            "for-each-ref",
            "--format=%(refname) %(objectname) %(upstream)",
            "refs/heads",
        ])
        .output();
    let mut buf = String::new();
    if let Ok(out) = out {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut fields = line.split_whitespace();
            let (Some(local_ref), Some(local_sha)) = (fields.next(), fields.next()) else {
                continue;
            };
            let remote_sha = fields
                .next()
                .filter(|s| !s.is_empty())
                .and_then(|upstream| repo.resolve_commit(upstream).ok())
                .unwrap_or_else(|| "0".repeat(40));
            buf.push_str(&format!(
                "{local_ref} {local_sha} {local_ref} {remote_sha}\n"
            ));
        }
    }
    buf
}

/// The audited push: audit the refs this command would move, then let git do
/// the moving. Git's own order is connect, advertise, hook, send - so a bare
/// `git push` spends the SSH credential before the pre-push hook exists.
/// Here evidence is produced first from the local mirror (stale by at most a
/// fetch, the same stand-in `check` uses) and the real push runs only on a
/// pass. Its hook then re-audits the refs git actually advertises: that run is
/// the authoritative verdict, and this pre-audit is advisory. The separation
/// keeps a failing audit from spending the credential while leaving git's
/// hook as the only authority on what is really being pushed. Probator may
/// reuse its sealed verdict for a head it has already judged, so the hook
/// does not always start a second model review.
fn cmd_push(config: Option<&PathBuf>, args: &[String]) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    let repo = git::Repo::discover(&PathBuf::from("."))?;
    let plan = push_plan(&repo, args)?;
    let mut ctx = context_for(
        &cfg,
        "pre-push",
        &PathBuf::from("."),
        None,
        &[],
        Some(plan.stdin),
    )?;
    ctx.push_remote = plan.remote.clone();
    let report = audit_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "push")?;
    if report.exit_code() != ExitCode::SUCCESS {
        return Ok(report.exit_code());
    }
    if plan.refs.is_empty() {
        // `git push` with no refspec would re-apply push.default and could
        // move a ref the plan never audited. Nothing selected is nothing to
        // send; report the no-op instead of handing git an empty command.
        eprintln!("gitvault: nothing to push - no ref moved and no git push started");
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!(
        "gitvault: audits passed; the `git push` that follows spends its own \
         SSH credential - no audit asked for it"
    );
    // Hand git the exact refspecs that were audited rather than the original
    // argument vector. `--all`, `--tags`, `--delete` and a default push have
    // already been expanded; options that could select another ref were
    // refused above. `--no-follow-tags` and `--no-recurse-submodules` override
    // the matching configuration, so no ref is added after the pre-audit.
    let mut command = std::process::Command::new("git");
    command
        .arg("-C")
        .arg(&ctx.repo_root)
        .arg("push")
        .args(&plan.args)
        .arg("--")
        .arg(plan.remote.as_deref().unwrap_or("origin"));
    for reference in &plan.refs {
        command.arg(reference.git_refspec());
    }
    let status = command
        .stdin(std::process::Stdio::inherit())
        .status()
        .context("failed to run git push")?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

/// A single ref the audited push will move. `gitvault push` hands git these
/// exact refspecs, so the set of audited lines and the set of refs git may
/// update are the same set, not two independently-parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedRef {
    local_ref: String,
    local_sha: String,
    remote_ref: String,
    remote_sha: String,
    delete: bool,
    force: bool,
}

impl PlannedRef {
    /// The `<local ref> <local sha> <remote ref> <remote sha>` line the
    /// pre-push hook would receive.
    fn audit_line(&self) -> String {
        if self.delete {
            format!(
                "(delete) {} {} {}",
                zero_sha(),
                self.remote_ref,
                self.remote_sha
            )
        } else {
            format!(
                "{} {} {} {}",
                self.local_ref, self.local_sha, self.remote_ref, self.remote_sha
            )
        }
    }

    /// The refspec handed to git. A deletion is `:<dst>`; a forced update
    /// keeps its leading `+`.
    fn git_refspec(&self) -> String {
        if self.delete {
            format!(":{}", self.remote_ref)
        } else if self.force {
            format!("+{}:{}", self.local_ref, self.remote_ref)
        } else if self.local_ref == self.remote_ref {
            self.local_ref.clone()
        } else {
            format!("{}:{}", self.local_ref, self.remote_ref)
        }
    }
}

/// What `cmd_push` audits before handing the push to git.
#[derive(Debug)]
struct PushPlan {
    /// The remote the refspecs target, as git would resolve it from the
    /// arguments (or the branch's configured push remote).
    remote: Option<String>,
    /// Every ref the command will move, already resolved against the local
    /// mirror. These are handed to git as explicit refspecs.
    refs: Vec<PlannedRef>,
    /// Non-ref-selection options that may pass through (`--force`, `--atomic`,
    /// `--dry-run`, ...). Ref selection and hook-skipping options never do.
    args: Vec<String>,
    /// The same refs rendered as the `<local ref> <local sha> <remote ref>
    /// <remote sha>` lines the hook would receive.
    stdin: String,
}

/// The push-argument shape the plan needs: which positional words are the
/// remote and the refspecs, which scope flags change what is sent, and which
/// options are safe to pass through unchanged.
#[derive(Default)]
struct PushArgs {
    remote: Option<String>,
    refspecs: Vec<String>,
    all: bool,
    mirror: bool,
    tags: bool,
    delete: bool,
    /// `--no-verify` (or a git-accepted abbreviation): it would tell the real
    /// `git push` to skip the pre-push hook, the authoritative audit of the
    /// refs git actually advertises.
    no_verify: bool,
    /// `--stdin`: the ref list would arrive on stdin, so it cannot be
    /// enumerated and audited before git consumes it.
    read_stdin: bool,
    /// `--follow-tags`: git would add annotated tags it selects after the
    /// pre-audit has already run.
    follow_tags: bool,
    /// `--prune`: git would delete remote refs this checkout has no local
    /// view of, so the pre-audit cannot name what the push removes.
    prune: bool,
    /// `--repo` supplied the remote; every positional word is then a
    /// refspec, not a remote name.
    repo_option: bool,
    /// A parameterised ref selection (`--branches=<pattern>`) or a transport
    /// that can publish submodule refs: not modelled by the pre-audit.
    unmodelled: Option<String>,
    /// Options that select neither refs nor the hook, such as `--force`,
    /// `--atomic` and `--dry-run`; forwarded to the reconstructed push.
    pass_through: Vec<String>,
}

/// Whether `arg` names `long`, or is an unambiguous prefix of it. git's
/// parse-options accepts enough of a long option to be unique (`--no-v`,
/// `--std`), so matching only the full spelling would leave a bypass.
fn is_long_option(arg: &str, long: &str, shortest: usize) -> bool {
    let name = arg.split_once('=').map(|(name, _)| name).unwrap_or(arg);
    name.len() >= shortest && long.starts_with(name)
}

/// The value of a push option that takes one, from `--flag=value` or the next
/// token. A next token beginning with `-` is not silently consumed as a value:
/// it would hide a following option behind a positional ref.
fn push_option_value(
    args: &[String],
    i: &mut usize,
    inline: Option<&str>,
    allow_hyphen: bool,
) -> Option<String> {
    if let Some(value) = inline {
        return Some(value.to_string());
    }
    let value = args.get(*i + 1)?;
    if value.starts_with('-') && !allow_hyphen {
        return None;
    }
    *i += 1;
    Some(value.clone())
}

fn parse_push_args(args: &[String]) -> PushArgs {
    let mut parsed = PushArgs::default();
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    let mut bare = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if bare {
            positional.push(arg);
            i += 1;
            continue;
        }
        if arg == "--" {
            bare = true;
            i += 1;
            continue;
        }
        let (name, inline_value) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (arg, None),
        };
        match name {
            "--all" => parsed.all = true,
            "--no-all" => parsed.all = false,
            "--branches" if inline_value.is_none() => parsed.all = true,
            "--no-branches" => parsed.all = false,
            "--mirror" => parsed.mirror = true,
            "--no-mirror" => parsed.mirror = false,
            "--tags" => parsed.tags = true,
            "--no-tags" => parsed.tags = false,
            "-d" | "--delete" => parsed.delete = true,
            "--no-delete" => parsed.delete = false,
            "-o" | "--push-option" => {
                if let Some(value) = push_option_value(args, &mut i, inline_value, true) {
                    parsed.pass_through.push(name.to_string());
                    parsed.pass_through.push(value);
                } else {
                    parsed.unmodelled = Some(format!("{name} has no value"));
                }
            }
            "--repo" => match push_option_value(args, &mut i, inline_value, false) {
                Some(value) if !value.is_empty() => {
                    parsed.remote = Some(value);
                    parsed.repo_option = true;
                }
                _ => parsed.unmodelled = Some("--repo has no value".to_string()),
            },
            "--exec" | "--receive-pack" => {
                if let Some(value) = push_option_value(args, &mut i, inline_value, false) {
                    parsed.pass_through.push(name.to_string());
                    parsed.pass_through.push(value);
                } else {
                    parsed.unmodelled = Some(format!("{name} has no value"));
                }
            }
            _ if is_long_option(arg, "--no-verify", 6) => parsed.no_verify = true,
            _ if is_long_option(arg, "--stdin", 5) => parsed.read_stdin = true,
            _ if is_long_option(arg, "--follow-tags", 7) => parsed.follow_tags = true,
            // `--prune` deletes remote refs this checkout cannot enumerate
            // from its mirror; the pre-audit must see every ref a push moves.
            _ if is_long_option(arg, "--prune", 6) => parsed.prune = true,
            _ if name == "--branches" => {
                parsed.unmodelled =
                    Some("--branches selects refs the pre-audit cannot enumerate".to_string());
            }
            _ if name == "--recurse-submodules" => {
                parsed.unmodelled =
                    Some("--recurse-submodules can publish submodule refs".to_string());
            }
            // Options that only affect transport or reporting, never the set
            // of refs or the hook. Each is forwarded verbatim.
            _ if matches!(
                name,
                "-f" | "--force"
                    | "-u"
                    | "--set-upstream"
                    | "--atomic"
                    | "--no-atomic"
                    | "--signed"
                    | "--no-signed"
                    | "-n"
                    | "--dry-run"
                    | "-v"
                    | "--verbose"
                    | "-q"
                    | "--quiet"
                    | "--progress"
                    | "--no-progress"
                    | "--no-verbose"
                    | "--no-quiet"
                    | "--no-dry-run"
                    | "--no-porcelain"
                    | "--no-set-upstream"
                    | "--no-force"
                    | "--no-force-with-lease"
                    | "--no-force-if-includes"
                    | "--porcelain"
                    | "--thin"
                    | "--no-thin"
                    | "--ipv4"
                    | "-4"
                    | "--ipv6"
                    | "-6"
                    | "--no-prune"
                    | "--verify"
                    | "--no-follow-tags"
                    | "--no-recurse-submodules"
            ) =>
            {
                parsed.pass_through.push(arg.to_string());
            }
            _ if is_long_option(arg, "--force-with-lease", 8)
                || is_long_option(arg, "--force-if-includes", 7) =>
            {
                parsed.pass_through.push(arg.to_string());
            }
            _ if arg.starts_with('-') => {
                if parsed.unmodelled.is_none() {
                    parsed.unmodelled = Some(format!(
                        "{arg} is not modelled by the pre-audit; push explicit refspecs instead"
                    ));
                }
            }
            _ => positional.push(arg),
        }
        i += 1;
    }
    if parsed.repo_option {
        parsed.refspecs = positional.iter().map(|s| s.to_string()).collect();
    } else {
        parsed.remote = positional.first().map(|s| s.to_string()).or(parsed.remote);
        parsed.refspecs = positional.iter().skip(1).map(|s| s.to_string()).collect();
    }
    parsed
}

impl PushArgs {
    /// Ref-selection options the pre-audit cannot model. Refusing them keeps
    /// the wrapper's promise: every ref git may publish has been judged before
    /// the transport is touched. `--no-verify` is worse still - it skips the
    /// real hook's re-check of the advertised refs entirely.
    fn unmodelled(&self) -> Option<&str> {
        if self.no_verify {
            Some("--no-verify would skip the pre-push audit that re-checks the advertised refs")
        } else if self.read_stdin {
            Some("--stdin keeps the ref list off the pre-audit's command line")
        } else if self.follow_tags {
            Some("--follow-tags lets git add tags after the pre-audit has run")
        } else if self.prune {
            // Prune deletes remote refs whose local counterpart is gone; the
            // pre-audit has no local name for them to judge or carry.
            Some("--prune would delete refs the local mirror cannot enumerate")
        } else if self.mirror {
            // A mirror can delete remote refs GitVault has no local view of;
            // the pre-audit cannot enumerate the whole target namespace.
            Some("--mirror would move refs the local mirror does not describe")
        } else {
            self.unmodelled.as_deref()
        }
    }
}

fn git_config(root: &Path, key: &str) -> Option<String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "--get", key])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Whether `remote` is configured to mirror the whole ref namespace. The
/// `--mirror` command-line flag is refused by the parser, but
/// `remote.<name>.mirror=true` gives git the same behaviour, and
/// `--no-mirror` does not override it - a mirrored push would publish refs
/// the plan never enumerated. `--get` drops a valueless key (git still treats
/// it as true), so the boolean is read with `--bool`, and an unreadable or
/// invalid value refuses rather than being mistaken for "not a mirror".
fn remote_mirrors(repo: &git::Repo, remote: &str) -> bool {
    let key = format!("remote.{remote}.mirror");
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo.root)
        .args(["config", "--bool", "--get", &key])
        .output();
    match output {
        Ok(out) => match out.status.code() {
            // The key is absent: not a mirror.
            Some(1) => false,
            Some(0) => String::from_utf8_lossy(&out.stdout).trim() == "true",
            // Bad value or another git failure: a configuration this plan
            // cannot read is not a remote it will push through.
            _ => true,
        },
        Err(_) => true,
    }
}

/// `(refname, objectname)` for every ref under `prefix` - heads or tags.
fn refs_under(repo: &git::Repo, prefix: &str) -> Vec<(String, String)> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(&repo.root)
        .args(["for-each-ref", "--format=%(refname) %(objectname)", prefix])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    match (fields.next(), fields.next()) {
                        (Some(name), Some(sha)) => Some((name.to_string(), sha.to_string())),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn zero_sha() -> String {
    "0".repeat(40)
}

/// The remote's position for `remote_ref`, read from this checkout's mirror.
/// Only branch destinations live under `refs/remotes`; tags and other
/// namespaces get the zeros a real first push would carry.
fn mirror_sha(repo: &git::Repo, remote: Option<&str>, remote_ref: &str) -> String {
    let Some(short) = remote_ref.strip_prefix("refs/heads/") else {
        return zero_sha();
    };
    remote
        .and_then(|name| {
            repo.resolve_commit(&format!("refs/remotes/{name}/{short}"))
                .ok()
        })
        .unwrap_or_else(zero_sha)
}

/// The heads the remote advertises right now, as `(refname, oid)`.
///
/// `push.default=matching` is defined by the remote's refs, not by this
/// checkout's mirror: a stale mirror would make the wrapper hand git refspecs
/// a real `git push` would not have selected (or omit ones it would). The
/// advertised set is read read-only before the audit, which is a credential
/// use but not a publication; a failed or unreadable answer refuses instead
/// of falling back to the mirror.
fn advertised_heads(repo: &git::Repo, remote: &str) -> anyhow::Result<Vec<(String, String)>> {
    eprintln!(
        "gitvault: reading {remote}'s advertised heads so push.default=matching selects \
         what git would send (a read-only credential use before its report)"
    );
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo.root)
        .args(["ls-remote", "--heads", "--", remote])
        .output()
        .context("failed to run git ls-remote")?;
    anyhow::ensure!(
        output.status.success(),
        "cannot read {remote}'s advertised heads; refusing push.default=matching rather \
         than selecting from a stale local mirror - pass explicit refspecs"
    );
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (oid, name) = line.split_once('\t')?;
            let name = name.trim();
            name.starts_with("refs/heads/")
                .then(|| (name.to_string(), oid.trim().to_string()))
        })
        .collect())
}

/// The ref name a bare destination word normalizes to, mirroring git's own
/// expansion: a tag source keeps `refs/tags/`, everything else is a branch.
fn normalize_dst(dst: &str, tag_source: bool) -> String {
    if dst.starts_with("refs/") {
        dst.to_string()
    } else if tag_source {
        format!("refs/tags/{dst}")
    } else {
        format!("refs/heads/{dst}")
    }
}

/// Resolve a refspec source to the `(local ref, local sha)` pair the hook
/// would report. Branches and tags resolve under their namespaces first so
/// the line names the ref, not a raw revision expression.
fn resolve_push_src(repo: &git::Repo, src: &str) -> anyhow::Result<(String, String)> {
    for candidate in [
        format!("refs/heads/{src}"),
        format!("refs/tags/{src}"),
        src.to_string(),
    ] {
        if let Ok(sha) = repo.resolve_commit(&candidate) {
            let local_ref = if candidate.starts_with("refs/") {
                candidate
            } else {
                src.to_string()
            };
            return Ok((local_ref, sha));
        }
    }
    anyhow::bail!("push source '{src}' does not resolve here - git would refuse it too")
}

/// The remote ref a deletion names. A plain name is resolved against the local
/// tag and branch namespaces, and a name that exists in both is refused: git's
/// short-name expansion would otherwise pick one, while the audit line and the
/// refspec handed to git could name different refs. A name that exists in
/// neither is refused too - the operator must spell the full remote ref rather
/// than have GitVault guess at a namespace for a ref this checkout cannot see.
fn deletion_ref(repo: &git::Repo, name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a deletion names no ref");
    if name.starts_with("refs/") {
        return Ok(name.to_string());
    }
    let branch = format!("refs/heads/{name}");
    let tag = format!("refs/tags/{name}");
    let has_branch = repo.resolve_commit(&branch).is_ok();
    let has_tag = repo.resolve_commit(&tag).is_ok();
    match (has_branch, has_tag) {
        (true, true) => anyhow::bail!(
            "deletion '{name}' is ambiguous: both {branch} and {tag} exist; name the \
             full ref so the audit line and git delete the same one"
        ),
        (true, false) => Ok(branch),
        (false, true) => Ok(tag),
        (false, false) => anyhow::bail!(
            "deletion '{name}' matches no local branch or tag; name the full remote \
             ref (refs/heads/{name} or refs/tags/{name})"
        ),
    }
}

/// One refspec word resolved into the ref the hook and git will both see.
/// `:dst` and `--delete` names are deletions; `+src[:dst]` keeps its forced
/// update; `src[:dst]` maps the resolved source onto the destination's mirror
/// position.
fn planned_ref(
    repo: &git::Repo,
    spec: &str,
    remote: Option<&str>,
    delete: bool,
) -> anyhow::Result<PlannedRef> {
    let (force, spec) = match spec.strip_prefix('+') {
        Some(spec) => (true, spec),
        None => (false, spec),
    };
    if let Some(dst) = spec.strip_prefix(':') {
        let remote_ref = deletion_ref(repo, dst)?;
        return Ok(PlannedRef {
            local_ref: String::new(),
            local_sha: zero_sha(),
            remote_ref: remote_ref.clone(),
            remote_sha: mirror_sha(repo, remote, &remote_ref),
            delete: true,
            force: false,
        });
    }
    let (src, dst) = match spec.split_once(':') {
        Some((src, dst)) => (src, dst),
        // No destination: the source name is the destination, except for
        // `HEAD`, which git resolves to the current branch's name.
        None => (spec, ""),
    };
    if delete {
        // `push --delete origin a b` lists plain names, not `:name` refspecs.
        let remote_ref = deletion_ref(repo, src)?;
        return Ok(PlannedRef {
            local_ref: String::new(),
            local_sha: zero_sha(),
            remote_ref: remote_ref.clone(),
            remote_sha: mirror_sha(repo, remote, &remote_ref),
            delete: true,
            force: false,
        });
    }
    let (local_ref, local_sha) = resolve_push_src(repo, src)?;
    // `git push origin HEAD` publishes the current branch under its own name.
    // Treating HEAD as a literal branch name would create refs/heads/HEAD and
    // push to a ref the operator never asked for.
    let remote_ref = if dst.is_empty() && src == "HEAD" {
        let branch = repo.current_branch().ok_or_else(|| {
            anyhow::anyhow!(
                "HEAD is detached and no destination was given - git would refuse too; \
                 name the remote branch explicitly (HEAD:<branch>)"
            )
        })?;
        format!("refs/heads/{branch}")
    } else {
        normalize_dst(
            if dst.is_empty() { src } else { dst },
            local_ref.starts_with("refs/tags/"),
        )
    };
    Ok(PlannedRef {
        local_ref,
        local_sha,
        remote_ref: remote_ref.clone(),
        remote_sha: mirror_sha(repo, remote, &remote_ref),
        delete: false,
        force,
    })
}

/// The remote a `git push` from this checkout would use, by git's own
/// precedence: the argument, `branch.<name>.pushRemote`,
/// `remote.pushDefault`, `branch.<name>.remote`, then `origin`. The same name
/// drives both the mirror lookup and the reconstructed push, so the two can
/// never target different repositories.
fn resolved_push_remote(repo: &git::Repo, explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    let branch = repo.current_branch();
    let branch_config = |key: &str| {
        branch
            .as_deref()
            .and_then(|branch| git_config(&repo.root, &format!("branch.{branch}.{key}")))
    };
    branch_config("pushRemote")
        .or_else(|| git_config(&repo.root, "remote.pushDefault"))
        .or_else(|| branch_config("remote"))
        .or_else(|| Some("origin".to_string()))
}

/// The upstream branch's local name, `refs/heads/` stripped: the destination
/// `simple` and `upstream` push to. `None` means the branch has no upstream.
fn upstream_branch(repo: &git::Repo, branch: &str) -> Option<String> {
    git_config(&repo.root, &format!("branch.{branch}.merge"))
        .and_then(|merge| merge.strip_prefix("refs/heads/").map(str::to_string))
}

/// The refs a bare `git push` of this checkout would carry, honoring
/// `push.default` exactly as git does:
///
/// * `simple` requires an upstream with the same name when it pushes to the
///   branch's pull remote; pushing to a different remote behaves as `current`;
/// * `upstream` requires an upstream on the branch's pull remote and pushes
///   to the upstream's name;
/// * `current` pushes the current branch to its own name;
/// * `matching` pushes only heads the target remote advertises; that set is
///   read read-only before the audit, not inferred from a stale local mirror.
///
/// A destination git would refuse is a refusal here too, never a synthesized
/// branch the operator did not ask for.
fn default_push_refs(repo: &git::Repo, remote: Option<&str>) -> anyhow::Result<Vec<PlannedRef>> {
    let mode = git_config(&repo.root, "push.default").unwrap_or_else(|| "simple".to_string());
    if mode == "nothing" {
        anyhow::bail!("push.default is 'nothing' and no refspec was given - git would refuse too");
    }
    if mode == "matching" {
        // Matching is defined by the remote's refs. Read the advertised set
        // read-only before the audit and use its object ids as the review
        // bases too; a stale local mirror is not authoritative for which refs
        // git would select.
        let remote = remote.unwrap_or("origin");
        let advertised = advertised_heads(repo, remote)?;
        let mut selected = Vec::new();
        for (name, sha) in refs_under(repo, "refs/heads") {
            let Some((_, remote_sha)) = advertised.iter().find(|(refname, _)| refname == &name)
            else {
                continue;
            };
            selected.push(PlannedRef {
                local_ref: name.clone(),
                local_sha: sha,
                remote_ref: name,
                remote_sha: remote_sha.clone(),
                delete: false,
                force: false,
            });
        }
        return Ok(selected);
    }
    let branch = repo.current_branch().ok_or_else(|| {
        anyhow::anyhow!("not on a branch and no refspec given - git would refuse this push too")
    })?;
    let local_ref = format!("refs/heads/{branch}");
    let local_sha = repo.resolve_commit(&local_ref)?;
    let upstream = upstream_branch(repo, &branch);
    // Git's default remote is `origin` even when `branch.<name>.remote` is
    // unset; `simple` treats a push there as the pull-remote case.
    let pull_remote = git_config(&repo.root, &format!("branch.{branch}.remote"))
        .unwrap_or_else(|| "origin".to_string());
    let pushing_elsewhere = remote.is_some_and(|remote| remote != pull_remote);
    let dst = match mode.as_str() {
        "current" => branch.clone(),
        "simple" => {
            if pushing_elsewhere {
                // Git switches to `current` semantics for another remote: no
                // upstream is required and the branch keeps its own name.
                branch.clone()
            } else {
                let Some(upstream) = upstream.as_deref() else {
                    anyhow::bail!(
                        "push.default is 'simple' and branch '{branch}' has no upstream branch - \
                         git would refuse too; pass an explicit refspec (or `-u`) instead"
                    );
                };
                if upstream != branch {
                    anyhow::bail!(
                        "push.default is 'simple' and the upstream branch '{upstream}' does not \
                         match '{branch}' - git would refuse too; pass an explicit refspec instead"
                    );
                }
                branch.clone()
            }
        }
        "upstream" => {
            let Some(upstream) = upstream.as_deref() else {
                anyhow::bail!(
                    "push.default is 'upstream' and branch '{branch}' has no upstream branch - \
                     git would refuse too; pass an explicit refspec instead"
                );
            };
            if !pushing_elsewhere {
                upstream.to_string()
            } else {
                anyhow::bail!(
                    "push.default is 'upstream' but the push remote is not the upstream of \
                     '{branch}' - git would refuse too; pass an explicit refspec instead"
                );
            }
        }
        other => {
            anyhow::bail!(
                "push.default is '{other}', which git does not accept - \
                 fix the configuration or pass an explicit refspec"
            )
        }
    };
    let remote_ref = format!("refs/heads/{dst}");
    Ok(vec![PlannedRef {
        local_ref,
        local_sha,
        remote_sha: mirror_sha(repo, remote, &remote_ref),
        remote_ref,
        delete: false,
        force: false,
    }])
}

/// Build the audit surface for `gitvault push`: the remote, the exact refs
/// git will be told to move, and the lines the pre-push hook would receive.
///
/// `--no-verify`, `--stdin`, `--follow-tags`, `--prune`, `--mirror`,
/// parameterised ref selection and any option the parser does not model are
/// refused: the plan must see every ref before the transport is touched. The
/// same `refs` vector is handed to git afterwards, so there is no second
/// argument parse that could select something the audit did not see.
fn push_plan(repo: &git::Repo, args: &[String]) -> anyhow::Result<PushPlan> {
    let parsed = parse_push_args(args);
    if let Some(why) = parsed.unmodelled() {
        anyhow::bail!(
            "gitvault push refuses this option: {why}\n  \
             push the refs explicitly (or use --tags) so the pre-audit sees every ref"
        );
    }
    if parsed.delete && (parsed.all || parsed.tags) {
        anyhow::bail!(
            "gitvault push refuses --delete with --all/--tags: name the refs to delete explicitly"
        );
    }
    if parsed.all && parsed.tags {
        anyhow::bail!("gitvault push refuses --all with --tags; git refuses that combination too");
    }
    // The remote git would push to, by its own precedence. The mirror lookup
    // and the reconstructed push both use this one name, so a configured
    // `pushRemote`/`remote.pushDefault` cannot make them disagree. A URL or
    // path here just misses every mirror, which reads as the honest "new refs"
    // zeros.
    let remote = resolved_push_remote(repo, parsed.remote.clone());
    if let Some(name) = remote.as_deref()
        && remote_mirrors(repo, name)
    {
        anyhow::bail!(
            "remote '{name}' sets remote.{name}.mirror=true, which would push the whole ref \
             namespace - GitVault cannot pre-audit that set; set the option to false or push \
             explicit refspecs to a non-mirror remote"
        );
    }
    // Git gives `remote.<name>.push` precedence over `push.default` when no
    // refspec or selector is on the command line. Those configured refspecs
    // can rename, force or delete refs, so following push.default instead
    // would audit (and publish) a different set than git would. Refuse the
    // bare push rather than guess; an explicit refspec or --all/--tags
    // bypasses the configured list, exactly as git does.
    let bare_push = !parsed.all && !parsed.tags && !parsed.delete && parsed.refspecs.is_empty();
    if bare_push
        && let Some(name) = remote.as_deref()
        && git_config(&repo.root, &format!("remote.{name}.push")).is_some()
    {
        anyhow::bail!(
            "remote '{name}' sets remote.{name}.push, whose configured refspecs GitVault \
             cannot pre-audit; push the refs explicitly (or use --all/--tags) so the \
             pre-audit sees every ref"
        );
    }
    let mut refs: Vec<PlannedRef> = Vec::new();
    if parsed.all {
        for (name, sha) in refs_under(repo, "refs/heads") {
            refs.push(PlannedRef {
                remote_sha: mirror_sha(repo, remote.as_deref(), &name),
                local_ref: name.clone(),
                local_sha: sha,
                remote_ref: name,
                delete: false,
                force: false,
            });
        }
    }
    if parsed.tags {
        for (name, sha) in refs_under(repo, "refs/tags") {
            refs.push(PlannedRef {
                local_ref: name.clone(),
                local_sha: sha,
                remote_sha: zero_sha(),
                remote_ref: name,
                delete: false,
                force: false,
            });
        }
    }
    for spec in &parsed.refspecs {
        refs.push(planned_ref(repo, spec, remote.as_deref(), parsed.delete)?);
    }
    // A bare push follows push.default. An explicit selector that matched
    // nothing (`--tags` with no tags, `matching` with no advertised head)
    // is a no-op, not an invitation to fall back to the current branch.
    let selected = parsed.all || parsed.tags || !parsed.refspecs.is_empty();
    if refs.is_empty() && !selected {
        if parsed.delete {
            anyhow::bail!("--delete without a ref name - git would refuse this push too");
        }
        refs = default_push_refs(repo, remote.as_deref())?;
    }
    refs.sort_by(|a, b| {
        (&a.remote_ref, &a.local_ref, a.delete).cmp(&(&b.remote_ref, &b.local_ref, b.delete))
    });
    refs.dedup_by(|a, b| {
        a.remote_ref == b.remote_ref && a.local_ref == b.local_ref && a.delete == b.delete
    });
    let mut stdin = refs
        .iter()
        .map(PlannedRef::audit_line)
        .collect::<Vec<_>>()
        .join("\n");
    if !stdin.is_empty() {
        stdin.push('\n');
    }
    let mut git_args = parsed.pass_through;
    // Override configuration that could add refs after the audit: follow-tags
    // and recursive submodule refs. `--prune` is refused above, `--mirror`
    // is refused above, and a mirror-configured remote is refused before the
    // plan is built; these close the command-line paths.
    for required in ["--no-follow-tags", "--no-recurse-submodules", "--no-prune"] {
        if !git_args.iter().any(|arg| arg == required) {
            git_args.push(required.to_string());
        }
    }
    Ok(PushPlan {
        remote,
        refs,
        args: git_args,
        stdin,
    })
}

/// Run the local interception gates and the delegated Probator audit, and
/// print the report BEFORE the routing signature is asked about. Audits first,
/// blessing after: the routing signature only gates the verdict, never the
/// audit.
///
/// `pre-push`, `pr` and `release` are publication boundaries unconditionally:
/// they spend credentials or put content on GitHub, so an uncertified routing
/// table refuses them only after the audit report is on screen. Local events
/// (`pre-commit`, the message hooks) never spend a credential and never reach
/// Probator, so they are not held hostage to a blessing. `working-tree` does
/// reach the engine, but it publishes nothing - it is an on-demand look at
/// the uncommitted tree - so it is not a publication boundary either.
fn audit_gate(
    cfg: &config::Config,
    cfg_sig: &configsig::SigState,
    policy: &config::Policy,
    policy_sig: &configsig::SigState,
    ctx: &checkers::Context,
    operation: &str,
) -> anyhow::Result<checkers::Report> {
    let boundary = matches!(ctx.event.as_str(), "pre-push" | "pr" | "release");
    // The rows are not executed, but a signed row naming another executor
    // would still be a signed claim that some other program is the audit
    // engine. Only probator may appear; a stale gitvault-review row refuses
    // the boundary before the engine runs. Local events never reach the
    // engine, so their policy rows are not consulted.
    if crate::probator::applies(&ctx.event) {
        policy.admit_engine_rows()?;
    }
    // The policy file is the signed declaration that this machine trusts
    // Probator as its audit engine. An uncertified policy cannot authorize a
    // publication audit at all, so the refusal comes before the engine runs.
    if let configsig::SigState::Invalid(reason) = policy_sig
        && boundary
    {
        anyhow::bail!(
            "refusing to run an uncertified audit policy: {reason}\n  \
             the policy authorizes Probator as the audit engine\n  \
             certify it: gitvault config sign"
        );
    }
    let report = checkers::audit(cfg, ctx, cfg_sig, policy_sig)?;
    report.print(&ctx.event);
    if let configsig::SigState::Invalid(reason) = cfg_sig
        && boundary
    {
        anyhow::bail!(
            "audits complete, but the routing table they ran against is uncertified: {reason}\n  \
             certify it: gitvault config sign   (then rerun this {operation})"
        );
    }
    Ok(report)
}

/// The publication gate every GitHub-reaching operation must pass: run the
/// audit, print the verdicts, and fail closed. One copy so a new publish path
/// cannot quietly forget it.
fn run_publication_gate(
    cfg: &config::Config,
    cfg_sig: &configsig::SigState,
    policy: &config::Policy,
    policy_sig: &configsig::SigState,
    ctx: &checkers::Context,
    operation: &str,
) -> anyhow::Result<()> {
    let report = audit_gate(cfg, cfg_sig, policy, policy_sig, ctx, operation)?;
    anyhow::ensure!(
        report.exit_code() == ExitCode::SUCCESS,
        "a blocking gate refused this {operation}; nothing was sent to GitHub"
    );
    Ok(())
}

fn cmd_hook(config: Option<&PathBuf>, event: &str, args: &[String]) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    // git runs hooks with cwd set to the top level of the working tree, so "."
    // resolves correctly and no directory argument is needed from the hook shim.
    // For pre-push, argv[0] is the remote the push targets.
    let ctx = context_for(&cfg, event, &PathBuf::from("."), None, args, None)?;
    let report = audit_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "operation")?;
    Ok(report.exit_code())
}

/// Fetch one remote ref into a process-private ref and return the commit it
/// resolved to.
///
/// The destination is unique per invocation, and it is deleted before this
/// function returns. `--no-write-fetch-head` leaves the shared `FETCH_HEAD`
/// untouched, so no concurrent or later fetch can change the object id this
/// review binds.
fn fetch_remote_ref(
    repo_root: &std::path::Path,
    remote: &str,
    source: &str,
    tag: &str,
) -> anyhow::Result<String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let destination = format!(
        "refs/gitvault/fetch/{}-{tag}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let result = (|| -> anyhow::Result<String> {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args([
                "fetch",
                "--no-tags",
                "--quiet",
                // Do not touch the shared FETCH_HEAD; the private ref is the
                // only handle this run reads back.
                "--no-write-fetch-head",
                "--",
                remote,
                &format!("+{source}:{destination}"),
            ])
            .status()
            .context("failed to run git fetch")?;
        anyhow::ensure!(
            status.success(),
            "cannot fetch {source} from {remote} for review"
        );
        git::commit_at(repo_root, &destination).ok_or_else(|| {
            anyhow::anyhow!("fetched {source} from {remote} but {destination} did not resolve")
        })
    })();
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["update-ref", "-d", &destination])
        .status();
    result
}

/// The remote whose URL names `slug`, never a different remote's.
fn remote_for_slug(repo_root: &std::path::Path, slug: &str) -> Option<String> {
    remote_names(repo_root).into_iter().find(|remote| {
        remote_slug(repo_root, remote).is_some_and(|candidate| candidate.eq_ignore_ascii_case(slug))
    })
}

/// Fetch `pull/<n>/head` and return the commit it resolved to.
///
/// Called at the gate boundary, before the audit runs: private content crosses
/// the transport here, and doing the fetch inside the audit would bury the
/// prompt inside the run where it reads as the audit demanding the vault. The
/// resolved sha is what the engine reviews and what the merge request then
/// names as its precondition.
fn fetch_pr_head(repo_root: &std::path::Path, number: u64, slug: &str) -> anyhow::Result<String> {
    eprintln!(
        "gitvault: fetching pull/{number}/head so the audit has the request's head \
         (a read-only credential use before its report)"
    );
    // The ref lives in the repository the request targets. `origin` is only
    // right when the checkout IS that repository: a fork checkout's own
    // `pull/<n>` namespace belongs to unrelated requests and would shadow the
    // real head with an unrelated commit. Resolve the remote whose slug is
    // the target.
    let remote = remote_for_slug(repo_root, slug).ok_or_else(|| {
        anyhow::anyhow!(
            "no remote in this checkout points at {slug}; \
             add it before reviewing that repository's pull requests"
        )
    })?;
    fetch_remote_ref(
        repo_root,
        &remote,
        &format!("refs/pull/{number}/head"),
        "pr-head",
    )
}

/// Fetch the proposed head branch from the remote that owns it and return the
/// commit the audit must review. A branch that cannot be resolved refuses the
/// boundary: auditing a local tracking ref after the remote has moved would
/// bless content the request does not propose. Called once before the audit
/// and once immediately before the POST, so the same resolved value can be
/// compared across the review.
fn fetch_pr_branch_head(
    repo_root: &std::path::Path,
    head: &str,
    slug: &str,
) -> anyhow::Result<String> {
    let (owner, branch) = match head.split_once(':') {
        Some((owner, branch)) => (Some(owner.trim()), branch.trim()),
        None => (None, head.trim()),
    };
    anyhow::ensure!(!branch.is_empty(), "the pull request head branch is empty");
    eprintln!(
        "gitvault: fetching {head} from its remote (a read-only credential use; \
         the audit binds the resolved commit)"
    );
    let remote = match owner {
        Some(owner) => {
            // `owner:branch` on the target's own owner means the target
            // repository; prefer its exact remote over a different repository
            // that happens to share the owner.
            let target_owner = slug.split('/').next().unwrap_or_default();
            let exact = if target_owner.eq_ignore_ascii_case(owner) {
                remote_for_slug(repo_root, slug)
            } else {
                None
            };
            exact.or_else(|| {
                remote_names(repo_root).into_iter().find(|remote| {
                    remote_slug(repo_root, remote).is_some_and(|candidate| {
                        candidate
                            .split('/')
                            .next()
                            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(owner))
                    })
                })
            })
        }
        None => remote_for_slug(repo_root, slug),
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "no remote in this checkout points at {}; add it before opening a pull request \
             from that head",
            owner.unwrap_or(slug)
        )
    })?;
    fetch_remote_ref(
        repo_root,
        &remote,
        &format!("refs/heads/{branch}"),
        "pr-branch",
    )
}

/// The branch name the target repository understands: drop a leading remote
/// name, even when the branch itself contains slashes (`origin/release/1.0`
/// is the branch `release/1.0`, not a branch named `origin`).
fn branch_for_api(repo_root: &std::path::Path, base: &str) -> String {
    let base = base.strip_prefix("refs/heads/").unwrap_or(base);
    let Some((first, rest)) = base.split_once('/') else {
        return base.to_string();
    };
    if remote_names(repo_root).iter().any(|r| r == first) {
        return rest.to_string();
    }
    base.to_string()
}

/// A tracking ref temporarily pointed at another remote's commit for the
/// duration of an audit. Probator resolves a pull request's base through
/// `refs/remotes/origin/<branch>`; when the request targets a repository this
/// checkout does not name `origin` (a fork workflow), the target commit is
/// placed there for the audit and the previous ref is put back afterwards.
#[derive(Debug)]
struct BorrowedTrackingRef {
    repo_root: PathBuf,
    reference: String,
    previous: Option<String>,
}

impl Drop for BorrowedTrackingRef {
    fn drop(&mut self) {
        let mut command = std::process::Command::new("git");
        command.arg("-C").arg(&self.repo_root).arg("update-ref");
        match &self.previous {
            Some(sha) => {
                command.arg(&self.reference).arg(sha);
            }
            None => {
                command.arg("-d").arg(&self.reference);
            }
        }
        // A failed restore leaves a tracking ref pointing at the target
        // base; it is reported but cannot be allowed to mask the audit result.
        if let Ok(output) = command.output()
            && !output.status.success()
        {
            eprintln!(
                "gitvault: warning: could not restore {} after the audit",
                self.reference
            );
        }
    }
}

/// The remote's default branch, read from its symbolic `HEAD`. Used only when
/// a pull request omits `--base`, where the target's default is the base the
/// request will actually use.
fn remote_default_branch(repo_root: &std::path::Path, remote: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-remote", "--symref", "--", remote, "HEAD"])
        .output()
        .context("failed to run git ls-remote")?;
    anyhow::ensure!(
        output.status.success(),
        "cannot resolve {remote}'s default branch for the pull request base; \
         pass --base <branch>"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let Some((reference, name)) = line.split_once('\t') else {
            continue;
        };
        if name.trim() == "HEAD"
            && let Some(branch) = reference.trim().strip_prefix("ref: refs/heads/")
        {
            return Ok(branch.to_string());
        }
    }
    anyhow::bail!(
        "cannot resolve {remote}'s default branch for the pull request base; \
         pass --base <branch>"
    )
}

/// Resolve the pull request's target branch for the audit, against the remote
/// that owns the target repository.
///
/// Probator resolves a PR base through `refs/remotes/origin/<branch>`, so the
/// tracking ref must be refreshed from the target's remote at the gate
/// boundary: a stale local ref would review a base the request no longer has,
/// and a fork checkout's `origin` is not the target at all. The resolved
/// branch, the commit it points at and an optional guard that restores
/// `origin`'s ref after the audit are returned together, so the attribution
/// gate and the engine read the same base commit.
fn local_pr_base(
    repo_root: &std::path::Path,
    base: &str,
    slug: &str,
) -> anyhow::Result<(Option<String>, String, Option<BorrowedTrackingRef>)> {
    let target = remote_for_slug(repo_root, slug).ok_or_else(|| {
        anyhow::anyhow!(
            "no remote in this checkout points at {slug}; \
             add it before reviewing that repository's pull requests"
        )
    })?;
    let base = base.trim();
    let branch = if base.is_empty() {
        eprintln!(
            "gitvault: reading {target}'s default branch so the audit has the request's \
             base (a read-only credential use before its report)"
        );
        remote_default_branch(repo_root, &target)?
    } else {
        let branch = branch_for_api(repo_root, base);
        anyhow::ensure!(!branch.is_empty(), "the pull request base branch is empty");
        branch
    };
    let target_tracking = format!("refs/remotes/{target}/{branch}");
    eprintln!(
        "gitvault: fetching {target}/{branch} so the audit has the request's base \
         (a read-only credential use before its report)"
    );
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args([
            "fetch",
            "--no-tags",
            "--quiet",
            "--no-write-fetch-head",
            "--",
            &target,
            &format!("+refs/heads/{branch}:{target_tracking}"),
        ])
        .status()
        .context("failed to run git fetch")?;
    anyhow::ensure!(
        status.success(),
        "cannot resolve the pull request base '{base}' from {target}; \
         fetch {target}/{branch} first"
    );
    let fetched = git::commit_at(repo_root, &target_tracking).ok_or_else(|| {
        anyhow::anyhow!("fetched {target}/{branch} but {target_tracking} did not resolve")
    })?;
    if target == "origin" {
        // The fetch already updated the ref Probator reads.
        return Ok((Some(branch), fetched, None));
    }
    // The engine reads origin's namespace. Point it at the target's freshly
    // fetched commit for this audit only.
    let reference = format!("refs/remotes/origin/{branch}");
    let previous = git::commit_at(repo_root, &reference);
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["update-ref", &reference, &fetched])
        .status()
        .context("failed to run git update-ref")?;
    anyhow::ensure!(
        status.success(),
        "cannot stage {target}/{branch} under {reference} for the audit"
    );
    let guard = BorrowedTrackingRef {
        repo_root: repo_root.to_path_buf(),
        reference,
        previous,
    };
    Ok((Some(branch), fetched, Some(guard)))
}

/// The merge request's own target branch and current head, read at the gate
/// boundary. A merge must audit the commits the request actually proposes onto
/// its target, not whatever branch this checkout happens to have checked out.
fn pull_request_metadata(
    cfg: &config::Config,
    vault: &vault::Vault,
    slug: &str,
    number: u64,
) -> anyhow::Result<(String, String)> {
    let req = get(
        format!("/repos/{slug}/pulls/{number}"),
        slug.to_string(),
        None,
    );
    let body = api::run_value(cfg, vault, &req).with_context(|| {
        format!(
            "cannot read pull request #{number} metadata; the merge must audit the \
             request's own target base and head"
        )
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&body).context("pull request metadata is not JSON")?;
    let base = value
        .pointer("/base/ref")
        .and_then(serde_json::Value::as_str)
        .filter(|base| !base.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pull request #{number} metadata has no base branch"))?;
    let head = value
        .pointer("/head/sha")
        .and_then(serde_json::Value::as_str)
        .filter(|head| !head.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pull request #{number} metadata has no head commit"))?;
    Ok((base.to_string(), head.to_string()))
}

/// The `Owner/Repo` a push actually lands on: the named remote's URL parsed
/// for its slug, never a different remote's.
fn remote_slug(repo_root: &std::path::Path, remote: &str) -> Option<String> {
    // `remote.<name>.url` is the configured URL: a url.insteadOf rewrite
    // changes the transport, not the repository's identity, and must not
    // hide which repo a remote points at.
    let url = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["config", &format!("remote.{remote}.url")])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    url.and_then(|url| git::slug_from_remote(&url))
}

fn remote_names(repo_root: &std::path::Path) -> Vec<String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["remote"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn cmd_records(config: Option<&PathBuf>, command: RecordsCommand) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    match command {
        RecordsCommand::List { json } => {
            let records = records::list(&cfg)?;
            if json {
                let summaries: Vec<_> = records.iter().map(records::Record::summary).collect();
                println!("{}", serde_json::to_string_pretty(&summaries)?);
                return Ok(ExitCode::SUCCESS);
            }
            if records.is_empty() {
                println!("no runs recorded in {}", records::run_dir(&cfg).display());
                return Ok(ExitCode::SUCCESS);
            }
            for record in &records {
                let checkers: Vec<String> = record
                    .outcomes
                    .iter()
                    .map(|o| {
                        format!(
                            "{} {} ({:.1}s)",
                            o.name,
                            o.outcome,
                            o.duration_ms as f64 / 1000.0
                        )
                    })
                    .collect();
                println!(
                    "{}  {}  {}  {}  {}",
                    records::iso8601(record.created_at),
                    record.id,
                    record.event,
                    if record.repository.is_empty() {
                        "-"
                    } else {
                        &record.repository
                    },
                    if record.passed { "passed" } else { "REFUSED" }
                );
                for checker in checkers {
                    println!("    {checker}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        RecordsCommand::Show { id, json } => {
            let record = records::show(&cfg, &id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
                return Ok(ExitCode::SUCCESS);
            }
            println!("run {}  {}", record.id, records::iso8601(record.created_at));
            println!("event      : {}", record.event);
            println!("repository : {}", record.repository);
            println!("identity   : {}", record.identity);
            println!("duration   : {:.1}s", record.duration_ms as f64 / 1000.0);
            println!(
                "verdict    : {}",
                if record.passed { "passed" } else { "refused" }
            );
            for outcome in &record.outcomes {
                println!(
                    "\n[{}] {} — {} ({:.1}s)",
                    outcome.severity,
                    outcome.name,
                    outcome.outcome,
                    outcome.duration_ms as f64 / 1000.0
                );
                for line in outcome.stdout.lines().chain(outcome.stderr.lines()) {
                    if !line.trim().is_empty() {
                        println!("    {line}");
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        RecordsCommand::Verify => {
            let links = records::verify(&cfg);
            if links.is_empty() {
                println!("no runs recorded in {}", records::run_dir(&cfg).display());
                return Ok(ExitCode::SUCCESS);
            }
            let mut worst = records::Link::Sound;
            for (id, link) in &links {
                if *link != records::Link::Sound {
                    println!("{id}  {}", link.label());
                }
                match link {
                    records::Link::Broken => worst = records::Link::Broken,
                    records::Link::Gap if worst != records::Link::Broken => {
                        worst = records::Link::Gap;
                    }
                    _ => {}
                }
            }
            let sound = links
                .iter()
                .filter(|(_, l)| *l == records::Link::Sound)
                .count();
            println!(
                "{} of {} records verify sound{}",
                sound,
                links.len(),
                match worst {
                    records::Link::Broken => " — REWRITTEN RECORDS FOUND",
                    records::Link::Gap => " — gaps found (pruned predecessors or deleted runs)",
                    _ => "",
                }
            );
            // Only a rewrite is a hard failure: an operator pruning or an
            // interrupted upgrade produces gaps, which are reported, not
            // prosecuted.
            Ok(if worst == records::Link::Broken {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

fn cmd_check(
    config: Option<&PathBuf>,
    event: &str,
    directory: &Path,
    tag: Option<&str>,
    pr_head: Option<&str>,
    pr_base: Option<&str>,
    pr_number: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    // `check` is the proposal-facing command: even an event that does not
    // reach the engine must not present a stale gitvault-review row as an
    // accepted policy.
    policy.admit_engine_rows()?;
    let mut ctx = context_for(&cfg, event, directory, tag.map(str::to_string), &[], None)?;
    ctx.pr_head = pr_head.map(str::to_string);
    ctx.pr_base = pr_base.map(str::to_string);
    ctx.pr_number = pr_number.map(str::to_string);
    let report = audit_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "check")?;
    Ok(report.exit_code())
}

fn cmd_auth(config: Option<&PathBuf>, command: AuthCommand) -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    match command {
        AuthCommand::Init => auth::cmd_init(&vault)?,
        AuthCommand::Add { account } => auth::cmd_add(&vault, &account)?,
        AuthCommand::Remove {
            account,
            token,
            keys,
            all,
        } => {
            // Exactly one scope must be chosen. Guessing would risk discarding a
            // token the user cannot re-derive.
            let chosen = [token, keys, all].iter().filter(|x| **x).count();
            if chosen == 0 {
                anyhow::bail!(
                    "choose what to remove: --token, --keys or --all\n                       (an unscoped removal used to delete everything, which discarded a live token)"
                );
            }
            if chosen > 1 {
                anyhow::bail!("--token, --keys and --all are mutually exclusive");
            }
            let what = if all {
                auth::RemoveWhat::All
            } else if keys {
                auth::RemoveWhat::Keys
            } else {
                auth::RemoveWhat::Token
            };
            auth::cmd_remove(&vault, &account, what)?
        }
        AuthCommand::RemoveKey { account, signing } => {
            auth::cmd_remove_key(&vault, &account, signing)?
        }
        AuthCommand::List { json } => {
            let cfg = config::Config::load(config)?;
            auth::cmd_list(&vault, &cfg, json)?;
        }
        AuthCommand::ImportKey {
            account,
            file,
            signing,
        } => {
            // Read the passphrase separately from the key: a combined prompt would
            // put both on one line, and stdin is the only channel that keeps it out
            // of argv and shell history. A signing key has its own passphrase -
            // it may legitimately differ from the account's authentication key.
            let pass = if signing {
                read_optional_passphrase("signing key")?
            } else {
                read_optional_passphrase("key")?
            };
            auth::cmd_import_key(&vault, &account, &file, signing, pass)?
        }
        AuthCommand::Status { account, json } => {
            let cfg = config::Config::load(config)?;
            auth::cmd_status(&vault, &cfg, account.as_deref(), json)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ handlers

fn cmd_unlock(ttl: Option<u64>) -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    if !vault.exists() {
        anyhow::bail!("no vault yet; run: gitvault auth init");
    }
    unlock::ensure_open(
        &vault,
        "GitVault: confirm to open the credential vault",
        true,
        ttl,
    )?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_lock() -> anyhow::Result<ExitCode> {
    unlock::clear()?;
    println!("vault locked");
    Ok(ExitCode::SUCCESS)
}

fn cmd_status(json: bool) -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    let remaining = unlock::remaining(&vault);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault": vault.exists(),
                "unlocked": remaining > 0,
                "remaining_seconds": remaining,
            })
        );
    } else {
        println!(
            "vault     : {}",
            if vault.exists() { "present" } else { "absent" }
        );
        println!(
            "state     : {}",
            if remaining > 0 {
                format!("open, {remaining}s remaining")
            } else {
                "locked".to_string()
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_config(config: Option<&PathBuf>, command: ConfigCommand) -> anyhow::Result<ExitCode> {
    match command {
        ConfigCommand::Keygen => cmd_config_keygen(),
        ConfigCommand::Sign => cmd_config_sign(config),
        ConfigCommand::Verify => cmd_config_verify(config),
    }
}

/// Create the configuration signing key: the private half goes into the vault,
/// the public half becomes the verification anchor.
///
/// The unlock gate is what makes this a governance act rather than a file
/// write: minting the key that attests the routing table costs a human
/// confirmation, the same as releasing a credential does.
fn cmd_config_keygen() -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    unlock::ensure_open(
        &vault,
        "GitVault: confirm to create a configuration signing key",
        false,
        None,
    )?;
    let (private, anchor_line) = configsig::keygen()?;
    vault.set_config_key(&private)?;

    let anchor = configsig::anchor_path();
    if let Some(parent) = anchor.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&anchor, &anchor_line)
        .with_context(|| format!("cannot write {}", anchor.display()))?;

    println!("configuration signing key stored in the vault");
    println!("verification anchor written: {}", anchor.display());
    match configsig::anchor_state(&anchor) {
        configsig::Anchor::Anchored => println!("enforcement armed (anchor is root-owned)"),
        _ => println!(
            "enforcement is NOT armed yet: the anchor must be root-owned\n  \
             run `gitvault install`, or: sudo chown root:wheel {}",
            anchor.display()
        ),
    }
    Ok(ExitCode::SUCCESS)
}

/// Bless the current configuration: editing the file is free, loading it is not.
fn cmd_config_sign(config: Option<&PathBuf>) -> anyhow::Result<ExitCode> {
    let path = config.cloned().unwrap_or_else(config::Config::default_path);
    if !path.exists() {
        anyhow::bail!("nothing to sign at {}", path.display());
    }
    // Checker rows left in the routing table migrate out before signing, so
    // each file is certified under its own signature. The policy no longer
    // selects checkers - it authorizes the engine - but its signature still
    // gates the publication boundary.
    if let Some(policy_path) = config::Config::migrate_checkers(&path)? {
        println!("moved checker entries to {}", policy_path.display());
    }
    // Resolve the policy from the routing table itself, not from the
    // conventional sibling: `audit_policy` is signed into that table, and a
    // custom path must be the file this command actually certifies.
    let (cfg, _, _) = config::Config::load_unverified(Some(&path))?;
    let policy_path = config::Policy::resolve(&path, &cfg);
    if cfg.audit_policy.is_some() && !policy_path.exists() {
        anyhow::bail!(
            "the routing table declares an audit policy at {} but the file is absent\n  \
             restore it or amend and re-certify: gitvault config sign",
            policy_path.display()
        );
    }
    let vault = vault::Vault::open()?;
    unlock::ensure_open(
        &vault,
        "GitVault: confirm to bless the GitVault configuration",
        false,
        None,
    )?;
    let key = vault.config_key()?;
    let sig = configsig::sign(&path, &key)?;
    println!("signed {} -> {}", path.display(), sig.display());
    if policy_path.exists() {
        let sig = configsig::sign(&policy_path, &key)?;
        println!("signed {} -> {}", policy_path.display(), sig.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// Report the attestation state. Read-only: it may advise, never gate.
fn cmd_config_verify(config: Option<&PathBuf>) -> anyhow::Result<ExitCode> {
    let path = config.cloned().unwrap_or_else(config::Config::default_path);
    let (cfg, _, _) = config::Config::load_unverified(Some(&path))?;
    let anchor = configsig::anchor_path();
    match configsig::anchor_state(&anchor) {
        configsig::Anchor::Absent => {
            println!("enforcement: inactive (no anchor at {})", anchor.display());
            println!("bootstrap: gitvault config keygen && gitvault install");
        }
        configsig::Anchor::Unanchored => {
            println!(
                "enforcement: INACTIVE ({} is not root-owned - it anchors nothing)",
                anchor.display()
            );
            println!("fix: gitvault install");
        }
        configsig::Anchor::Anchored => {
            println!("enforcement: armed (anchor root-owned)");
            match configsig::verify(&path) {
                Ok(()) => println!("signature: valid for {}", path.display()),
                Err(e) => {
                    eprintln!("signature: INVALID - {e:#}");
                    return Ok(ExitCode::FAILURE);
                }
            }
            let policy_path = config::Policy::resolve(&path, &cfg);
            if cfg.audit_policy.is_some() && !policy_path.exists() {
                eprintln!(
                    "signature: INVALID - the routing table declares an audit policy at {} but the file is absent",
                    policy_path.display()
                );
                return Ok(ExitCode::FAILURE);
            }
            if policy_path.exists() {
                match configsig::verify(&policy_path) {
                    Ok(()) => println!("signature: valid for {}", policy_path.display()),
                    Err(e) => {
                        eprintln!("signature: INVALID - {e:#}");
                        return Ok(ExitCode::FAILURE);
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Install `src` at `target` atomically, with `mode` permissions: the bytes
/// land on a temporary file in the same directory, then `rename(2)` swaps it
/// into place. Both properties this path needs live in the rename:
///
/// - A running process keeps the inode it mapped; rewriting that file's
///   contents in place invalidates its pages and macOS kills it with a code
///   signature error mid-audit. A rename swaps the directory entry, never
///   the mapped file.
/// - A file ever executed while root-owned is provenance-poisoned
///   permanently; only a fresh inode clears the record, so overwriting in
///   place can never cure it.
// The SHA-256 of `path` as it stands, for the post-install verification the
// privileged step demands.
fn installed_digest(path: &Path) -> anyhow::Result<[u8; 32]> {
    use sha2::Digest as _;
    let bytes = std::fs::read(path).with_context(|| format!("cannot hash {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Install `src` at `target` atomically and answer the digest of the bytes
/// that were read - the value the caller later expects at `target`, carried
/// from the trusted source rather than re-derived from whatever the path
/// holds when the immutable flag runs.
fn install_atomic(src: &Path, target: &Path, mode: u32) -> anyhow::Result<[u8; 32]> {
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    // An unpredictable name plus `create_new` keeps a planted entry from
    // steering the write; the stamp makes a pre-created attacker file
    // statistically impossible rather than merely refusing a stale one.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|e| e.as_nanos())
        .unwrap_or(0);
    let tmp = target.with_extension(format!("staging-{}-{stamp}", std::process::id()));
    // The handle is held for the whole staging: a same-user process can
    // rename over the path, but it cannot replace what this descriptor
    // writes to, and the inode compare below catches the rename before the
    // staged bytes are swapped into place.
    let mut staged = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(file) => file,
        Err(_) => {
            anyhow::bail!(
                "staging path {} already exists - refusing to install over it",
                tmp.display()
            );
        }
    };
    let result = (|| -> anyhow::Result<[u8; 32]> {
        use sha2::Digest as _;
        let bytes = std::fs::read(src)
            .with_context(|| format!("cannot read {} for staging", src.display()))?;
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        staged
            .write_all(&bytes)
            .with_context(|| format!("cannot stage {} for {}", src.display(), target.display()))?;
        staged.sync_all()?;
        staged.set_permissions(std::fs::Permissions::from_mode(mode))?;
        let created = staged.metadata()?;
        drop(staged);
        let on_disk = std::fs::symlink_metadata(&tmp)
            .with_context(|| format!("staged file {} vanished before install", tmp.display()))?;
        anyhow::ensure!(
            on_disk.is_file()
                && !on_disk.file_type().is_symlink()
                && on_disk.ino() == created.ino(),
            "staged file {} was replaced before install - refusing",
            tmp.display()
        );
        std::fs::rename(&tmp, target).with_context(|| {
            format!(
                "cannot move {} into place at {}",
                tmp.display(),
                target.display()
            )
        })?;
        // The installed bytes must still be the staged bytes: a same-user
        // rename between the swap and this read lands a foreign binary at
        // the trusted path, which the schg step would then immobilise.
        let installed = std::fs::read(target)
            .with_context(|| format!("cannot verify installed {}", target.display()))?;
        anyhow::ensure!(
            installed == bytes,
            "installed {} was replaced before verification - refusing",
            target.display()
        );
        Ok(digest)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Provision this machine: deploy the binary, lay down the hook dispatchers,
/// then hand the enforcement surface to root.
///
/// The privileged step is one `sudo` run inside this command. What lands under
/// root: the binary, the hooks directory and - when present - the signature
/// anchor. What deliberately stays user-owned: `config.toml` (edits are
/// allowed, only unsigned loads are refused) and its `.sig` sidecar
/// (rewritten by every `gitvault config sign`). Probator is installed
/// separately: GitVault never ships or copies it, but a `probator` and
/// `probator-agent` already beside the binary join the locked set.
/// The dispatcher every event stub execs. Three rules it enforces:
/// - The gateway binary is the fixed install path below, never an
///   environment override: `GITVAULT_BIN=/bin/true git push` would otherwise
///   run no gate at all.
/// - Every dispatcher invocation runs the gate. An inheritable "already
///   chained" marker used to let repository-controlled hook code suppress
///   it: a local pre-push hook could start a nested `git push` that then
///   published without an audit. Nested hooks are simply gated again - the
///   gate never invokes git operations that would recurse back into a
///   dispatcher.
/// - The recursion bound lives on the repository-local hook, never on the
///   gate: `GITVAULT_LOCAL_HOOK_CHAIN` records which hook names already ran
///   their local counterpart in this chain, so a hook that re-enters itself
///   through a nested operation is gated again but not re-run. Each event
///   can nest at most once per name on the chain, which bounds the whole
///   recursion without ever skipping an audit.
fn dispatcher_script(target: &Path) -> String {
    format!(
        "#!/usr/bin/env bash\n\
         set -u\n\
         HOOK=\"${{1:?hook name required}}\"; shift || true\n\
         GITVAULT_BIN=\"{}\"\n\
         if [ ! -x \"$GITVAULT_BIN\" ]; then\n\
         \x20 printf 'gitvault: not installed; refusing the action\\n' >&2\n\
         \x20 exit 1\n\
         fi\n\
         \"$GITVAULT_BIN\" hook \"$HOOK\" || exit $?\n\
         case \":${{GITVAULT_LOCAL_HOOK_CHAIN-}}:\" in\n\
         \x20 *\":$HOOK:\"*) exit 0 ;;\n\
         esac\n\
         REPO_LOCAL_HOOK=\"$(git rev-parse --show-toplevel 2>/dev/null || true)/.githooks/$HOOK\"\n\
         if [ -x \"$REPO_LOCAL_HOOK\" ]; then\n\
         \x20 GITVAULT_LOCAL_HOOK_CHAIN=\"${{GITVAULT_LOCAL_HOOK_CHAIN-}}$HOOK:\" \"$REPO_LOCAL_HOOK\" \"$@\"; exit $?\n\
         fi\n\
         exit 0\n",
        target.display()
    )
}

/// A stub finds its dispatcher by its own location: a caller who redirects
/// HOME at push time must not point the gate at a substitute _dispatch in a
/// writable directory.
fn hook_stub_script(event: &str) -> String {
    format!("#!/usr/bin/env bash\nexec \"$(dirname -- \"$0\")/_dispatch\" {event} \"$@\"\n")
}

fn cmd_install() -> anyhow::Result<ExitCode> {
    // The installed surface and the anchor must both live under the account
    // home, even when HOME points somewhere else: a redirect must not split
    // the trust root from the files it protects.
    let home = configsig::account_home()?;
    let bin_dir = home.join(".local/bin");
    let hooks = home.join(".git-hooks");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&hooks)?;

    // Hand the removed review engine's machine-local policy lists to the
    // configured engine and delete the dead GitVault copies before anything
    // is locked down. The engine reads `withheld-names.txt` and
    // `repo-deps.txt` from its own config root; a second copy under GitVault
    // would be an unread, stale policy source. A conflicting pair refuses
    // instead of picking one. The anchor is handed to root later in this
    // command, so resolve the root the armed engine will read (the account
    // home's fixed configuration directory), not the pre-install unarmed
    // state that could honour a caller's XDG_CONFIG_HOME. When this install
    // arms, lists the engine itself wrote under the unarmed XDG root move
    // across too; otherwise arming would silently change which lists it reads.
    let arming = configsig::anchor_path().exists();
    for (source, action) in config::migrate_legacy_policy_data(arming)? {
        match action {
            config::LegacyPolicyMove::Moved => eprintln!(
                "gitvault: moved policy data {} into the engine's config root",
                source.display()
            ),
            config::LegacyPolicyMove::DuplicateRemoved => eprintln!(
                "gitvault: removed duplicate policy data {} (the engine's identical copy remains)",
                source.display()
            ),
        }
    }

    // An armed installation hands publication verdicts to the engine, so it
    // must not arm with no engine to run. Probator is installed separately;
    // refusing here is what keeps install order from becoming a silent
    // weakening. An unarmed first install may still warn and proceed, because
    // no boundary trusts the engine yet.
    let installed_engine = probator::installed_engine_path();
    if arming && installed_engine.is_none() {
        anyhow::bail!(
            "refusing to arm without an audit engine: probator is not installed at {}\n  \
             install Probator first, then re-run `gitvault install`",
            bin_dir.join("probator").display()
        );
    }

    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);

    // The enforcement surface this run will immobilise: everything the steps
    // below lay down, the Touch ID helper and audit engine when they exist
    // already. The engine is never installed or copied here - Probator is a
    // separate tool - but it is locked if present.
    let target = bin_dir.join("gitvault");
    let sign_wrapper = bin_dir.join("gitvault-sign");
    let mut immobilise: Vec<PathBuf> = vec![target.clone(), sign_wrapper.clone()];
    // The audit engine is not shipped here, but if it is already installed it
    // belongs to the enforcement surface: a same-user process that can swap
    // `probator` for a program printing an empty findings array can pass every
    // audit. Lock what exists; never copy or install it.
    for name in ["probator", "probator-agent"] {
        let engine = bin_dir.join(name);
        if engine.exists() {
            immobilise.push(engine);
        }
    }
    let touchid = bin_dir.join("gitvault-touchid");
    if touchid.exists() {
        immobilise.push(touchid.clone());
    }
    immobilise.push(hooks.clone());
    let anchor = configsig::anchor_path();
    let anchor_armed = anchor.exists();
    // The anchor joins the enforcement surface: root-owned AND schg-flagged.
    // Ownership alone is not protection - the file sits under a user-writable
    // config directory where a same-UID process could unlink it and drop a
    // substitute; the system-immutable flag is what removes that move.
    if anchor_armed {
        immobilise.push(anchor.clone());
    }

    // Release what a previous install froze and hand the files back to this
    // user, so the copies below can replace them. Self-healing too: binaries
    // root-owned by an earlier install are refused by AppleSystemPolicy, so
    // they must return to user ownership before anything runs or is copied
    // over them. Missing flags and missing paths are expected here.
    let _ = std::process::Command::new("sudo")
        .args(["chflags", "-R", "noschg"])
        .args(&immobilise)
        .status();
    let user = std::env::var("USER").context("USER is not set")?;
    // chown refuses a missing path outright; a not-yet-installed target is
    // the normal first-install case, so only existing paths are handed back.
    let existing: Vec<&PathBuf> = immobilise.iter().filter(|p| p.exists()).collect();
    let status = std::process::Command::new("sudo")
        .args(["chown", "-R", &format!("{user}:staff")])
        .args(&existing)
        .status()
        .context("failed to run sudo chown")?;
    if !status.success() {
        anyhow::bail!("sudo chown failed; the enforcement surface stays locked");
    }
    // The anchor's ownership is claimed here, before the flag step: a file
    // that already carries schg cannot be chowned.
    if anchor_armed {
        let status = std::process::Command::new("sudo")
            .args(["chown", "root:wheel"])
            .arg(&anchor)
            .status()
            .context("failed to run sudo chown on the anchor")?;
        if !status.success() {
            anyhow::bail!("sudo chown of the anchor failed");
        }
    }

    // 1. Deploy the binaries atomically. A rename over the target gives the
    //    fresh inode a poisoned provenance record needs AND never touches the
    //    mapped pages a running process holds - the in-place rewrite that
    //    used to kill a mid-audit runner with a code signature error.
    //
    //    Reinstalling through the installed binary itself: exe and target are
    //    the same file, and copying it onto itself would only churn the inode.
    // The bytes the immutable flag must land on: for every file this run
    // installs or writes, the digest is carried from the trusted source -
    // not re-derived from the path later, where a swap between install and
    // flag would bless attacker bytes. Files locked but never written here
    // (a separately installed engine, an existing sign wrapper) keep the
    // self-consistent before/after comparison alone.
    let mut expected: std::collections::HashMap<PathBuf, [u8; 32]> =
        std::collections::HashMap::new();
    let self_install = target
        .canonicalize()
        .map(|resolved| resolved == exe)
        .unwrap_or(false);
    if !self_install {
        expected.insert(target.clone(), install_atomic(&exe, &target, 0o755)?);
    }
    // Warn, but do not install: the audit engine is installed and versioned on
    // its own. Its absence refuses every publication audit at run time; an
    // armed install was already refused above.
    if installed_engine.is_none() {
        eprintln!(
            "gitvault: probator is not installed at {} - \
             publication audits will refuse until it is installed and this install is re-run",
            bin_dir.join("probator").display()
        );
    }
    if !sign_wrapper.exists() {
        const WRAPPER: &str = "#!/bin/sh\n# git needs gpg.ssh.program to be one executable path.\nexec \"$HOME/.local/bin/gitvault\" sign \"$@\"\n";
        std::fs::write(&sign_wrapper, WRAPPER)?;
        use sha2::Digest as _;
        expected.insert(sign_wrapper.clone(), sha2::Sha256::digest(WRAPPER).into());
    }
    std::fs::set_permissions(&sign_wrapper, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot make {} executable", sign_wrapper.display()))?;
    // The touchid helper is a Mach-O too: if an earlier run left it poisoned,
    // a rewrite onto a fresh inode cures it the same way.
    if touchid.exists() {
        let mode = touchid
            .metadata()
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o755);
        expected.insert(touchid.clone(), install_atomic(&touchid, &touchid, mode)?);
    }

    // 2. Hook dispatchers, (re)generated every install: these are this
    //    program's own files, and a stale one keeps yesterday's resolution
    //    rules - a dispatcher left over from an earlier install must not keep
    //    an inheritable skip marker or a $HOME-resolved path.
    let dispatch = hooks.join("_dispatch");
    std::fs::write(&dispatch, dispatcher_script(&target))?;
    // Scripts land mode 0644 from fs::write; a hook git cannot execute is a
    // gate that silently does not run, so the executable bit is enforced on
    // every install, not only on first write.
    std::fs::set_permissions(&dispatch, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot make {} executable", dispatch.display()))?;
    for event in [
        "pre-commit",
        "pre-push",
        "commit-msg",
        "prepare-commit-msg",
        "pre-applypatch",
    ] {
        let stub = hooks.join(event);
        std::fs::write(&stub, hook_stub_script(event))?;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("cannot make {} executable", stub.display()))?;
    }

    // 3. Immobilise the enforcement surface. Two mechanisms, chosen by what the
    //    kernel actually enforces:
    //
    //    - Executables and the hooks directory get the SYSTEM IMMUTABLE flag
    //      (schg): ownership stays with the user so AppleSystemPolicy still
    //      launches the adhoc-signed binary, but content cannot be modified or
    //      removed without sudo. chowning a user-built binary to root instead
    //      gets it killed at exec - "load code signature error 2" - because the
    //      system provenance record still says a user process created it.
    //    - The signature anchor goes to root ownership: anchor_state() only
    //      trusts a root-owned public key, which is the property that makes the
    //      trust root un-repointable. Ownership was already restored to the
    //      invoking user above, before the copies.
    //
    //    The bytes the immutable flag lands on must be the bytes this run
    //    installed - proven by comparing each target against the digest
    //    carried from its trusted source, not a fresh hash of whatever the
    //    path holds now. A same-user process can rename over a target
    //    between the copy and this privileged step, so files this run did
    //    not install are hashed here and the flag is refused rather than
    //    applied to a swapped-in binary. The second check after chflags
    //    closes the residual window: a swap that slipped in is detected on
    //    both inode and content, unlocked and refused.
    // The enumeration must be complete before the flag lands: an entry that
    // cannot be inspected - unreadable metadata, an unlistable directory, a
    // vanished child - would otherwise be made system-immutable without ever
    // being hashed or compared. Every traversal error is fatal here, never a
    // skipped entry.
    //
    // The record covers every object the flag will touch: regular files are
    // pinned by inode AND content digest, directories and symlinks by inode
    // alone (a symlink's target is nobody's business here - the object being
    // frozen is the link itself). The flag is then applied to exactly this
    // enumerated set with no recursion, so nothing the manifest never saw
    // can receive it.
    let mut staged_digests: Vec<(PathBuf, u64, Option<[u8; 32]>, bool)> = Vec::new();
    let mut flag_targets: Vec<PathBuf> = Vec::new();
    let mut flag_links: Vec<PathBuf> = Vec::new();
    for path in &immobilise {
        let mut stack = vec![path.clone()];
        while let Some(entry) = stack.pop() {
            let meta = std::fs::symlink_metadata(&entry).with_context(|| {
                format!(
                    "cannot inspect {} before the immutable flag",
                    entry.display()
                )
            })?;
            if meta.is_dir() && !meta.file_type().is_symlink() {
                for child in std::fs::read_dir(&entry).with_context(|| {
                    format!("cannot list {} before the immutable flag", entry.display())
                })? {
                    stack.push(
                        child
                            .with_context(|| {
                                format!("cannot inspect an entry under {}", entry.display())
                            })?
                            .path(),
                    );
                }
                staged_digests.push((entry.clone(), meta.ino(), None, false));
                flag_targets.push(entry);
                continue;
            }
            if meta.file_type().is_symlink() {
                // Flagged on the link itself (`chflags -h`): following it
                // would freeze whatever it happens to point at.
                staged_digests.push((entry.clone(), meta.ino(), None, true));
                flag_links.push(entry);
                continue;
            }
            if !meta.is_file() {
                // A fifo, socket or device is flagged like anything else -
                // an unflagged object could be swapped through its name -
                // but it has no bytes to pin.
                staged_digests.push((entry.clone(), meta.ino(), None, false));
                flag_targets.push(entry);
                continue;
            }
            let now = installed_digest(&entry)?;
            if let Some(expected) = expected.get(&entry) {
                anyhow::ensure!(
                    &now == expected,
                    "{} no longer holds the installed bytes before the immutable flag - refusing",
                    entry.display()
                );
            }
            staged_digests.push((entry.clone(), meta.ino(), Some(now), false));
            flag_targets.push(entry);
        }
    }
    if !flag_targets.is_empty() {
        let status = std::process::Command::new("sudo")
            .args(["chflags", "schg"])
            .args(&flag_targets)
            .status()
            .context("failed to invoke sudo - enter the login password when asked")?;
        if !status.success() {
            anyhow::bail!("sudo chflags failed; nothing below was applied");
        }
    }
    if !flag_links.is_empty() {
        let status = std::process::Command::new("sudo")
            .args(["chflags", "-h", "schg"])
            .args(&flag_links)
            .status()
            .context("failed to invoke sudo - enter the login password when asked")?;
        if !status.success() {
            anyhow::bail!("sudo chflags -h failed; nothing below was applied");
        }
    }
    // The manifest is verified after the flag: every object flagged must
    // still be the exact object enumerated - inode for every kind, content
    // digest for regular files. Anything else swapped in is unlocked and
    // refused.
    for (path, ino, digest, is_link) in &staged_digests {
        let meta = std::fs::symlink_metadata(path);
        let inode_ok = meta.as_ref().ok().map(|m| m.ino()) == Some(*ino);
        let content_ok = match digest {
            Some(expected) => installed_digest(path).ok().as_ref() == Some(expected),
            None => true,
        };
        if !inode_ok || !content_ok {
            let undo: &[&str] = if *is_link {
                &["chflags", "-h", "noschg"]
            } else {
                &["chflags", "noschg"]
            };
            let _ = std::process::Command::new("sudo")
                .args(undo)
                .arg(path)
                .status();
            anyhow::bail!(
                "{} changed between staging and the immutable flag - the install is refused",
                path.display()
            );
        }
    }
    println!("installed to {}", bin_dir.display());
    println!("enforcement surface is immutable (schg):");
    for p in &immobilise {
        println!("  {}", p.display());
    }
    if anchor_armed {
        println!(
            "signature enforcement: armed ({} is root-owned)",
            anchor.display()
        );
    } else {
        println!(
            "signature enforcement: inactive - no anchor yet\n  \
             next: gitvault config keygen && gitvault config sign && gitvault install"
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn cmd_api(
    config: Option<&PathBuf>,
    path: String,
    method: String,
    fields: Vec<String>,
    raw_fields: Vec<String>,
    headers: Vec<String>,
    input: Option<String>,
    jq: Option<String>,
    repo: Option<String>,
    identity: Option<String>,
    follow: bool,
    silent: bool,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;

    let target = match (repo, identity) {
        (Some(slug), _) => api::Target::Repo(slug),
        (None, Some(key)) => api::Target::Identity(key),
        // Default to the working tree, which is what makes routing automatic.
        (None, None) => match git::Repo::discover(&PathBuf::from(".")) {
            Ok(r) => match r.slug() {
                Some(slug) => api::Target::Repo(slug),
                None => anyhow::bail!(
                    "the current repository has no parsable origin; \
                     pass --repo OWNER/NAME or --identity NAME"
                ),
            },
            Err(_) => {
                anyhow::bail!("not in a repository; pass --repo OWNER/NAME or --identity NAME")
            }
        },
    };

    let split = |v: Vec<String>| -> anyhow::Result<Vec<(String, String)>> {
        v.into_iter()
            .map(|kv| {
                kv.split_once('=')
                    .map(|(k, val)| (k.to_string(), val.to_string()))
                    .ok_or_else(|| anyhow::anyhow!("expected key=value, got '{kv}'"))
            })
            .collect()
    };

    let body = match input {
        Some(v) if v.starts_with('@') => Some(std::fs::read_to_string(&v[1..])?),
        other => other,
    };

    // The publication boundary applies to the raw API surface too: `api` is a
    // credential broker, but a write that puts repository content or refs on
    // GitHub must go through the audited commands, not around them. The check
    // lives here - not inside api::run - because the gated verbs (pr create,
    // release create) call api::run themselves after their audits.
    if let Some(reason) = publication_surface(&method, &path) {
        eprintln!(
            "gitvault: refusing unaudited publication via api: {reason}\n  \
             use the gated command instead: `gitvault pr create`, `gitvault pr merge`,\n  \
             `gitvault release create`, or `git push` through the pre-push hook"
        );
        return Ok(ExitCode::from(2));
    }

    let req = api::Request {
        method,
        path,
        target,
        fields: split(fields)?,
        raw_fields: split(raw_fields)?,
        headers,
        body,
        body_stream: None,
        follow,
        mutation: api::Mutation::Read,
        jq,
        silent,
    };
    // A refusal is a failure. Returning success for a denied operation would let a
    // caller chain past it with `&&`, which is exactly the mistake this gate exists
    // to prevent.
    match api::run(&cfg, &vault, &req) {
        Ok(code) => Ok(ExitCode::from(code as u8)),
        Err(err) => {
            eprintln!("gitvault: {err:#}");
            Ok(ExitCode::from(2))
        }
    }
}

/// The generic `api` broker's verdict: every mutating method refuses and
/// only reads stay open. No repository write is verified-safe metadata -
/// issues, labels, comments, state flips and the rest all emit events that
/// can trigger privileged Actions workflows, which is CI authority spent
/// outside the audited path. The few mutating operations the product keeps
/// (the audited commands' POSTs and the narrowly justified removals of
/// unaudited state) never reach this classifier: they are marked at the
/// credential moment instead (see `api::Mutation`).
fn publication_surface(method: &str, path: &str) -> Option<String> {
    if matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    ) {
        return None;
    }
    let verb = method.to_ascii_uppercase();
    // The route is what the server matches: everything from `?` or `#` on is
    // a parameter the transport still sends but the path classifier must not
    // see. `contents?ref=x` is a contents write and `graphql?q=...` still
    // reaches the mutation endpoint, so classifying the raw string would let
    // a query suffix detach the route's final segment from every match. All
    // refusal text shows the stripped route only - a query can carry a
    // credential such as an access_token parameter.
    let shown = path.split(['?', '#']).next().unwrap_or(path);
    // A dot segment (including a percent-encoded spelling) is normalized by
    // curl and the API server after this match would run. It is refused as a
    // publication attempt rather than matched against a different path than
    // the one the transport will send. The same rule lives in api::request_url,
    // so a traversal cannot slip past this check and still be sent.
    if crate::api::path_has_traversal(path) {
        return Some(format!("{verb} /{shown} (unsafe path segment)"));
    }
    // Match the route the server will see, not the raw percent spelling:
    // `%63ontents` is a contents write, and `%2f` changes the segment
    // boundaries. A percent escape that survives one decode - anywhere in the
    // path, including owner/repo - is ambiguous, so the write refuses instead
    // of guessing what a second decode would route to.
    let Some(decoded) = crate::api::decoded_api_path(path) else {
        return Some(format!("{verb} /{shown} (undecodable path)"));
    };
    if decoded.contains('%') {
        return Some(format!("{verb} /{shown} (double-encoded path)"));
    }
    if crate::api::has_encoded_separator(path) {
        return Some(format!("{verb} /{shown} (encoded path separator)"));
    }
    let path = decoded.trim_start_matches('/');
    let route = path.split(['?', '#']).next().unwrap_or(path);
    // Curl glob metacharacters never appear in a legitimate API path. The
    // broker always sends --globoff, so they cannot expand on the wire; a
    // write that still spells them is judged publication surface outright
    // rather than classified from a shape curl might once have expanded
    // into several requests.
    if verb != "GET" && verb != "HEAD" && verb != "OPTIONS" && path.contains(['{', '}', '[', ']']) {
        return Some(format!("{verb} /{route} (curl glob metacharacters)"));
    }
    let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
    let first = segments.first().copied();
    // The GraphQL endpoint carries mutations - createRef, updateRef,
    // mergePullRequest, createRelease - inside a body this classifier cannot
    // audit, and a read-only query cannot be told from a mutation without
    // parsing the document. Refuse it outright: a write through `api` would
    // otherwise publish around the audited commands.
    if first == Some("graphql") {
        return Some(format!("{verb} /{route} (GraphQL endpoint)"));
    }
    // Every mutating verb reaching here fails closed. The audited commands
    // - push, pr create/merge, release create - never pass through this
    // classifier, so any write still arriving is one the audit cannot see.
    // There is no verified-safe metadata allowlist: every repository
    // mutation emits events (issues, label, milestone, project,
    // issue_comment, commit_comment, pull_request, repository...) that can
    // trigger privileged Actions workflows holding repository credentials,
    // and the generic broker cannot prove a caller's write will not. CI
    // authority spent outside the audited path is publication power, so
    // the generic `api` broker is read-only by verdict.
    Some(format!("{verb} /{route}"))
}

fn cmd_pr(
    config: Option<&PathBuf>,
    command: PrCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    // Audit first, blessing after: the routing table is parsed without its
    // signature so the audit can run. A metadata read that spends the vault
    // token re-checks the signature in api::authorize before issuance, so an
    // uncertified table cannot borrow a credential while it waits for the
    // report; the publication verdict itself is still decided after the audit.
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let vault = vault::Vault::open()?;

    let slug = match repo {
        Some(s) => s,
        None => git::Repo::discover(&PathBuf::from("."))?
            .slug()
            .ok_or_else(|| anyhow::anyhow!("no origin remote; pass --repo OWNER/NAME"))?,
    };

    let merge_audited = matches!(command, PrCommand::Merge { .. });
    let (method, path, fields, raw_fields, jq, expected_head) = match command {
        PrCommand::Create {
            title,
            body,
            head,
            base,
            draft,
        } => {
            let head = match head {
                Some(h) => h,
                None => git::Repo::discover(&PathBuf::from("."))?
                    .current_branch()
                    .ok_or_else(|| anyhow::anyhow!("cannot determine the current branch"))?,
            };
            let base = base.unwrap_or_default();
            // The publication boundary. A branch pushed through GitVault already
            // passed the same audit at pre-push -- a range that did is reused, not
            // paid for twice; content that reached the remote from elsewhere is
            // reviewed here before the request proposes it. The engine resolves
            // base/head in the local repository, the only place the content exists.
            let mut ctx =
                context_for(&cfg, "pr", &PathBuf::from("."), None, &[], None).map_err(|err| {
                    anyhow::anyhow!(
                        "reviewing a pull request needs a checkout of the repository\n  \
                     {err:#}\n  \
                     push the branch through GitVault, or run this from its working tree"
                    )
                })?;
            // Cross-repository naming splits two spellings apart: the API
            // wants `owner:branch` for a fork head and the bare branch for
            // the base, while the local audit resolves an immutable commit
            // fetched from the remote that owns the head. Resolve both from
            // that remote now; a head that cannot be fetched refuses the
            // boundary instead of blessing a stale tracking ref. The base is
            // fetched from the target's own remote and staged in the
            // namespace Probator reads; the guard restores it after the audit.
            let repo_root = ctx.repo_root.clone();
            let audited_head = fetch_pr_branch_head(&repo_root, &head, &slug)?;
            ctx.pr_head = Some(audited_head.clone());
            let (resolved_base, base_sha, base_guard) = local_pr_base(&repo_root, &base, &slug)?;
            ctx.pr_base = resolved_base.clone();
            ctx.pr_base_sha = Some(base_sha.clone());
            let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
            run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "pull request")?;
            drop(base_guard);
            // A branch that advances between the fetch and the POST would
            // create a request containing a commit the audit never saw, and a
            // base that moves rewrites the diff under review for the same
            // window. Both refs are read again now and judged as one pair:
            // either side moving refuses before anything is sent, and the
            // refusal says which tip changed.
            let (latest, (base_now_ref, base_now, base_now_guard)) = (
                fetch_pr_branch_head(&repo_root, &head, &slug)?,
                local_pr_base(&repo_root, &base, &slug)?,
            );
            anyhow::ensure!(
                latest.eq_ignore_ascii_case(&audited_head)
                    && base_now.eq_ignore_ascii_case(&base_sha)
                    && base_now_ref == resolved_base,
                "pull request refs moved while the audit ran \
                 (head {audited_head} -> {latest}, base {}@{base_sha} \
                 -> {}@{base_now}); nothing was sent - rerun the request",
                resolved_base.as_deref().unwrap_or("<default>"),
                base_now_ref.as_deref().unwrap_or("<default>")
            );
            drop(base_now_guard);
            let mut f = vec![("title".to_string(), title), ("head".to_string(), head)];
            if let Some(b) = body {
                f.push(("body".to_string(), b));
            }
            if let Some(b) = resolved_base {
                f.push(("base".to_string(), b));
            }
            (
                "POST",
                format!("/repos/{slug}/pulls"),
                f,
                vec![("draft".to_string(), draft.to_string())],
                Some(".html_url".to_string()),
                Some((audited_head, base_sha)),
            )
        }
        PrCommand::List { state, limit, json } => (
            "GET",
            format!("/repos/{slug}/pulls?state={state}&per_page={limit}"),
            vec![],
            vec![],
            if json {
                None
            } else {
                Some(".[].html_url".to_string())
            },
            None,
        ),
        PrCommand::View { number, json } => (
            "GET",
            format!("/repos/{slug}/pulls/{number}"),
            vec![],
            vec![],
            if json {
                None
            } else {
                Some(".html_url".to_string())
            },
            None,
        ),
        PrCommand::Merge {
            number,
            method,
            subject,
            base,
        } => {
            // Merging publishes into the base branch -- the same class of
            // permanent record as creating. The head may not be checked out
            // here, so it is fetched now, at the gate boundary, and frozen
            // into the context: a fetch inside the audit would ask for
            // credentials in the middle of the run, where the prompt reads
            // as the audit demanding them. Nothing reaches GitHub until the
            // audit passes.
            let mut ctx =
                context_for(&cfg, "pr", &PathBuf::from("."), None, &[], None).map_err(|err| {
                    anyhow::anyhow!(
                        "reviewing a merge request needs a checkout of the repository\n  \
                     {err:#}\n  \
                     run this from its working tree"
                    )
                })?;
            ctx.pr_number = Some(number.to_string());
            // The request's target branch, not the checkout's default: the
            // audit range must be the one the merge will create. Without an
            // explicit --base, read it from the request itself. A supplied
            // --base drives the audit only as a cross-check: once the audit
            // has passed, the request's real base is read again and a
            // mismatch refuses before anything is merged. The same read gives
            // the head the API currently reports, so a branch that moves
            // between that read and the fetch is refused rather than silently
            // audited at a different commit.
            let mut requested_base = base.filter(|base| !base.trim().is_empty());
            let metadata = if requested_base.is_none() {
                // The first credential-bearing read in a merge.
                // api::authorize re-checks the routing certificate before the
                // token is issued, so an unsigned table refuses here instead
                // of reading private request data and only failing at the gate.
                let (api_base, api_head) = pull_request_metadata(&cfg, &vault, &slug, number)?;
                requested_base = Some(api_base.clone());
                Some((api_base, api_head))
            } else {
                None
            };
            let audited_head = fetch_pr_head(&ctx.repo_root, number, &slug)?;
            if let Some((_, expected)) = &metadata {
                anyhow::ensure!(
                    audited_head.eq_ignore_ascii_case(expected),
                    "pull request #{number} head moved from {expected} to {audited_head} \
                     while the review was starting; rerun the merge"
                );
            }
            let repo_root = ctx.repo_root.clone();
            ctx.pr_head = Some(audited_head.clone());
            let (resolved_base, base_sha, base_guard) =
                local_pr_base(&repo_root, requested_base.as_deref().unwrap_or(""), &slug)?;
            ctx.pr_base = resolved_base;
            ctx.pr_base_sha = Some(base_sha);
            let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
            run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "merge")?;
            drop(base_guard);
            // The audit can take minutes, and the request's base and head are
            // mutable during it. Re-read the request after the audit and
            // immediately before the merge PUT, whether --base was supplied or
            // read from the request: a retarget or a moved head between that
            // read and the merge must refuse rather than land on content the
            // engine did not review.
            let (api_base, api_head) = pull_request_metadata(&cfg, &vault, &slug, number)?;
            let audited_branch = match &metadata {
                // A caller-supplied --base drove the audit; compare the
                // request's current target against the branch actually
                // audited (the API name, after any remote-prefix stripping).
                None => branch_for_api(&repo_root, requested_base.as_deref().unwrap_or("")),
                // The request's own base drove the audit; it must still be
                // that base.
                Some(_) => requested_base.clone().unwrap_or_default(),
            };
            anyhow::ensure!(
                audited_branch == api_base,
                "pull request #{number} targets '{api_base}', not \
                 '{audited_branch}'; rerun with the request's base or without --base"
            );
            anyhow::ensure!(
                audited_head.eq_ignore_ascii_case(&api_head),
                "pull request #{number} head moved from {api_head} to {audited_head} \
                 while the audit ran; rerun the merge"
            );
            let mut f = vec![("merge_method".to_string(), method)];
            if let Some(s) = subject {
                f.push(("commit_title".to_string(), s));
            }
            // GitHub merges the head it holds now. Naming the audited commit
            // makes a moved head a 409 refusal instead of an unaudited merge.
            f.push(("sha".to_string(), audited_head));
            (
                "PUT",
                format!("/repos/{slug}/pulls/{number}/merge"),
                f,
                vec![],
                Some(".message".to_string()),
                None,
            )
        }
        PrCommand::Close { number } => (
            "PATCH",
            format!("/repos/{slug}/pulls/{number}"),
            vec![("state".to_string(), "closed".to_string())],
            vec![],
            Some(".state".to_string()),
            None,
        ),
        PrCommand::Comment { number, body } => (
            "POST",
            format!("/repos/{slug}/issues/{number}/comments"),
            vec![("body".to_string(), body)],
            vec![],
            Some(".html_url".to_string()),
            None,
        ),
    };

    let mut req = api::Request {
        method: method.to_string(),
        path,
        target: api::Target::Repo(slug.clone()),
        fields,
        raw_fields,
        headers: vec![],
        body: None,
        body_stream: None,
        follow: false,
        mutation: api::Mutation::Read,
        jq,
        silent: false,
    };
    if merge_audited {
        // The merge arm already ran `run_publication_gate` and re-verified
        // the request's head and base after it: the PUT lands exactly what
        // the audit judged, which is what Audited means at the credential
        // boundary.
        req.mutation = api::Mutation::Audited;
    }
    // A created pull request carries the head and base the API actually used.
    // If either advanced between the last read and the POST, the request
    // contains a commit or a diff base the audit never saw: close it and
    // refuse rather than report a passing publication. The response is read
    // instead of printed so both can be judged before the command calls the
    // request open. The create endpoint accepts no server-side conditional
    // for either ref - the re-read before the POST bounds the window and the
    // post-create verify is the containment, so the residual race is only
    // the span of one request.
    if let Some((expected_head, expected_base)) = expected_head {
        req.mutation = api::Mutation::Audited;
        req.jq = Some(".html_url, .head.sha, .base.sha, .number".to_string());
        let body = api::run_value(&cfg, &vault, &req)?;
        let mut lines = body.lines();
        let url = lines.next().unwrap_or_default().trim().to_string();
        let created_head = lines.next().unwrap_or_default().trim().to_string();
        let created_base = lines.next().unwrap_or_default().trim().to_string();
        let number = lines.next().unwrap_or_default().trim().to_string();
        if !created_head.eq_ignore_ascii_case(&expected_head)
            || !created_base.eq_ignore_ascii_case(&expected_base)
        {
            close_pull_request(&cfg, &vault, &slug, &number);
            anyhow::bail!(
                "the pull request was created at head {created_head} base {created_base}, \
                 but the audit reviewed head {expected_head} base {expected_base}; \
                 it has been closed rather than propose unaudited content"
            );
        }
        if !url.is_empty() {
            println!("{url}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let code = api::run(&cfg, &vault, &req)?;
    Ok(ExitCode::from(code as u8))
}

/// Close a pull request whose head moved past the audited commit. This is a
/// containment action, not a publication: it only changes request metadata.
fn close_pull_request(cfg: &config::Config, vault: &vault::Vault, slug: &str, number: &str) {
    if number.is_empty() || !number.chars().all(|c| c.is_ascii_digit()) {
        return;
    }
    let mut request = get(
        format!("/repos/{slug}/pulls/{number}"),
        slug.to_string(),
        None,
    );
    request.method = "PATCH".into();
    request.fields.push(("state".into(), "closed".into()));
    request.silent = true;
    // Containment: the mutation removes a pull request the audit judged
    // unaudited - it shrinks unaudited server-side state, never adds to it.
    request.mutation = api::Mutation::Containment;
    match api::run(cfg, vault, &request) {
        Ok(0) => eprintln!(
            "gitvault: closed pull request #{number} because its head moved past the audit"
        ),
        Ok(code) => eprintln!(
            "gitvault: could not close pull request #{number} (HTTP {code}); close it manually"
        ),
        Err(err) => eprintln!(
            "gitvault: could not close pull request #{number}: {err:#}; close it manually"
        ),
    }
}

// ------------------------------------------------- gh-style convenience layer
//
// Each of these is a thin mapping from a familiar gh invocation onto a REST call.
// The value is in the shape of the call and the output, not in extra capability:
// `gitvault api` can express all of it. They exist so that an agent reaching for
// `gh pr list` finds something shaped the same way, and so that the routed
// identity is applied without the caller having to think about which account.

/// Resolve the OWNER/NAME to act on: explicit, else the working tree.
fn resolve_slug(explicit: Option<String>) -> anyhow::Result<String> {
    if let Some(s) = explicit {
        return Ok(s);
    }
    git::Repo::discover(&PathBuf::from("."))?
        .slug()
        .ok_or_else(|| {
            anyhow::anyhow!("no origin remote here; pass OWNER/NAME or run in a checkout")
        })
}

fn emit(cfg: &config::Config, vault: &vault::Vault, req: api::Request) -> anyhow::Result<ExitCode> {
    match api::run(cfg, vault, &req) {
        Ok(code) => Ok(ExitCode::from(code as u8)),
        Err(err) => {
            eprintln!("gitvault: {err:#}");
            Ok(ExitCode::from(2))
        }
    }
}

fn get(path: String, slug: String, jq: Option<String>) -> api::Request {
    api::Request {
        method: "GET".into(),
        path,
        target: api::Target::Repo(slug),
        fields: vec![],
        raw_fields: vec![],
        headers: vec![],
        body: None,
        body_stream: None,
        follow: false,
        mutation: api::Mutation::Read,
        jq,
        silent: false,
    }
}

fn cmd_issue(
    config: Option<&PathBuf>,
    command: IssueCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;
    let slug = resolve_slug(repo)?;

    let req = match command {
        IssueCommand::Create { title, body } => {
            let mut r = get(
                format!("/repos/{slug}/issues"),
                slug.clone(),
                Some(".html_url".into()),
            );
            r.method = "POST".into();
            r.fields.push(("title".into(), title));
            if let Some(b) = body {
                r.fields.push(("body".into(), b));
            }
            r
        }
        IssueCommand::List { state, limit, json } => get(
            format!("/repos/{slug}/issues?state={state}&per_page={limit}"),
            slug.clone(),
            if json {
                None
            } else {
                Some(".[].html_url".into())
            },
        ),
        IssueCommand::View { number, json } => get(
            format!("/repos/{slug}/issues/{number}"),
            slug.clone(),
            if json { None } else { Some(".html_url".into()) },
        ),
        IssueCommand::Comment { number, body } => {
            let mut r = get(
                format!("/repos/{slug}/issues/{number}/comments"),
                slug.clone(),
                Some(".html_url".into()),
            );
            r.method = "POST".into();
            r.fields.push(("body".into(), body));
            r
        }
        // The two arms bind identically, so the action is decided by the arm itself
        // rather than by re-testing `command`, which the match has already moved.
        IssueCommand::Close { number } => {
            let mut r = get(
                format!("/repos/{slug}/issues/{number}"),
                slug.clone(),
                Some(".state".into()),
            );
            r.method = "PATCH".into();
            r.fields.push(("state".into(), "closed".to_string()));
            r
        }
        IssueCommand::Reopen { number } => {
            let mut r = get(
                format!("/repos/{slug}/issues/{number}"),
                slug.clone(),
                Some(".state".into()),
            );
            r.method = "PATCH".into();
            r.fields.push(("state".into(), "open".to_string()));
            r
        }
    };
    emit(&cfg, &vault, req)
}

fn cmd_repo(config: Option<&PathBuf>, command: RepoCommand) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;

    let req = match command {
        RepoCommand::View { slug, json } => {
            let slug = resolve_slug(slug)?;
            let jq = if json {
                None
            } else {
                Some(".full_name".into())
            };
            get(format!("/repos/{slug}"), slug.clone(), jq)
        }
        RepoCommand::List {
            owner,
            limit,
            visibility,
            json,
        } => {
            // Listing by owner is not scoped to a repository, so the target is the
            // owner's most specific identity rather than a slug. OWNER/- keeps the
            // owner rule authoritative without inventing a repository.
            //
            // The endpoint differs by owner type: `/orgs/...` returns 404 for a personal
            // account, which is indistinguishable from "no such owner". The account type
            // is resolved first, and an unknown type is reported rather than guessed.
            let probe = get(
                format!("/users/{owner}"),
                format!("{owner}/.github"),
                Some(".type".into()),
            );
            let kind = api::run_value(&cfg, &vault, &probe)?;
            let base = match kind.trim() {
                "Organization" => format!("/orgs/{owner}/repos"),
                _ => format!("/users/{owner}/repos"),
            };
            get(
                format!("{base}?per_page={limit}&type={visibility}"),
                format!("{owner}/.github"),
                if json {
                    None
                } else {
                    Some(".[].full_name".into())
                },
            )
        }
        RepoCommand::DefaultBranch { slug } => {
            let slug = resolve_slug(slug)?;
            get(
                format!("/repos/{slug}"),
                slug.clone(),
                Some(".default_branch".into()),
            )
        }
    };
    emit(&cfg, &vault, req)
}

/// Refuse a release whose tag already exists at a different commit. For a new
/// tag, `target_commitish` will create it at the audited commit. The remote is
/// consulted at the boundary, after the audit produced its verdict and before
/// the release request can publish anything.
/// Whether the remote tag exists at all - the caller needs the distinction:
/// a missing tag is bound by creating its ref atomically, an existing one
/// must already name the audited commit, and a vanished one after creation
/// is a moved boundary.
fn verify_remote_tag(
    repo_root: &std::path::Path,
    slug: &str,
    tag: &str,
    audited: &str,
) -> anyhow::Result<bool> {
    let remote = remote_for_slug(repo_root, slug).ok_or_else(|| {
        anyhow::anyhow!(
            "no remote in this checkout points at {slug}; \
             add it before creating a release"
        )
    })?;
    eprintln!(
        "gitvault: checking remote tag {tag} so the release names the audited commit \
         (the only credential use this release needs before creating it)"
    );
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args([
            "ls-remote",
            "--tags",
            "--",
            &remote,
            &format!("refs/tags/{tag}"),
            &format!("refs/tags/{tag}^{{}}"),
        ])
        .output()
        .context("failed to run git ls-remote")?;
    anyhow::ensure!(
        output.status.success(),
        "cannot resolve remote tag {tag} before creating the release"
    );
    let mut tag_oid = None;
    let mut peeled = None;
    let peeled_name = format!("refs/tags/{tag}^{{}}");
    let tag_name = format!("refs/tags/{tag}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let Some((oid, name)) = line.split_once('\t') else {
            continue;
        };
        if name == peeled_name {
            peeled = Some(oid.trim());
        } else if name == tag_name {
            tag_oid = Some(oid.trim());
        }
    }
    if let Some(actual) = peeled.or(tag_oid) {
        anyhow::ensure!(
            actual.eq_ignore_ascii_case(audited),
            "remote tag {tag} points at {actual}, but the audit reviewed {audited}; \
             refusing to create a release that describes unaudited content"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Bind the tag to the audited commit atomically. `release create` creates
/// a missing tag itself - at `target_commitish` but with no conditional
/// guard, so a tag that appeared between the ls-remote check and the
/// release POST would bind whatever the racer chose. Creating the ref first
/// makes that conflict fail loudly (`POST /git/refs` refuses an existing
/// ref), and a racer's tag must still resolve to the audited commit before
/// the release is built on it.
fn create_remote_tag_ref(
    cfg: &config::Config,
    vault: &vault::Vault,
    repo_root: &std::path::Path,
    slug: &str,
    tag: &str,
    audited: &str,
) -> anyhow::Result<()> {
    let mut req = get(
        format!("/repos/{slug}/git/refs"),
        slug.to_string(),
        Some(".ref".into()),
    );
    req.method = "POST".into();
    req.fields.push(("ref".into(), format!("refs/tags/{tag}")));
    req.fields.push(("sha".into(), audited.to_string()));
    req.mutation = api::Mutation::Audited;
    if let Err(why) = api::run_value(cfg, vault, &req) {
        // The only conflict worth continuing past is an already-existing
        // tag that names the audited commit: whoever won the race still
        // produced the binding this release needs.
        let bound = verify_remote_tag(repo_root, slug, tag, audited).unwrap_or(false);
        anyhow::ensure!(
            bound,
            "creating refs/tags/{tag} failed and no remote tag names the audited commit: {why:#}"
        );
    }
    Ok(())
}

fn cmd_release(
    config: Option<&PathBuf>,
    command: ReleaseCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    // The release boundary runs before any credential is touched: the verdict
    // does not depend on the vault, and a refusal must be possible even where
    // the vault is locked. Nothing reaches GitHub until the registry passes.
    let mut release_audit: Option<ReleaseAudit> = None;
    if let ReleaseCommand::Create { tag, assets, .. } = &command {
        let mut ctx = context_for(
            &cfg,
            "release",
            &PathBuf::from("."),
            Some(tag.clone()),
            &[],
            None,
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "reviewing a release needs a checkout with the tagged commit\n  \
                     {err:#}\n  \
                     run this from the tagged working tree"
            )
        })?;
        // Asset files are judged before the audit: a bad path refuses before
        // any review time or credential is spent. The snapshots are staged
        // under GitVault's private state root - proven outside this checkout
        // - and kept open: the scan and the upload each consume a share of
        // the same descriptor, never a replaceable path.
        let mut staged = check_release_assets(&cfg, assets, &ctx.repo_root)?;
        staged.share_with_audit()?;
        // The audit binds the exact asset bytes: name, size, digest and the
        // inherited-descriptor reference go into the evidence, so the
        // privacy scan judges and the upload reads the identical byte
        // sequence on every platform the descriptor share exists.
        ctx.release_assets = staged
            .assets
            .iter()
            .map(|a| {
                (
                    a.name.clone(),
                    a.size,
                    a.sha256.clone(),
                    a.audit_ref.clone().unwrap_or_default(),
                    a.sealed,
                )
            })
            .collect();
        ctx.inherited_fds = staged.shared.clone();
        let repo_root = ctx.repo_root.clone();
        let audited = ctx
            .release_commit
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the release audit has no commit"))?;
        let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
        run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "release")?;
        // The gate passed on whatever the scan saw - now prove it saw the
        // whole staged image: a pipe-fed share that stopped short would
        // have blessed bytes the upload later sends unaudited.
        staged.verify_delivered()?;
        release_audit = Some(ReleaseAudit {
            repo_root,
            audited,
            assets: staged,
        });
    }
    let vault = vault::Vault::open()?;
    let slug = resolve_slug(repo)?;

    let req = match command {
        ReleaseCommand::List { limit, json } => get(
            format!("/repos/{slug}/releases?per_page={limit}"),
            slug.clone(),
            if json {
                None
            } else {
                Some(".[].tag_name".into())
            },
        ),
        ReleaseCommand::View { tag, json } => get(
            format!("/repos/{slug}/releases/tags/{tag}"),
            slug.clone(),
            if json { None } else { Some(".html_url".into()) },
        ),
        ReleaseCommand::Create {
            tag,
            name,
            notes,
            draft,
            prerelease,
            ..
        } => {
            let ReleaseAudit {
                repo_root,
                audited,
                assets: staged,
            } = release_audit
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("the release audit did not run"))?;
            let tag_exists = verify_remote_tag(repo_root, &slug, &tag, audited)?;
            if !tag_exists {
                // A missing tag is bound atomically, not left for the
                // release POST to create unguarded: the ref creation itself
                // refuses if the tag appeared in between.
                create_remote_tag_ref(&cfg, &vault, repo_root, &slug, &tag, audited)?;
            }
            let mut r = get(
                format!("/repos/{slug}/releases"),
                slug.clone(),
                Some(".html_url".into()),
            );
            r.method = "POST".into();
            r.fields.push(("tag_name".into(), tag.clone()));
            // A new tag is created at the commit the audit reviewed, not at
            // whatever the target repository's default branch happens to be.
            r.fields.push(("target_commitish".into(), audited.clone()));
            r.mutation = api::Mutation::Audited;
            // Every release is created as a draft: assets upload while it is
            // invisible, the tag is re-verified against the audited commit,
            // and only then is the release published. A failure deletes the
            // draft rather than leaving a half-uploaded release public.
            r.raw_fields.push(("draft".into(), "true".to_string()));
            r.raw_fields
                .push(("prerelease".into(), prerelease.to_string()));
            if let Some(n) = name {
                r.fields.push(("name".into(), n));
            }
            if let Some(b) = notes {
                r.fields.push(("body".into(), b));
            }
            return create_release_staged(
                &cfg,
                &vault,
                &slug,
                r,
                &StagedRelease {
                    repo_root: repo_root.as_path(),
                    audited: audited.as_str(),
                    tag: &tag,
                    assets: &staged.assets,
                    keep_draft: draft,
                },
            );
        }
        ReleaseCommand::Delete { tag } => {
            // Release deletion is not an audited path and cannot be made one
            // from here: the API offers no atomic draft-only precondition,
            // `release:deleted` fires webhooks even for drafts, and a
            // collaborator publishing in the check/delete window would make
            // the same request emit an event that triggers privileged
            // workflows. Failed-transaction drafts are cleaned up internally
            // by the release flow itself.
            anyhow::bail!(
                "release '{tag}' was not deleted: deleting a release emits events \
                 that can trigger workflows, and no atomic draft-only check \
                 exists - remove it through GitHub if it is really meant to go"
            );
        }
    };
    emit(&cfg, &vault, req)
}

/// What a release audit settles before the create request is built: the
/// checkout it ran in, the commit it judged, and the staged asset snapshots
/// the audit and upload are bound to.
struct ReleaseAudit {
    repo_root: PathBuf,
    audited: String,
    assets: StagedAssets,
}

/// How the staged bytes are held between the audit and the upload.
/// Linux/Android use a sealed `memfd`: an inode no path can name, whose
/// write refusal is enforced by the kernel on every open description.
/// Other unix targets have no primitive that revokes writes through
/// already-open descriptors (Darwin `uchg` is judged at open, not write),
/// so there the bytes live in private process memory: no inode exists to
/// capture, no description to race, and the audited bytes and the uploaded
/// bytes are literally the same image read twice. Non-unix keeps a named
/// snapshot in the staging directory.
#[derive(Debug)]
enum AssetImage {
    #[cfg(any(target_os = "linux", target_os = "android", not(unix)))]
    File(std::fs::File),
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    Bytes(std::sync::Arc<Vec<u8>>),
}

/// What the release audit binds: the asset's upload name, size and content
/// digest, computed before the audit so the evidence names the exact bytes
/// that may be published. The held `image` is the binding object: the scan
/// reads through a descriptor of it and the upload streams it, so no
/// filesystem path between staging and publish can redirect either side to
/// different bytes.
#[derive(Debug)]
struct ReleaseAsset {
    /// The operator's original path - diagnostics only, never read at upload
    /// time.
    path: PathBuf,
    /// The staged bytes' binding image, held from staging to publish.
    image: AssetImage,
    /// The `/dev/fd/N` reference the audit evidence names, once the
    /// descriptor share for the audit child exists.
    audit_ref: Option<String>,
    /// Whether the snapshot carries the OS seal this platform can give it
    /// (`uchg` on macOS). Publication refuses an unsealed snapshot: without
    /// it a same-user process could rewrite the staged bytes between the
    /// audit and the upload.
    sealed: bool,
    name: String,
    size: u64,
    sha256: String,
}

impl ReleaseAsset {
    /// A fresh reader over the staged bytes. A sealed memfd is duplicated
    /// and rewound; an in-memory image is served through an anonymous pipe
    /// a writer thread feeds - in both cases what the consumer opens is a
    /// descriptor, never a path a same-user process could swap.
    #[cfg(unix)]
    fn open_bytes(&self) -> anyhow::Result<std::fs::File> {
        let (file, evidence) = self.open_image()?;
        // Upload readers carry no delivery question; drop the drain check
        // rather than leak the parent's copy of the read end.
        #[cfg(unix)]
        if let Some((_receipt, drain)) = evidence {
            unsafe {
                libc::close(drain);
            }
        }
        Ok(file)
    }

    /// A reader plus, on in-memory images, the delivery evidence pair: the
    /// receipt proving the writer pushed every staged byte into the pipe and
    /// a parent-held read descriptor proving the consumer drained it - the
    /// audit side can tell a truncated stream (unwritten bytes, or bytes left
    /// unread in the buffer) from a complete one, where a bare EOF could not.
    /// `None` on kernel-bound images - a duplicated descriptor carries no
    /// delivery question.
    #[cfg(unix)]
    #[cfg_attr(
        not(all(unix, not(any(target_os = "linux", target_os = "android")))),
        allow(dead_code)
    )]
    fn open_image(&self) -> anyhow::Result<(std::fs::File, Option<DeliveryEvidence>)> {
        match &self.image {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            AssetImage::File(file) => {
                use std::io::Seek as _;
                let mut clone = file.try_clone().context("cannot clone the staged image")?;
                clone.rewind()?;
                Ok((clone, None))
            }
            #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
            AssetImage::Bytes(bytes) => {
                use std::os::fd::FromRawFd as _;
                let mut pipes = [0i32; 2];
                anyhow::ensure!(
                    unsafe { libc::pipe(pipes.as_mut_ptr()) } == 0,
                    "cannot open the staged image's pipe: {}",
                    std::io::Error::last_os_error()
                );
                for fd in pipes {
                    unsafe {
                        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    }
                }
                // The parent keeps its own read end: after the audit children
                // exit, the bytes still sitting in this pipe are exactly what
                // the consumer never read. It is CLOEXEC so no child inherits
                // a second reader that would hide an undrained buffer.
                let drain = unsafe { libc::fcntl(pipes[0], libc::F_DUPFD_CLOEXEC, 0) };
                anyhow::ensure!(
                    drain >= 0,
                    "cannot keep a drain check on the staged image's pipe: {}",
                    std::io::Error::last_os_error()
                );
                let (ack, delivered) = std::sync::mpsc::channel();
                bytes_writer()
                    .send((bytes.clone(), pipes[1], ack))
                    .map_err(|_| anyhow::anyhow!("the staged-image writer is gone"))?;
                Ok((
                    unsafe { std::fs::File::from_raw_fd(pipes[0]) },
                    Some((delivered, drain)),
                ))
            }
        }
    }

    /// Whether the staged bytes still cannot be altered before upload:
    /// the kernel answers for a sealed memfd; an in-memory image needs no
    /// kernel answer because nothing outside this process can reach it.
    /// Checked again at publish - a lost seal means the audit-to-upload
    /// binding cannot be proven and the release refuses.
    fn sealed_now(&self) -> bool {
        match &self.image {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            AssetImage::File(file) => asset_is_sealed(file),
            #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
            AssetImage::Bytes(_) => true,
            #[cfg(not(unix))]
            AssetImage::File(_) => false,
        }
    }
}

/// The consumer-side delivery proof a pipe-fed staged image hands back:
/// the writer's completion receipt and the parent's own read descriptor,
/// which is read to EOF after the audit - whatever it yields is exactly
/// what the consumer never drained. Only in-memory images need it - a
/// sealed kernel inode cannot truncate silently.
#[cfg_attr(not(unix), allow(dead_code))]
type DeliveryEvidence = (std::sync::mpsc::Receiver<bool>, i32);

/// GitHub's documented ceilings: a release carries at most 1000 assets and
/// each asset must stay under 2 GiB. Both refuse before any byte is read,
/// hashed or requested.
const MAX_RELEASE_ASSETS: usize = 1000;
const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// On unixes without a real anonymous-inode primitive the staged image is a
/// `Vec<u8>`: private memory, not an inode. A signed budget can raise the
/// DISK ceiling, but it must not silently raise a RAM residency - one
/// release's staged set is capped here regardless of the signed budget.
/// Platforms with a kernel-backed image (memfd) are not bound by this.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const MAX_MEMORY_STAGING_BYTES: u64 = 1024 * 1024 * 1024;

/// In-memory staged images are served through anonymous pipes by a single
/// multiplexed writer: every pipe's write end is `O_NONBLOCK` and a `poll`
/// loop feeds whichever reader has room. A reader that stalls mid-image -
/// a consumer killed mid-audit - parks only its own slot: the writer never
/// blocks on any single pipe, so any number of stalled readers cannot
/// starve the next consumer, and a reader that ends early reports
/// `EPIPE`/`POLLERR` and frees its slot.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
type ImageJob = (std::sync::Arc<Vec<u8>>, i32, std::sync::mpsc::Sender<bool>);

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn bytes_writer() -> &'static std::sync::mpsc::Sender<ImageJob> {
    static WRITER: std::sync::OnceLock<std::sync::mpsc::Sender<ImageJob>> =
        std::sync::OnceLock::new();
    WRITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<ImageJob>();
        std::thread::spawn(move || {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};
            /// `ack` reports exactly once when the job leaves the queue:
            /// `true` only if every staged byte reached the pipe - a
            /// short, failed or abandoned stream reports `false`, so the
            /// audit side can tell a truncated image from a complete one.
            struct Job {
                image: std::sync::Arc<Vec<u8>>,
                file: std::fs::File,
                offset: usize,
                ack: std::sync::mpsc::Sender<bool>,
            }
            impl Drop for Job {
                fn drop(&mut self) {
                    let _ = self.ack.send(self.offset >= self.image.len());
                }
            }
            /// `None` on a failed `F_SETFL`: a pipe that could not be made
            /// nonblocking is never queued - a blocking write to a stalled
            /// reader would stop this one worker. Closing the write end
            /// instead gives the consumer an immediate EOF, fail-closed.
            /// (The untouched `ack` then drops unanswered, which the audit
            /// side also reads as not-delivered.)
            fn take(item: ImageJob) -> Option<Job> {
                let (image, fd, ack) = item;
                loop {
                    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == 0 {
                        return Some(Job {
                            image,
                            file: unsafe { std::fs::File::from_raw_fd(fd) },
                            offset: 0,
                            ack,
                        });
                    }
                    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                        unsafe {
                            libc::close(fd);
                        }
                        return None;
                    }
                }
            }
            let mut jobs: Vec<Job> = Vec::new();
            loop {
                // Admit every queued job before polling: a stalled pipe parks
                // its own slot and never delays the admission of new work.
                loop {
                    match rx.try_recv() {
                        Ok(item) => {
                            if let Some(job) = take(item) {
                                jobs.push(job);
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                    }
                }
                if jobs.is_empty() {
                    match rx.recv() {
                        Ok(item) => {
                            if let Some(job) = take(item) {
                                jobs.push(job);
                            }
                        }
                        Err(_) => return,
                    }
                    continue;
                }
                let mut polled: Vec<libc::pollfd> = jobs
                    .iter()
                    .map(|job| libc::pollfd {
                        fd: job.file.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    })
                    .collect();
                // The poll quantum bounds how long a newly queued job waits
                // for its first write cycle - it is no reader's deadline.
                if unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, 100) } < 0
                {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return;
                }
                let mut keep = vec![true; jobs.len()];
                for (i, job) in jobs.iter_mut().enumerate() {
                    let re = polled[i].revents;
                    if re & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                        keep[i] = false;
                        continue;
                    }
                    if re & libc::POLLOUT == 0 {
                        continue;
                    }
                    while job.offset < job.image.len() {
                        let written = unsafe {
                            libc::write(
                                job.file.as_raw_fd(),
                                job.image[job.offset..].as_ptr().cast(),
                                (job.image.len() - job.offset).min(64 * 1024),
                            )
                        };
                        if written > 0 {
                            job.offset += written as usize;
                        } else if written < 0
                            && std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::WouldBlock
                        {
                            break;
                        } else {
                            keep[i] = false;
                            break;
                        }
                    }
                    if job.offset >= job.image.len() {
                        keep[i] = false;
                    }
                }
                let mut i = 0;
                jobs.retain(|_| {
                    let alive = keep[i];
                    i += 1;
                    alive
                });
            }
        });
        tx
    })
}
/// The default aggregate budget for one release's assets. Platform limits are
/// not free local disk and bandwidth: a set past this size is staged only when
/// the signed rules name a larger `release_asset_budget`.
const DEFAULT_ASSET_BUDGET_BYTES: u64 = 512 * 1024 * 1024;

/// The staged set of the operator's asset files. On unix the snapshots are
/// anonymous inodes - created under the pinned staging root and unlinked
/// before a byte lands - so the open descriptors are the only way to reach
/// the bytes, and closing them frees everything. Elsewhere a per-release
/// directory holds the snapshots and is removed at drop, but only the
/// directory this guard actually created: a cleanup that cannot prove the
/// path still sits inside the private staging root removes nothing.
#[derive(Debug)]
struct StagedAssets {
    /// `Some` only on platforms whose snapshots keep names; anonymous
    /// snapshots (and the empty asset set) own no directory.
    dir: Option<PathBuf>,
    /// The canonical staging root `dir` was created under: the boundary a
    /// cleanup must prove before deleting anything.
    root: PathBuf,
    assets: Vec<ReleaseAsset>,
    /// Descriptor numbers reserved for the audit child's inheritance; closed
    /// when the staged set drops.
    shared: Vec<i32>,
    /// One delivery evidence pair per audit share on in-memory images: the
    /// pipe writer's completion receipt and a parent-held read descriptor
    /// whose leftover bytes are exactly what the consumer never drained.
    /// Empty on kernel-bound images and before sharing.
    delivery: Vec<DeliveryEvidence>,
}

impl Drop for StagedAssets {
    fn drop(&mut self) {
        #[cfg(unix)]
        for fd in &self.shared {
            unsafe {
                libc::close(*fd);
            }
        }
        let Some(dir) = &self.dir else {
            return;
        };
        // A swapped staging path must never drag the delete outside the
        // private root: resolve both sides and refuse the removal rather
        // than follow a planted link into the checkout or the state root.
        let inside = dir
            .canonicalize()
            .ok()
            .map(|resolved| resolved.starts_with(&self.root))
            .unwrap_or(false);
        if inside {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl StagedAssets {
    /// Reserve one descriptor number per asset for the audit child to
    /// inherit. `F_DUPFD_CLOEXEC` keeps the duplicate out of unrelated
    /// spawns until the gate's pre-exec clears the flag; the `/dev/fd/N`
    /// reference it yields is image-bound, so the scanner reads exactly
    /// the bytes the upload will send, whatever happens to the staged
    /// path.
    #[cfg(unix)]
    fn share_with_audit(&mut self) -> anyhow::Result<()> {
        use std::os::unix::io::AsRawFd as _;
        for (index, asset) in self.assets.iter_mut().enumerate() {
            // The share is a fresh reader positioned at the first byte -
            // a dup'd description of the sealed inode, or the read end of
            // the pipe an image writer feeds. In-memory images also hand
            // back the delivery evidence: a truncated or unread stream must
            // read differently from a complete one after the gate.
            let (reader, evidence) = asset.open_image()?;
            let fd = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 100 + index) };
            anyhow::ensure!(
                fd >= 0,
                "cannot share the staged asset '{}' with the audit",
                asset.name
            );
            if let Some(evidence) = evidence {
                self.delivery.push(evidence);
            }
            self.shared.push(fd);
            asset.audit_ref = Some(format!("/dev/fd/{fd}"));
        }
        Ok(())
    }

    /// Called once the audit children have finished: every pipe-fed share
    /// must prove its whole staged image was *consumed*, not merely written.
    /// A writer's completion receipt alone is not enough - a consumer that
    /// read a prefix and exited leaves the tail undrained in the pipe, which
    /// a bare EOF or a producer-side ack cannot distinguish from a full
    /// read. The parent's own read end answers that without a raceable
    /// sample: it reads to EOF, and whatever arrives is exactly the bytes
    /// the consumer never took - the writer keeps pumping as space frees,
    /// so the count is a stable post-exit measurement, not a snapshot the
    /// producer could outrun. The parent's inherited-fd copies are spent
    /// first so only this drain remains a reader.
    #[cfg(unix)]
    fn verify_delivered(&mut self) -> anyhow::Result<()> {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;
        for fd in self.shared.drain(..) {
            unsafe {
                libc::close(fd);
            }
        }
        let mut complete = true;
        for (delivered, drain) in self.delivery.drain(..) {
            // Owning the descriptor as a File closes it on every path. A
            // read error refuses too: a drain that cannot be measured is
            // a consumption that cannot be proven.
            let mut file = unsafe { std::fs::File::from_raw_fd(drain) };
            let mut drained = 0u64;
            let mut buf = [0u8; 8192];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => drained += n as u64,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        complete = false;
                        break;
                    }
                }
            }
            complete &= delivered.recv().unwrap_or(false) && drained == 0;
        }
        anyhow::ensure!(
            complete,
            "an audited asset stream was not consumed to its end - the gate \
             may have judged a truncated image while the upload would serve \
             the full asset; refusing"
        );
        Ok(())
    }

    /// Descriptor inheritance is what binds the scan to the upload; where it
    /// cannot be established, a release with assets must refuse rather than
    /// fall back to a path a same-user process could swap.
    #[cfg(not(unix))]
    fn share_with_audit(&mut self) -> anyhow::Result<()> {
        if self.assets.is_empty() {
            return Ok(());
        }
        anyhow::bail!("release assets need descriptor-bound staging, which this platform lacks")
    }

    #[cfg(not(unix))]
    fn verify_delivered(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Stream a SHA-256 through a fixed buffer from any readable source:
/// hashing must stay constant-memory however large the audited asset is.
/// Reading through an already-open handle binds the digest to that inode,
/// not to a path that could be swapped before the upload reads it again.
#[cfg(test)]
fn sha256_reader(mut source: impl std::io::Read) -> anyhow::Result<String> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot hash '{}'", path.display()))?;
    sha256_reader(file).with_context(|| format!("cannot hash '{}'", path.display()))
}

/// Open an asset source for a single judged read: `O_NOFOLLOW` refuses a
/// symlink swapped in after the caller's own checks, `O_NONBLOCK` keeps a
/// FIFO from holding the open forever, and the shape/size judgement then
/// happens on the descriptor itself rather than a re-looked-up path.
#[cfg(unix)]
fn open_asset_source(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::io::FromRawFd as _;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("--asset '{}' is not a readable file", path.display()))?;
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    anyhow::ensure!(
        fd >= 0,
        "--asset '{}' is not a readable file",
        path.display()
    );
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn open_asset_source(path: &Path) -> anyhow::Result<std::fs::File> {
    std::fs::File::open(path)
        .with_context(|| format!("--asset '{}' is not a readable file", path.display()))
}

/// A directory pinned on a descriptor: `open`/`openat` with `O_DIRECTORY`,
/// `O_NOFOLLOW` and `O_CLOEXEC`, so the held handle names the inode the
/// boundary check judged - not a path a same-user process can swap to a
/// link into the checkout. Every child created under it uses `mkdirat` /
/// `openat` relative to the pin, never a re-resolved path string.
#[cfg(unix)]
fn open_pinned_dir(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
) -> anyhow::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| "cannot pin a directory on a descriptor");
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// A snapshot created inside a pinned directory: `O_EXCL` so nothing could
/// have planted the predictable name, `O_NOFOLLOW` so a same-tick swap to a
/// link cannot redirect the create, mode 0600 at birth.
#[cfg(unix)]
fn create_pinned_file(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    mode: libc::c_uint,
) -> anyhow::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| "cannot create a snapshot under the pinned directory");
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// The canonical path of the inode a descriptor actually holds - `F_GETPATH`
/// on the BSDs and macOS, `/proc/self/fd` where procfs is the mechanism.
/// Comparing this against the path-level validation result proves the pin
/// named the directory that was judged; a descriptor whose path cannot be
/// established fails closed.
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn fd_canonical_path(file: &std::fs::File) -> anyhow::Result<PathBuf> {
    use std::os::fd::AsRawFd as _;
    let mut buf = vec![0u8; libc::MAXPATHLEN as usize];
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| "cannot establish the pinned directory's path");
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let path = PathBuf::from(String::from_utf8_lossy(&buf[..end]).into_owned());
    path.canonicalize()
        .with_context(|| "cannot canonicalize the pinned directory's path")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fd_canonical_path(file: &std::fs::File) -> anyhow::Result<PathBuf> {
    use std::os::fd::AsRawFd as _;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .with_context(|| "cannot establish the pinned directory's path")
}

/// A unix target without a descriptor-path mechanism cannot prove a pinned
/// directory is the one that was judged: descriptor-relative staging is
/// unavailable there, so the operation refuses rather than trust a path.
#[cfg(all(
    unix,
    not(target_vendor = "apple"),
    not(target_os = "linux"),
    not(target_os = "android"),
    not(target_os = "freebsd"),
    not(target_os = "openbsd"),
    not(target_os = "netbsd"),
    not(target_os = "dragonfly")
))]
fn fd_canonical_path(_file: &std::fs::File) -> anyhow::Result<PathBuf> {
    anyhow::bail!("descriptor path resolution is unsupported on this platform")
}

/// The private root staged asset snapshots live under: GitVault's own state
/// directory, never `TMPDIR`. A staging root the environment selects could
/// resolve inside the checkout and let generated snapshots enter the
/// audited tree; this root is fixed and compared against the canonical
/// repository before a byte is written.
fn release_staging_root() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| configsig::home_dir().join(".local").join("state"));
    base.join("gitvault").join("staging")
}

/// Pair each `--asset` file with the name GitHub will store - the file's
/// basename - plus the size and digest that bind its bytes to the audit.
/// Run before the release is created so a bad path or a duplicate upload
/// name refuses before anything is published.
fn check_release_assets(
    cfg: &config::Config,
    paths: &[PathBuf],
    repo_root: &Path,
) -> anyhow::Result<StagedAssets> {
    let budget = cfg
        .rules
        .release_asset_budget
        .unwrap_or(DEFAULT_ASSET_BUDGET_BYTES);
    stage_release_assets(paths, repo_root, &release_staging_root(), budget)
}

/// A staged snapshot must be a truly anonymous inode: a named file carries
/// a link/rename surface for the whole instant it exists. Linux and
/// Android hand back a `memfd` - an inode with no name anywhere, which the
/// kernel itself then seals. Other unix targets hold the staged bytes in
/// private process memory instead (see `AssetImage::Bytes`): no macOS or
/// BSD primitive revokes writes through already-open descriptions - uchg
/// is checked at open time, not write time - so an inode could never be
/// trusted there, and private memory answers the same guarantee by
/// construction.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn anonymous_snapshot() -> anyhow::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;
    let name = std::ffi::CString::new("gitvault-release").expect("an ASCII name");
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    anyhow::ensure!(
        fd >= 0,
        "cannot create an anonymous staged snapshot: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Seal a memfd's inode: F_SEAL_WRITE plus the grow/shrink/seal seals make
/// every description - including this one and any a same-user process
/// could open through /proc - refuse writes from then on. The audit and
/// the upload both read through descriptions of this inode, and none can
/// mutate what the other judged.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn seal_staged(file: &mut std::fs::File) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd as _;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    anyhow::ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != -1,
        "cannot seal the staged asset inode - refusing before the audit sees it"
    );
    Ok(())
}

/// Whether the staged descriptor still cannot be written: a `memfd` asks
/// the kernel for its seals. Checked again at publish: a seal that
/// vanished between the audit and the upload means the binding cannot be
/// proven.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn asset_is_sealed(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd as _;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    seals >= 0 && seals & libc::F_SEAL_SEAL != 0 && seals & libc::F_SEAL_WRITE != 0
}

fn stage_release_assets(
    paths: &[PathBuf],
    repo_root: &Path,
    staging_root: &Path,
    budget: u64,
) -> anyhow::Result<StagedAssets> {
    anyhow::ensure!(
        paths.len() <= MAX_RELEASE_ASSETS,
        "a release carries at most {MAX_RELEASE_ASSETS} assets; {} were given",
        paths.len()
    );
    // Nothing to stage: no directory is created and the staging-root
    // boundary check does not run, so a bare release does not depend on
    // where the state root happens to resolve. The guard owns nothing -
    // `dir` stays empty so its cleanup can never remove a path it did not
    // make.
    if paths.is_empty() {
        return Ok(StagedAssets {
            dir: None,
            root: PathBuf::new(),
            assets: Vec::new(),
            shared: Vec::new(),
            delivery: Vec::new(),
        });
    }
    // Every asset is snapshotted into a private copy before the audit and
    // kept open until publication ends: the scan inherits a descriptor share
    // and the upload streams the same open file, so neither side ever trusts
    // a filesystem path a same-user process could replace. The staging root
    // must sit outside the audited checkout - generated bytes inside the
    // review boundary would contaminate what the audit scans.
    let repo_canonical = repo_root
        .canonicalize()
        .with_context(|| format!("cannot resolve repository {}", repo_root.display()))?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(staging_root).with_context(|| {
        format!(
            "cannot create asset staging root {}",
            staging_root.display()
        )
    })?;
    let root_canonical = staging_root
        .canonicalize()
        .with_context(|| format!("cannot resolve staging root {}", staging_root.display()))?;
    anyhow::ensure!(
        !root_canonical.starts_with(&repo_canonical),
        "asset staging root resolves inside the audited repository - refusing \
         (root {}, repo {})",
        crate::records::redact(&staging_root.display().to_string()),
        crate::records::redact(&repo_root.display().to_string())
    );
    // Preflight every asset before any snapshot exists: open each source
    // once with no-follow semantics, judge it on that descriptor (a swap
    // after a path-level check cannot turn a regular file into a FIFO or a
    // larger file mid-read), dedupe the upload names, and total the declared
    // sizes with checked addition. A set that overflows the signed budget
    // refuses here - no staging directory, no copied bytes.
    struct Prepared {
        path: PathBuf,
        name: String,
        source: std::fs::File,
        declared: u64,
    }
    let mut names = std::collections::HashSet::new();
    let mut prepared: Vec<Prepared> = Vec::with_capacity(paths.len());
    let mut declared_total = 0u64;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("--asset '{}' has no usable file name", path.display())
            })?;
        anyhow::ensure!(
            names.insert(name),
            "--asset names the upload '{name}' twice"
        );
        let source = open_asset_source(path)
            .with_context(|| format!("--asset '{}' is not a readable file", path.display()))?;
        let meta = source
            .metadata()
            .with_context(|| format!("--asset '{}' is not a readable file", path.display()))?;
        anyhow::ensure!(
            meta.is_file(),
            "--asset '{}' is not a regular file",
            path.display()
        );
        anyhow::ensure!(
            meta.len() < MAX_ASSET_BYTES,
            "--asset '{}' exceeds the 2 GiB release-asset limit",
            path.display()
        );
        declared_total = declared_total.checked_add(meta.len()).with_context(|| {
            format!(
                "the asset set overflows a byte count at '{}'",
                path.display()
            )
        })?;
        anyhow::ensure!(
            declared_total <= budget,
            "the asset set totals over the {budget} byte release budget \
             ({} bytes so far, '{}' included) - raise rules.release_asset_budget \
             in the signed configuration for a deliberately large release",
            declared_total,
            path.display()
        );
        // On unixes without a kernel anonymous-inode primitive the staged
        // image is resident process memory; the signed budget may raise the
        // disk ceiling, never the RAM one - refuse before any byte is read.
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        anyhow::ensure!(
            declared_total <= MAX_MEMORY_STAGING_BYTES,
            "the asset set totals over the {} byte in-memory staging limit \
             ({} bytes so far, '{}' included) - this platform keeps staged \
             images in private memory and no signature may raise that",
            MAX_MEMORY_STAGING_BYTES,
            declared_total,
            path.display()
        );
        prepared.push(Prepared {
            path: path.clone(),
            name: name.to_string(),
            source,
            declared: meta.len(),
        });
    }
    // Unix snapshots never touch the staging directory at all - a sealed
    // memfd or an in-memory image has no path to pin. The boundary check
    // above still judged the root, which is what the named-snapshot
    // fallback below writes under on other platforms.
    #[cfg(not(unix))]
    let dir = {
        let dir = staging_root.join(format!(
            "release-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder
            .create(&dir)
            .with_context(|| format!("cannot stage assets in {}", dir.display()))?;
        let dir_canonical = dir
            .canonicalize()
            .with_context(|| format!("cannot resolve staged asset dir {}", dir.display()))?;
        anyhow::ensure!(
            dir_canonical.parent() == Some(root_canonical.as_path())
                && !dir_canonical.starts_with(&repo_canonical),
            "the staged asset dir resolves outside the validated staging \
             root or inside the repository - refusing"
        );
        dir
    };
    // On unix the snapshots are unlinked anonymous inodes: there is no
    // staging directory for the guard to own or clean up. Elsewhere the
    // per-release directory keeps its cleanup proof.
    #[cfg(not(unix))]
    let staged_dir = Some(dir);
    #[cfg(unix)]
    let staged_dir: Option<PathBuf> = None;
    let mut staged = StagedAssets {
        dir: staged_dir,
        root: root_canonical,
        assets: Vec::with_capacity(paths.len()),
        shared: Vec::with_capacity(paths.len()),
        delivery: Vec::new(),
    };
    let mut staged_bytes = 0u64;
    for (index, prepared) in prepared.into_iter().enumerate() {
        let (path, name, mut source, declared) = (
            prepared.path,
            prepared.name,
            prepared.source,
            prepared.declared,
        );
        // The snapshot is private from the instant it exists: on unix it is
        // an anonymous inode (memfd or a shared-memory object), so there is
        // no directory entry at any point - nothing to link, rename, swap
        // or leave behind. Only the held descriptor addresses the bytes,
        // and sealing below trades the writable description for one that
        // provably cannot mutate them.
        // One pass does the copy and the digest together: the hash describes
        // the bytes that actually landed in the snapshot, so the staged
        // digest is the audited digest by construction. The read is bounded
        // twice - by the per-asset cap and by the aggregate budget's
        // remainder: a source that grew after preflight is cut off at the
        // budget line rather than discovered over it at the end.
        //
        let _ = index;
        // Where the bytes land depends on what the platform can prove:
        // Linux/Android stream into a `memfd` (constant memory, then kernel
        // seals); other unix collects into private memory, which needs no
        // seal because no same-user process can name or reach it; non-unix
        // keeps the named-snapshot fallback under the staging directory.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut sink: std::fs::File = anonymous_snapshot()
            .with_context(|| format!("cannot stage asset '{}'", path.display()))?;
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        let mut sink: Vec<u8> = Vec::new();
        #[cfg(not(unix))]
        let mut sink: std::fs::File = {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            options
                .open(dir.join(format!("{index:04}")))
                .with_context(|| format!("cannot stage asset '{}'", path.display()))?
        };
        let (sha256, total) = {
            use sha2::Digest as _;
            use std::io::Read as _;
            let mut hasher = sha2::Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let read = source
                    .read(&mut buffer)
                    .with_context(|| format!("cannot stage asset '{}'", path.display()))?;
                if read == 0 {
                    break;
                }
                total += read as u64;
                anyhow::ensure!(
                    total < MAX_ASSET_BYTES,
                    "--asset '{}' exceeds the 2 GiB release-asset limit",
                    path.display()
                );
                anyhow::ensure!(
                    staged_bytes + total <= budget,
                    "--asset '{}' grew past the {budget} byte release budget \
                     while staging - refusing before the write",
                    path.display()
                );
                // A source that grows mid-copy must not outrun the RAM
                // ceiling either: on platforms whose staged image is a
                // Vec, every chunk is checked against the hard memory cap
                // before it lands, not just the preflight's declared sum.
                #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
                anyhow::ensure!(
                    staged_bytes + total <= MAX_MEMORY_STAGING_BYTES,
                    "--asset '{}' grew past the {} byte in-memory staging \
                     limit while staging - refusing before the write",
                    path.display(),
                    MAX_MEMORY_STAGING_BYTES
                );
                use std::io::Write as _;
                sink.write_all(&buffer[..read])
                    .with_context(|| format!("cannot stage asset '{}'", path.display()))?;
                hasher.update(&buffer[..read]);
            }
            (
                hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                total,
            )
        };
        // The staged size is the measured copy, not the source's earlier
        // metadata: a file that changed length mid-staging produced a torn
        // snapshot whose declared Content-Length would misframe the upload.
        anyhow::ensure!(
            total == declared,
            "--asset '{}' changed size while staging ({} -> {} bytes) - refusing",
            path.display(),
            declared,
            total
        );
        staged_bytes += total;
        // Seal the snapshot the moment its digest exists: nothing - not a
        // same-user rename and not an in-place write - may alter the staged
        // bytes between the audit's read and the upload's stream. The seal
        // is structural on every supported unix: the kernel seals the
        // memfd, or the bytes never become an inode at all.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let (image, sealed) = {
            seal_staged(&mut sink)
                .with_context(|| format!("cannot seal the staged asset '{}'", path.display()))?;
            (AssetImage::File(sink), true)
        };
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        let (image, sealed) = (AssetImage::Bytes(std::sync::Arc::new(sink)), true);
        #[cfg(not(unix))]
        let (image, sealed) = (AssetImage::File(sink), false);
        staged.assets.push(ReleaseAsset {
            path: path.clone(),
            image,
            audit_ref: None,
            sealed,
            name: name.to_string(),
            size: total,
            sha256,
        });
    }
    Ok(staged)
}

/// Create the release as a draft, upload each verified asset, re-verify the
/// tag still names the audited commit, then publish - unless `--draft` asked
/// the release to stay invisible. The draft keeps a half-uploaded or
/// tag-moved release from ever becoming public: any failure deletes it.
/// Deleting the draft also discards bytes already uploaded - a deliberate
/// trade: a draft left behind would be unaudited server-side state, and the
/// audited digest set binds the release as a whole rather than per asset,
/// so a retry re-verifies and re-transmits rather than resuming under a
/// draft the audit never saw.
/// The verified release context a staged publish needs beyond the request:
/// where the audit ran, the commit it judged, the tag being created and the
/// digest-bound assets.
struct StagedRelease<'a> {
    repo_root: &'a Path,
    audited: &'a str,
    tag: &'a str,
    assets: &'a [ReleaseAsset],
    keep_draft: bool,
}

fn create_release_staged(
    cfg: &config::Config,
    vault: &vault::Vault,
    slug: &str,
    mut req: api::Request,
    staged: &StagedRelease<'_>,
) -> anyhow::Result<ExitCode> {
    // Every staged asset must still be sealed before a release exists: the
    // seal is what lets the upload stream bytes the audit judged, and a
    // snapshot that lost it - or never carried it on this platform - cannot
    // prove the published bytes will be the audited ones.
    for asset in staged.assets {
        anyhow::ensure!(
            asset.sealed && asset.sealed_now(),
            "staged asset '{}' is not sealed - refusing before the release exists",
            asset.path.display()
        );
    }
    req.jq = Some(".id, .html_url".into());
    let created = api::run_value(cfg, vault, &req)?;
    let mut lines = created.lines();
    let id = lines.next().unwrap_or_default().trim().to_string();
    anyhow::ensure!(!id.is_empty(), "the created release reported no id");
    // The created draft binds the audited commit at once: an existing tag
    // resolves to its live commit here, a new tag is created at
    // `target_commitish`. If the tag already moved, the draft recorded
    // unaudited content - it is deleted, not kept.
    match verify_remote_tag(staged.repo_root, slug, staged.tag, staged.audited) {
        Ok(true) => {}
        Ok(false) => {
            delete_release_quietly(cfg, vault, slug, &id);
            anyhow::bail!(
                "the remote tag {} vanished while the draft was created - the draft was deleted",
                staged.tag
            );
        }
        Err(why) => {
            delete_release_quietly(cfg, vault, slug, &id);
            return Err(why.context("the draft bound unaudited content and was deleted"));
        }
    }
    let upload = (|| -> anyhow::Result<()> {
        for asset in staged.assets {
            // The published bytes must be the audited bytes: the descriptor
            // held since staging is streamed into curl and hashed on the
            // wire, so nothing between the audit and the request - not a
            // path swap and not a write to the staged inode - can publish
            // bytes the scan did not judge. The rewind matters: the audit's
            // descriptor share leaves the offset wherever the scan ended.
            let file = asset
                .open_bytes()
                .with_context(|| format!("cannot read staged asset '{}'", asset.path.display()))?;
            let mut up = get(
                format!(
                    "{}/repos/{slug}/releases/{id}/assets?name={}",
                    api::UPLOAD_ROOT,
                    api::percent_encode(&asset.name)
                ),
                slug.to_string(),
                Some(".browser_download_url".into()),
            );
            up.method = "POST".into();
            up.mutation = api::Mutation::Audited;
            up.headers
                .push("Content-Type: application/octet-stream".into());
            up.headers.push(format!("Content-Length: {}", asset.size));
            up.body_stream = Some(file);
            let (url, sent) = api::run_value_streamed(cfg, vault, &up)
                .with_context(|| format!("uploading release asset '{}'", asset.name))?;
            anyhow::ensure!(
                sent == asset.sha256,
                "asset '{}' sent bytes that diverge from the audited digest ({}) - refusing",
                asset.name,
                asset.path.display()
            );
            println!("{}", url.trim());
        }
        Ok(())
    })();
    if let Err(why) = upload {
        delete_release_quietly(cfg, vault, slug, &id);
        return Err(why.context("the draft release was deleted after the staged publish failed"));
    }
    // A tag move past this point cannot retarget the bound draft, but it
    // would publish a release naming a tag that now points at unaudited
    // content. That is unrecoverable by this run: the draft stays put for
    // the operator to inspect rather than being silently deleted or
    // published on a stale binding.
    let still_bound = verify_remote_tag(staged.repo_root, slug, staged.tag, staged.audited)
        .context("the tag moved after the draft was bound; it stays unpublished for inspection")?;
    anyhow::ensure!(
        still_bound,
        "the remote tag {} vanished after the draft was bound; it stays unpublished for inspection",
        staged.tag
    );
    if staged.keep_draft {
        if let Some(url) = lines.next() {
            println!("{}", url.trim());
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Publishing is the last point the release can still be held: read the
    // draft's own recorded commit back and refuse to make public a release
    // that names anything but the audited head.
    let bound = get(
        format!("/repos/{slug}/releases/{id}"),
        slug.to_string(),
        Some(".target_commitish".into()),
    );
    let resolved = api::run_value(cfg, vault, &bound).unwrap_or_default();
    anyhow::ensure!(
        resolved.trim().eq_ignore_ascii_case(staged.audited),
        "the draft release resolves to '{}' not the audited {} - it stays a draft",
        resolved.trim(),
        staged.audited
    );
    let mut publish = get(
        format!("/repos/{slug}/releases/{id}"),
        slug.to_string(),
        Some(".html_url".into()),
    );
    publish.method = "PATCH".into();
    publish.mutation = api::Mutation::Audited;
    publish
        .raw_fields
        .push(("draft".into(), "false".to_string()));
    emit(cfg, vault, publish)
}

/// Best-effort cleanup of a draft that must not be published: a failure here
/// is reported but cannot hide the original error.
fn delete_release_quietly(cfg: &config::Config, vault: &vault::Vault, slug: &str, id: &str) {
    let mut delete = get(
        format!("/repos/{slug}/releases/{id}"),
        slug.to_string(),
        None,
    );
    delete.method = "DELETE".into();
    delete.silent = true;
    delete.mutation = api::Mutation::Containment;
    if let Err(why) = api::run(cfg, vault, &delete) {
        eprintln!(
            "gitvault: warning - the failed draft release {id} could not be deleted: {why:#}"
        );
    }
}

fn cmd_run(
    config: Option<&PathBuf>,
    command: RunCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;
    let slug = resolve_slug(repo)?;

    let req = match command {
        RunCommand::List { limit, json } => get(
            format!("/repos/{slug}/actions/runs?per_page={limit}"),
            slug.clone(),
            if json {
                None
            } else {
                Some(".workflow_runs[0].status".into())
            },
        ),
        RunCommand::View { id, json } => get(
            format!("/repos/{slug}/actions/runs/{id}"),
            slug.clone(),
            if json { None } else { Some(".html_url".into()) },
        ),
        RunCommand::Logs { id, run } => {
            let mut req = get(
                if run {
                    format!("/repos/{slug}/actions/runs/{id}/logs")
                } else {
                    format!("/repos/{slug}/actions/jobs/{id}/logs")
                },
                slug.clone(),
                None,
            );
            // The endpoint's 302 reaches a signed download URL on a
            // download-allowlist host; the broker fetches it in-process
            // with no credential at all, so the log body streams out while
            // token and signed URL both stay inside the vault.
            req.follow = true;
            req
        }
    };
    emit(&cfg, &vault, req)
}

/// SSH transport proxy entry point.
///
/// A refusal is a failure and must exit non-zero: git interprets ssh's exit status
/// as the transport result, so returning success for a denied repository would let
/// a push proceed as if authentication had happened.
fn cmd_ssh(config: Option<&PathBuf>, args: &[String]) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;
    match ssh::run(&cfg, &vault, args) {
        Ok(code) => Ok(ExitCode::from(code as u8)),
        Err(err) => {
            eprintln!("gitvault: {err:#}");
            Ok(ExitCode::from(2))
        }
    }
}

/// Read a key passphrase from stdin, if one is provided.
///
/// An empty line means "no passphrase". Reading it here rather than accepting it
/// as an argument keeps it out of argv and out of shell history.
fn read_optional_passphrase(what: &str) -> anyhow::Result<Option<String>> {
    let t = auth::read_secret_line(
        &format!("passphrase for this {what} (empty if none, input hidden): "),
        "the key passphrase",
    )?;
    Ok(if t.is_empty() { None } else { Some(t) })
}

/// Commit-signing proxy entry point.
fn cmd_sign(config: Option<&PathBuf>, args: &[String]) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let vault = vault::Vault::open()?;
    let cwd = std::env::current_dir()?;
    match sign::run(&cfg, &vault, args, &cwd) {
        Ok(code) => Ok(ExitCode::from(code as u8)),
        Err(err) => {
            // git surfaces a non-zero signer exit as a failed commit, which is the
            // correct outcome for a refused signature.
            eprintln!("gitvault: {err:#}");
            Ok(ExitCode::from(2))
        }
    }
}

/// Print the public half of the signing key git should expect.
///
/// Reads from the vault, so no `.pub` file has to exist. Falls back to an empty
/// string rather than failing: git treats a non-zero exit here as a configuration
/// error, and an empty result is the honest answer when no key is held.
fn cmd_signing_key(
    config: Option<&PathBuf>,
    account: Option<String>,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let account = match account {
        Some(a) => a,
        None => {
            let path = match repo {
                Some(slug) => git::Repo::for_slug(&slug),
                None => git::Repo::discover(&std::env::current_dir()?)?,
            };
            // Same rule as every credential path: the assertion may state an
            // expectation for the identity gate, it must not pick the account
            // whose key material is used.
            let outcome = identity::resolve(&cfg, &path, true)?;
            outcome.account.unwrap_or_default()
        }
    };
    if account.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let vault = vault::Vault::open()?;
    match vault.signing_key_public(&account) {
        Ok(public) => println!("{public}"),
        // Reported on stderr, not swallowed. An empty result with a zero exit is
        // indistinguishable from success, and that cost real debugging time: the
        // silent path hid a missing passphrase.
        Err(err) => eprintln!("gitvault: no signing key for '{account}': {err:#}"),
    }
    // Always succeed: git treats a non-zero exit here as a configuration error, and
    // this command only supplies a key hint. The signer itself is what refuses.
    Ok(ExitCode::SUCCESS)
}

/// File, list, rule on, and rescind objections to checker findings.
///
/// Filing writes an unsigned pending record; it moves nothing. Ruling or
/// rescinding is the gated step: the biometric confirmation opens the vault,
/// the configuration key re-signs `objections.toml`, and only a ledger whose
/// signature verifies waives anything at audit time.
fn cmd_objection(command: ObjectionCommand) -> anyhow::Result<ExitCode> {
    match command {
        ObjectionCommand::File {
            checker,
            finding,
            verdict,
            reason,
            directory,
        } => {
            let slug = remote_slug(&directory, "origin").unwrap_or_default();
            let head = std::process::Command::new("git")
                .arg("-C")
                .arg(&directory)
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            let mut pending = objection::load_pending().map_err(anyhow::Error::msg)?;
            let id = format!(
                "ob-{}-{:04x}",
                jiff::Timestamp::now().strftime("%Y%m%d"),
                rand::random::<u16>()
            );
            let entry = if verdict {
                objection::Pending {
                    id: id.clone(),
                    repo: slug,
                    checker: checker.clone(),
                    kind: "verdict".into(),
                    file: String::new(),
                    line: None,
                    fingerprint: None,
                    head,
                    reason: reason.clone(),
                    filed_at: jiff::Timestamp::now().to_string(),
                }
            } else {
                let spec = finding
                    .as_deref()
                    .context("--finding FILE[:LINE] or --verdict is required")?;
                let (file, line) = match spec.rsplit_once(':') {
                    Some((f, l)) if l.chars().all(|c| c.is_ascii_digit()) => {
                        (f.to_string(), l.parse::<u64>().ok())
                    }
                    _ => (spec.to_string(), None),
                };
                let report = latest_report(&checker)
                    .with_context(|| format!("no report.json for checker '{checker}'"))?;
                let findings = report["findings"].as_array().cloned().unwrap_or_default();
                let hit = findings
                    .iter()
                    .find(|f| {
                        f["severity"].as_str() == Some("blocking")
                            && f["file"].as_str() == Some(file.as_str())
                            && line.is_none_or(|l| f["line"].as_u64() == Some(l))
                    })
                    .with_context(|| {
                        format!(
                            "no blocking finding at {file}{} in the latest {checker} report",
                            line.map(|l| format!(":{l}")).unwrap_or_default()
                        )
                    })?;
                let fingerprint = objection::fingerprint(
                    &checker,
                    &file,
                    hit["line"].as_u64().unwrap_or(0),
                    hit["evidence"].as_str().unwrap_or(""),
                );
                objection::Pending {
                    id: id.clone(),
                    repo: slug,
                    checker: checker.clone(),
                    kind: "finding".into(),
                    file,
                    line: hit["line"].as_u64(),
                    fingerprint: Some(fingerprint),
                    head,
                    reason: reason.clone(),
                    filed_at: jiff::Timestamp::now().to_string(),
                }
            };
            pending.push(entry);
            objection::write_pending(&pending).map_err(anyhow::Error::msg)?;
            println!(
                "filed {id} — pending until ruled: gitvault objection rule {id} --overrule|--sustain"
            );
        }
        ObjectionCommand::List => {
            let pending = objection::load_pending().map_err(anyhow::Error::msg)?;
            let rulings = objection::load_rulings();
            if pending.is_empty() && rulings.is_empty() {
                println!("no objections filed");
                return Ok(ExitCode::SUCCESS);
            }
            for p in &pending {
                println!(
                    "pending  {} {} {} {} — {}",
                    p.id,
                    p.checker,
                    p.kind,
                    if p.file.is_empty() {
                        p.head[..8.min(p.head.len())].to_string()
                    } else {
                        format!("{}:{}", p.file, p.line.unwrap_or(0))
                    },
                    p.reason
                );
            }
            for r in &rulings {
                println!(
                    "ruled    {} {} {} {} → {} — {}",
                    r.id,
                    r.checker,
                    r.kind,
                    if r.file.is_empty() {
                        r.head[..8.min(r.head.len())].to_string()
                    } else {
                        format!("{}:{}", r.file, r.line.unwrap_or(0))
                    },
                    r.verdict,
                    r.reason
                );
            }
        }
        ObjectionCommand::Rule {
            id,
            overrule,
            sustain,
            reason,
        } => {
            let verdict = if overrule {
                "overruled"
            } else if sustain {
                "sustained"
            } else {
                anyhow::bail!("rule needs --overrule or --sustain");
            };
            let mut pending = objection::load_pending().map_err(anyhow::Error::msg)?;
            let position = pending
                .iter()
                .position(|p| p.id == id)
                .with_context(|| format!("no pending objection '{id}'"))?;
            let p = pending.remove(position);
            let vault = vault::Vault::open()?;
            unlock::ensure_open(
                &vault,
                &format!("GitVault: confirm to {verdict} objection {id}"),
                false,
                None,
            )?;
            let key = vault.config_key()?;
            let mut rulings = objection::load_rulings();
            rulings.push(objection::Ruling {
                id: p.id,
                repo: p.repo,
                checker: p.checker,
                kind: p.kind,
                file: p.file,
                line: p.line,
                fingerprint: p.fingerprint,
                head: p.head,
                verdict: verdict.into(),
                objection: p.reason,
                reason: reason.unwrap_or_default(),
                ruled_at: jiff::Timestamp::now().to_string(),
            });
            objection::write_rulings(&rulings, &key).map_err(anyhow::Error::msg)?;
            objection::write_pending(&pending).map_err(anyhow::Error::msg)?;
            println!("ruled {id} {verdict}; ledger signed");
        }
        ObjectionCommand::Rescind { id } => {
            let mut rulings = objection::load_rulings();
            let before = rulings.len();
            rulings.retain(|r| r.id != id);
            if rulings.len() == before {
                anyhow::bail!("no ruling '{id}'");
            }
            let vault = vault::Vault::open()?;
            unlock::ensure_open(
                &vault,
                &format!("GitVault: confirm to rescind objection {id}"),
                false,
                None,
            )?;
            let key = vault.config_key()?;
            objection::write_rulings(&rulings, &key).map_err(anyhow::Error::msg)?;
            println!("rescinded {id}; ledger re-signed");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// A checker's newest report.json under the engine's profile run history.
/// The root comes from the same armed-aware resolver as the engine child's
/// data root, so an objection always binds the report the engine wrote.
fn latest_report(checker: &str) -> Option<serde_json::Value> {
    let runs = crate::probator::profiles_root()
        .join(checker)
        .join(format!("{checker}-runs"));
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(runs).ok()?.flatten() {
        let report = entry.path().join("report.json");
        let Ok(meta) = report.metadata() else {
            continue;
        };
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if newest.as_ref().is_none_or(|(t, _)| modified > *t) {
            newest = Some((modified, report));
        }
    }
    let (_, path) = newest?;
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ASSET_BYTES, MAX_RELEASE_ASSETS, branch_for_api, check_release_assets,
        dispatcher_script, fetch_remote_ref, hook_stub_script, local_pr_base, outgoing_push_stdin,
        parse_push_args, publication_surface, push_plan, release_staging_root, remote_mirrors,
        sha256_file, sha256_reader, stage_release_assets, verify_remote_tag,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-main-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cfg() -> crate::config::Config {
        crate::config::Config::default()
    }

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = Command::new("git")
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
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A remote-prefixed base keeps the slashes that belong to the branch:
    /// `origin/release/1.0` is `release/1.0`, not a branch named `origin`.
    #[test]
    fn a_remote_prefixed_base_keeps_slashes_after_the_remote() {
        let dir = scratch("base-slash");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(
            &dir,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/acme/repo.git",
            ],
        );
        git(
            &dir,
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/up/repo.git",
            ],
        );
        assert_eq!(branch_for_api(&dir, "origin/release/1.0"), "release/1.0");
        assert_eq!(branch_for_api(&dir, "upstream/feature/x"), "feature/x");
        assert_eq!(branch_for_api(&dir, "main"), "main");
        assert_eq!(branch_for_api(&dir, "feature/x"), "feature/x");
        assert_eq!(
            branch_for_api(&dir, "other/release/1.0"),
            "other/release/1.0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fetched head is captured through a private ref, so a concurrent fetch
    /// cannot move the object id this review binds, and the shared FETCH_HEAD
    /// is not read or rewritten.
    #[test]
    fn a_private_fetch_captures_the_object_without_touching_fetch_head() {
        let root = scratch("private-fetch");
        let remote = root.join("remote.git");
        git(&root, &["init", "--bare", "-q", remote.to_str().unwrap()]);
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        git(&source, &["init", "-q", "-b", "main"]);
        std::fs::write(source.join("one"), "base\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "base"]);
        git(
            &source,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&source, &["push", "-q", "origin", "main"]);
        let expected = git(&source, &["rev-parse", "HEAD"]);

        let local = root.join("local");
        std::fs::create_dir_all(&local).unwrap();
        git(&local, &["init", "-q", "-b", "main"]);
        git(
            &local,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let fetch_head = local.join(".git").join("FETCH_HEAD");
        std::fs::write(&fetch_head, "deadbeef\t\tbranch 'main' of fixture\n").unwrap();
        let before = std::fs::read_to_string(&fetch_head).unwrap();

        let captured = fetch_remote_ref(&local, "origin", "refs/heads/main", "fixture").unwrap();
        assert_eq!(captured, expected);
        assert_eq!(
            std::fs::read_to_string(&fetch_head).unwrap(),
            before,
            "the shared FETCH_HEAD must not be written or read as the capture"
        );
        assert!(
            git(&local, &["for-each-ref", "refs/gitvault/fetch"]).is_empty(),
            "the private fetch ref must be deleted"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A PR base is fetched from the remote that owns the target repository,
    /// refreshed even when a tracking ref already exists, and a fork
    /// checkout's origin namespace is restored after the audit.
    #[test]
    fn a_pr_base_is_fetched_from_the_target_remote_and_refreshed() {
        let root = scratch("pr-base");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        git(&target, &["init", "--bare", "-q"]);
        let fork = root.join("fork");
        std::fs::create_dir_all(&fork).unwrap();
        git(&fork, &["init", "--bare", "-q"]);

        let dir = root.join("work");
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        git(
            &dir,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/acme/fork.git",
            ],
        );
        git(
            &dir,
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/acme/repo.git",
            ],
        );
        // The URL rewrite keeps the configured remote identity (`acme/repo`)
        // while the fetch itself resolves to a local bare repository.
        git(
            &dir,
            &[
                "config",
                &format!("url.file://{}.insteadOf", target.display()),
                "https://github.com/acme/repo.git",
            ],
        );
        git(
            &dir,
            &[
                "config",
                &format!("url.file://{}.insteadOf", fork.display()),
                "https://github.com/acme/fork.git",
            ],
        );

        std::fs::write(dir.join("one"), "one\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "one"]);
        let target_head = git(&dir, &["rev-parse", "HEAD"]);
        git(
            &dir,
            &[
                "push",
                "-q",
                target.to_str().unwrap(),
                &format!("{target_head}:refs/heads/release/1.0"),
                &format!("{target_head}:refs/heads/main"),
            ],
        );
        git(&target, &["symbolic-ref", "HEAD", "refs/heads/main"]);

        // A stale local origin ref must not be the audited base.
        std::fs::write(dir.join("two"), "two\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "two"]);
        let stale = git(&dir, &["rev-parse", "HEAD"]);
        git(
            &dir,
            &["update-ref", "refs/remotes/origin/release/1.0", &stale],
        );

        let (base, base_sha, guard) =
            local_pr_base(&dir, "origin/release/1.0", "acme/repo").unwrap();
        assert_eq!(base, Some("release/1.0".to_string()));
        assert_eq!(
            base_sha, target_head,
            "the attribution base and the audit base must be the same commit"
        );
        assert_eq!(
            branch_for_api(&dir, "origin/release/1.0"),
            "release/1.0",
            "a remote name is a prefix, not part of a slashed branch"
        );
        let guard = guard.expect("a non-origin target needs a borrowed origin ref");
        assert_eq!(
            git(&dir, &["rev-parse", "refs/remotes/origin/release/1.0"]),
            target_head,
            "the audit base must be the target's refreshed commit, not the stale mirror"
        );
        assert_eq!(
            git(&dir, &["rev-parse", "refs/remotes/upstream/release/1.0"]),
            target_head
        );
        drop(guard);
        assert_eq!(
            git(&dir, &["rev-parse", "refs/remotes/origin/release/1.0"]),
            stale,
            "the checkout's own origin ref is restored after the audit"
        );

        // An omitted base follows the target's default, not origin's.
        let (base, base_sha, guard) = local_pr_base(&dir, "", "acme/repo").unwrap();
        assert_eq!(base, Some("main".to_string()));
        assert_eq!(base_sha, target_head);
        drop(guard);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An existing remote tag must point at the audited commit; a new tag is
    /// allowed (the release request will create it at `target_commitish`).
    #[test]
    fn a_release_tag_must_match_the_audited_commit() {
        let root = scratch("release-tag");
        let remote = root.join("remote.git");
        git(&root, &["init", "--bare", "-q", remote.to_str().unwrap()]);
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        git(&source, &["init", "-q", "-b", "main"]);
        std::fs::write(source.join("one"), "base\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "base"]);
        git(&source, &["tag", "v1"]);
        git(
            &source,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&source, &["push", "-q", "origin", "main", "v1"]);
        let audited = git(&source, &["rev-parse", "HEAD"]);

        let local = root.join("local");
        std::fs::create_dir_all(&local).unwrap();
        git(&local, &["init", "-q", "-b", "main"]);
        git(
            &local,
            &[
                "config",
                &format!("url.{}.insteadOf", remote.display()),
                "https://github.com/acme/repo.git",
            ],
        );
        git(
            &local,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/acme/repo.git",
            ],
        );
        verify_remote_tag(&local, "acme/repo", "v1", &audited).expect("matching tag");
        verify_remote_tag(&local, "acme/repo", "v2", &audited).expect("new tag");
        let err = verify_remote_tag(
            &local,
            "acme/repo",
            "v1",
            "0000000000000000000000000000000000000000",
        )
        .expect_err("a tag at another commit must refuse");
        assert!(err.to_string().contains("points at"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--asset` files are paired with their basename before the release is
    /// created, so a missing file or a directory refuses before anything is
    /// published. The digest is what binds the audited bytes to the upload,
    /// and the open descriptor is what the scan and the upload both consume -
    /// the operator's original path is evidence only.
    #[test]
    fn release_assets_are_checked_before_the_create() {
        let root = scratch("release-assets");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();
        let staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        assert_eq!(staged.assets.len(), 1);
        assert_eq!(staged.assets[0].name, "app-v1.0.zip");
        assert_eq!(staged.assets[0].size, 3);
        assert_eq!(staged.assets[0].sha256.len(), 64);
        assert!(check_release_assets(&cfg(), &[root.join("missing.bin")], &root).is_err());
        assert!(check_release_assets(&cfg(), std::slice::from_ref(&root), &root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The binding is the open descriptor plus the seal on the inode: the
    /// snapshot never had a directory entry - a memfd or shm object carries
    /// no path at all - so there is nothing to swap, and the seal refuses
    /// writes even through a duplicate descriptor. The scan reads and the
    /// upload re-hashes that same description.
    #[cfg(unix)]
    #[test]
    fn staged_descriptor_survives_a_path_swap() {
        let root = scratch("release-asset-swap");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();
        let mut staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        let digest = staged.assets[0].sha256.clone();
        // No name ever existed: a path swap has nothing to work against.
        let leftover_names: Vec<_> = std::fs::read_dir(release_staging_root())
            .map(|entries| entries.flatten().filter(|e| e.path().is_file()).collect())
            .unwrap_or_default();
        assert!(
            leftover_names.is_empty(),
            "anonymous snapshots leave no names behind: {leftover_names:?}"
        );
        // The seal is provable on the held image: a sealed memfd answers
        // the kernel; private bytes are unreachable by construction.
        assert!(staged.assets[0].sealed);
        assert!(staged.assets[0].sealed_now());
        let file = staged.assets[0].open_bytes().unwrap();
        assert_eq!(sha256_reader(&file).unwrap(), digest);
        // The audit's own share reaches the same inode through /dev/fd.
        staged.share_with_audit().unwrap();
        let audit = staged.assets[0].audit_ref.clone().unwrap();
        assert!(audit.starts_with("/dev/fd/"), "{audit}");
        assert_eq!(
            sha256_reader(std::fs::File::open(&audit).unwrap()).unwrap(),
            digest
        );
        assert!(!staged.shared.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A write to the staged bytes - the shape a concurrent-writer attack
    /// takes - cannot move the audited digest on any sealed platform. A
    /// sealed memfd refuses the write in the kernel; an in-memory image
    /// offers no writable surface at all: a same-user process can neither
    /// name it nor open it, and every reader gets the same bytes.
    #[cfg(unix)]
    #[test]
    fn staged_inode_writes_change_the_streamed_digest() {
        let root = scratch("release-asset-write");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();
        let staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        let digest = staged.assets[0].sha256.clone();
        assert!(staged.assets[0].sealed_now());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::io::Write as _;
            let mut dup = match &staged.assets[0].image {
                super::AssetImage::File(file) => file.try_clone().unwrap(),
            };
            assert!(
                dup.write_all(b"mutated").is_err(),
                "a sealed snapshot must refuse writes through any descriptor"
            );
        }
        // Whichever image holds the bytes, two readers see the audited
        // digest: that is the immutability the audit binds.
        let first = staged.assets[0].open_bytes().unwrap();
        let second = staged.assets[0].open_bytes().unwrap();
        assert_eq!(sha256_reader(first).unwrap(), digest);
        assert_eq!(sha256_reader(second).unwrap(), digest);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Readers that never drain their pipes park only their own slots: the
    /// multiplexed writer keeps feeding any later consumer to completion.
    /// (Only platforms whose staged image lives in memory serve pipes;
    /// sealed memfds duplicate descriptors and never stall a sibling.)
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    #[test]
    fn stalled_asset_readers_cannot_starve_a_later_consumer() {
        let root = scratch("release-asset-stall");
        let file = root.join("app-v1.0.zip");
        // Larger than any platform's pipe buffer, so an undrained reader
        // guarantees a mid-image stall rather than a quick full write.
        let payload: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&file, &payload).unwrap();
        let staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        let stalled: Vec<std::fs::File> = (0..4)
            .map(|_| staged.assets[0].open_bytes().unwrap())
            .collect();
        let mut fifth = staged.assets[0].open_bytes().unwrap();
        // Each poll waits on kernel readiness inside a bounded assertion:
        // a starved pipe would fail here instead of hanging the suite.
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        let mut got = Vec::with_capacity(payload.len());
        let mut buf = [0u8; 8192];
        while got.len() < payload.len() {
            let mut pfd = libc::pollfd {
                fd: fifth.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&mut pfd, 1, 15_000) },
                1,
                "stalled sibling readers must not starve a later consumer"
            );
            let read = fifth.read(&mut buf).unwrap();
            assert!(read > 0, "the staged pipe closed before the image drained");
            got.extend_from_slice(&buf[..read]);
        }
        assert_eq!(got, payload);
        drop(stalled);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The delivery receipt makes a truncated audit stream refuse: a
    /// consumer that reads part of the image and closes cannot pass as a
    /// fully delivered share, where a bare EOF looked identical to a
    /// complete one. A drained share still verifies.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    #[test]
    fn a_truncated_audit_stream_fails_delivery_verification() {
        let payload: Vec<u8> = (0..512 * 1024u32).map(|i| (i % 251) as u8).collect();
        // Truncated: the "audit child" reads a few bytes then closes.
        let root = scratch("release-asset-trunc");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, &payload).unwrap();
        let mut staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        staged.share_with_audit().unwrap();
        {
            use std::io::Read as _;
            let mut partial = std::fs::File::open(format!("/dev/fd/{}", staged.shared[0])).unwrap();
            let mut buf = [0u8; 4096];
            partial.read_exact(&mut buf).unwrap();
        }
        assert!(
            staged.verify_delivered().is_err(),
            "a partially read share must fail delivery verification"
        );
        drop(staged);
        let _ = std::fs::remove_dir_all(&root);
        // Complete: a fully drained share passes the same check.
        let root = scratch("release-asset-full");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, &payload).unwrap();
        let mut staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        staged.share_with_audit().unwrap();
        {
            use std::io::Read as _;
            let mut full = std::fs::File::open(format!("/dev/fd/{}", staged.shared[0])).unwrap();
            let mut drained = Vec::new();
            full.read_to_end(&mut drained).unwrap();
            assert_eq!(drained, payload);
            drop(full);
        }
        // verify closes the parent's copies (the "child" is done) and then
        // collects the receipt the writer reported when it finished.
        staged
            .verify_delivered()
            .expect("a fully drained share must verify");
        drop(staged);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An image smaller than the pipe's capacity is the case a producer-side
    /// receipt cannot judge: the writer completes before the consumer ever
    /// reads, so `true` from the ack alone would pass a share the audit
    /// closed after a prefix - or never opened. The parent's drain
    /// descriptor reports the bytes still sitting unread.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    #[test]
    fn a_prefix_read_of_a_small_image_fails_delivery_verification() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        // Prefix read: the consumer drains part of the small image then
        // closes; the writer long since reported success.
        let root = scratch("release-asset-prefix");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, &payload).unwrap();
        let mut staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        staged.share_with_audit().unwrap();
        {
            use std::io::Read as _;
            let mut partial = std::fs::File::open(format!("/dev/fd/{}", staged.shared[0])).unwrap();
            let mut buf = [0u8; 1024];
            partial.read_exact(&mut buf).unwrap();
        }
        assert!(
            staged.verify_delivered().is_err(),
            "a prefix-only read of a small image must fail delivery verification"
        );
        drop(staged);
        let _ = std::fs::remove_dir_all(&root);
        // Never read: the consumer closed without taking a byte.
        let root = scratch("release-asset-unread");
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, &payload).unwrap();
        let mut staged = check_release_assets(&cfg(), std::slice::from_ref(&file), &root).unwrap();
        staged.share_with_audit().unwrap();
        assert!(
            staged.verify_delivered().is_err(),
            "an unread share must fail delivery verification"
        );
        drop(staged);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Relocating the staging root mid-flight loses nothing and gains the
    /// attacker nothing: the snapshots are anonymous inodes addressed only
    /// by their open descriptors, so the rename moves an empty directory
    /// name while the audited bytes stay bound to the held descriptors.
    #[cfg(unix)]
    #[test]
    fn relocating_the_staging_root_loses_no_snapshot() {
        let base = scratch("release-relocate");
        let repo = base.join("repo");
        let staging = base.join("staging");
        std::fs::create_dir_all(&repo).unwrap();
        let file = base.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();
        let staged =
            stage_release_assets(std::slice::from_ref(&file), &repo, &staging, u64::MAX).unwrap();
        let digest = staged.assets[0].sha256.clone();
        let moved = base.join("staging-moved");
        std::fs::rename(&staging, &moved).unwrap();
        let file = staged.assets[0].open_bytes().unwrap();
        assert_eq!(
            sha256_reader(file).unwrap(),
            digest,
            "the descriptor still serves the audited image after relocation"
        );
        drop(staged);
        let leftovers = std::fs::read_dir(&moved).map(|e| e.count()).unwrap_or(0);
        assert_eq!(leftovers, 0, "a relocated root holds no lingering names");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A release with no assets stages no directory - and its guard must
    /// delete none either: the staging root and anything already inside it
    /// are untouched when the empty set drops.
    #[test]
    fn an_empty_release_deletes_nothing_it_did_not_create() {
        let root = scratch("release-empty");
        let staging_root = root.join("staged");
        let canary = staging_root.join("keep");
        std::fs::create_dir_all(&canary).unwrap();
        std::fs::write(canary.join("file"), b"stays").unwrap();
        {
            let staged = stage_release_assets(&[], &root, &staging_root, u64::MAX).unwrap();
            assert!(staged.dir.is_none());
        }
        assert!(
            canary.join("file").exists(),
            "an empty release must not remove state it never created"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A staging root that resolves inside the audited checkout would let
    /// generated snapshots contaminate the review boundary; it refuses
    /// before any byte is written.
    #[test]
    fn staging_inside_the_repository_refuses() {
        let root = scratch("release-staging-inside");
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();
        let err = stage_release_assets(
            std::slice::from_ref(&file),
            &repo,
            &repo.join("staged"),
            u64::MAX,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("inside the audited repository"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A staging root planted as a symlink is judged on its canonical
    /// target: a link that resolves inside the checkout refuses at the
    /// boundary, while a link resolving outside it stages cleanly - the
    /// snapshots are anonymous inodes, so nothing about the root's path
    /// spelling can reach the bytes.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_staging_root_is_judged_on_its_target() {
        let root = scratch("release-staging-swap");
        let repo = root.join("repo");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let file = root.join("app-v1.0.zip");
        std::fs::write(&file, b"zip").unwrap();

        // A link into the checkout resolves inside the audited tree: refuse.
        std::fs::create_dir_all(repo.join("staged")).unwrap();
        let inside = root.join("staging-inside");
        std::os::unix::fs::symlink(repo.join("staged"), &inside).unwrap();
        let err = stage_release_assets(std::slice::from_ref(&file), &repo, &inside, u64::MAX)
            .unwrap_err()
            .to_string();
        assert!(err.contains("inside the audited repository"), "{err}");

        // A link to an outside directory stages anonymous snapshots fine.
        let outside = root.join("staging-outside");
        std::os::unix::fs::symlink(&elsewhere, &outside).unwrap();
        stage_release_assets(std::slice::from_ref(&file), &repo, &outside, u64::MAX).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The documented ceilings refuse before a byte is read: 1001 paths -
    /// none of which exist - are rejected by count alone, and a file at the
    /// 2 GiB boundary is rejected by metadata. A FIFO is refused without a
    /// read that could never end.
    #[test]
    fn release_asset_limits_refuse_before_reading() {
        let many: Vec<PathBuf> = (0..=MAX_RELEASE_ASSETS)
            .map(|i| PathBuf::from(format!("/definitely/missing/{i}.bin")))
            .collect();
        let root = scratch("release-asset-count");
        let err = check_release_assets(&cfg(), &many, &root)
            .unwrap_err()
            .to_string();
        assert!(err.contains("1000"), "{err}");

        let root = scratch("release-asset-size");
        // A sparse file reports the boundary size without holding the bytes:
        // metadata alone must refuse it.
        let big = root.join("big.bin");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(MAX_ASSET_BYTES).unwrap();
        drop(file);
        let err = check_release_assets(&cfg(), std::slice::from_ref(&big), &root)
            .unwrap_err()
            .to_string();
        assert!(err.contains("2 GiB"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An over-budget multi-file set refuses at preflight: every name and
    /// declared size is judged before the staging directory exists, so a
    /// refused set copies nothing.
    #[test]
    fn an_over_budget_asset_set_stages_nothing() {
        let repo = scratch("release-budget-repo");
        git(&repo, &["init", "-q", "-b", "main"]);
        let dir = scratch("release-budget");
        let staging = dir.join("staging");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, vec![0u8; 1024]).unwrap();
        std::fs::write(&b, vec![0u8; 1024]).unwrap();
        let err = stage_release_assets(
            &[a, b],
            &repo,
            &staging,
            1024 + 512, // each file fits alone; together they overflow
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("release budget"), "{err}");
        // The staging root may exist from the boundary check, but a refused
        // set must not leave a snapshot directory behind.
        let snapshots: Vec<_> = std::fs::read_dir(&staging)
            .map(|entries| entries.flatten().collect())
            .unwrap_or_default();
        assert!(
            snapshots.is_empty(),
            "a refused set must not stage snapshots: {snapshots:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// The streamed digest is the same SHA-256 a whole-buffer hash produces.
    #[test]
    fn release_asset_hash_is_streamed() {
        let root = scratch("release-asset-hash");
        let file = root.join("known.bin");
        std::fs::write(&file, b"abc").unwrap();
        // sha256("abc"), well-known.
        assert_eq!(
            sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// git treats a valueless `mirror` key as true, while `git config --get`
    /// answers an empty string. The plan must not read that as "not a mirror":
    /// the real push would still mirror the whole namespace.
    #[test]
    fn a_valueless_remote_mirror_key_is_refused() {
        let dir = scratch("mirror-bool");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(
            &dir,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/acme/repo.git",
            ],
        );
        let repo = crate::git::Repo::for_test(
            &dir.to_string_lossy(),
            Some("https://github.com/acme/repo.git"),
        );
        assert!(!remote_mirrors(&repo, "origin"));
        let config = dir.join(".git").join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("\n[remote \"origin\"]\n\tmirror\n");
        std::fs::write(&config, text).unwrap();
        assert!(
            remote_mirrors(&repo, "origin"),
            "a valueless mirror key is true to git and must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The publication surface refuses every write that lands content or moves
    /// refs, including absolute-URL forms, while reads and metadata writes
    /// stay open. An absolute URL that no longer normalizes silently unguards
    /// the whole list, so that form is exercised explicitly.
    #[test]
    fn the_api_broker_refuses_every_mutating_verb() {
        for (method, path) in [
            ("PUT", "/repos/o/r/contents/src/lib.rs"),
            ("POST", "/repos/o/r/git/refs"),
            ("POST", "/repos/o/r/git/tags"),
            ("PATCH", "/repos/o/r/git/refs/heads/main"),
            ("DELETE", "/repos/o/r/git/refs/heads/stale"),
            ("POST", "/repos/o/r/merges"),
            ("POST", "/repos/o/r/merge-upstream"),
            ("POST", "/repos/o/r/pulls"),
            ("PUT", "/repos/o/r/pulls/7/merge"),
            ("PUT", "/repos/o/r/pulls/7/update-branch"),
            ("POST", "/repos/o/r/releases"),
            ("PATCH", "/repos/o/r/releases/9"),
            ("POST", "/repos/o/r/statuses/deadbeef"),
            // The publication surface is safe only if absolute URLs still
            // normalize onto the path the match runs against.
            ("POST", "https://api.github.com/repos/o/r/statuses/deadbeef"),
            // A dot segment is resolved by curl/the server after matching, so
            // every spelling of it is refused instead of matched raw.
            ("POST", "/repos/o/r/../r/statuses/deadbeef"),
            ("PUT", "/repos/o/r/contents/../../r/contents/src/lib.rs"),
            ("POST", "/repos/o/r/./git/refs"),
            ("POST", "/repos/o/r/%2e%2e/r/statuses/deadbeef"),
            ("POST", "/repos/o/r/%2E%2E/r/git/refs"),
            ("POST", "/repos/o/r/.%2e/r/releases"),
            ("POST", "/repos/o/r/%2e%2e%2fr/statuses/deadbeef"),
            ("POST", "/repos/o/r/..%5Cr/statuses/deadbeef"),
            // A percent-encoded route name must match the route the server
            // will decode, not slip past as an unknown segment.
            ("POST", "/repos/o/r/%63ontents/src/lib.rs"),
            ("PUT", "/repos/o/r/%63%6f%6e%74%65%6e%74%73/src/lib.rs"),
            ("POST", "/repos/o/r/%67it/refs"),
            ("PUT", "/repos/o/r/pulls/7/%6derge"),
            ("POST", "/repos/o/r/%72eleases"),
            // An encoded separator changes the segment boundaries after the
            // check; a doubly encoded one still carries a percent escape.
            // The doubled form is refused across the whole path, including
            // owner/repo, so it cannot shift where the surface starts.
            ("POST", "/repos/o/r/contents%2Fsrc%2Flib.rs"),
            ("POST", "/repos/o/r/statuses%2Fdeadbeef"),
            ("POST", "/repos/o/r/releases%252F9"),
            ("POST", "/repos/o%252fr/r/contents/x"),
            ("POST", "/repos/o/r%252f..%252fstatuses/deadbeef"),
            // CI-authority surfaces: every write under actions can trigger a
            // privileged workflow - dispatch, rerun, approval - so the whole
            // subtree refuses on any mutating verb, not only dispatches.
            ("POST", "/repos/o/r/dispatches"),
            ("POST", "/repos/o/r/actions/workflows/ci.yml/dispatches"),
            ("POST", "/repos/o/r/actions/workflows/42/dispatches"),
            ("POST", "/repos/o/r/actions/runs/42/rerun"),
            ("POST", "/repos/o/r/actions/runs/42/approve"),
            ("POST", "/repos/o/r/actions/runs/42/cancel"),
            ("DELETE", "/repos/o/r/actions/runs/42/logs"),
            ("PUT", "/repos/o/r/actions/permissions/access"),
            // GraphQL mutations reach every write surface inside a body this
            // classifier cannot audit; the endpoint is refused outright.
            ("POST", "/graphql"),
            ("POST", "https://api.github.com/graphql"),
            ("POST", "/graphql?query=mutation{createRef}"),
            // A query suffix is a parameter, not part of the route: the
            // classifier must not let it detach the final segment from the
            // match, and refusal text must not echo it (it can carry a
            // credential parameter).
            ("POST", "/graphql?access_token=REDACTED"),
            ("PUT", "/repos/o/r/contents/src/lib.rs?ref=main"),
            ("POST", "/repos/o/r/merges?base=main"),
            ("POST", "/repos/o/r/dispatches?client_payload=x"),
            ("POST", "/repos/o/r/actions/runs/42/rerun?force=true"),
            // Repository-lifecycle, ref-moving and trust-moving writes mint
            // or move publication homes without an audited push.
            ("POST", "/repos/o/r/forks"),
            ("POST", "/repos/o/r/generate"),
            ("PUT", "/repos/o/r/import"),
            ("POST", "/repos/o/r/transfer"),
            ("POST", "/repos/o/r/branches/main/rename"),
            ("PATCH", "/repos/o/r/branches/main/protection"),
            ("POST", "/repos/o/r/pages/builds"),
            ("POST", "/repos/o/r/keys"),
            ("POST", "/repos/o/r/hooks"),
            ("POST", "/repos/o/r/deployments"),
            // CI check, ruleset and environment-secret controls: a check
            // run spends CI authority, a ruleset rewrites ref protection,
            // an environment write rewrites secrets - all named refuses.
            ("POST", "/repos/o/r/check-runs"),
            ("POST", "/repos/o/r/check-suites"),
            ("PATCH", "/repos/o/r/check-runs/9"),
            ("POST", "/repos/o/r/rulesets"),
            ("PUT", "/repos/o/r/rulesets/5"),
            ("DELETE", "/repos/o/r/rules/branch/main"),
            ("PUT", "/repos/o/r/environments/prod"),
            ("PUT", "/repos/o/r/environments/prod/secrets/K"),
            // The repository root's mutating verbs are the widest surface:
            // visibility flips, renames, archives and deletion.
            ("PATCH", "/repos/o/r"),
            ("DELETE", "/repos/o/r"),
            ("PUT", "/repos/o/r"),
            // Trust-moving surfaces fail closed without being named:
            // collaborators, invitations, app installation, advisory
            // workspaces and tag protection all land on the deny default.
            ("PUT", "/repos/o/r/collaborators/bob"),
            ("POST", "/repos/o/r/security-advisories"),
            ("POST", "/repos/o/r/tags/protection"),
            ("PUT", "/repos/o/r/installation"),
            ("POST", "/repos/o/r/invitations/3"),
            ("PUT", "/repos/o/r/automated-security-fixes"),
            ("PUT", "/repos/o/r/vulnerability-alerts"),
            // An unmodelled surface GitHub adds tomorrow fails closed too.
            ("POST", "/repos/o/r/whatever-comes-next"),
            // Repo and migration creation outside repos/* publishes new
            // homes without the gate ever seeing a push.
            ("POST", "/user/repos"),
            ("POST", "/orgs/acme/repos"),
            ("POST", "/user/migrations"),
            ("POST", "/orgs/acme/migrations"),
            // There is no verified-safe metadata write through the generic
            // broker: every repository mutation emits events (issues,
            // label, milestone, project, issue_comment, commit_comment,
            // pull_request, repository) that can trigger privileged
            // Actions workflows with repository credentials - CI authority
            // the audit never saw spent. All of these now refuse.
            ("POST", "/repos/o/r/issues"),
            ("POST", "/repos/o/r/issues/3/comments"),
            ("PATCH", "/repos/o/r/issues/9"),
            ("PATCH", "/repos/o/r/pulls/7"),
            ("POST", "/repos/o/r/labels"),
            ("POST", "/repos/o/r/milestones"),
            ("PUT", "/repos/o/r/topics"),
            ("POST", "/repos/o/r/issues/9/assignees"),
            ("POST", "/repos/o/r/projects"),
            ("PATCH", "/repos/o/r/comments/4"),
            ("POST", "/repos/o/r/commit_comments"),
            ("POST", "/repos/o/r/pulls/7/comments"),
            ("POST", "/repos/o/r/pulls/7/reviews"),
            ("POST", "/repos/o/r/issues?milestone=1"),
            // Account-level trust and metadata writes outside repos/*
            // fail the same way - an unmodelled route refuses.
            ("POST", "/user/keys"),
            ("POST", "/user/emails"),
            ("PATCH", "/user"),
            ("POST", "/user/gpg_keys"),
        ] {
            assert!(
                publication_surface(method, path).is_some(),
                "{method} {path} mutates outside the audit and must be refused"
            );
        }
        for (method, path) in [
            ("GET", "/repos/o/r/contents/src/lib.rs"),
            ("GET", "/repos/o/r/pulls/7"),
            ("GET", "/repos/o/r/%63ontents/src/lib.rs"), // a read stays a read
            ("GET", "/repos/o/r/issues"),
            ("GET", "/repos/o/r/issues/3/comments"),
            ("GET", "/repos/o/r/actions/runs"), // an Actions read stays open
            ("GET", "/repos/o/r/actions/runs/42/logs"), // logs are metadata reads
            ("GET", "/repos/o/r/check-runs"),   // checks read fine
            ("GET", "/repos/o/r/environments/prod/secrets/K"), // secrets' names read
            ("HEAD", "/repos/o/r/releases/latest"),
            ("OPTIONS", "/repos/o/r"),
            ("GET", "/user/repos"),
            ("GET", "/orgs/acme/repos"),
            // Query parameters on a read stay open.
            ("GET", "/repos/o/r/issues?milestone=1"),
        ] {
            assert!(
                publication_surface(method, path).is_none(),
                "{method} {path} is a read and must stay open"
            );
        }
    }

    /// `check` outside a hook has no ref list on stdin; the synthesized lines
    /// must name every outgoing branch with its upstream (or zeros for a
    /// first push) so the gate reviews real targets instead of passing empty.
    #[test]
    fn a_hookless_check_synthesizes_the_refs_a_push_would_carry() {
        let dir = std::env::temp_dir().join(format!(
            "gv-check-refs-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-b", "main"]);
        std::fs::write(dir.join("a"), "a").unwrap();
        git(&dir, &["add", "a"]);
        git(&dir, &["commit", "-m", "a"]);
        let first = git(&dir, &["rev-parse", "HEAD"]);
        // main tracks an upstream that is one commit behind: an outgoing push.
        git(
            &dir,
            &["remote", "add", "origin", "git@github.com:Owner/Repo.git"],
        );
        git(&dir, &["update-ref", "refs/remotes/origin/main", &first]);
        git(&dir, &["config", "branch.main.remote", "origin"]);
        git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
        std::fs::write(dir.join("b"), "b").unwrap();
        git(&dir, &["add", "b"]);
        git(&dir, &["commit", "-m", "b"]);
        let head = git(&dir, &["rev-parse", "HEAD"]);
        // feature has no upstream: a first push, remote sha is zeros.
        git(&dir, &["checkout", "-b", "feature"]);

        let stdin = outgoing_push_stdin(&crate::git::Repo::for_test(
            &dir.to_string_lossy(),
            Some("git@github.com:Owner/Repo.git"),
        ));
        assert!(
            stdin.contains(&format!("refs/heads/main {head} refs/heads/main {first}")),
            "{stdin}"
        );
        assert!(
            stdin.contains(&format!(
                "refs/heads/feature {head} refs/heads/feature {}",
                "0".repeat(40)
            )),
            "{stdin}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Push arguments keep flags out of the positionals: the remote is the
    /// first bare word, refspecs the rest, and value-flags consume their
    /// token so `-o ci.skip` never reads as a ref name.
    #[test]
    fn push_args_split_flags_from_the_remote_and_refspecs() {
        let parsed = parse_push_args(&[
            "-u".into(),
            "--force".into(),
            "origin".into(),
            "main".into(),
            "dev:stable".into(),
        ]);
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert_eq!(parsed.refspecs, ["main", "dev:stable"]);

        let parsed = parse_push_args(&[
            "-o".into(),
            "ci.skip".into(),
            "--delete".into(),
            "origin".into(),
            "old".into(),
        ]);
        assert!(parsed.delete);
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert_eq!(parsed.refspecs, ["old"]);

        let parsed = parse_push_args(&["--tags".into(), "origin".into()]);
        assert!(parsed.tags);
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert!(parsed.refspecs.is_empty());

        // With --repo the first positional is a refspec, not the remote.
        let parsed = parse_push_args(&[
            "--repo".into(),
            "origin".into(),
            "main".into(),
            "dev".into(),
        ]);
        assert_eq!(parsed.remote.as_deref(), Some("origin"));
        assert_eq!(parsed.refspecs, ["main", "dev"]);

        // Ref-selection options that bypass the pre-audit's enumeration are
        // recognised, including git's unambiguous long-option abbreviations.
        for spelling in ["--no-verify", "--no-verif", "--no-v"] {
            let parsed = parse_push_args(&[spelling.into(), "origin".into()]);
            assert!(parsed.no_verify, "{spelling}");
            assert!(parsed.unmodelled().is_some(), "{spelling}");
        }
        for spelling in ["--stdin", "--stdi", "--std"] {
            let parsed = parse_push_args(&[spelling.into(), "origin".into()]);
            assert!(parsed.read_stdin, "{spelling}");
            assert!(parsed.unmodelled().is_some(), "{spelling}");
        }
        for spelling in ["--follow-tags", "--follow-tag", "--follow"] {
            let parsed = parse_push_args(&[spelling.into(), "origin".into()]);
            assert!(parsed.follow_tags, "{spelling}");
            assert!(parsed.unmodelled().is_some(), "{spelling}");
        }
        // A push-option value is not a flag, even when it names one.
        let parsed = parse_push_args(&["-o".into(), "--no-verify".into(), "origin".into()]);
        assert!(!parsed.no_verify);
        assert!(parsed.unmodelled().is_none());
    }

    /// `gitvault push` audits what this push actually carries: the refspec
    /// arguments and the local mirror decide the ref lines, so a partial
    /// push never pays for branches that stay home and never skips the ones
    /// that move.
    #[test]
    fn a_push_plan_maps_the_refs_the_push_carries() {
        let dir = std::env::temp_dir().join(format!(
            "gv-push-plan-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-b", "main"]);
        std::fs::write(dir.join("a"), "a").unwrap();
        git(&dir, &["add", "a"]);
        git(&dir, &["commit", "-m", "a"]);
        let first = git(&dir, &["rev-parse", "HEAD"]);
        git(
            &dir,
            &["remote", "add", "origin", "git@github.com:Owner/Repo.git"],
        );
        git(&dir, &["update-ref", "refs/remotes/origin/main", &first]);
        git(&dir, &["config", "branch.main.remote", "origin"]);
        git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
        std::fs::write(dir.join("b"), "b").unwrap();
        git(&dir, &["add", "b"]);
        git(&dir, &["commit", "-m", "b"]);
        let head = git(&dir, &["rev-parse", "HEAD"]);
        git(&dir, &["checkout", "-b", "feature"]);
        git(&dir, &["tag", "v1"]);
        let zeros = "0".repeat(40);
        let repo = crate::git::Repo::for_test(
            &dir.to_string_lossy(),
            Some("git@github.com:Owner/Repo.git"),
        );

        // A bare push follows push.default simple. `feature` has no upstream
        // yet, so git would refuse; the wrapper must not synthesize one.
        let error = push_plan(&repo, &[]).unwrap_err();
        assert!(error.to_string().contains("no upstream branch"), "{error}");
        git(&dir, &["config", "branch.feature.remote", "origin"]);
        git(
            &dir,
            &["config", "branch.feature.merge", "refs/heads/feature"],
        );
        let plan = push_plan(&repo, &[]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("refs/heads/feature {head} refs/heads/feature {zeros}\n")
        );
        assert_eq!(plan.refs[0].git_refspec(), "refs/heads/feature");
        for required in ["--no-follow-tags", "--no-recurse-submodules", "--no-prune"] {
            assert!(
                plan.args.iter().any(|arg| arg == required),
                "{required}: {:?}",
                plan.args
            );
        }

        // A differently named upstream is the other `simple` refusal: git
        // will not silently push the branch to the upstream's name.
        git(
            &dir,
            &["config", "branch.feature.merge", "refs/heads/release"],
        );
        let error = push_plan(&repo, &[]).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
        git(
            &dir,
            &["config", "branch.feature.merge", "refs/heads/feature"],
        );

        // `upstream` pushes to the upstream name; it refuses a push remote
        // that is not the branch's upstream remote, exactly as git does.
        git(&dir, &["config", "push.default", "upstream"]);
        let plan = push_plan(&repo, &[]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("refs/heads/feature {head} refs/heads/feature {zeros}\n")
        );
        git(
            &dir,
            &["remote", "add", "fork", "git@github.com:Owner/Fork.git"],
        );
        git(&dir, &["config", "branch.feature.pushRemote", "fork"]);
        assert!(
            push_plan(&repo, &[])
                .unwrap_err()
                .to_string()
                .contains("not the upstream"),
            "an upstream push to another remote must refuse"
        );
        git(&dir, &["config", "--unset", "branch.feature.pushRemote"]);

        // `simple` treats another push remote as `current`: no upstream is
        // required and the branch keeps its own name.
        git(&dir, &["config", "push.default", "simple"]);
        git(&dir, &["config", "--unset", "branch.feature.merge"]);
        git(&dir, &["config", "--unset", "branch.feature.remote"]);
        git(&dir, &["config", "branch.feature.pushRemote", "fork"]);
        git(&dir, &["update-ref", "refs/remotes/fork/feature", &head]);
        let plan = push_plan(&repo, &[]).unwrap();
        assert_eq!(plan.remote.as_deref(), Some("fork"));
        assert_eq!(
            plan.stdin,
            format!("refs/heads/feature {head} refs/heads/feature {head}\n")
        );

        // `remote.pushDefault` is the next step of git's precedence; the
        // mirror lookup and the reconstructed push use the same name.
        git(&dir, &["config", "--unset", "branch.feature.pushRemote"]);
        git(&dir, &["config", "remote.pushDefault", "fork"]);
        let plan = push_plan(&repo, &[]).unwrap();
        assert_eq!(plan.remote.as_deref(), Some("fork"));
        assert_eq!(plan.refs[0].remote_sha, head);
        // An explicit remote still wins over every configured default.
        let plan = push_plan(&repo, &["origin".into(), "feature".into()]).unwrap();
        assert_eq!(plan.remote.as_deref(), Some("origin"));
        git(&dir, &["config", "--unset", "remote.pushDefault"]);

        // `matching` is defined by the remote's advertised heads, not by the
        // local mirror. Seed a real remote with main+feature and prove a head
        // the remote does not advertise is neither audited nor sent.
        let advertised = dir.join("advertised.git");
        git(
            &dir,
            &["init", "--bare", "-q", advertised.to_str().unwrap()],
        );
        // Push the objects the bare remote will advertise; the test's local
        // commits do not otherwise exist in its object store.
        git(
            &dir,
            &["remote", "add", "advertised", advertised.to_str().unwrap()],
        );
        git(
            &dir,
            &["push", "-q", "advertised", "feature:refs/heads/feature"],
        );
        // The remote's main is the earlier commit, deliberately different
        // from the local mirror the old selection would have consulted.
        git(&advertised, &["update-ref", "refs/heads/main", &first]);
        git(&dir, &["branch", "local-only"]);
        // A stale mirror must not select a head the remote does not have.
        git(
            &dir,
            &["update-ref", "refs/remotes/advertised/local-only", &head],
        );
        git(&dir, &["config", "branch.feature.pushRemote", "advertised"]);
        git(&dir, &["config", "push.default", "matching"]);
        let plan = push_plan(&repo, &[]).unwrap();
        let matching: Vec<&str> = plan.refs.iter().map(|r| r.remote_ref.as_str()).collect();
        assert_eq!(
            matching,
            vec!["refs/heads/feature", "refs/heads/main"],
            "{matching:?}"
        );
        let by_ref = |name: &str| {
            plan.refs
                .iter()
                .find(|r| r.remote_ref == name)
                .map(|r| r.remote_sha.clone())
        };
        assert_eq!(
            by_ref("refs/heads/main"),
            Some(first.clone()),
            "the advertised object id, not the mirror, is the review base"
        );
        assert_eq!(by_ref("refs/heads/feature"), Some(head.clone()));
        // A matching push whose remote cannot be read refuses: git would
        // select from refs this wrapper never saw.
        git(
            &dir,
            &[
                "remote",
                "add",
                "offline",
                "/nonexistent/gitvault-matching-remote",
            ],
        );
        git(&dir, &["config", "branch.feature.pushRemote", "offline"]);
        let error = push_plan(&repo, &[]).unwrap_err();
        assert!(
            error.to_string().contains("advertised heads"),
            "an unreadable matching remote must refuse: {error}"
        );
        git(&dir, &["config", "--unset", "branch.feature.pushRemote"]);
        git(&dir, &["config", "--unset", "push.default"]);

        // An unknown mode is a refusal, not a guess at what git meant.
        git(&dir, &["config", "push.default", "sideways"]);
        assert!(push_plan(&repo, &[]).is_err());
        git(&dir, &["config", "--unset", "push.default"]);

        // An explicit refspec audits that ref alone, against its mirror.
        git(&dir, &["update-ref", "refs/remotes/origin/feature", &head]);
        let plan = push_plan(&repo, &["origin".into(), "main".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("refs/heads/main {head} refs/heads/main {first}\n")
        );
        assert_eq!(plan.refs[0].git_refspec(), "refs/heads/main");

        // `git push origin HEAD` publishes the current branch, not a branch
        // literally named HEAD. The hook line keeps the source spelling.
        let plan = push_plan(&repo, &["origin".into(), "HEAD".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("HEAD {head} refs/heads/feature {head}\n")
        );
        assert_eq!(plan.refs[0].git_refspec(), "HEAD:refs/heads/feature");
        let plan = push_plan(&repo, &["origin".into(), "HEAD:release".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("HEAD {head} refs/heads/release {zeros}\n")
        );

        // src:dst names the destination; a delete carries the zero head.
        let plan = push_plan(&repo, &["origin".into(), "main:release".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("refs/heads/main {head} refs/heads/release {zeros}\n")
        );
        assert_eq!(
            plan.refs[0].git_refspec(),
            "refs/heads/main:refs/heads/release"
        );
        // A deletion resolves against the tag and branch namespaces, and both
        // the audit line and the refspec name the same remote ref.
        git(&dir, &["branch", "old", &first]);
        let plan = push_plan(&repo, &["origin".into(), "--delete".into(), "v1".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("(delete) {zeros} refs/tags/v1 {zeros}\n")
        );
        assert_eq!(plan.refs[0].git_refspec(), ":refs/tags/v1");
        let plan = push_plan(&repo, &["origin".into(), "--delete".into(), "old".into()]).unwrap();
        assert_eq!(plan.refs[0].remote_ref, "refs/heads/old");
        assert_eq!(plan.refs[0].git_refspec(), ":refs/heads/old");
        let plan = push_plan(&repo, &["origin".into(), ":v1".into()]).unwrap();
        assert_eq!(plan.refs[0].git_refspec(), ":refs/tags/v1");
        // A name in both namespaces is ambiguous: refusing is the only way
        // the audit and git cannot disagree about what is deleted.
        git(&dir, &["tag", "dup", &first]);
        git(&dir, &["branch", "dup", &first]);
        let error =
            push_plan(&repo, &["origin".into(), "--delete".into(), "dup".into()]).unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error}");
        git(&dir, &["tag", "-d", "dup"]);
        git(&dir, &["branch", "-D", "dup"]);
        // A name in neither namespace needs the full ref.
        let error =
            push_plan(&repo, &["origin".into(), "--delete".into(), "ghost".into()]).unwrap_err();
        assert!(
            error.to_string().contains("no local branch or tag"),
            "{error}"
        );
        // A fully qualified deletion is carried through unchanged.
        let plan = push_plan(
            &repo,
            &["origin".into(), "--delete".into(), "refs/heads/old".into()],
        )
        .unwrap();
        assert_eq!(plan.refs[0].git_refspec(), ":refs/heads/old");

        // A forced source keeps its plus so git is told the same thing the
        // audit was told.
        let plan = push_plan(&repo, &["origin".into(), "+main:release".into()]).unwrap();
        assert_eq!(
            plan.refs[0].git_refspec(),
            "+refs/heads/main:refs/heads/release"
        );

        // --tags enumerates tags; a missing source refuses like git would.
        let plan = push_plan(&repo, &["origin".into(), "--tags".into()]).unwrap();
        assert_eq!(
            plan.stdin,
            format!("refs/tags/v1 {head} refs/tags/v1 {zeros}\n")
        );
        assert_eq!(plan.refs[0].git_refspec(), "refs/tags/v1");
        // With the tag gone, `--tags` selects nothing; it must not fall back
        // to push.default and send the current branch.
        git(&dir, &["tag", "-d", "v1"]);
        let plan = push_plan(&repo, &["origin".into(), "--tags".into()]).unwrap();
        assert!(
            plan.refs.is_empty(),
            "--tags with no tags selected {}",
            plan.refs.len()
        );
        assert!(push_plan(&repo, &["origin".into(), "nosuch".into()]).is_err());

        // The wrapper refuses what its pre-audit cannot enumerate. In
        // particular --no-verify would skip the hook that re-checks the refs
        // git actually advertises, so the pre-audit could not be the last
        // word either.
        for option in [
            "--no-verify",
            "--no-v",
            "--stdin",
            "--follow-tags",
            "--prune",
            "--prun",
            "--mirror",
            "--branches=release*",
            "--recurse-submodules=on-demand",
            "--unknown-option",
        ] {
            let error = push_plan(&repo, &["origin".into(), option.into()]).unwrap_err();
            assert!(
                error.to_string().contains("refuses this option")
                    || error.to_string().contains("refuses --delete"),
                "{option}: {error}"
            );
        }
        assert!(
            push_plan(
                &repo,
                &["origin".into(), "--delete".into(), "--tags".into()]
            )
            .is_err()
        );

        // `remote.<name>.mirror=true` makes git push the whole ref namespace;
        // `--no-mirror` does not override it, so the row must refuse before
        // the audit is spent on a set the plan cannot enumerate.
        git(&dir, &["config", "remote.origin.mirror", "true"]);
        let error = push_plan(&repo, &["origin".into(), "main".into()]).unwrap_err();
        assert!(
            error.to_string().contains("mirror=true"),
            "a mirror-configured remote must refuse: {error}"
        );
        git(&dir, &["config", "--unset", "remote.origin.mirror"]);
        assert!(push_plan(&repo, &["origin".into(), "main".into()]).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `remote.<name>.push` outranks `push.default` for a bare push. Its
    /// configured refspecs can rename, force or delete refs, so following
    /// push.default would audit a different set than git would publish. The
    /// bare push refuses; an explicit refspec or selector overrides the
    /// configured list exactly as it does in git.
    #[test]
    fn a_configured_remote_push_refspec_refuses_a_bare_push() {
        let dir = std::env::temp_dir().join(format!(
            "gv-configured-push-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-b", "main"]);
        std::fs::write(dir.join("a"), "a").unwrap();
        git(&dir, &["add", "a"]);
        git(&dir, &["commit", "-m", "a"]);
        git(
            &dir,
            &["remote", "add", "origin", "git@github.com:Owner/Repo.git"],
        );
        git(&dir, &["config", "branch.main.remote", "origin"]);
        git(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
        let repo = crate::git::Repo::for_test(
            &dir.to_string_lossy(),
            Some("git@github.com:Owner/Repo.git"),
        );
        assert!(push_plan(&repo, &[]).is_ok());

        git(
            &dir,
            &[
                "config",
                "remote.origin.push",
                "refs/heads/main:refs/heads/release",
            ],
        );
        let error = push_plan(&repo, &[]).unwrap_err();
        assert!(
            error.to_string().contains("remote.origin.push"),
            "a configured refspec must refuse a bare push: {error}"
        );
        // An explicit refspec bypasses the configured list and is audited as
        // written.
        let plan = push_plan(&repo, &["origin".into(), "main".into()]).unwrap();
        assert_eq!(plan.refs[0].remote_ref, "refs/heads/main");
        // A selector is the other override git honors.
        assert!(push_plan(&repo, &["origin".into(), "--tags".into()]).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A repository-local hook that starts a nested `git push` must not escape
    /// the gate, and the recursion must stay bounded: the nested push
    /// re-enters the dispatcher and is audited as a publication of its own,
    /// but the chain marker stops the local hook from running again. The
    /// hook below nests UNCONDITIONALLY - it is the dispatcher's chain, not
    /// the repository's cooperation, that bounds the recursion at one nested
    /// dispatch per hook name.
    #[test]
    fn a_local_hooks_nested_push_is_gated_again() {
        let dir = scratch("nested-push");
        let remote = dir.join("remote.git");
        let repo = dir.join("repo");
        let hooks = dir.join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        git(&dir, &["init", "-q", "--bare", remote.to_str().unwrap()]);
        git(&dir, &["init", "-q", "-b", "main", repo.to_str().unwrap()]);
        std::fs::write(repo.join("a"), "a").unwrap();
        git(&repo, &["add", "a"]);
        git(&repo, &["commit", "-m", "a"]);

        // The gate is a stub executable that records each invocation; the
        // dispatcher under test is the real generated script pointed at it.
        let gate = dir.join("gate");
        let log = dir.join("gate.log");
        std::fs::write(
            &gate,
            format!("#!/bin/sh\necho \"$*\" >> \"{}\"\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(hooks.join("_dispatch"), dispatcher_script(&gate)).unwrap();
        std::fs::write(hooks.join("pre-push"), hook_stub_script("pre-push")).unwrap();
        for script in ["_dispatch", "pre-push"] {
            std::fs::set_permissions(hooks.join(script), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        // The repository-controlled hook nests unconditionally: every nested
        // dispatch gates the push it carries, and the chain marker is what
        // stops the recursion - not anything the repository chooses.
        let githooks = repo.join(".githooks");
        std::fs::create_dir_all(&githooks).unwrap();
        std::fs::write(
            githooks.join("pre-push"),
            "#!/bin/sh\ngit push origin HEAD:refs/heads/nested 2>/dev/null || true\n",
        )
        .unwrap();
        std::fs::set_permissions(
            githooks.join("pre-push"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        git(
            &repo,
            &["config", "core.hooksPath", hooks.to_str().unwrap()],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&repo, &["push", "origin", "HEAD:refs/heads/main"]);

        // One gate for the outer push, one for the nested push the local
        // hook started: exactly two invocations - the chain bound holds and
        // no publication slipped the audit.
        let record = std::fs::read_to_string(&log).unwrap();
        let entries: Vec<&str> = record.lines().collect();
        assert_eq!(entries, ["hook pre-push", "hook pre-push"]);
        // Both refs landed on the remote.
        assert_eq!(
            git(&repo, &["ls-remote", "origin", "refs/heads/*"])
                .lines()
                .count(),
            2
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
