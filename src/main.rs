//! GitVault - hold the identity, intercept the action, run the checkers.
//!
//! The binary is the only component that decides *who* is acting. It never
//! executes code from the repository it inspects: checkers are external commands
//! launched with a neutral working directory, and the repository path reaches them
//! as an absolute argument rather than by changing into it.

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
mod records;
mod seal;
mod sign;
mod ssh;
mod tempsecret;
mod unlock;
mod vault;

use std::io::{IsTerminal, Read};
use std::os::unix::fs::PermissionsExt;
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

    /// Run the registered checkers for a git hook event.
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

    /// Run the registered checkers outside a hook, for testing, for CI, and
    /// to resume reviews a rate-limited provider left unfinished. For
    /// `--event pre-push` the refs git would hand the hook are derived from
    /// the checkout's outgoing branches when stdin supplies none.
    Check {
        #[arg(long, default_value = "pre-commit")]
        event: String,
        #[arg(long, default_value = ".")]
        directory: PathBuf,
        /// Run only this checker.
        #[arg(long)]
        only: Option<String>,
        /// The release tag or exact commit, for `--event release`.
        #[arg(long)]
        tag: Option<String>,
    },

    /// Inspect recorded checker runs.
    ///
    /// Read-only: no vault, no network, no writes. Records are built to be
    /// read by someone other than the person who ran the gate, so nothing
    /// here may describe this machine's paths.
    Records {
        #[command(subcommand)]
        command: RecordsCommand,
    },

    /// Show the effective checker registry.
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

    /// Sign the configuration and the audit policy after editing them.
    ///
    /// Editing `config.toml` or `checkers.toml` stays a plain file edit; this
    /// command is the ceremony that certifies both, gated by the same human
    /// confirmation as releasing a credential. `[[checkers]]` rows still left
    /// in `config.toml` migrate into `checkers.toml` first, so each file is
    /// certified under its own signature.
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
    /// One recorded run, including what each checker printed.
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
            only,
            tag,
        } => cmd_check(
            cli.config.as_ref(),
            &event,
            &directory,
            only.as_deref(),
            tag.as_deref(),
        ),
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
        println!("remote     : {}", repo.remote().unwrap_or("(none)"));
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
    let (cfg, cfg_path, _) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    if let configsig::SigState::Invalid(reason) = &policy_sig {
        eprintln!("warning: audit policy is uncertified - {reason}");
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&policy.checkers)?);
        return Ok(ExitCode::SUCCESS);
    }
    if policy.checkers.is_empty() {
        println!("no checkers registered");
        return Ok(ExitCode::SUCCESS);
    }
    for c in &policy.checkers {
        println!(
            "{:<24} on={:<26} severity={:<9} timeout={}s",
            c.name,
            c.on.join(","),
            c.severity,
            c.timeout_secs
        );
        println!("    kind    : {:?}", c.kind);
        println!("    command : {}", c.command.join(" "));
    }
    Ok(ExitCode::SUCCESS)
}

/// Build the run context shared by `hook` and `check`.
fn context_for(
    cfg: &config::Config,
    event: &str,
    directory: &Path,
    release_tag: Option<String>,
    hook_args: &[String],
) -> anyhow::Result<checkers::Context> {
    let repo = git::Repo::discover(directory)?;
    let outcome = identity::resolve(cfg, &repo, false)?;

    // git hands pre-push its refs on stdin:
    //   <local ref> <local sha> <remote ref> <remote sha>
    // Outside a hook nobody supplies them: a terminal would only block on
    // input nobody intends to type, and an empty list reads as "nothing to
    // review" - a vacuous pass at a publication boundary. `check` then
    // synthesizes the refs a push of this checkout would carry, which is also
    // what a scheduled resume of unfinished reviews needs to drive the gate.
    let stdin = if event == "pre-push" {
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
        pr_head: None,
        pr_number: None,
        release_tag,
        release_commit,
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

/// Run the certified audit policy and print the report BEFORE any signature
/// question is asked. Audits first, blessing after: the routing signature only
/// gates the verdict, never the audit.
///
/// `pre-push`, `pr` and `release` are publication boundaries unconditionally:
/// they spend credentials or put content on GitHub, so an uncertified policy
/// or routing table refuses them even when the policy registers no checkers -
/// an emptied policy file must never read as "no audit required". Every other
/// event is held to the signatures only when the policy's commands would
/// actually execute: an event the policy says nothing about runs nothing, and
/// local work (commits, messages) is never held hostage to a blessing.
/// `allow_proposed` splits the audit tool from the enforcement path: `check`
/// audits a policy as a *proposal* - the evidence must exist before the
/// blessing can be asked for - while hooks and publication fail closed.
/// The directory `gitvault-review install` materializes checker contracts
/// into. A proposed policy may only run contracts living here - the install
/// surface is operator-controlled, so a contract inside it is not something a
/// tampered checkers.toml could have written.
fn profiles_root() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".local")
                .join("share")
        });
    base.join("gitvault").join("profiles")
}

/// Whether one row of an uncertified ("proposed") policy may execute. The
/// signature boundary exists because checker rows are arbitrary code, so a
/// proposal may only invoke the trusted audit runner that lives beside this
/// binary: `baseline`, or `run --contract` on a contract installed under the
/// profiles root. Anything else must refuse the run, not be skipped - an
/// unsigned file sneaking in a foreign command cannot launder a partial audit.
fn admissible_proposed_row(
    checker: &config::Checker,
    repo_root: &Path,
) -> Result<Option<PathBuf>, String> {
    if checker.kind != config::Kind::Exec {
        return Err(format!(
            "kind '{:?}' is not the plain exec a proposal may run",
            checker.kind
        ));
    }
    // A proposal gets no environment of its own at all: `GITVAULT_*` context
    // would retarget the audit and loader variables like DYLD_* or PATH turn
    // the trusted runner into a different process. Installed rows carry none.
    if let Some(key) = checker.env.keys().next() {
        return Err(format!(
            "env '{key}' — a proposal may not override the runner environment"
        ));
    }
    let declared = checker.command.first().map(String::as_str).unwrap_or("");
    let trusted = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("gitvault-review")))
        .ok_or_else(|| "the audit runner sibling is not installed".to_string())?;
    let trusted = std::fs::canonicalize(&trusted).unwrap_or(trusted);
    let declared_path = std::fs::canonicalize(declared)
        .map_err(|_| format!("command '{declared}' does not resolve"))?;
    if declared_path != trusted {
        return Err(format!(
            "command '{declared}' is not the audit runner next to this binary"
        ));
    }
    // Exact argument shape: the runner may only ever audit this repository.
    // `{repo}` resolves to the run context's root; a literal path must be the
    // same directory so a proposal cannot grade an unrelated tree.
    let tail = &checker.command[1..];
    let mut contract: Option<PathBuf> = None;
    let mut seen_repo = false;
    let sub = tail.first().map(String::as_str).unwrap_or("");
    if sub != "baseline" && sub != "run" {
        return Err(format!(
            "subcommand '{sub}' is not one a proposal may invoke"
        ));
    }
    let mut args = tail[1..].iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--repo" => {
                if seen_repo {
                    return Err("duplicate --repo".to_string());
                }
                seen_repo = true;
                let value = args.next().ok_or("--repo without a value")?;
                if value != "{repo}" {
                    let canon = std::fs::canonicalize(value)
                        .map_err(|_| format!("--repo '{value}' does not resolve"))?;
                    let root = std::fs::canonicalize(repo_root)
                        .unwrap_or_else(|_| repo_root.to_path_buf());
                    if canon != root {
                        return Err(format!(
                            "--repo '{value}' is not the repository under review"
                        ));
                    }
                }
            }
            "--contract" if sub == "run" => {
                if contract.is_some() {
                    return Err("duplicate --contract".to_string());
                }
                let value = args.next().ok_or("--contract without a value")?;
                contract = Some(proposed_contract_path_at(value)?);
            }
            other => return Err(format!("argument '{other}' is outside the audit shape")),
        }
    }
    if !seen_repo {
        return Err("missing --repo binding to the repository under review".to_string());
    }
    if sub == "run" && contract.is_none() {
        return Err("run without --contract".to_string());
    }
    Ok(contract)
}

/// The `--contract` a proposed `run` row may name, as a path value.
fn proposed_contract_path_at(contract: &str) -> Result<PathBuf, String> {
    let contract_path = std::fs::canonicalize(contract)
        .map_err(|_| format!("contract '{contract}' does not resolve"))?;
    let root = std::fs::canonicalize(profiles_root()).unwrap_or_else(|_| profiles_root());
    if contract_path.starts_with(&root) {
        Ok(contract_path)
    } else {
        Err(format!(
            "contract '{contract}' is outside the installed profiles root"
        ))
    }
}

/// Installed reviewer contracts that cover `event` at blocking severity — the
/// operator-controlled set a proposed boundary policy must still audit with.
/// Enumeration, read and parse failures fail closed: an unreadable installed
/// contract cannot silently shrink the set the proposal is checked against.
fn installed_boundary_contracts(event: config::Event) -> Result<Vec<(PathBuf, String)>, String> {
    let root = std::fs::canonicalize(profiles_root()).unwrap_or_else(|_| profiles_root());
    let mut contracts = Vec::new();
    let pattern_dirs = std::fs::read_dir(&root)
        .map_err(|e| format!("cannot enumerate {}: {e}", root.display()))?;
    for pattern_dir in pattern_dirs {
        let pattern_dir =
            pattern_dir.map_err(|e| format!("cannot enumerate {}: {e}", root.display()))?;
        let plugins = pattern_dir.path().join("plugins");
        let entries = match std::fs::read_dir(&plugins) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot enumerate {}: {e}", plugins.display())),
        };
        for entry in entries {
            let entry =
                entry.map_err(|e| format!("cannot enumerate {}: {e}", plugins.display()))?;
            let path = entry.path().join("contract.json");
            if !path.is_file() {
                continue;
            }
            let raw =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let doc = serde_json::from_str::<serde_json::Value>(&raw)
                .map_err(|e| format!("{}: unreadable contract: {e}", path.display()))?;
            let covers = doc["on"]
                .as_array()
                .map(|on| on.iter().any(|e| e.as_str() == Some(event.name())))
                .unwrap_or(false);
            let blocking = doc["severity"].as_str() == Some("blocking");
            if covers && blocking {
                let name = doc["name"].as_str().unwrap_or("?").to_string();
                contracts.push((path, name));
            }
        }
    }
    Ok(contracts)
}

fn audit_gate(
    cfg: &config::Config,
    cfg_sig: &configsig::SigState,
    policy: &config::Policy,
    policy_sig: &configsig::SigState,
    ctx: &checkers::Context,
    operation: &str,
    only: Option<&str>,
    allow_proposed: bool,
) -> anyhow::Result<checkers::Report> {
    let event = config::Event::parse(&ctx.event)?;
    let selected = policy.checkers_for(event);
    let boundary = matches!(
        event,
        config::Event::PrePush | config::Event::Pr | config::Event::Release
    );
    // Rows may carry a `repos` scope that `run_all` honors by dropping
    // non-matching rows. Every completeness judgment below must reason
    // about the rows that would actually execute for this repository -
    // a policy scoped entirely elsewhere must not count as audit evidence.
    let effective: Vec<&config::Checker> = selected
        .iter()
        .copied()
        .filter(|c| only.is_some() || c.applies_to(ctx.repo_slug.as_deref(), &ctx.repo_root))
        .filter(|c| only.is_none_or(|name| c.name == name))
        .collect();
    // Checker rows are arbitrary code, so running them unsigned is the
    // privilege hole this guard closes. `selected` only shapes the refusal
    // message; it is never a precondition for checking the signature.
    if let configsig::SigState::Invalid(reason) = policy_sig
        && (boundary || !selected.is_empty())
    {
        let declared = if selected.is_empty() {
            format!("it registers no checkers for {}", event.name())
        } else {
            format!(
                "it declares:\n    {}",
                selected
                    .iter()
                    .map(|c| format!("{} -> {}", c.name, c.command.join(" ")))
                    .collect::<Vec<_>>()
                    .join("\n    ")
            )
        };
        if !allow_proposed {
            anyhow::bail!(
                "refusing to run an uncertified audit policy: {reason}\n  \
                 {declared}\n  \
                 if this is the policy audits should enforce, certify it: gitvault config sign"
            );
        }
        eprintln!(
            "gitvault: auditing the proposed audit policy (uncertified: {reason})\n  \
             {declared}\n  \
             the signature stays last - certify only after these audits pass: \
             gitvault config sign"
        );
        // `--only` narrows the run to one row, but a boundary proposal's
        // blessing needs evidence from the whole required set - a partial
        // audit that passes must never stand in for it.
        if boundary && only.is_some() {
            anyhow::bail!(
                "refusing to audit the proposed audit policy partially: --only \
                 runs a single checker, but a {} proposal must produce \
                 evidence from every applicable reviewer",
                event.name()
            );
        }
        // Even as a proposal the file stays inert where it counts: only rows
        // that invoke the trusted audit runner beside this binary may run,
        // bound to this repository and this installed contract set. The
        // commands are still audited - as content - by the runners that
        // do execute.
        let mut covered: Vec<(&config::Checker, Option<PathBuf>)> = Vec::new();
        for checker in &selected {
            match admissible_proposed_row(checker, &ctx.repo_root) {
                Ok(contract) => covered.push((checker, contract)),
                Err(why) => anyhow::bail!(
                    "refusing to run the proposed audit policy: checker '{}' \
                     escapes the audit-runner boundary: {why}",
                    checker.name
                ),
            }
        }
        // A boundary proposal cannot downgrade the audit it must produce:
        // the deterministic baseline sweep and every installed blocking
        // contract for this event still run, at blocking severity, or the
        // evidence under-certifies the policy an operator would then sign.
        if boundary && !selected.is_empty() {
            let baseline_kept = covered.iter().any(|(checker, found)| {
                found.is_none()
                    && checker.severity == config::Severity::Blocking
                    && checker.applies_to(ctx.repo_slug.as_deref(), &ctx.repo_root)
            });
            if !baseline_kept {
                anyhow::bail!(
                    "refusing to run the proposed audit policy: the \
                     publication-baseline sweep is missing or downgraded for \
                     {} - a boundary proposal must keep the deterministic \
                     baseline at blocking severity",
                    event.name()
                );
            }
            let installed = installed_boundary_contracts(event).map_err(|why| {
                anyhow::anyhow!(
                    "refusing to run the proposed audit policy: the installed \
                     blocking-reviewer set cannot be established: {why}"
                )
            })?;
            for (contract, name) in installed {
                let hit = covered.iter().any(|(checker, found)| {
                    checker.severity == config::Severity::Blocking
                        && found.as_ref() == Some(&contract)
                        && checker.applies_to(ctx.repo_slug.as_deref(), &ctx.repo_root)
                });
                if !hit {
                    anyhow::bail!(
                        "refusing to run the proposed audit policy: installed \
                         reviewer '{name}' is missing or downgraded for {} - a \
                         boundary proposal must keep every installed blocking \
                         reviewer",
                        event.name()
                    );
                }
            }
        }
    }
    let report = checkers::run_all(cfg, policy, ctx, cfg_sig, policy_sig, only)?;
    report.print(&ctx.event);
    if let configsig::SigState::Invalid(reason) = cfg_sig
        && (boundary || !selected.is_empty())
    {
        anyhow::bail!(
            "audits complete, but the routing table they ran against is uncertified: {reason}\n  \
             certify it: gitvault config sign   (then rerun this {operation})"
        );
    }
    // A publication boundary must produce audit evidence. An empty policy -
    // signed or not - runs only the built-in gates and then vacuously
    // passes, which is precisely the "no audit happened" state a boundary
    // exists to prevent. Signature problems still refuse first; an empty
    // policy adds its own refusal here, not a blessing.
    if boundary && effective.is_empty() {
        let why = if selected.is_empty() {
            format!("no checkers are registered for {}", event.name())
        } else {
            format!(
                "no checkers registered for {} apply to this repository",
                event.name()
            )
        };
        anyhow::bail!(
            "{why} - a publication boundary needs audit evidence, not a \
             vacuous pass"
        );
    }
    Ok(report)
}

/// The publication gate every GitHub-reaching operation must pass: run the
/// checkers registered for the event, print the verdicts, and fail closed.
/// One copy so a new publish path cannot quietly forget it.
fn run_publication_gate(
    cfg: &config::Config,
    cfg_sig: &configsig::SigState,
    policy: &config::Policy,
    policy_sig: &configsig::SigState,
    ctx: &checkers::Context,
    operation: &str,
) -> anyhow::Result<()> {
    let report = audit_gate(
        cfg, cfg_sig, policy, policy_sig, ctx, operation, None, false,
    )?;
    anyhow::ensure!(
        report.exit_code() == ExitCode::SUCCESS,
        "a blocking checker refused this {operation}; nothing was sent to GitHub"
    );
    Ok(())
}

fn cmd_hook(config: Option<&PathBuf>, event: &str, args: &[String]) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    // git runs hooks with cwd set to the top level of the working tree, so "."
    // resolves correctly and no directory argument is needed from the hook shim.
    // For pre-push, argv[0] is the remote the push targets.
    let ctx = context_for(&cfg, event, &PathBuf::from("."), None, args)?;
    let report = audit_gate(
        &cfg,
        &cfg_sig,
        &policy,
        &policy_sig,
        &ctx,
        "operation",
        None,
        false,
    )?;
    if report.exit_code() == ExitCode::SUCCESS && event == "pre-push" {
        // Pending attestations drain on every audited push - including an
        // up-to-date one that moves no refs - so a first push's deferred
        // status always finds a later trigger, ruleset or not.
        drain_pending_attestations(&cfg)?;
        publish_audited_status(&cfg, &ctx)?;
    }
    Ok(report.exit_code())
}

/// Mark every head this push actually audited with the `gitvault/audited`
/// commit status, so a server-side required check can enforce "the reviewed
/// revision is the one that landed" - closing `--no-verify`, the web UI and
/// other machines into the same gate.
///
/// The attestation stays honest by marking only heads the audit examined:
/// the deterministic and semantic review covers every pushed ref, so each
/// new head earns its mark. A `verify` row exercises one candidate revision
/// (the checked-out or first head) - it strengthens the evidence without
/// being the basis for the multi-head marking. A tip already reachable from
/// the pushed remote's refs added no unreviewed content to this audit, so
/// it earns no status here. The credential spend happens now, after the
/// report exists - audits first, blessing after.
fn publish_audited_status(cfg: &config::Config, ctx: &checkers::Context) -> anyhow::Result<()> {
    // Attest where the push lands: the push remote's own repository. A named
    // remote that cannot resolve gets no attestation at all - falling back to
    // an unrelated slug would mark the wrong repository with evidence meant
    // for this one. An unnamed remote (a `check` context) uses origin's slug.
    let slug = match ctx.push_remote.as_deref() {
        Some(name) => match remote_slug(&ctx.repo_root, name) {
            Some(slug) => slug,
            None => {
                eprintln!(
                    "gitvault: push remote '{name}' does not resolve to a repository; \
                     audited status not posted"
                );
                return Ok(());
            }
        },
        None => match ctx.repo_slug.clone() {
            Some(slug) => slug,
            // No remote to attest against; nothing was sent anywhere.
            None => return Ok(()),
        },
    };
    let mut heads: Vec<String> = Vec::new();
    for line in ctx.stdin.as_deref().unwrap_or("").lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(sha) = fields.get(1) else { continue };
        if sha.trim_matches('0').is_empty() {
            continue; // a deletion has no head to mark
        }
        let sha = (*sha).to_string();
        if !heads.contains(&sha) {
            heads.push(sha);
        }
    }
    if heads.is_empty() {
        return Ok(());
    }
    let vault = vault::Vault::open()?;
    for sha in heads {
        // A pushed object is not always a commit: an annotated tag carries its
        // tag object, and /statuses on one 422s - which fail-closed would turn
        // into a refusal after the audits already passed. Peel to the commit;
        // an object with no commit has no status surface and is skipped.
        let Some(commit) = peel_commit(&ctx.repo_root, &sha) else {
            continue;
        };
        // Skip tips the pushed remote already holds: the audit skipped them
        // too, so marking them would attest to a review that never happened.
        // Scoped to the push remote's own mirrors - another remote holding
        // the commit says nothing about this repository, and counting it
        // would deadlock a ruleset that requires the status there.
        let mirror = ctx
            .push_remote
            .as_deref()
            .map(|name| format!("refs/remotes/{name}"))
            .unwrap_or_else(|| "refs/remotes".to_string());
        if git::refs_containing(&ctx.repo_root, &commit, &[&mirror]) {
            continue;
        }
        let code = api::run(cfg, &vault, &audited_status_request(&slug, &commit))?;
        if code != 0 {
            // A status only attaches to a commit GitHub already knows, and a
            // first-time head arrives with this very push. Probe: an unknown
            // commit is the chicken-and-egg case - stage the objects under a
            // ref no branch ruleset watches, post the status against the now
            // known commit, and this same push then lands with its mark.
            // A commit GitHub does know and still cannot mark is a real
            // failure, and the push fails closed rather than landing
            // unattested.
            let known = api::run(cfg, &vault, &commit_known_probe(&slug, &commit))? == 0;
            anyhow::ensure!(
                !known,
                "the audit passed but the `gitvault/audited` status could not be posted \
                 for {commit}; the push is refused rather than landing without its evidence"
            );
            if staged_attestation(cfg, ctx, &vault, &slug, &commit) {
                eprintln!("gitvault: marked {commit:.12} audited on {slug} (objects staged)");
                continue;
            }
            eprintln!(
                "gitvault: {commit:.12} is not on {slug} yet and staging it failed - this \
                 push lands the objects and the remote refuses the ref update for the \
                 missing status; run `git push` again to attest and land (the audits are \
                 already sealed)"
            );
            record_pending_attestation(cfg, &slug, &sha, &ctx.repo_root);
            continue;
        }
        eprintln!("gitvault: marked {commit:.12} audited on {slug}");
    }
    Ok(())
}

/// The `gitvault/audited` commit-status request - one authority for both the
/// immediate and the deferred posting path, so the context a ruleset
/// requires cannot drift between them.
fn audited_status_request(slug: &str, sha: &str) -> api::Request {
    api::Request {
        method: "POST".to_string(),
        path: format!("/repos/{slug}/statuses/{sha}"),
        target: api::Target::Repo(slug.to_string()),
        fields: vec![
            ("state".to_string(), "success".to_string()),
            ("context".to_string(), "gitvault/audited".to_string()),
            (
                "description".to_string(),
                "publication audit passed on this machine".to_string(),
            ),
        ],
        raw_fields: Vec::new(),
        headers: Vec::new(),
        body: None,
        jq: None,
        silent: true,
    }
}

/// Stage a first-time head so the status can post in the same push: push
/// the commit to `refs/gitvault/incoming/<sha>` - a ref branch rulesets do
/// not watch - post the attestation, then delete the staging ref. The
/// status rides the commit, not the ref, so the mark survives the cleanup
/// and the real push lands already attested. `--no-verify` keeps the
/// staging pushes from re-entering this hook. Any failure leaves the
/// caller on the deferred path.
fn staged_attestation(
    cfg: &config::Config,
    ctx: &checkers::Context,
    vault: &vault::Vault,
    slug: &str,
    commit: &str,
) -> bool {
    let Some(remote) = ctx.push_remote.as_deref() else {
        return false;
    };
    let staging = format!("refs/gitvault/incoming/{commit}");
    let stage = std::process::Command::new("git")
        .arg("-C")
        .arg(&ctx.repo_root)
        .args([
            "push",
            "--no-verify",
            "-q",
            remote,
            &format!("{commit}:{staging}"),
        ])
        .output();
    if !stage.map(|out| out.status.success()).unwrap_or(false) {
        return false;
    }
    let marked = api::run(cfg, vault, &audited_status_request(slug, commit))
        .map(|code| code == 0)
        .unwrap_or(false);
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&ctx.repo_root)
        .args(["push", "--no-verify", "-q", remote, &format!(":{staging}")])
        .output();
    marked
}

/// Whether GitHub can name the commit - the chicken-and-egg probe the
/// immediate path uses to tell "lands with this push" from "real posting
/// failure". The deferred path skips it: a failed POST keeps the pending
/// file either way, so the retry itself is the probe.
fn commit_known_probe(slug: &str, sha: &str) -> api::Request {
    api::Request {
        method: "GET".to_string(),
        path: format!("/repos/{slug}/commits/{sha}"),
        target: api::Target::Repo(slug.to_string()),
        fields: Vec::new(),
        raw_fields: Vec::new(),
        headers: Vec::new(),
        body: None,
        jq: None,
        silent: true,
    }
}

/// One deferred `gitvault/audited` posting: the audit that produced it is
/// sealed, only the remote's knowledge of the commit was missing.
fn pending_dir(cfg: &config::Config) -> PathBuf {
    records::run_dir(cfg)
        .parent()
        .map(|dir| dir.join("pending"))
        .unwrap_or_else(|| PathBuf::from("pending"))
}

/// Stash the attestation this push could not post. The file is a reminder,
/// not the authority: it names the pushed object, and the drain re-proves
/// against the sealed record chain before credentials are spent. Only the
/// pushed sha goes in the name so a repeated first push dedupes itself.
fn record_pending_attestation(cfg: &config::Config, slug: &str, sha: &str, repo: &Path) {
    let dir = pending_dir(cfg);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let name = format!("{}__{}.json", slug.replace('/', "_"), sha);
    let body = serde_json::json!({
        "slug": slug,
        "sha": sha,
        "repo": repo,
        "recorded_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    let _ = std::fs::write(
        dir.join(name),
        serde_json::to_string_pretty(&body).unwrap_or_default(),
    );
}

/// Read one pending attestation file into `(slug, pushed sha, repo)`. Slug
/// and sha are shape-checked before either can reach a request path or a
/// `git` argument: a pending file is same-user writable input, so it is
/// parsed like one.
fn read_pending(path: &Path) -> Option<(String, String, PathBuf)> {
    let raw = std::fs::read_to_string(path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let slug = doc["slug"].as_str()?.to_string();
    let sha = doc["sha"].as_str()?.to_string();
    let repo = PathBuf::from(doc["repo"].as_str()?);
    let slug_ok = slug.split('/').count() == 2
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    let sha_ok = sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit());
    (slug_ok && sha_ok).then_some((slug, sha, repo))
}

/// Whether the sealed run log carries a passed pre-push that pushed `sha` to
/// `slug` - the evidence a deferred attestation replays. A planted pending
/// file earns nothing on its own: only a commit a real audited run already
/// pushed may be marked. `Sound` and `Gap` links both carry a recomputing
/// self-seal (a gap means the predecessor was pruned or lost, not that this
/// record was rewritten); `Broken` and `Unsealed` evidence is refused.
fn pending_attested(cfg: &config::Config, slug: &str, sha: &str) -> bool {
    let links: std::collections::HashMap<String, records::Link> =
        records::verify(cfg).into_iter().collect();
    records::list(cfg).unwrap_or_default().into_iter().any(|r| {
        r.passed
            && r.event == "pre-push"
            && r.repository == slug
            && matches!(
                links.get(&r.id),
                Some(records::Link::Sound | records::Link::Gap)
            )
            && r.range
                .refs
                .lines()
                .any(|line| line.split_whitespace().nth(1) == Some(sha))
    })
}

/// Post every deferred attestation whose commit the remote now knows. Each
/// entry must re-earn its mark before the vault is even opened: the pushed
/// sha peels to the commit in the recording repo (content-addressed, so the
/// relation cannot be forged), and the sealed record chain must show a
/// passed audit pushing that sha. A commit still unknown keeps its file -
/// the failed POST is the probe, so no extra request exists - and per-entry
/// errors stay best-effort: a stale, forged or unroutable pending must not
/// hold every later push hostage; the file remains for the next drain.
fn drain_pending_attestations(cfg: &config::Config) -> anyhow::Result<()> {
    let dir = pending_dir(cfg);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(());
    };
    let mut pending: Vec<(PathBuf, String, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some((slug, sha, repo)) = read_pending(&path) else {
            eprintln!(
                "gitvault: ignoring malformed pending attestation {}",
                path.display()
            );
            continue;
        };
        let Some(commit) = peel_commit(&repo, &sha) else {
            eprintln!(
                "gitvault: pending attestation for {slug}@{sha:.12} cannot be peeled in {repo:?}; keeping"
            );
            continue;
        };
        if !pending_attested(cfg, &slug, &sha) {
            eprintln!(
                "gitvault: pending attestation for {slug}@{sha:.12} has no sealed audit to replay; not posting"
            );
            continue;
        }
        pending.push((path, slug, commit));
    }
    if pending.is_empty() {
        return Ok(());
    }
    let vault = match vault::Vault::open() {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("gitvault: vault unavailable, deferred attestations wait: {error}");
            return Ok(());
        }
    };
    for (path, slug, commit) in pending {
        match api::run(cfg, &vault, &audited_status_request(&slug, &commit)) {
            Ok(0) => {
                let _ = std::fs::remove_file(&path);
                eprintln!("gitvault: marked {commit:.12} audited on {slug} (deferred)");
            }
            Ok(_) => {} // commit not known to the remote yet - retry next run
            Err(error) => {
                eprintln!("gitvault: deferred attestation for {slug}@{commit:.12} failed: {error}");
            }
        }
    }
    Ok(())
}

/// The `Owner/Repo` a push actually lands on: the named remote's URL parsed
/// for its slug, never a different remote's.
fn remote_slug(repo_root: &std::path::Path, remote: &str) -> Option<String> {
    let url = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["remote", "get-url", remote])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    url.and_then(|url| git::slug_from_remote(&url))
}

/// The commit a pushed object attests to, when it has one: annotated tags and
/// other non-commit objects peel through `^{commit}`, a plain commit resolves
/// to itself.
fn peel_commit(repo_root: &std::path::Path, sha: &str) -> Option<String> {
    git::commit_at(repo_root, sha)
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
    only: Option<&str>,
    tag: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
    let ctx = context_for(&cfg, event, directory, tag.map(str::to_string), &[])?;
    let report = audit_gate(
        &cfg,
        &cfg_sig,
        &policy,
        &policy_sig,
        &ctx,
        "check",
        only,
        true,
    )?;
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
            // of argv and shell history.
            let pass = if signing {
                None
            } else {
                read_optional_passphrase()?
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
    // each file is certified under its own signature: the blessing the user
    // gives here covers exactly what both files contain now.
    if config::Config::migrate_checkers(&path)? {
        println!(
            "moved checker entries to {}",
            config::Policy::path_for(&path).display()
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
    let policy_path = config::Policy::path_for(&path);
    if policy_path.exists() {
        let sig = configsig::sign(&policy_path, &key)?;
        println!("signed {} -> {}", policy_path.display(), sig.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// Report the attestation state. Read-only: it may advise, never gate.
fn cmd_config_verify(config: Option<&PathBuf>) -> anyhow::Result<ExitCode> {
    let path = config.cloned().unwrap_or_else(config::Config::default_path);
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
            let policy_path = config::Policy::path_for(&path);
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

/// Provision this machine: deploy the binary beside it, lay down the hook
/// dispatchers, then hand the enforcement surface to root.
///
/// The privileged step is one `sudo` run inside this command. What lands under
/// root: the binaries, the hooks directory and - when present - the signature
/// anchor. What deliberately stays user-owned: `config.toml` and
/// `checkers.toml` (edits are allowed, only unsigned loads are refused) and
/// their `.sig` sidecars (rewritten by every `gitvault config sign`).
fn cmd_install() -> anyhow::Result<ExitCode> {
    let home = PathBuf::from(std::env::var("HOME").context("HOME is not set")?);
    let bin_dir = home.join(".local/bin");
    let hooks = home.join(".git-hooks");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&hooks)?;

    // The enforcement surface this run will immobilise: everything the steps
    // below lay down, plus sibling helpers that exist already.
    let target = bin_dir.join("gitvault");
    let sign_wrapper = bin_dir.join("gitvault-sign");
    let mut immobilise: Vec<PathBuf> = vec![target.clone(), sign_wrapper.clone()];
    let touchid = bin_dir.join("gitvault-touchid");
    if touchid.exists() {
        immobilise.push(touchid.clone());
    }
    immobilise.push(hooks.clone());
    let anchor = configsig::anchor_path();
    let anchor_armed = anchor.exists();

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

    // 1. Deploy the binary next to any sibling helpers. An existing target is
    //    REMOVED first: fs::copy overwrites in place, preserving the inode - and
    //    the kernel's provenance record with it. A file that was ever executed
    //    while root-owned is poisoned permanently ("Killed: 9"); restoring
    //    ownership and clearing xattrs do not revive it. A fresh inode carries
    //    a clean record, and that is the only cure.
    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    // Reinstalling through the installed binary itself: exe and target are
    // the same file. Removing the target would delete the running binary
    // before the copy — the self-delete that loses the gate entirely.
    let self_install = target
        .canonicalize()
        .map(|resolved| resolved == exe)
        .unwrap_or(false);
    if target.exists() && !self_install {
        std::fs::remove_file(&target).with_context(|| {
            format!(
                "cannot remove {} before reinstall - is it still schg-flagged?",
                target.display()
            )
        })?;
    }
    if !self_install {
        std::fs::copy(&exe, &target)
            .with_context(|| format!("cannot install {} to {}", exe.display(), target.display()))?;
    }
    if !sign_wrapper.exists() {
        std::fs::write(
            &sign_wrapper,
            "#!/bin/sh\n# git needs gpg.ssh.program to be one executable path.\nexec \"$HOME/.local/bin/gitvault\" sign \"$@\"\n",
        )?;
    }
    std::fs::set_permissions(&sign_wrapper, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot make {} executable", sign_wrapper.display()))?;
    // The touchid helper is a Mach-O too: if an earlier run left it poisoned,
    // a rewrite onto a fresh inode cures it the same way.
    if touchid.exists() {
        let bytes = std::fs::read(&touchid)
            .with_context(|| format!("cannot read {}", touchid.display()))?;
        let mode = touchid
            .metadata()
            .map(|m| m.permissions())
            .unwrap_or_else(|_| std::fs::Permissions::from_mode(0o755));
        std::fs::remove_file(&touchid)
            .with_context(|| format!("cannot refresh {}", touchid.display()))?;
        std::fs::write(&touchid, &bytes)
            .with_context(|| format!("cannot rewrite {}", touchid.display()))?;
        std::fs::set_permissions(&touchid, mode)?;
    }

    // 2. Hook dispatchers, written only when missing: an existing dispatcher is
    //    an operator's file, not something a reinstall may overwrite.
    let dispatch = hooks.join("_dispatch");
    if !dispatch.exists() {
        std::fs::write(
            &dispatch,
            "#!/usr/bin/env bash\n\
             set -u\n\
             HOOK=\"${1:?hook name required}\"; shift || true\n\
             # The gateway binary is fixed, never an environment override:\n\
             # an env-set substitute would let `GITVAULT_BIN=/bin/true git push`\n\
             # run no gate at all.\n\
             GITVAULT_BIN=\"$HOME/.local/bin/gitvault\"\n\
             if [ ! -x \"$GITVAULT_BIN\" ]; then\n\
             \x20 printf 'gitvault: not installed; refusing the action\\n' >&2\n\
             \x20 exit 1\n\
             fi\n\
             if [ \"${GIT_IDENTITY_GUARD_CHAINED:-0}\" != \"1\" ]; then\n\
             \x20 \"$GITVAULT_BIN\" hook \"$HOOK\" || exit $?\n\
             fi\n\
             REPO_LOCAL_HOOK=\"$(git rev-parse --show-toplevel 2>/dev/null || true)/.githooks/$HOOK\"\n\
             if [ -x \"$REPO_LOCAL_HOOK\" ]; then\n\
             \x20 export GIT_IDENTITY_GUARD_CHAINED=1\n\
             \x20 \"$REPO_LOCAL_HOOK\" \"$@\"; exit $?\n\
             fi\n\
             exit 0\n",
        )?;
    }
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
        if !stub.exists() {
            std::fs::write(
                &stub,
                format!(
                    "#!/usr/bin/env bash\nexec \"$HOME/.git-hooks/_dispatch\" {event} \"$@\"\n"
                ),
            )?;
        }
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
    let status = std::process::Command::new("sudo")
        .args(["chflags", "-R", "schg"])
        .args(&immobilise)
        .status()
        .context("failed to invoke sudo - enter the login password when asked")?;
    if !status.success() {
        anyhow::bail!("sudo chflags failed; nothing below was applied");
    }
    let mut anchor_ok = false;
    if anchor_armed {
        let status = std::process::Command::new("sudo")
            .args(["chown", "root:wheel"])
            .arg(&anchor)
            .status()
            .context("failed to run sudo chown on the anchor")?;
        anchor_ok = status.success();
        if !anchor_ok {
            anyhow::bail!("sudo chown of the anchor failed");
        }
    }

    println!("installed to {}", bin_dir.display());
    println!("enforcement surface is immutable (schg):");
    for p in &immobilise {
        println!("  {}", p.display());
    }
    if anchor_armed && anchor_ok {
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

/// The write surfaces that publish repository content or move refs. Matching
/// is on the API path after the `/repos/{owner}/{repo}` prefix: anything that
/// lands content (file writes, git objects, merges, release artifacts) or moves
/// refs belongs to the audited commands. Reads and non-publication writes
/// (issues, comments, labels, PR metadata) stay open.
fn publication_surface(method: &str, path: &str) -> Option<String> {
    if matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    ) {
        return None;
    }
    // Normalize an absolute API URL back to its path before matching. The
    // origin lives in api::API_ROOT alone - a second literal here would drift
    // from it, skip normalization, and silently unguard absolute-URL writes.
    let path = path
        .strip_prefix(crate::api::API_ROOT)
        .unwrap_or(path)
        .trim_start_matches('/')
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // repos/{owner}/{repo}/<surface>/...
    if segments.len() < 3 || segments[0] != "repos" {
        return None;
    }
    let tail: Vec<&str> = segments[3..].to_vec();
    let verb = method.to_ascii_uppercase();
    let hit = match tail.first().copied() {
        // File contents and every git object/ref write.
        Some("contents" | "git") => true,
        // Branch merges performed server-side, and a fork syncing its branch
        // from upstream - both move a ref without the local gate seeing it.
        Some("merges" | "merge-upstream") => true,
        // Creating a pull request, or merging one or updating its branch from
        // the base. Metadata writes (PATCH title/body, reviewers, comments)
        // are not publication.
        Some("pulls") => {
            verb == "POST" && tail.len() == 1
                || tail
                    .get(2)
                    .is_some_and(|seg| *seg == "merge" || *seg == "update-branch")
        }
        // Releases and their assets, created or edited.
        Some("releases") => true,
        // Commit statuses are the audit's attestation channel: a hand-posted
        // `gitvault/audited` would forge the receipt the server-side check
        // trusts. The audited path posts them through api::run internally.
        Some("statuses") => true,
        _ => false,
    };
    hit.then(|| format!("{verb} /{path}"))
}

fn cmd_pr(
    config: Option<&PathBuf>,
    command: PrCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    // Audit first, blessing after: the routing table is parsed without its
    // signature so the registry can run; the gate asks for certification only
    // after the evidence is produced, and credentials flow only once it holds.
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    let vault = vault::Vault::open()?;

    let slug = match repo {
        Some(s) => s,
        None => git::Repo::discover(&PathBuf::from("."))?
            .slug()
            .ok_or_else(|| anyhow::anyhow!("no origin remote; pass --repo OWNER/NAME"))?,
    };

    let (method, path, fields, jq) = match command {
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
            // reviewed here before the request proposes it. The checker resolves
            // base/head in the local repository, the only place the content exists.
            let mut ctx =
                context_for(&cfg, "pr", &PathBuf::from("."), None, &[]).map_err(|err| {
                    anyhow::anyhow!(
                        "reviewing a pull request needs a checkout of the repository\n  \
                     {err:#}\n  \
                     push the branch through GitVault, or run this from its working tree"
                    )
                })?;
            ctx.pr_base = Some(base.clone());
            ctx.pr_head = Some(head.clone());
            let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
            run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "pull request")?;
            let mut f = vec![
                ("title".to_string(), title),
                ("head".to_string(), head),
                ("draft".to_string(), draft.to_string()),
            ];
            if let Some(b) = body {
                f.push(("body".to_string(), b));
            }
            if !base.is_empty() {
                f.push(("base".to_string(), base));
            }
            (
                "POST",
                format!("/repos/{slug}/pulls"),
                f,
                Some(".html_url".to_string()),
            )
        }
        PrCommand::List { state, limit, json } => (
            "GET",
            format!("/repos/{slug}/pulls?state={state}&per_page={limit}"),
            vec![],
            if json {
                None
            } else {
                Some(".[].html_url".to_string())
            },
        ),
        PrCommand::View { number, json } => (
            "GET",
            format!("/repos/{slug}/pulls/{number}"),
            vec![],
            if json {
                None
            } else {
                Some(".html_url".to_string())
            },
        ),
        PrCommand::Merge {
            number,
            method,
            subject,
        } => {
            // Merging publishes into the base branch -- the same class of
            // permanent record as creating. The head may not be checked out
            // here, so the checker is told the request number and fetches the
            // head itself; nothing reaches GitHub until it passes.
            let mut ctx =
                context_for(&cfg, "pr", &PathBuf::from("."), None, &[]).map_err(|err| {
                    anyhow::anyhow!(
                        "reviewing a merge request needs a checkout of the repository\n  \
                     {err:#}\n  \
                     run this from its working tree"
                    )
                })?;
            ctx.pr_number = Some(number.to_string());
            let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
            run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "merge")?;
            let mut f = vec![("merge_method".to_string(), method)];
            if let Some(s) = subject {
                f.push(("commit_title".to_string(), s));
            }
            (
                "PUT",
                format!("/repos/{slug}/pulls/{number}/merge"),
                f,
                Some(".message".to_string()),
            )
        }
        PrCommand::Close { number } => (
            "PATCH",
            format!("/repos/{slug}/pulls/{number}"),
            vec![("state".to_string(), "closed".to_string())],
            Some(".state".to_string()),
        ),
        PrCommand::Comment { number, body } => (
            "POST",
            format!("/repos/{slug}/issues/{number}/comments"),
            vec![("body".to_string(), body)],
            Some(".html_url".to_string()),
        ),
    };

    let req = api::Request {
        method: method.to_string(),
        path,
        target: api::Target::Repo(slug),
        fields,
        raw_fields: vec![],
        headers: vec![],
        body: None,
        jq,
        silent: false,
    };
    let code = api::run(&cfg, &vault, &req)?;
    Ok(ExitCode::from(code as u8))
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

fn cmd_release(
    config: Option<&PathBuf>,
    command: ReleaseCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let (cfg, cfg_path, cfg_sig) = config::Config::load_unverified(config)?;
    // The release boundary runs before any credential is touched: the verdict
    // does not depend on the vault, and a refusal must be possible even where
    // the vault is locked. Nothing reaches GitHub until the registry passes.
    if let ReleaseCommand::Create { tag, .. } = &command {
        let (policy, _policy_path, policy_sig) = config::Policy::load_state(&cfg_path, &cfg)?;
        let ctx = context_for(&cfg, "release", &PathBuf::from("."), Some(tag.clone()), &[])
            .map_err(|err| {
                anyhow::anyhow!(
                    "reviewing a release needs a checkout with the tagged commit\n  \
                     {err:#}\n  \
                     run this from the tagged working tree"
                )
            })?;
        run_publication_gate(&cfg, &cfg_sig, &policy, &policy_sig, &ctx, "release")?;
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
        } => {
            let mut r = get(
                format!("/repos/{slug}/releases"),
                slug.clone(),
                Some(".html_url".into()),
            );
            r.method = "POST".into();
            r.fields.push(("tag_name".into(), tag.clone()));
            r.fields.push(("draft".into(), draft.to_string()));
            r.fields.push(("prerelease".into(), prerelease.to_string()));
            if let Some(n) = name {
                r.fields.push(("name".into(), n));
            }
            if let Some(b) = notes {
                r.fields.push(("body".into(), b));
            }
            r
        }
        ReleaseCommand::Delete { tag } => {
            // Deleting a release needs its numeric id, so resolve it first. Two
            // requests, but it spares the caller from knowing that.
            let id_req = get(
                format!("/repos/{slug}/releases/tags/{tag}"),
                slug.clone(),
                Some(".id".into()),
            );
            let id = api::run_value(&cfg, &vault, &id_req)?;
            let mut r = get(
                format!("/repos/{slug}/releases/{}", id.trim()),
                slug.clone(),
                None,
            );
            r.method = "DELETE".into();
            r
        }
    };
    emit(&cfg, &vault, req)
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
fn read_optional_passphrase() -> anyhow::Result<Option<String>> {
    use anyhow::Context as _;
    use std::io::BufRead;
    eprint!("passphrase for this key (empty if none): ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("could not read the key passphrase")?;
    let t = line.trim_end_matches(['\n', '\r']).to_string();
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

/// A checker's newest report.json under its profile run history.
fn latest_report(checker: &str) -> Option<serde_json::Value> {
    let runs = profiles_root()
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
        admissible_proposed_row, audit_gate, drain_pending_attestations, outgoing_push_stdin,
        pending_attested, profiles_root, proposed_contract_path_at, publication_surface,
        read_pending, record_pending_attestation,
    };
    use crate::checkers::Context;
    use crate::config::{Config, Policy};
    use crate::configsig::SigState;
    use crate::records;
    use std::path::PathBuf;
    use std::process::Command;

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

    fn ctx(event: &str) -> Context {
        Context {
            event: event.to_string(),
            repo_root: PathBuf::from("/synthetic/repo"),
            repo_slug: Some("Owner/Repo".into()),
            identity: "personal".into(),
            account: None,
            via_default: true,
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

    /// A `checkers.toml` that exists but registers no checkers used to skip
    /// both signature refusals: one local write disarmed the publication
    /// boundary with zero audits and zero signature checks. The refusal is
    /// now unconditional at the events that publish or spend credentials.
    #[test]
    fn boundary_events_refuse_an_uncertified_policy_even_when_empty() {
        let cfg = Config::default();
        let policy = Policy::default();
        for event in ["pre-push", "pr", "release"] {
            let err = match audit_gate(
                &cfg,
                &SigState::Inactive,
                &policy,
                &SigState::Invalid("checkers.toml is unsigned".into()),
                &ctx(event),
                "test",
                None,
                false,
            ) {
                Err(err) => err,
                Ok(_) => panic!("{event} must refuse an uncertified audit policy"),
            };
            assert!(
                err.to_string().contains("uncertified audit policy"),
                "{err}"
            );
        }
        // An event the policy gates nothing for still passes: nothing would
        // execute, so local work is not held hostage to a blessing.
        assert!(
            audit_gate(
                &cfg,
                &SigState::Inactive,
                &policy,
                &SigState::Invalid("checkers.toml is unsigned".into()),
                &ctx("pre-commit"),
                "test",
                None,
                false,
            )
            .is_ok()
        );
    }

    /// `check` is the audit-before-blessing tool: a proposed policy change
    /// must be exercisable *before* it is signed, or signing would always
    /// come first. Enforcement paths keep refusing the same file. A boundary
    /// the proposal registers nothing for still refuses: no audit ran, so
    /// there is no evidence to bless.
    #[test]
    fn check_audits_a_proposed_policy_the_enforcer_would_refuse() {
        let cfg = Config::default();
        let policy = Policy::default();
        let err = audit_gate(
            &cfg,
            &SigState::Inactive,
            &policy,
            &SigState::Invalid("checkers.toml is unsigned".into()),
            &ctx("pre-push"),
            "check",
            None,
            true,
        )
        .expect_err("an empty policy cannot bless a boundary, proposed or not");
        assert!(err.to_string().contains("audit evidence"), "{err}");
        // A non-boundary event stays free of the blessing: nothing would run,
        // so local work is not held hostage to a signature.
        assert!(
            audit_gate(
                &cfg,
                &SigState::Inactive,
                &policy,
                &SigState::Invalid("checkers.toml is unsigned".into()),
                &ctx("pre-commit"),
                "check",
                None,
                true,
            )
            .is_ok()
        );
    }

    /// The routing-table refusal is unconditional at the same boundaries: a
    /// certified-but-empty policy must not skip it either.
    #[test]
    fn boundary_events_refuse_an_uncertified_routing_table() {
        let cfg = Config::default();
        let policy = Policy::default();
        for event in ["pre-push", "pr", "release"] {
            let err = match audit_gate(
                &cfg,
                &SigState::Invalid("config.toml is unsigned".into()),
                &policy,
                &SigState::Inactive,
                &ctx(event),
                "check",
                None,
                false,
            ) {
                Err(err) => err,
                Ok(_) => panic!("{event} must refuse an uncertified routing table"),
            };
            assert!(err.to_string().contains("uncertified"), "{err}");
        }
        // Non-boundary events keep the checker-registration criterion.
        assert!(
            audit_gate(
                &cfg,
                &SigState::Invalid("config.toml is unsigned".into()),
                &policy,
                &SigState::Inactive,
                &ctx("pre-commit"),
                "check",
                None,
                false,
            )
            .is_ok()
        );
    }

    /// The publication surface refuses every write that lands content or moves
    /// refs, including absolute-URL forms, while reads and metadata writes
    /// stay open. An absolute URL that no longer normalizes silently unguards
    /// the whole list, so that form is exercised explicitly.
    #[test]
    fn the_api_surface_refuses_only_publication_writes() {
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
            // The audited channel is safe only if absolute URLs still
            // normalize onto the path the match runs against.
            ("POST", "https://api.github.com/repos/o/r/statuses/deadbeef"),
        ] {
            assert!(
                publication_surface(method, path).is_some(),
                "{method} {path} publishes and must be refused"
            );
        }
        for (method, path) in [
            ("GET", "/repos/o/r/contents/src/lib.rs"),
            ("GET", "/repos/o/r/pulls/7"),
            ("POST", "/repos/o/r/issues"),
            ("POST", "/repos/o/r/issues/3/comments"),
            ("PATCH", "/repos/o/r/pulls/7"), // metadata edit, not publication
            ("POST", "/repos/o/r/labels"),
            ("POST", "/repos/o/r/pulls/7/merge-ish"), // not the merge endpoint
        ] {
            assert!(
                publication_surface(method, path).is_none(),
                "{method} {path} does not publish and must stay open"
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

    /// The pending-file contract is the drain's only input: a deferred
    /// attestation must land where the drain looks and read back the slug
    /// and sha it was recorded with, or key drift silently disables the
    /// whole mechanism.
    #[test]
    fn a_pending_attestation_round_trips_through_its_file() {
        let dir = std::env::temp_dir().join(format!(
            "gv-pending-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let cfg = Config {
            record_dir: Some(dir.join("runs")),
            ..Default::default()
        };
        let sha = "a".repeat(40);
        record_pending_attestation(&cfg, "Owner/Repo", &sha, &dir);
        let file = dir.join("pending").join(format!("Owner_Repo__{sha}.json"));
        assert!(file.is_file(), "pending file missing at {}", file.display());
        assert_eq!(
            read_pending(&file),
            Some(("Owner/Repo".to_string(), sha.clone(), dir.clone()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pending file is same-user writable, so a planted one must not earn
    /// a posting: without a sealed passed run pushing that sha, the drain
    /// refuses and keeps the file - before the vault is ever opened.
    #[test]
    fn a_planted_pending_attestation_is_not_posted() {
        let dir = std::env::temp_dir().join(format!(
            "gv-pending-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let cfg = Config {
            record_dir: Some(dir.join("runs")),
            ..Default::default()
        };
        // Write a real commit in a real repo so the peel check cannot be the
        // reason the entry is skipped: only the missing evidence may refuse.
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init"]);
        std::fs::write(repo.join("a"), "a").unwrap();
        git(&repo, &["add", "a"]);
        git(&repo, &["commit", "-m", "a"]);
        let sha = git(&repo, &["rev-parse", "HEAD"]);
        record_pending_attestation(&cfg, "Owner/Repo", &sha, &repo);
        let file = dir.join("pending").join(format!("Owner_Repo__{sha}.json"));

        // No run records exist: the claim is forged, the drain must hold.
        drain_pending_attestations(&cfg).unwrap();
        assert!(file.is_file(), "forged pending was posted or dropped");
        // And a pushed sha that does appear in a sealed passing record is
        // the only shape that may post - assert the predicate sees the gap.
        assert!(!pending_attested(&cfg, "Owner/Repo", &sha));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The positive half of the binding: a sealed, passed pre-push record
    /// whose refs pushed the sha is accepted as evidence; rewriting it
    /// breaks the seal and the evidence with it.
    #[test]
    fn only_a_sealed_passed_push_record_attests_a_pending_sha() {
        let dir = std::env::temp_dir().join(format!(
            "gv-attest-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let run_dir = dir.join("runs");
        let cfg = Config {
            record_dir: Some(run_dir.clone()),
            ..Default::default()
        };
        let sha = "b".repeat(40);
        let record_dir = run_dir.join("0000000001-a1a1");
        std::fs::create_dir_all(&record_dir).unwrap();
        let mut record = records::Record {
            id: "0000000001-a1a1".to_string(),
            created_at: 1,
            duration_ms: 0,
            event: "pre-push".to_string(),
            repository: "Owner/Repo".to_string(),
            identity: "synthetic".to_string(),
            account: "Fixture-Acct".to_string(),
            range: records::Range {
                refs: format!("refs/heads/main {sha} refs/heads/main {}", "0".repeat(40)),
                pr_base: None,
                pr_head: None,
                pr_number: None,
                release_tag: None,
                release_commit: None,
            },
            routing_signature: "valid".to_string(),
            policy_signature: "valid".to_string(),
            passed: true,
            blocking_failures: 0,
            outcomes: Vec::new(),
            seal: String::new(),
            seal_prev: String::new(),
        };
        record.seal = crate::seal::seal("", &serde_json::to_value(&record).unwrap());
        let file = record_dir.join("engine.json");
        let write = |r: &records::Record| {
            std::fs::write(&file, serde_json::to_string_pretty(r).unwrap()).unwrap();
        };
        write(&record);
        assert!(pending_attested(&cfg, "Owner/Repo", &sha));

        // A different sha - one the recorded push never carried - has no
        // evidence, and tampering with the refs breaks the seal either way.
        assert!(!pending_attested(&cfg, "Owner/Repo", &"c".repeat(40)));
        record.range.refs = format!(
            "refs/heads/main {} refs/heads/main {}",
            "c".repeat(40),
            "0".repeat(40)
        );
        write(&record); // stale seal: rewritten after sealing
        assert!(!pending_attested(&cfg, "Owner/Repo", &sha));
        assert!(!pending_attested(&cfg, "Owner/Repo", &"c".repeat(40)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_proposal_never_executes_arbitrary_commands() {
        // The signature boundary exists because checker rows are code: a
        // proposed policy that names anything but the trusted audit runner
        // is refused, not executed.
        let shell_row = crate::config::Checker {
            name: "evil".into(),
            on: vec!["pre-push".into()],
            kind: crate::config::Kind::Exec,
            severity: crate::config::Severity::Blocking,
            timeout_secs: 0,
            phase: 0,
            command: vec!["/bin/sh".into(), "-c".into(), "touch /tmp/x".into()],
            env: Default::default(),
            repos: vec![],
        };
        let repo = std::env::temp_dir().join(format!("gv-prop-{:04x}", rand::random::<u16>()));
        std::fs::create_dir_all(&repo).unwrap();
        assert!(admissible_proposed_row(&shell_row, &repo).is_err());
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn a_proposal_row_is_bound_to_the_reviewed_repository() {
        let runner = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("gitvault-review");
        // Any installed contract supplies the in-root path the shape needs;
        // both fixtures only exist where the toolchain is deployed.
        let contract = std::fs::read_dir(profiles_root())
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .flat_map(|dir| {
                std::fs::read_dir(dir.path().join("plugins"))
                    .ok()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .collect::<Vec<_>>()
            })
            .map(|entry| entry.path().join("contract.json"))
            .find(|path| path.is_file());
        let (Some(contract), true) = (contract, runner.exists()) else {
            return;
        };
        let repo = std::env::temp_dir().join(format!("gv-prop-{:04x}", rand::random::<u16>()));
        std::fs::create_dir_all(&repo).unwrap();
        let row = |tail: &[String]| crate::config::Checker {
            name: "probe".into(),
            on: vec!["pre-push".into()],
            kind: crate::config::Kind::Exec,
            severity: crate::config::Severity::Blocking,
            timeout_secs: 0,
            phase: 0,
            command: std::iter::once(runner.display().to_string())
                .chain(tail.iter().cloned())
                .collect(),
            env: Default::default(),
            repos: vec![],
        };
        let contract = contract.display().to_string();
        // The canonical installed shape passes; a literal path bound to the
        // same repository does too.
        for tail in [
            vec!["run", "--contract", &contract, "--repo", "{repo}"],
            vec![
                "run",
                "--contract",
                &contract,
                "--repo",
                &repo.display().to_string(),
            ],
            vec!["baseline", "--repo", "{repo}"],
        ] {
            let good = row(&tail.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            assert!(
                admissible_proposed_row(&good, &repo).is_ok(),
                "canonical row {tail:?} refused"
            );
        }
        // A different repository, extra arguments, help flags and a
        // contract-less run all refuse.
        for tail in [
            vec!["run", "--contract", &contract, "--repo", "/"],
            vec![
                "run",
                "--contract",
                &contract,
                "--repo",
                "{repo}",
                "--verbose",
            ],
            vec!["run", "--help"],
            vec!["run", "--contract", &contract],
            vec!["baseline", "--repo", "/"],
        ] {
            let bad = row(&tail.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            assert!(
                admissible_proposed_row(&bad, &repo).is_err(),
                "tail {tail:?} passed"
            );
        }
        // Reserved context variables cannot be overridden by a proposal.
        let mut poisoned = row(&[
            "run".into(),
            "--contract".into(),
            contract.clone(),
            "--repo".into(),
            "{repo}".into(),
        ]);
        poisoned.env.insert("GITVAULT_PUSH_REFS".into(), "x".into());
        assert!(admissible_proposed_row(&poisoned, &repo).is_err());
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// A boundary proposal audited under `--only` produces evidence from a
    /// single row, yet the completeness check sees the configured set - the
    /// partial pass could then be signed as if every reviewer ran.
    #[test]
    fn a_boundary_proposal_refuses_a_partial_audit() {
        let cfg = Config::default();
        let mut policy = Policy::default();
        policy.checkers.push(crate::config::Checker {
            name: "anything".into(),
            on: vec!["pre-push".into()],
            kind: crate::config::Kind::Exec,
            severity: crate::config::Severity::Blocking,
            timeout_secs: 0,
            phase: 0,
            command: vec!["/bin/true".into()],
            env: Default::default(),
            repos: vec![],
        });
        let err = audit_gate(
            &cfg,
            &SigState::Inactive,
            &policy,
            &SigState::Invalid("checkers.toml is unsigned".into()),
            &ctx("pre-push"),
            "check",
            Some("anything"),
            true,
        )
        .expect_err("--only must refuse a boundary proposal");
        assert!(err.to_string().contains("partially"), "{err}");
        // A signed policy keeps `--only` as the operator's debug tool; the
        // refusal belongs to the proposal path alone.
        let outcome = audit_gate(
            &cfg,
            &SigState::Inactive,
            &policy,
            &SigState::Valid,
            &ctx("pre-push"),
            "check",
            Some("anything"),
            true,
        );
        assert!(
            !outcome
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default()
                .contains("partially"),
            "the partial-audit refusal must not reach a certified policy"
        );
    }

    /// The deterministic baseline is part of the audit a boundary policy must
    /// produce: a proposal whose semantic reviewers all pass while the sweep
    /// is absent would certify away the script-layer gate.
    #[test]
    fn a_boundary_proposal_keeps_the_baseline_sweep() {
        let runner = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("gitvault-review");
        let contract = std::fs::read_dir(profiles_root())
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .flat_map(|dir| {
                std::fs::read_dir(dir.path().join("plugins"))
                    .ok()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .collect::<Vec<_>>()
            })
            .map(|entry| entry.path().join("contract.json"))
            .find(|path| path.is_file());
        let (Some(contract), true) = (contract, runner.exists()) else {
            return;
        };
        let cfg = Config::default();
        let mut policy = Policy::default();
        policy.checkers.push(crate::config::Checker {
            name: "reviewer".into(),
            on: vec!["pre-push".into()],
            kind: crate::config::Kind::Exec,
            severity: crate::config::Severity::Blocking,
            timeout_secs: 0,
            phase: 0,
            command: vec![
                runner.display().to_string(),
                "run".into(),
                "--contract".into(),
                contract.display().to_string(),
                "--repo".into(),
                "{repo}".into(),
            ],
            env: Default::default(),
            repos: vec![],
        });
        let err = audit_gate(
            &cfg,
            &SigState::Inactive,
            &policy,
            &SigState::Invalid("checkers.toml is unsigned".into()),
            &ctx("pre-push"),
            "check",
            None,
            true,
        )
        .expect_err("a proposal with no baseline row must refuse");
        assert!(err.to_string().contains("baseline"), "{err}");
    }

    #[test]
    fn a_proposed_contract_must_live_under_the_profiles_root() {
        let err = proposed_contract_path_at("/etc/passwd").unwrap_err();
        assert!(err.contains("profiles root"), "{err}");
        assert!(proposed_contract_path_at("/nonexistent/contract.json").is_err());
    }

    /// Rows scoped to another repository satisfy `checkers_for` but never
    /// execute under `run_all`'s `applies_to` filter. A boundary whose whole
    /// event set is scoped elsewhere must refuse - the review surface is
    /// the rows that would actually run, not the rows that exist.
    #[test]
    fn a_boundary_refuses_a_policy_scoped_away_from_this_repository() {
        let cfg = Config::default();
        let mut policy = Policy::default();
        policy.checkers.push(crate::config::Checker {
            name: "elsewhere".into(),
            on: vec!["pre-push".into()],
            kind: crate::config::Kind::Exec,
            severity: crate::config::Severity::Blocking,
            timeout_secs: 0,
            phase: 0,
            command: vec!["/bin/true".into()],
            env: Default::default(),
            repos: vec!["someone/other-repo".into()],
        });
        let err = audit_gate(
            &cfg,
            &SigState::Inactive,
            &policy,
            &SigState::Valid,
            &ctx("pre-push"),
            "check",
            None,
            true,
        )
        .expect_err("a boundary with zero applicable checkers must refuse");
        assert!(
            err.to_string().contains("apply to this repository"),
            "{err}"
        );
    }
}
