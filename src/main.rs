//! GitVault - hold the identity, intercept the action, run the checkers.
//!
//! The binary is the only component that decides *who* is acting. It never
//! executes code from the repository it inspects: checkers are external commands
//! launched with a neutral working directory, and the repository path reaches them
//! as an absolute argument rather than by changing into it.

mod api;
mod auth;
mod checkers;
mod records;
mod config;
mod git;
mod identity;
mod sign;
mod ssh;
mod unlock;
mod vault;

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

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

    /// Run the registered checkers outside a hook, for testing and for CI.
    Check {
        #[arg(long, default_value = "pre-commit")]
        event: String,
        #[arg(long, default_value = ".")]
        directory: PathBuf,
        /// Run only this checker.
        #[arg(long)]
        only: Option<String>,
        /// The release tag, for `--event release`.
        #[arg(long)]
        tag: Option<String>,
    },

    /// Inspect recorded checker runs.
    ///
    /// Read-only: no vault, no network, no writes. This is what the dashboard
    /// page reads, so nothing here may describe this machine's paths.
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
        #[arg(long)]
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
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Create the vault key. Run once per machine.
    Init,
    /// Store a token for an account. Reads the token from stdin.
    Add {
        account: String,
    },
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
        } => cmd_check(cli.config.as_ref(), &event, &directory, only.as_deref(), tag.as_deref()),
        Command::Records { command } => cmd_records(cli.config.as_ref(), command),
        Command::Checkers { json } => cmd_checkers(cli.config.as_ref(), json),
        Command::Auth { command } => cmd_auth(cli.config.as_ref(), command),
        Command::Unlock { ttl } => cmd_unlock(ttl),
        Command::Lock => cmd_lock(),
        Command::Status { json } => cmd_status(json),
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
    directory: &PathBuf,
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
            repo.remote().unwrap_or("(none)")
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
    let cfg = config::Config::load(config)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg.checkers)?);
        return Ok(ExitCode::SUCCESS);
    }
    if cfg.checkers.is_empty() {
        println!("no checkers registered");
        return Ok(ExitCode::SUCCESS);
    }
    for c in &cfg.checkers {
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
    directory: &PathBuf,
    release_tag: Option<String>,
) -> anyhow::Result<checkers::Context> {
    let repo = git::Repo::discover(directory)?;
    let outcome = identity::resolve(cfg, &repo, false)?;

    // git hands pre-push its refs on stdin:
    //   <local ref> <local sha> <remote ref> <remote sha>
    let stdin = if event == "pre-push" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Some(buf)
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
        pr_base: None,
        pr_head: None,
        pr_number: None,
        release_tag,
        release_commit,
    })
}

fn cmd_hook(
    config: Option<&PathBuf>,
    event: &str,
    _args: &[String],
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    // git runs hooks with cwd set to the top level of the working tree, so "."
    // resolves correctly and no directory argument is needed from the hook shim.
    let ctx = context_for(&cfg, event, &PathBuf::from("."), None)?;
    let report = checkers::run_all(&cfg, &ctx, None)?;
    report.print(event);
    Ok(report.exit_code())
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
                    .map(|o| format!("{} {} ({:.1}s)", o.name, o.outcome, o.duration_ms as f64 / 1000.0))
                    .collect();
                println!(
                    "{}  {}  {}  {}  {}",
                    records::iso8601(record.created_at),
                    record.id,
                    record.event,
                    if record.repository.is_empty() { "-" } else { &record.repository },
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
            println!("verdict    : {}", if record.passed { "passed" } else { "refused" });
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
    }
}

fn cmd_check(
    config: Option<&PathBuf>,
    event: &str,
    directory: &PathBuf,
    only: Option<&str>,
    tag: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
    let ctx = context_for(&cfg, event, directory, tag.map(str::to_string))?;
    let report = checkers::run_all(&cfg, &ctx, only)?;
    report.print(event);
    Ok(report.exit_code())
}

fn cmd_auth(config: Option<&PathBuf>, command: AuthCommand) -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    match command {
        AuthCommand::Init => auth::cmd_init(&vault)?,
        AuthCommand::Add { account } => auth::cmd_add(&vault, &account)?,
        AuthCommand::Remove { account, token, keys, all } => {
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
    unlock::ensure_open(&vault, "GitVault: confirm to open the credential vault", true, ttl)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_lock() -> anyhow::Result<ExitCode> {
    unlock::clear()?;
    println!("vault locked");
    Ok(ExitCode::SUCCESS)
}

fn cmd_status(json: bool) -> anyhow::Result<ExitCode> {
    let vault = vault::Vault::open()?;
    let remaining = unlock::remaining();
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
            Err(_) => anyhow::bail!("not in a repository; pass --repo OWNER/NAME or --identity NAME"),
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

fn cmd_pr(
    config: Option<&PathBuf>,
    command: PrCommand,
    repo: Option<String>,
) -> anyhow::Result<ExitCode> {
    let cfg = config::Config::load(config)?;
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
            let base = match base {
                Some(b) => b,
                None => String::new(),
            };
            // The publication boundary. A branch pushed through GitVault already
            // passed the same audit at pre-push -- a range that did is reused, not
            // paid for twice; content that reached the remote from elsewhere is
            // reviewed here before the request proposes it. The checker resolves
            // base/head in the local repository, the only place the content exists.
            let mut ctx = context_for(&cfg, "pr", &PathBuf::from("."), None).map_err(|_| {
                anyhow::anyhow!(
                    "reviewing a pull request needs a checkout of the repository; \
                     push the branch through GitVault, or run this from its working tree"
                )
            })?;
            ctx.pr_base = Some(base.clone());
            ctx.pr_head = Some(head.clone());
            let report = checkers::run_all(&cfg, &ctx, None)?;
            report.print("pr");
            if report.exit_code() != ExitCode::SUCCESS {
                anyhow::bail!("a blocking checker refused this pull request; nothing was sent to GitHub");
            }
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
            ("POST", format!("/repos/{slug}/pulls"), f, Some(".html_url".to_string()))
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
            if json { None } else { Some(".html_url".to_string()) },
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
            let mut ctx = context_for(&cfg, "pr", &PathBuf::from("."), None).map_err(|_| {
                anyhow::anyhow!(
                    "reviewing a merge request needs a checkout of the repository; \
                     run this from its working tree"
                )
            })?;
            ctx.pr_number = Some(number.to_string());
            let report = checkers::run_all(&cfg, &ctx, None)?;
            report.print("pr");
            if report.exit_code() != ExitCode::SUCCESS {
                anyhow::bail!("a blocking checker refused this merge; nothing was sent to GitHub");
            }
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
        .ok_or_else(|| anyhow::anyhow!("no origin remote here; pass OWNER/NAME or run in a checkout"))
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
            let mut r = get(format!("/repos/{slug}/issues"), slug.clone(), Some(".html_url".into()));
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
            if json { None } else { Some(".[].html_url".into()) },
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
            let jq = if json { None } else { Some(".full_name".into()) };
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
                if json { None } else { Some(".[].full_name".into()) },
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
    let cfg = config::Config::load(config)?;
    // The release boundary runs before any credential is touched: the verdict
    // does not depend on the vault, and a refusal must be possible even where
    // the vault is locked. Nothing reaches GitHub until the registry passes.
    if let ReleaseCommand::Create { tag, .. } = &command {
        let ctx = context_for(&cfg, "release", &PathBuf::from("."), Some(tag.clone()))
            .map_err(|_| {
                anyhow::anyhow!(
                    "reviewing a release needs a checkout with the tagged commit; \
                     run this from the tagged working tree"
                )
            })?;
        let report = checkers::run_all(&cfg, &ctx, None)?;
        report.print("release");
        if report.exit_code() != ExitCode::SUCCESS {
            anyhow::bail!("a blocking checker refused this release; nothing was sent to GitHub");
        }
    }
    let vault = vault::Vault::open()?;
    let slug = resolve_slug(repo)?;

    let req = match command {
        ReleaseCommand::List { limit, json } => get(
            format!("/repos/{slug}/releases?per_page={limit}"),
            slug.clone(),
            if json { None } else { Some(".[].tag_name".into()) },
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
            if json { None } else { Some(".workflow_runs[0].status".into()) },
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
    use std::io::BufRead;
    eprint!("passphrase for this key (empty if none): ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return Ok(None);
    }
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
            let outcome = identity::resolve(&cfg, &path, false)?;
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
