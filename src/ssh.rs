//! SSH transport proxy.
//!
//! Git invokes this in place of `ssh` (via `core.sshCommand`). It receives the
//! same argv git would have given ssh, which is where the routing information
//! lives:
//!
//! ```text
//! ssh git@github.com-acme git-receive-pack 'acme/protocol.git'
//!     ^ host alias              ^ operation          ^ repository path
//! ```
//!
//! The SSH agent protocol carries none of this - an agent sees only a key blob and
//! the data to sign - so a plain ssh-agent cannot apply a per-repository policy.
//! This proxy can, because the repository is right there in the arguments.
//!
//! The private key is never written to disk. A throwaway `ssh-agent` is started,
//! the key is loaded into it, and ssh is pointed at that socket. An agent cannot
//! read a file that does not exist.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::git::Repo;
use crate::identity;
use crate::unlock;
use crate::vault::Vault;

/// What git asked ssh to do.
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    /// Host as written, e.g. `git@github.com-acme`.
    pub host: String,
    /// `git-upload-pack`, `git-receive-pack`, or a plain command.
    pub operation: Option<String>,
    /// `OWNER/REPO` parsed out of the repository path, when present.
    pub slug: Option<String>,
    /// True for `ssh -G`, which asks ssh to print its resolved configuration
    /// instead of connecting. Git uses it to probe settings.
    pub config_query: bool,
}

/// Parse git's ssh arguments.
///
/// Options are skipped rather than parsed: git passes `-o SendEnv=GIT_PROTOCOL`
/// and similar, and the only things needed here are the first bare word (host)
/// and the repository path inside the command.
pub fn parse(args: &[String]) -> Result<Invocation> {
    let mut config_query = false;
    let mut positional: Vec<&str> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-G" {
            config_query = true;
            i += 1;
        } else if a == "-o" || a == "-p" || a == "-i" || a == "-F" || a == "-l" {
            i += 2; // option plus its value
        } else if a.starts_with('-') {
            i += 1;
        } else {
            positional.push(a);
            i += 1;
        }
    }

    let host = positional
        .first()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("ssh was invoked without a host; cannot route"))?;

    let rest = positional.get(1..).unwrap_or(&[]);
    let command = rest.join(" ");
    let operation = rest.first().map(|s| s.to_string());

    // The repository is the last quoted or bare path in the command.
    let slug = command
        .split_whitespace()
        .filter(|t| t.contains('/'))
        .next_back()
        .map(|t| t.trim_matches(|c| c == '\'' || c == '"').to_string())
        .and_then(|path| {
            let path = path.trim_end_matches(".git");
            let mut parts = path.split('/').filter(|p| !p.is_empty());
            match (parts.next(), parts.next()) {
                (Some(o), Some(r)) => Some(format!("{o}/{r}")),
                _ => None,
            }
        });

    Ok(Invocation {
        host,
        operation,
        slug,
        config_query,
    })
}

/// Run the proxy.
pub fn run(cfg: &Config, vault: &Vault, args: &[String]) -> Result<i32> {
    let inv = parse(args)?;

    // `-G` prints configuration and never authenticates, so routing it would only
    // break git's probing.
    if inv.config_query {
        return exec_plain(args);
    }

    let slug = inv.slug.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine the target repository from the ssh command\n  \
             host: {}\n  \
             refusing to authenticate without knowing which repository this is",
            inv.host
        )
    })?;

    let repo = Repo::for_slug(&slug);
    let outcome = identity::resolve(cfg, &repo, false)?;
    let account = outcome
        .account
        .clone()
        .ok_or_else(|| anyhow::anyhow!("identity '{}' has no account", outcome.identity))?;

    // Same refusals as the API path, for the same reasons.
    if outcome.reason.starts_with("rules.default") {
        bail!(
            "refusing to authenticate: no explicit rule for owner '{:?}'\n  \
             resolved account: {account}",
            repo.owner().unwrap_or_default()
        );
    }

    // The window is asked for here, at the moment the key is actually needed.
    // A push's checkers run first - inside git's pre-push hook - and cost the
    // time they cost; a window opened before them would expire during the
    // audit, stranding the push at the authentication step. Prompting here is
    // what makes "audits first, credentials after" hold.
    unlock::ensure_open(
        vault,
        &format!("GitVault: confirm to authenticate {account} over SSH"),
        false,
    )?;
    let key = vault.ssh_key_for(&account)?;
    let passphrase = vault.passphrase_for(&account);

    // A throwaway agent holds the key in memory. Nothing is written to disk.
    let mut agent = Command::new("ssh-agent")
        .arg("-s")
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to start a temporary ssh-agent")?;

    let out = agent.wait_with_output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let sock = extract_agent_var(&text, "SSH_AUTH_SOCK")
        .ok_or_else(|| anyhow::anyhow!("ssh-agent did not report SSH_AUTH_SOCK"))?;
    let agent_pid = extract_agent_var(&text, "SSH_AGENT_PID");

    // Load the key without it touching the filesystem: ssh-add reads a key file,
    // so it is fed through a pipe on stdin via /dev/fd.
    // ssh-add cannot be fed an encrypted key through a pipe: it prompts on the
    // terminal. SSH_ASKPASS supplies the passphrase instead, so no unencrypted copy
    // of the key ever reaches the filesystem.
    let askpass = match &passphrase {
        Some(p) => Some(askpass_script(p)?),
        None => None,
    };
    let mut add_cmd = Command::new("ssh-add");
    add_cmd
        .arg("-")
        .env("SSH_AUTH_SOCK", &sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(path) = &askpass {
        add_cmd
            .env("SSH_ASKPASS", path)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0");
    }
    let mut add = add_cmd.spawn().context("failed to run ssh-add")?;
    {
        use std::io::Write;
        let mut stdin = add.stdin.take().ok_or_else(|| anyhow::anyhow!("no ssh-add stdin"))?;
        stdin.write_all(key.as_bytes())?;
    }
    let add_out = add.wait_with_output()?;
    if let Some(path) = &askpass {
        let _ = std::fs::remove_file(path);
    }
    if !add_out.status.success() {
        let _ = kill_agent(agent_pid.as_deref());
        bail!(
            "could not load the key into the temporary agent: {}",
            String::from_utf8_lossy(&add_out.stderr).trim()
        );
    }

    // Run the real ssh with the throwaway agent and no identities of its own.
    let status = Command::new("ssh")
        .args(args)
        .env("SSH_AUTH_SOCK", &sock)
        .env_remove("SSH_AGENT_PID")
        .status()
        .context("failed to run ssh")?;

    let _ = kill_agent(agent_pid.as_deref());
    Ok(status.code().unwrap_or(1))
}

/// Pass straight through, for `-G` and any other non-authenticating call.
fn exec_plain(args: &[String]) -> Result<i32> {
    let status = Command::new("ssh")
        .args(args)
        .status()
        .context("failed to run ssh")?;
    Ok(status.code().unwrap_or(1))
}

pub fn extract_agent_var(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{name}=")) {
            return Some(rest.split(';').next().unwrap_or(rest).trim().to_string());
        }
    }
    None
}

fn kill_agent(pid: Option<&str>) -> Result<()> {
    if let Some(pid) = pid {
        let _ = Command::new("kill").arg(pid).status();
    }
    Ok(())
}

/// Write a short-lived askpass helper.
///
/// The file is 0700, contains the passphrase, and is removed as soon as ssh-add
/// returns. The passphrase is passed as an argument to the shell inside the script
/// rather than interpolated into it, so a passphrase containing shell
/// metacharacters cannot alter the script.
pub fn askpass_script(passphrase: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "gitvault-askpass-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let script = "#!/bin/sh\nprintf '%s\\n' \"$GITVAULT_ASKPASS_VALUE\"\n";
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    // The value travels in the environment of this process and its child, never in
    // the script text and never in argv.
    // SAFETY: single-threaded at this point in the call.
    unsafe { std::env::set_var("GITVAULT_ASKPASS_VALUE", passphrase) };
    Ok(path)
}

/// Path helper for tests and callers that know only a slug.
pub fn slug_remote(slug: &str) -> String {
    format!("git@github.com:{slug}.git")
}

#[allow(dead_code)]
fn unused(_: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_the_shape_git_actually_uses() {
        let inv = parse(&args(&[
            "git@github.com-acme",
            "git-receive-pack 'acme/protocol.git'",
        ]))
        .unwrap();
        assert_eq!(inv.host, "git@github.com-acme");
        assert_eq!(inv.operation.as_deref(), Some("git-receive-pack 'acme/protocol.git'"));
        assert_eq!(inv.slug.as_deref(), Some("acme/protocol"));
        assert!(!inv.config_query);
    }

    #[test]
    fn skips_options_and_their_values() {
        let inv = parse(&args(&[
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "-p",
            "443",
            "git@github.com-platform",
            "git-upload-pack",
            "'platform-org/engine.git'",
        ]))
        .unwrap();
        assert_eq!(inv.host, "git@github.com-platform");
        assert_eq!(inv.slug.as_deref(), Some("platform-org/engine"));
    }

    #[test]
    fn recognises_the_configuration_query() {
        let inv = parse(&args(&["-G", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com-acme"])).unwrap();
        assert!(inv.config_query);
        assert_eq!(inv.slug, None);
    }

    #[test]
    fn refuses_when_no_repository_can_be_determined() {
        // No path in the command: authenticating would mean acting without knowing
        // which repository is being touched.
        let inv = parse(&args(&["git@github.com-acme", "some-command"])).unwrap();
        assert_eq!(inv.slug, None);
    }

    #[test]
    fn a_missing_host_is_an_error() {
        assert!(parse(&args(&["-G"])).is_err());
    }

    #[test]
    fn strips_quotes_and_the_git_suffix() {
        let inv = parse(&args(&["git@github.com", "git-upload-pack", "\"Owner/Repo.git\""])).unwrap();
        assert_eq!(inv.slug.as_deref(), Some("Owner/Repo"));
    }
}
