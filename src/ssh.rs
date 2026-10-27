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

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::git::Repo;
use crate::identity;
use crate::tempsecret::TempSecret;
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
        .rfind(|t| t.contains('/'))
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
    // Credentials follow the operator's rules, never repository content: an
    // assertion file must not pick which account's key is used, so it is not
    // consulted here.
    let outcome = identity::resolve(cfg, &repo, true)?;
    let account = outcome
        .account
        .clone()
        .ok_or_else(|| anyhow::anyhow!("identity '{}' has no account", outcome.identity))?;

    // Same refusals as the API path, for the same reasons.
    if outcome.via_default {
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
        None,
    )?;
    let key = vault.ssh_key_for(&account)?;
    let passphrase = vault.passphrase_for(&account);

    // A throwaway agent holds the key in memory. Nothing is written to disk.
    // The guard's Drop kills the agent on every exit path, including an error
    // after the key was loaded - nothing below may skip that teardown.
    let agent = start_agent()?;
    load_key(&agent.sock, &key, passphrase.as_deref(), false)?;

    // Run the real ssh with the throwaway agent and no identities of its own.
    // A substituted ssh would inherit SSH_AUTH_SOCK and could ask the agent to
    // sign more than this connection's handshake, so it is resolved the same
    // trusted way as the helpers that touch the key itself.
    let status = Command::new(trusted_tool("ssh")?)
        .args(args)
        .env("SSH_AUTH_SOCK", &agent.sock)
        .env_remove("SSH_AGENT_PID")
        // The passphrase only ever lives in the ssh-add child's environment;
        // strip it from the connection process whatever the caller's env held.
        .env_remove("GITVAULT_ASKPASS_VALUE")
        .status()
        .context("failed to run ssh")?;

    Ok(status.code().unwrap_or(1))
}

/// Pass straight through, for `-G` and any other non-authenticating call.
fn exec_plain(args: &[String]) -> Result<i32> {
    let status = Command::new(trusted_tool("ssh")?)
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

/// The credential-sensitive SSH helpers must be the platform's own binaries:
/// a PATH-resolved `ssh-add` in a writable directory would receive the
/// plaintext key this module exists to keep off disk. Each executable is
/// checked by the same rule the audit engine and the transport pass.
#[cfg(unix)]
pub(crate) fn trusted_tool(name: &str) -> Result<PathBuf> {
    let program = PathBuf::from(format!("/usr/bin/{name}"));
    anyhow::ensure!(
        crate::configsig::executable_is_trusted(&program),
        "the {name} executable {} is not trusted (root-owned, unwritable, \
         non-replaceable chain required)",
        program.display()
    );
    Ok(program)
}

#[cfg(not(unix))]
pub(crate) fn trusted_tool(name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(name))
}

/// A throwaway ssh-agent holding a vault key.
pub struct Agent {
    pub sock: String,
    pub pid: Option<String>,
}

impl Agent {
    pub fn stop(&self) {
        let _ = kill_agent(self.pid.as_deref());
    }
}

/// The agent dies with its guard: an early return, a failed load or a refused
/// connection can never leave a live process holding the vault key.
impl Drop for Agent {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start a private ssh-agent; the caller stops it when the operation ends.
pub fn start_agent() -> Result<Agent> {
    let agent = Command::new(trusted_tool("ssh-agent")?)
        .arg("-s")
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to start a temporary ssh-agent")?;
    let out = agent.wait_with_output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let sock = extract_agent_var(&text, "SSH_AUTH_SOCK")
        .ok_or_else(|| anyhow::anyhow!("ssh-agent did not report SSH_AUTH_SOCK"))?;
    let pid = extract_agent_var(&text, "SSH_AGENT_PID");
    Ok(Agent { sock, pid })
}

/// Write a short-lived askpass helper; the passphrase itself is never in the
/// script, the file's name, or argv.
///
/// The returned guard holds the path and deletes the file on drop. The script
/// reads `GITVAULT_ASKPASS_VALUE` from its own environment, so the caller sets
/// that variable on the exact child (ssh-add or ssh-keygen) that may ask -
/// never on this process, where every later child would inherit it.
pub fn askpass_script() -> Result<TempSecret> {
    let script = "#!/bin/sh\nprintf '%s\\n' \"$GITVAULT_ASKPASS_VALUE\"\n";
    TempSecret::write(script, 0o700)
}

/// Feed `key` to `ssh-add` over a stdin pipe so no key file touches the disk.
///
/// An encrypted key prompts ssh-add on the terminal; SSH_ASKPASS answers it
/// with a passphrase that travels in the child's environment only.
/// `require_passphrase` marks callers whose keys are always encrypted (the
/// signing path): without one, ssh-add's prompt would consume the piped key as
/// its answer - measured: "Error loading key (stdin): invalid format". The
/// transport path passes false because unencrypted keys are legitimate there.
pub fn load_key(
    sock: &str,
    key: &str,
    passphrase: Option<&str>,
    require_passphrase: bool,
) -> Result<()> {
    let askpass = match passphrase {
        Some(_) => Some(askpass_script()?),
        None => None,
    };
    if askpass.is_none() && require_passphrase {
        bail!(
            "no passphrase is held for this key, so ssh-add would prompt and consume \
             the piped key as the answer\n  \
             re-import with the passphrase: gitvault auth import-key <account> <file>"
        );
    }
    let mut cmd = Command::new(trusted_tool("ssh-add")?);
    cmd.arg("-")
        .env("SSH_AUTH_SOCK", sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let (Some(guard), Some(p)) = (&askpass, passphrase) {
        // execve needs a real path, so a /dev/fd spelling cannot serve an
        // executable helper. Instead the child's cwd is bound to the pinned
        // scratch directory and SSH_ASKPASS is the RELATIVE name: the exec
        // resolves `./name` inside the pinned inode, and no path component
        // a same-user process could reparent stands in the lookup.
        #[cfg(unix)]
        {
            guard.fchdir_child(&mut cmd);
            cmd.env("SSH_ASKPASS", Path::new(".").join(guard.name()));
        }
        #[cfg(not(unix))]
        cmd.env("SSH_ASKPASS", guard.path()?);
        cmd.env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .env("GITVAULT_ASKPASS_VALUE", p);
    }
    let mut child = cmd.spawn().context("failed to run ssh-add")?;
    {
        use std::io::Write;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("no ssh-add stdin"))?;
        stdin.write_all(key.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "could not load the key into the temporary agent: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

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
        assert_eq!(
            inv.operation.as_deref(),
            Some("git-receive-pack 'acme/protocol.git'")
        );
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
        let inv = parse(&args(&[
            "-G",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com-acme",
        ]))
        .unwrap();
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
        let inv = parse(&args(&[
            "git@github.com",
            "git-upload-pack",
            "\"Owner/Repo.git\"",
        ]))
        .unwrap();
        assert_eq!(inv.slug.as_deref(), Some("Owner/Repo"));
    }

    #[test]
    fn askpass_never_touches_this_processs_environment() {
        // The passphrase belongs in the ssh-add child's env, set by load_key -
        // never in ours, where every later child (ssh, ssh-keygen) inherits it.
        let _guard = TempSecret::write("x", 0o600).unwrap();
        let _script = askpass_script().unwrap();
        assert!(
            std::env::var_os("GITVAULT_ASKPASS_VALUE").is_none(),
            "writing the askpass helper must not leave the passphrase channel set"
        );
    }

    #[test]
    fn temp_secrets_are_private_atomically_and_unique() {
        use std::os::unix::fs::PermissionsExt;
        let a = TempSecret::write("first", 0o600).unwrap();
        let b = TempSecret::write("second", 0o600).unwrap();
        assert_ne!(
            a.path().unwrap(),
            b.path().unwrap(),
            "secret files must not collide"
        );
        let mode = std::fs::metadata(a.path().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the file must be private from creation, not chmodded after"
        );
        assert!(a.path().unwrap().exists());
        let held = a.path().unwrap().to_path_buf();
        drop(a);
        assert!(!held.exists(), "the guard deletes the file when it drops");
    }
}
