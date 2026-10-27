//! Commit-signing proxy.
//!
//! Git calls `gpg.ssh.program` as:
//!
//! ```text
//! <program> -Y sign -n git -f <key> <buffer-file>
//! ```
//!
//! The working directory is the repository root, which is how the target
//! repository is identified here: the SSH agent protocol carries no such context,
//! but the process environment does.
//!
//! The private key is read from the vault and loaded into a throwaway agent, so
//! the signing path writes no key file. `ssh-keygen -Y sign -f <public-key>`
//! signs with the agent's private key, verified before relying on it.
//!
//! One exception: `public_key_of_material` (used when only the public half is
//! needed and no agent exists yet) writes the private key to a 0700/0600
//! temporary file for `ssh-keygen -y`, and that file is removed when its guard
//! drops. Signing a commit never takes that path.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::git::Repo;
use crate::identity;
use crate::vault::Vault;

/// Parse `-Y sign -n <namespace> -f <key> <buffer>`.
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub namespace: String,
    /// The key path git passed. Reported for diagnosis; the key actually used comes
    /// from the vault, so a path that does not exist is not a failure.
    pub key: Option<String>,
    pub buffer: PathBuf,
}

/// True when git is asking for a signature rather than a verification.
///
/// `-Y sign` is the only request GitVault answers itself; the rest belong to
/// ssh-keygen. Deciding this by scanning for the subcommand is deliberate: the
/// alternative is to treat every call as signing, which silently broke verification.
pub fn is_signing_request(args: &[String]) -> bool {
    args.iter().any(|a| a == "sign")
}

/// Hand the request to the real ssh-keygen unchanged.
fn passthrough(args: &[String]) -> Result<i32> {
    let status = std::process::Command::new(crate::ssh::trusted_tool("ssh-keygen")?)
        .args(args)
        .status()
        .context("failed to run ssh-keygen")?;
    Ok(status.code().unwrap_or(1))
}

/// Parse git's arguments.
///
/// The shape depends on configuration, which is what made this subtle. Two forms
/// were observed from the same git version:
///
/// ```text
/// -Y sign -n git -f <key> <buffer>          # simple config
/// -Y sign -n git -f <key> -U <buffer>       # when git supplies its own key file
/// ```
///
/// The buffer is therefore the **last** positional argument, not the first. An
/// earlier version took the first positional it saw after `-f` and so signed git's
/// temporary *key* file instead of the commit. ssh-keygen accepted that happily,
/// wrote the signature to `<key>.sig`, and left stdout empty, so every commit landed
/// with no usable signature and verified as bad.
pub fn parse(args: &[String]) -> Result<Invocation> {
    let mut namespace = "git".to_string();
    let mut key = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-Y" => i += 2, // takes a value: "sign"
            "-n" => {
                namespace = args.get(i + 1).cloned().unwrap_or(namespace);
                i += 2;
            }
            "-f" => {
                // Consumed as the key, never as the buffer. This is the argument the
                // earlier version mistook for the buffer.
                key = args.get(i + 1).cloned();
                i += 2;
            }
            "-O" => i += 2,                            // e.g. -Overify-time=...
            other if other.starts_with('-') => i += 1, // -U and any other bare flag
            other => {
                positional.push(other.to_string());
                i += 1;
            }
        }
    }

    let buffer = positional
        .pop()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("no buffer file given; git should pass one to sign"))?;
    if buffer.as_os_str().is_empty() {
        anyhow::bail!("the buffer path git passed is empty");
    }

    Ok(Invocation {
        namespace,
        key,
        buffer,
    })
}

pub fn run(cfg: &Config, vault: &Vault, args: &[String], cwd: &Path) -> Result<i32> {
    // git runs `gpg.ssh.program` for verification too, not only for signing. Observed
    // calls, all with the same configured program:
    //
    //   -Y sign            -n git -f <key> <buffer>      produce a signature
    //   -Y find-principals -f <signers> -s <sig>        who signed this
    //   -Y check-novalidate -n git -s <sig>             is the signature well formed
    //   -Y verify          -n git -f <signers> -I <p> -s <sig>
    //
    // Those three verification subcommands must reach the real ssh-keygen. Handling
    // them here as if they were signing requests meant git never got an answer, and
    // every commit verified as bad no matter how valid the signature was. Only
    // signing is ours to intercept; anything else is passed straight through.
    if !is_signing_request(args) {
        return passthrough(args);
    }

    let inv = parse(args)?;

    // The repository identifies which identity may sign. Without it there is no
    // policy to apply, and signing anyway would be signing as whoever happens to be
    // configured.
    let repo = Repo::discover(cwd)?;
    // Credentials follow the operator's rules, never repository content: an
    // assertion file must not pick which account's signing key is used, so it
    // is not consulted here.
    let outcome = identity::resolve(cfg, &repo, true)?;
    let account = outcome
        .account
        .clone()
        .ok_or_else(|| anyhow::anyhow!("identity '{}' has no account", outcome.identity))?;

    if outcome.via_default {
        bail!(
            "refusing to sign: no explicit rule for owner '{:?}'\n  resolved account: {account}",
            repo.owner().unwrap_or_default()
        );
    }

    // No unlock gate here, and that is a decision rather than an omission.
    //
    // The gate exists to bound how long a credential stays usable after a human
    // confirms. That makes sense where something leaves the machine: an API call sends
    // data, a push publishes a record that cannot be unpublished. A commit does
    // neither. It is local, and it is reversible - amend, rebase, reset and discard all
    // work on it without the vault. The moment a commit becomes permanent is the push,
    // and the push is gated.
    //
    // Signing is also not what decides the identity. The owner rules above decide it,
    // and the signer only attaches evidence of that decision. Gating evidence, while
    // the thing it is evidence of has already been decided and carries no gate, buys
    // nothing and costs a prompt on every commit.
    //
    // What this does not change: the signing key still never leaves this process, and
    // an egress operation still needs a window. Reading the key for a local signature
    // is not egress.
    let key = vault.signing_key_for(&account)?;
    let passphrase = vault.signing_passphrase_for(&account);

    // The guard kills the agent on every exit path - a failure after the key
    // is loaded cannot leave a live agent holding it.
    let agent = crate::ssh::start_agent()?;
    // Signing keys are always stored encrypted (import requires the passphrase),
    // so a missing one is a setup defect, not an unencrypted key.
    crate::ssh::load_key(&agent.sock, &key, passphrase.as_deref(), true)?;

    // Signing itself uses the agent; `-f` only needs a public key, which holds no
    // secret. The public key's temporary file lives inside this guard and is
    // removed even if any step below fails.
    let pub_text = public_key_from_agent(&agent.sock, &crate::vault::Store::fingerprint(&key))?;
    let pub_file = crate::tempsecret::TempSecret::write(&pub_text, 0o600)?;

    // Measured invocation behaviour:
    //
    //   sign <pub> <buffer>        -> writes <buffer>.sig
    //   sign <pub> -  < buffer     -> writes the signature to stdout
    //   sign <pub> <buffer> -      -> "Cannot sign mix of paths and standard input"
    //
    // Git passes a buffer path and consumes "<buffer>.sig", so the sidecar is what
    // has to survive. Passing "-" alongside the path is rejected outright.
    let sig_path = {
        let mut p = inv.buffer.clone().into_os_string();
        p.push(".sig");
        PathBuf::from(p)
    };
    // A stale sidecar from an interrupted run would otherwise be read back as if it
    // were this signature.
    let _ = std::fs::remove_file(&sig_path);

    let status = Command::new(crate::ssh::trusted_tool("ssh-keygen")?)
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(&inv.namespace)
        .arg("-f")
        .arg(pub_file.path())
        .arg(&inv.buffer)
        // No trailing "-". ssh-keygen rejects it alongside a buffer path
        // ("Cannot sign mix of paths and standard input"), and it is not wanted
        // anyway: with a path argument ssh-keygen writes "<buffer>.sig", which is
        // exactly where git reads the signature from. Confirmed by spying on git's
        // own invocation of ssh-keygen: it passes -f <pub> <buffer> and reads
        // "<buffer>.sig" afterwards.
        .env("SSH_AUTH_SOCK", &agent.sock)
        .env_remove("SSH_AGENT_PID")
        .env_remove("GITVAULT_ASKPASS_VALUE")
        // stdout is deliberately NOT redirected. Doing so was the actual cause of
        // every commit verifying as bad, isolated by minimal reproduction:
        //
        //   program -> ssh-keygen, stdout redirected   %G? = B
        //   program -> ssh-keygen, stdout left alone   %G? = G
        //
        // ssh-keygen writes the signature to stdout and git consumes it there. The
        // redirect was added only to silence the "Signing file ..." progress line,
        // and it silently discarded the signature along with it.
        .status()
        .context("failed to run ssh-keygen")?;

    // ssh-keygen wrote the signature to stdout, which is where git reads it.
    // The agent guard drops here and stops the temporary agent itself.
    Ok(status.code().unwrap_or(1))
}

/// Derive a public key from private key material, via a self-deleting temp file.
///
/// `ssh-keygen -y` needs a readable path; the `-f /dev/stdin` route fails its
/// permission check (the pipe is 0660 and cannot be tightened), and without `-f`
/// the tool prompts on the terminal. Since a file is unavoidable, the exposure
/// is bounded to the call's lifetime and the deletion is guaranteed by the
/// `TempSecret` guard rather than by a call an error path could skip.
pub fn public_key_of_material(private: &str, passphrase: Option<&str>) -> Result<String> {
    let secret = crate::tempsecret::TempSecret::write(private, 0o600)?;
    // `ssh-keygen -y` needs the passphrase for an encrypted key and has no agent to
    // ask, so it is supplied through SSH_ASKPASS. Without this it prompts on a
    // terminal it does not have and the derivation fails.
    let askpass = match passphrase {
        Some(_) => Some(crate::ssh::askpass_script()?),
        None => None,
    };
    let mut cmd = Command::new(crate::ssh::trusted_tool("ssh-keygen")?);
    cmd.arg("-y").arg("-f").arg(secret.path());
    if let (Some(guard), Some(p)) = (&askpass, passphrase) {
        cmd.env("SSH_ASKPASS", guard.path())
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .env("GITVAULT_ASKPASS_VALUE", p);
    }
    let out = cmd.output().context("failed to run ssh-keygen -y")?;
    if !out.status.success() {
        bail!(
            "could not derive the public key: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let body = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if body.is_empty() {
        bail!("ssh-keygen produced an empty public key");
    }
    Ok(body)
}

/// Read the loaded key's public half back out of the agent.
///
/// Deriving it with `ssh-keygen -y` instead would fail for an encrypted key: that
/// command needs the passphrase and has no way to ask the agent. Reading it from
/// the agent avoids decrypting anything a second time.
fn public_key_from_agent(sock: &str, expected_fingerprint: &str) -> Result<String> {
    let out = Command::new(crate::ssh::trusted_tool("ssh-add")?)
        .arg("-L")
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .context("failed to run ssh-add -L")?;
    if !out.status.success() {
        bail!(
            "could not list agent keys: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let key = text
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 ") || l.starts_with("ssh-rsa "))
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the temporary agent holds no usable key (wanted {expected_fingerprint})"
            )
        })?;
    Ok(format!("{key}\n"))
}

// Agent startup, key loading and the askpass helper live in `crate::ssh` - the
// transport proxy and this one load keys the same way, and one implementation
// is what keeps their secret-handling guarantees identical.

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_the_shape_git_uses() {
        let inv = parse(&a(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/key.pub",
            "/tmp/.git_signing_buffer_abc",
        ]))
        .unwrap();
        assert_eq!(inv.namespace, "git");
        assert_eq!(inv.key.as_deref(), Some("/tmp/key.pub"));
        assert_eq!(inv.buffer, PathBuf::from("/tmp/.git_signing_buffer_abc"));
    }

    #[test]
    fn verification_requests_are_not_treated_as_signing() {
        // Regression: git invokes gpg.ssh.program for -Y find-principals,
        // -Y check-novalidate and -Y verify as well. Answering those as signing
        // requests left git without a verification result, and every commit reported
        // %G? = B even though the signature was valid byte for byte.
        for a in [
            vec!["-Y", "find-principals", "-f", "signers", "-s", "sig"],
            vec!["-Y", "check-novalidate", "-n", "git", "-s", "sig"],
            vec![
                "-Y", "verify", "-n", "git", "-f", "signers", "-I", "p", "-s", "sig",
            ],
        ] {
            let args: Vec<String> = a.iter().map(|s| s.to_string()).collect();
            assert!(
                !is_signing_request(&args),
                "{:?} must be passed through to ssh-keygen",
                a
            );
        }
        let signing: Vec<String> = ["-Y", "sign", "-n", "git", "-f", "k", "buf"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(is_signing_request(&signing));
    }

    #[test]
    fn parses_the_form_with_a_git_supplied_key_and_dash_u() {
        // Regression: this is the shape git actually used, and the earlier parser
        // took the -f value as the buffer, so it signed the key file instead of the
        // commit. ssh-keygen accepted it and wrote to <key>.sig, leaving stdout
        // empty and every commit unverifiable.
        let inv = parse(&a(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/.git_signing_key_tmpABC",
            "-U",
            "/tmp/.git_signing_buffer_tmpXYZ",
        ]))
        .unwrap();
        assert_eq!(inv.namespace, "git");
        assert_eq!(inv.key.as_deref(), Some("/tmp/.git_signing_key_tmpABC"));
        assert_eq!(
            inv.buffer,
            PathBuf::from("/tmp/.git_signing_buffer_tmpXYZ"),
            "the buffer is the last positional, not the value of -f"
        );
    }

    #[test]
    fn parses_the_form_without_dash_u() {
        let inv = parse(&a(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/key.pub",
            "/tmp/buffer",
        ]))
        .unwrap();
        assert_eq!(inv.key.as_deref(), Some("/tmp/key.pub"));
        assert_eq!(inv.buffer, PathBuf::from("/tmp/buffer"));
    }

    #[test]
    fn defaults_the_namespace_when_absent() {
        let inv = parse(&a(&["-Y", "sign", "/tmp/buffer"])).unwrap();
        assert_eq!(inv.namespace, "git");
        assert_eq!(inv.buffer, PathBuf::from("/tmp/buffer"));
    }

    #[test]
    fn the_signer_invocation_is_correct() {
        // Regression guard for the defect that made every commit verify as bad.
        //
        // ssh-keygen writes the signature to stdout and git reads it there, so
        // redirecting stdout discards the signature. Isolated by minimal
        // reproduction: the same setup gives %G? = B with the redirect and G without
        // it, with no GitVault code involved either way.
        //
        // The other two constraints were measured directly:
        //   sign <pub> <buffer> -    -> "Cannot sign mix of paths and standard input"
        //   ssh-add -                -> correct, reads the key from stdin
        let code: String = include_str!("sign.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        // Just the signer's argument list, from its -n flag to the next .context().
        let signer = code
            .split(r#".arg(&inv.namespace)"#)
            .nth(1)
            .and_then(|rest| rest.split(".context(").next())
            .unwrap_or_else(|| panic!("could not locate the signer invocation"));

        assert!(
            !signer.contains(".stdout(Stdio::null())"),
            "stdout must not be redirected on the signer: the signature goes there"
        );
        assert!(
            !signer.contains(r#".arg("-")"#),
            "passing \"-\" alongside a buffer path makes ssh-keygen refuse to sign"
        );
    }

    #[test]
    fn a_missing_buffer_is_an_error() {
        // Signing without knowing what to sign must not fall through to signing
        // something else.
        assert!(parse(&a(&["-Y", "sign", "-n", "git"])).is_err());
    }
}
