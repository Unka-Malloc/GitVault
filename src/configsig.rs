//! Configuration attestation: the routing table is signed, not merely read.
//!
//! `config.toml` carries no secret - it is a *routing table*: which repository
//! may be acted on by which identity, backed by which account's credentials.
//! What it needs is integrity, not confidentiality, so the primitive is a
//! signature, not encryption:
//!
//! * the private key lives in the vault, so blessing a configuration costs the
//!   same human confirmation as releasing a credential (`gitvault config sign`),
//! * the public anchor lives in `config.pub` beside the configuration, and it
//!   only counts when root owns it - a same-user process can rewrite the
//!   configuration, but it can neither re-sign it nor swap the anchor,
//! * reads stay free: every hook verifies the signature with the public key
//!   and refuses an unsigned or tampered file, fail-closed.
//!
//! Why the anchor must be root-owned: a same-user process can write every file
//! under `~/.config/gitvault`, so a public key stored there at user ownership
//! could be replaced together with the configuration it is meant to judge.
//! `gitvault install` performs the one privileged step; after it, mutating the
//! routing table requires a fingerprint, not write access to a file.
//!
//! Honest residual: the vault key itself is keychain-held and readable by a
//! determined same-user process (see `unlock.rs`), which means a purpose-built
//! attack could extract the signing key and forge a signature. This layer
//! removes casual and accidental mutation and forces a ceremony; it is not a
//! Secure-Enclave-grade boundary.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// Signature namespace and principal. Both stay fixed forever: they are what
/// separates a configuration signature from a commit signature produced by the
/// same key machinery.
pub const NAMESPACE: &str = "gitvault-config";
pub const PRINCIPAL: &str = "gitvault-config";

/// The trusted public anchor. Only meaningful while root-owned: a file any
/// same-user process can overwrite anchors nothing.
///
/// Deliberately not XDG-honoured: the anchor is the trust root. If it moved
/// with `XDG_CONFIG_HOME`, pointing that variable elsewhere would disarm
/// enforcement - the trust root must not follow the file it protects.
pub fn anchor_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home)
        .join(".config")
        .join("gitvault")
        .join("config.pub")
}

/// The signature sidecar for a configuration path.
pub fn sig_path(config_path: &Path) -> PathBuf {
    let mut p = config_path.as_os_str().to_os_string();
    p.push(".sig");
    PathBuf::from(p)
}

/// How much the anchor file can be trusted right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// No anchor: legacy mode, unsigned configurations are accepted.
    Absent,
    /// Present but user-owned: a same-user process could have planted it, so it
    /// anchors nothing. Verification stays off and a warning is printed so the
    /// setup gap is visible rather than silent.
    Unanchored,
    /// Root-owned: enforcement is on, unsigned or wrongly signed configurations
    /// are refused.
    Anchored,
}

pub fn anchor_state(anchor: &Path) -> Anchor {
    if !anchor.exists() {
        return Anchor::Absent;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(anchor)
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
        {
            Anchor::Anchored
        } else {
            Anchor::Unanchored
        }
    }
    #[cfg(not(unix))]
    {
        Anchor::Anchored
    }
}

/// Verify `config_path` against its signature sidecar, when enforcement is on.
///
/// Called from `Config::load`, which every gitvault surface funnels through, so
/// a tampered routing table cannot be used anywhere - including read-only
/// surfaces, which would otherwise lull the operator with a wrong answer.
pub fn verify(config_path: &Path) -> Result<()> {
    // Test escape, debug builds only - the same convention as
    // GITVAULT_UNLOCK_STATE and GITVAULT_TOUCHID. Integration fixtures pass an
    // unsigned `--config`; a release binary never honours this variable.
    if cfg!(debug_assertions) && std::env::var_os("GITVAULT_UNSIGNED_OK").is_some() {
        return Ok(());
    }
    let anchor = anchor_path();
    match anchor_state(&anchor) {
        Anchor::Absent => return Ok(()),
        Anchor::Unanchored => {
            eprintln!(
                "gitvault: {} exists but is not root-owned; signature enforcement is inactive\n  \
                 fix: run `gitvault install` (or sudo chown root:wheel {})",
                anchor.display(),
                anchor.display()
            );
            return Ok(());
        }
        Anchor::Anchored => {}
    }

    let sig = sig_path(config_path);
    if !sig.exists() {
        bail!(
            "{} is unsigned\n  bless the current file: gitvault config sign",
            config_path.display()
        );
    }

    verify_signed(config_path, &anchor).map_err(|e| {
        anyhow::anyhow!(
            "{} failed signature verification: {e:#}\n  \
             if the edit is intended, bless it: gitvault config sign",
            config_path.display()
        )
    })
}

/// Verify `config_path` against the signature sidecar under `anchor`. The root
/// -ownership gate lives in `verify`; this is the ssh-keygen step itself.
fn verify_signed(config_path: &Path, anchor: &Path) -> Result<()> {
    let sig = sig_path(config_path);
    if !sig.exists() {
        bail!("no signature sidecar at {}", sig.display());
    }
    let mut child = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(anchor)
        .arg("-I")
        .arg(PRINCIPAL)
        .arg("-n")
        .arg(NAMESPACE)
        .arg("-s")
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run ssh-keygen -Y verify")?;
    {
        use std::io::Write;
        let data = std::fs::read(config_path)
            .with_context(|| format!("cannot read {}", config_path.display()))?;
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(&data)
            .context("could not feed the configuration to ssh-keygen")?;
    }
    let out = child
        .wait_with_output()
        .context("ssh-keygen -Y verify did not finish")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Sign `config_path` in place, producing `<config>.sig` beside it.
///
/// The private key arrives as material, never as a path the caller picked: it
/// was fetched from the vault after the biometric gate, and it is materialised
/// only inside a self-deleting `TempSecret` for the single ssh-keygen call.
pub fn sign(config_path: &Path, key_material: &str) -> Result<PathBuf> {
    let secret = crate::ssh::TempSecret::write(key_material, 0o600)?;
    let sig = sig_path(config_path);
    // A stale sidecar must not be read back as this signature.
    let _ = std::fs::remove_file(&sig);
    let status = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(NAMESPACE)
        .arg("-f")
        .arg(secret.path())
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .context("failed to run ssh-keygen -Y sign")?;
    if !status.success() {
        bail!("ssh-keygen refused to sign {}", config_path.display());
    }
    if !sig.exists() {
        bail!("ssh-keygen produced no signature at {}", sig.display());
    }
    Ok(sig)
}

/// Generate the ed25519 pair that attests the configuration.
///
/// Returns `(private_key_material, anchor_line)` where the anchor line is in
/// allowed-signers form: `<principal> ssh-ed25519 <key>`.
pub fn keygen() -> Result<(String, String)> {
    // ssh-keygen wants a path to write to; the pair is read back and the
    // directory removed on every path below it.
    let dir = std::env::temp_dir().join(format!(
        "gitvault-keygen-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let out = keygen_in(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn keygen_in(dir: &Path) -> Result<(String, String)> {
    let key = dir.join("key");
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", PRINCIPAL, "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .context("failed to run ssh-keygen -t ed25519")?;
    if !status.success() {
        bail!("ssh-keygen could not generate the configuration signing key");
    }
    let private = std::fs::read_to_string(&key).context("private key was not produced")?;
    let public_line = std::fs::read_to_string(key.with_extension("pub"))
        .context("public key was not produced")?;
    // `<type> <key> <comment>` -> `<principal> <type> <key>` (allowed-signers).
    let mut fields = public_line.split_whitespace();
    let (Some(kind), Some(body)) = (fields.next(), fields.next()) else {
        bail!("ssh-keygen produced a malformed public key");
    };
    Ok((private, format!("{PRINCIPAL} {kind} {body}\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gv-cfg-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn have_ssh_keygen() -> bool {
        Command::new("ssh-keygen")
            .arg("-Y")
            .arg("sign")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    #[test]
    fn a_user_owned_anchor_does_not_arm_enforcement() {
        let d = dir("anchor");
        let anchor = d.join("config.pub");
        std::fs::write(&anchor, "gitvault-config ssh-ed25519 AAAA\n").unwrap();
        assert_eq!(anchor_state(&anchor), Anchor::Unanchored);
        assert_eq!(anchor_state(&d.join("missing.pub")), Anchor::Absent);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper_refusal() {
        if !have_ssh_keygen() {
            return;
        }
        let d = dir("roundtrip");
        let cfg = d.join("config.toml");
        let anchor = d.join("config.pub");
        let (private, public_line) = keygen().unwrap();
        std::fs::write(&cfg, "[rules]\ndefault = \"personal\"\n").unwrap();
        std::fs::write(&anchor, &public_line).unwrap();

        let sig = sign(&cfg, &private).unwrap();
        assert!(sig.exists());
        verify_signed(&cfg, &anchor).unwrap();

        // A single-byte edit must not verify.
        std::fs::write(&cfg, "[rules]\ndefault = \"attacker\"\n").unwrap();
        assert!(verify_signed(&cfg, &anchor).is_err());

        // Nor may a missing sidecar pass.
        let _ = std::fs::remove_file(&sig);
        assert!(verify_signed(&cfg, &anchor).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
