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

/// The user's real home, not the `HOME` environment variable. The anchor, the
/// installed engine and the child environment are security-relevant, so
/// `HOME=/tmp/attacker` must not move them. `libc` is already in the
/// dependency graph through the TLS stack; this is the one direct use.
#[cfg(unix)]
pub fn real_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;

    let mut buffer = vec![0 as libc::c_char; 4096];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut passwd,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || passwd.pw_dir.is_null() {
        return None;
    }
    let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
    let home = PathBuf::from(OsStr::from_bytes(home.to_bytes()));
    (!home.as_os_str().is_empty()).then_some(home)
}

#[cfg(not(unix))]
pub fn real_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The account home, falling back to `HOME` only where the platform cannot
/// answer. Every caller that needs an authoritative home uses this one
/// function so the anchor, the engine and the installed files cannot drift.
pub fn home_dir() -> PathBuf {
    real_home()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Like [`home_dir`], but refuses an unresolvable home instead of silently
/// landing files in the current directory.
pub fn account_home() -> Result<PathBuf> {
    real_home()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve the account home directory"))
}

/// Whether an executable may be trusted to answer a security question.
///
/// The property is the *system* immutable flag (`schg`), or root ownership on
/// a path whose whole parent chain is protected from this user. The user
/// immutable flag (`uchg`) is deliberately not enough: the same user who
/// would replace the binary can clear that flag without a password. Root
/// ownership alone is not enough either when the file sits in a directory this
/// user can write: ownership of an inode does not pin a name, and a same-user
/// process can rename a different binary over the path between this check and
/// the exec that trusts it. `gitvault install` gives an existing binary
/// `schg`; for a root-owned file in a root-owned, non-user-writable chain
/// (`/usr/bin`) the name cannot be swapped without root.
///
/// The path itself is judged, never a target it links to: the lookup uses
/// `symlink_metadata` and requires a regular, non-symlink file. Otherwise a
/// same-user process could plant a link at the helper or engine path pointing
/// at any root-owned executable that happens to succeed (`/usr/bin/true`),
/// turning a root-ownership check into an answer it did not give.
pub fn executable_is_trusted(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as _;
        use std::os::unix::fs::MetadataExt as _;
        if trusted_executable_locked(meta.st_flags()) {
            return true;
        }
        // Without schg the name itself must be protected, and the inode too:
        // root-owned, no write access beyond the owner (group/other bits or
        // an ACL entry would let a non-root principal edit the bytes in
        // place), and no ancestor this user could rename through.
        meta.uid() == 0
            && !file_is_untrusted_writable(&meta)
            && !has_extended_acl(path)
            && !path_is_user_replaceable(path)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::MetadataExt as _;
        meta.uid() == 0 && !file_is_untrusted_writable(&meta) && !path_is_user_replaceable(path)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The `schg` half of the trust decision with the metadata already read. Split
/// out so the flag check is testable without invoking `sudo`.
#[cfg(target_os = "macos")]
fn trusted_executable_locked(flags: u32) -> bool {
    const SF_IMMUTABLE: u32 = 0x0002_0000;
    flags & SF_IMMUTABLE != 0
}

/// Group/other write bits on the inode itself: a same-user (or group-member)
/// process could rewrite the bytes in place without ever renaming the path.
/// Owner write stays permitted - a root-owned file's owner bit protects
/// nothing additional, and removing it is root's own choice.
#[cfg(unix)]
fn file_is_untrusted_writable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o022 != 0
}

/// macOS access-control entries on the file itself. An ACL can grant write to
/// a principal the mode bits exclude, so any extended entry makes a non-`schg`
/// executable untrusted. `acl_get_link_np` does not follow a final symlink -
/// matching the `symlink_metadata` judgement - and an absent ACL reads as no
/// entries rather than an error.
#[cfg(target_os = "macos")]
fn has_extended_acl(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    unsafe extern "C" {
        fn acl_get_link_np(path: *const libc::c_char, kind: u32) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *const libc::c_void,
            entry_id: i32,
            entry: *mut *mut libc::c_void,
        ) -> i32;
        fn acl_free(obj: *mut libc::c_void) -> i32;
    }
    const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: i32 = 0;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    unsafe {
        let acl = acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            // A null result is only "no extended ACL" when the query says
            // so: ENOENT is the documented no-list outcome. Any other error
            // means the ACL could not be inspected, and an uninspectable
            // ACL may grant write access - fail closed.
            return std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT);
        }
        let mut entry = std::ptr::null_mut();
        let present = acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) == 0;
        acl_free(acl);
        present
    }
}

/// Linux exposes extended ACLs through the `system.posix_acl_access` xattr:
/// its presence means entries beyond the mode bits exist. A listing that
/// fails is not proof of absence - fail closed like the macOS query.
#[cfg(target_os = "linux")]
fn has_extended_acl(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    unsafe {
        let needed = libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0);
        if needed <= 0 {
            return needed < 0;
        }
        let mut list = vec![0u8; needed as usize];
        let got = libc::llistxattr(path.as_ptr(), list.as_mut_ptr().cast(), list.len());
        if got < 0 {
            return true;
        }
        list[..got as usize]
            .split(|b| *b == 0)
            .any(|name| name == b"system.posix_acl_access")
    }
}

/// Where no ACL primitive is known, a path cannot be proven protected:
/// report it writable rather than bless an ancestor nobody inspected.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn has_extended_acl(_path: &Path) -> bool {
    true
}

/// Whether any ancestor of `path` lets a non-root user rename entries. A
/// root-owned file below such a directory can have its name swapped for
/// another inode between a trust check and exec, so ownership of the file
/// alone cannot be trusted there.
///
/// Two chains are judged, not one. The spelling's own parents matter
/// because a symlinked component is swapped by whoever writes its parent;
/// the canonical target's ancestors matter because a swap deeper in the
/// resolved tree moves every name beneath it. A component either chain
/// cannot inspect - a failed stat, a non-directory ancestor, an unreadable
/// ACL - is not provably protected, so the answer fails closed.
#[cfg(unix)]
fn path_is_user_replaceable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let mut candidates: Vec<PathBuf> = path.ancestors().skip(1).map(PathBuf::from).collect();
    match path.canonicalize() {
        Ok(resolved) => {
            candidates.extend(resolved.ancestors().skip(1).map(PathBuf::from));
        }
        Err(_) => {
            // The resolved chain cannot be inspected at all - the executable
            // may not even exist - and an uninspectable chain is not
            // provably protected.
            return true;
        }
    }
    for d in &candidates {
        let Ok(meta) = std::fs::metadata(d) else {
            return true;
        };
        // An ancestor that is not a directory cannot hold the name being
        // checked; the chain is malformed, not protected.
        if !meta.is_dir() {
            return true;
        }
        // Non-root ownership, or group/other write: someone other than root
        // can rename the directory's entries. Root-owned 0755 chains are the
        // trusted shape (`/usr`, `/usr/bin`).
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return true;
        }
        // An extended ACL can grant add_file/delete_child to a non-root
        // principal even on a root-owned 0755 directory - mode bits alone
        // cannot see it, and an ACL that cannot be inspected may grant the
        // rename this check exists to rule out.
        if has_extended_acl(d) {
            return true;
        }
    }
    false
}

/// The trusted public anchor. Only meaningful while root-owned: a file any
/// same-user process can overwrite anchors nothing.
///
/// Deliberately not XDG-honoured: the anchor is the trust root. If it moved
/// with `XDG_CONFIG_HOME`, pointing that variable elsewhere would disarm
/// enforcement - the trust root must not follow the file it protects.
pub fn anchor_path() -> PathBuf {
    // Test escape, debug builds only: an integration fixture cannot chown a
    // file to root, so it points the anchor at a path it owns to arm
    // enforcement.
    // A release binary never honours the variable.
    if cfg!(debug_assertions)
        && let Ok(explicit) = std::env::var("GITVAULT_ANCHOR")
    {
        return PathBuf::from(explicit);
    }
    home_dir()
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
    /// Present but not immobilised: a same-user process could plant or replace
    /// it, so it anchors nothing. Boundaries fail closed rather than downgrade
    /// to unsigned acceptance.
    Unanchored,
    /// Root-owned and irreplaceable by this user: enforcement is on, unsigned
    /// or wrongly signed configurations are refused.
    Anchored,
}

/// Whether the anchor's inode and name are beyond this user's reach: a
/// root-owned regular file, no group/other write or extended ACL, and either
/// the system-immutable flag or a directory chain no non-root rename can move.
/// A root-owned file under a user-writable parent is still replaceable - the
/// parent lets a same-UID process unlink it and drop a substitute anchor.
#[cfg(unix)]
fn anchor_is_protected(anchor: &Path, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    if meta.uid() != 0 || file_is_untrusted_writable(meta) || has_extended_acl(anchor) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as _;
        if trusted_executable_locked(meta.st_flags()) {
            return true;
        }
    }
    !path_is_user_replaceable(anchor)
}

pub fn anchor_state(anchor: &Path) -> Anchor {
    if !anchor.exists() {
        return Anchor::Absent;
    }
    // The GITVAULT_ANCHOR escape also arms enforcement: the fixture's file
    // cannot be made root-owned. Arming is all the override can do - it can
    // never weaken a check the real anchor would have run. It arms only the
    // exact path it names, so a caller that resolves a different path (for
    // example from a redirected HOME) cannot borrow the fixture's authority.
    if cfg!(debug_assertions)
        && std::env::var_os("GITVAULT_ANCHOR")
            .is_some_and(|explicit| Path::new(&explicit) == anchor)
    {
        return Anchor::Anchored;
    }
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(anchor) {
            Ok(meta) if anchor_is_protected(anchor, &meta) => Anchor::Anchored,
            // An anchor that exists but cannot be proven protected is not
            // "absent": treating it as legacy mode would let a same-user
            // process disarm enforcement by degrading the file.
            _ => Anchor::Unanchored,
        }
    }
    #[cfg(not(unix))]
    {
        Anchor::Anchored
    }
}

/// Where a file's signature stands, without refusing it. Audit surfaces
/// classify first so the audits can run (or visibly decline) before the
/// operator is asked to bless anything: the signature certifies what was
/// already shown, it is never a blind precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigState {
    /// Enforcement is armed and the file verifies against its sidecar.
    Valid,
    /// Enforcement is armed; the file is unsigned or fails verification.
    /// The reason is operator-facing.
    Invalid(String),
    /// No root-owned anchor (or a test escape): enforcement is inactive
    /// and the file is accepted as-is.
    Inactive,
}

/// Classify `path` without refusing it - the audit-first counterpart of
/// [`verify`].
pub fn signature_state(config_path: &Path) -> SigState {
    let anchor = anchor_path();
    match anchor_state(&anchor) {
        Anchor::Absent => SigState::Inactive,
        // An anchor that cannot be proven protected is a degraded trust root:
        // unsigned or tampered routing must refuse, not fall back to legacy
        // acceptance - otherwise deleting the flag removes enforcement.
        Anchor::Unanchored => SigState::Invalid(format!(
            "the trust anchor {} is present but not protected (root-owned and \
             system-immutable or beneath a root-owned chain) - enforcement \
             cannot tell armed from tampered; run `gitvault install`",
            anchor.display()
        )),
        Anchor::Anchored => {
            if !sig_path(config_path).exists() {
                return SigState::Invalid(format!("{} is unsigned", config_path.display()));
            }
            match verify_signed(config_path, None, &anchor) {
                Ok(()) => SigState::Valid,
                Err(e) => SigState::Invalid(format!(
                    "{} failed signature verification: {e:#}",
                    config_path.display()
                )),
            }
        }
    }
}

/// [`signature_state`] over caller-supplied bytes instead of a fresh read. The
/// credential broker uses this so the buffer it authorized from is the buffer
/// the signature was checked against - a file replaced between the parse and
/// the credential moment cannot pass on a different signed copy.
pub fn signature_state_for(config_path: &Path, data: &[u8]) -> SigState {
    let anchor = anchor_path();
    match anchor_state(&anchor) {
        Anchor::Absent => SigState::Inactive,
        Anchor::Unanchored => SigState::Invalid(format!(
            "the trust anchor {} is present but not protected - refusing to \
             trust unsigned routing; run `gitvault install`",
            anchor.display()
        )),
        Anchor::Anchored => {
            if !sig_path(config_path).exists() {
                return SigState::Invalid(format!("{} is unsigned", config_path.display()));
            }
            match verify_signed(config_path, Some(data), &anchor) {
                Ok(()) => SigState::Valid,
                Err(e) => SigState::Invalid(format!(
                    "{} failed signature verification: {e:#}",
                    config_path.display()
                )),
            }
        }
    }
}

/// Verify `config_path` against its signature sidecar, when enforcement is on.
///
/// Called from `Config::load`, which every credential-bearing surface funnels
/// through, so a tampered routing table cannot route credentials anywhere.
/// Audit surfaces use [`signature_state`] instead: they run first and ask for
/// the blessing afterwards.
pub fn verify(config_path: &Path) -> Result<()> {
    match signature_state(config_path) {
        SigState::Valid | SigState::Inactive => Ok(()),
        SigState::Invalid(reason) => {
            bail!("{reason}\n  if the edit is intended, bless it: gitvault config sign")
        }
    }
}

/// Verify `config_path` against its signature sidecar under `anchor`. The root
/// -ownership gate lives in `verify`; this is the ssh-keygen step itself.
/// `data` supplies the bytes to verify; `None` reads the file at this moment.
fn verify_signed(config_path: &Path, data: Option<&[u8]>, anchor: &Path) -> Result<()> {
    let sig = sig_path(config_path);
    if !sig.exists() {
        bail!("no signature sidecar at {}", sig.display());
    }
    let mut child = Command::new(crate::ssh::trusted_tool("ssh-keygen")?)
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
        let owned;
        let data = match data {
            Some(data) => data,
            None => {
                owned = std::fs::read(config_path)
                    .with_context(|| format!("cannot read {}", config_path.display()))?;
                &owned
            }
        };
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(data)
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
    let secret = crate::tempsecret::TempSecret::write(key_material, 0o600)?;
    let sig = sig_path(config_path);
    // A stale sidecar must not be read back as this signature.
    let _ = std::fs::remove_file(&sig);
    // On unix the signer runs with its working directory bound to the
    // secret's pinned scratch directory (fchdir in pre_exec): the relative
    // -f name resolves through the pinned inode, so no path component a
    // same-user process could reparent stands between the check and the
    // open. ssh-keygen's -f/.pub sibling convention rules out /dev/fd for
    // it, and config_path must be absolute for the re-bound cwd.
    #[cfg(unix)]
    let config_arg = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    #[cfg(not(unix))]
    let config_arg = config_path.to_path_buf();
    let mut cmd = Command::new(crate::ssh::trusted_tool("ssh-keygen")?);
    cmd.arg("-Y").arg("sign").arg("-n").arg(NAMESPACE).arg("-f");
    #[cfg(unix)]
    {
        secret.fchdir_child(&mut cmd);
        cmd.arg(secret.name());
    }
    #[cfg(not(unix))]
    cmd.arg(secret.path()?);
    let status = cmd
        .arg(&config_arg)
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
    // directory removed on every path below it. The scratch root is the
    // private one, not TMPDIR: a caller-selected temp directory can sit inside
    // the checkout being audited, and this file holds a signing key. The
    // guard stays alive for the whole keygen and `path()` re-verifies the
    // pinned directory at each use, so a mid-run relocation cannot write the
    // key into a moved root or hide that it did.
    let scratch = crate::tempsecret::private_temp_root()?;
    let leaf = format!(
        "gitvault-keygen-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    // On unix the leaf is pinned by descriptor from creation: the keygen
    // child's cwd IS the leaf inode (fchdir in pre_exec), the keypair is
    // read back through openat on that same descriptor, and cleanup is
    // unlinkat relative to it plus the root's rmdir - no path a same-user
    // process could swap, move or replant stands between "where the key
    // lands" and "what cleanup removes".
    #[cfg(unix)]
    {
        let leaf_dir = scratch.mkdir_leaf(std::ffi::OsStr::new(&leaf), 0o700)?;
        let out = keygen_in_leaf(&leaf_dir);
        leaf_dir.unlink(std::ffi::OsStr::new("key"));
        leaf_dir.unlink(std::ffi::OsStr::new("key.pub"));
        out
    }
    #[cfg(not(unix))]
    {
        let dir = scratch.path()?.join(&leaf);
        std::fs::create_dir_all(&dir)?;
        let out = keygen_in_path(&dir, &scratch).and_then(|pair| {
            scratch
                .path()
                .map(|_| pair)
                .context("the signing-key scratch root moved during keygen - refusing")
        });
        let _ = std::fs::remove_dir_all(&dir);
        out
    }
}

/// Unix: the leaf descriptor is the whole lookup root - ssh-keygen writes
/// `key`/`key.pub` inside it (child cwd bound by fchdir), and both halves
/// are read back through openat on that descriptor.
#[cfg(unix)]
fn keygen_in_leaf(leaf: &crate::tempsecret::PinnedLeaf) -> Result<(String, String)> {
    let mut cmd = Command::new(crate::ssh::trusted_tool("ssh-keygen")?);
    leaf.fchdir_child(&mut cmd);
    let status = cmd
        .args(["-t", "ed25519", "-N", "", "-C", PRINCIPAL, "-f", "key"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .context("failed to run ssh-keygen -t ed25519")?;
    if !status.success() {
        bail!("ssh-keygen could not generate the configuration signing key");
    }
    let private = leaf
        .read(std::ffi::OsStr::new("key"))
        .context("private key was not produced")?;
    let public = leaf
        .read(std::ffi::OsStr::new("key.pub"))
        .context("public key was not produced")?;
    let private = String::from_utf8(private).context("private key is not utf-8")?;
    let public_line = String::from_utf8(public).context("public key is not utf-8")?;
    // `<type> <key> <comment>` -> `<principal> <type> <key>` (allowed-signers).
    let mut fields = public_line.split_whitespace();
    let (Some(kind), Some(body)) = (fields.next(), fields.next()) else {
        bail!("ssh-keygen produced a malformed public key");
    };
    Ok((private, format!("{PRINCIPAL} {kind} {body}\n")))
}

/// Non-unix fallback: no descriptor-relative API exists, so the leaf is
/// path-based inside the pinned scratch root (itself re-asserted after
/// the child returns).
#[cfg(not(unix))]
fn keygen_in_path(
    dir: &Path,
    _scratch: &crate::tempsecret::ScratchRoot,
) -> Result<(String, String)> {
    let key = dir.join("key");
    let status = Command::new(crate::ssh::trusted_tool("ssh-keygen")?)
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
        let Ok(program) = crate::ssh::trusted_tool("ssh-keygen") else {
            return false;
        };
        Command::new(program)
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
    fn the_anchor_follows_the_account_home_not_home_env() {
        let Some(account) = real_home() else {
            return;
        };
        let redirected = dir("redirected-home");
        let old_home = std::env::var_os("HOME");
        let old_anchor = std::env::var_os("GITVAULT_ANCHOR");
        // SAFETY: this unit test is the only one that mutates HOME here; the
        // assertions use the account database, not the environment.
        unsafe {
            std::env::set_var("HOME", &redirected);
            std::env::remove_var("GITVAULT_ANCHOR");
        }
        let expected = account.join(".config").join("gitvault").join("config.pub");
        assert_eq!(anchor_path(), expected);
        assert_ne!(
            anchor_path(),
            redirected
                .join(".config")
                .join("gitvault")
                .join("config.pub"),
            "HOME must not move the trust root"
        );
        unsafe {
            match old_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            if let Some(value) = old_anchor {
                std::env::set_var("GITVAULT_ANCHOR", value);
            }
        }
        let _ = std::fs::remove_dir_all(&redirected);
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
        verify_signed(&cfg, None, &anchor).unwrap();

        // A single-byte edit must not verify.
        std::fs::write(&cfg, "[rules]\ndefault = \"attacker\"\n").unwrap();
        assert!(verify_signed(&cfg, None, &anchor).is_err());

        // Nor may a missing sidecar pass.
        let _ = std::fs::remove_file(&sig);
        assert!(verify_signed(&cfg, None, &anchor).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_user_owned_mutable_file_is_not_a_trusted_executable() {
        let d = dir("untrusted-exec");
        let binary = d.join("helper");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(
            !executable_is_trusted(&binary),
            "a same-user process could replace this file"
        );
        assert!(!executable_is_trusted(&d.join("missing")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The path is judged, not a target it points at. A same-user process that
    /// can create `~/.local/bin/gitvault-touchid` as a link to `/usr/bin/true`
    /// would otherwise turn "root-owned" into an executable that answers yes
    /// to every prompt without involving a human.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_root_owned_executable_is_not_trusted() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let target = std::fs::read_dir("/usr/bin")
            .expect("this platform needs /usr/bin for the root-owned fixture")
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                std::fs::symlink_metadata(path)
                    .map(|meta| {
                        meta.is_file() && meta.uid() == 0 && meta.permissions().mode() & 0o111 != 0
                    })
                    .unwrap_or(false)
            })
            .expect("this platform needs a root-owned regular executable to test against");
        assert!(
            executable_is_trusted(&target),
            "the regular root-owned target must itself be trusted: {}",
            target.display()
        );

        let d = dir("symlink-exec");
        let link = d.join("helper");
        symlink(&target, &link).unwrap();
        assert!(
            !executable_is_trusted(&link),
            "a planted link to a trusted target must not inherit its trust"
        );

        let dangling = d.join("dangling");
        symlink(d.join("does-not-exist"), &dangling).unwrap();
        assert!(
            !executable_is_trusted(&dangling),
            "a dangling link is not an executable"
        );

        // The installed helper is a regular `schg` file on this machine. A link
        // to it must not inherit the flag either; the check is skipped where no
        // such installation exists so the test stays portable.
        let installed = home_dir()
            .join(".local")
            .join("bin")
            .join("gitvault-touchid");
        if executable_is_trusted(&installed) {
            let mirrored = d.join("installed-helper");
            symlink(&installed, &mirrored).unwrap();
            assert!(
                !executable_is_trusted(&mirrored),
                "a link to a system-immutable helper must not be trusted"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Root ownership protects a name only while the whole parent chain is
    /// also protected; the *system* immutable flag protects it anywhere. A
    /// user immutable flag (`uchg`) can be cleared by that user without a
    /// password, so it must not count.
    #[cfg(target_os = "macos")]
    #[test]
    fn only_root_or_system_immutability_trusts_an_executable() {
        const UF_IMMUTABLE: u32 = 0x0000_0002;
        const SF_IMMUTABLE: u32 = 0x0002_0000;
        assert!(!trusted_executable_locked(0));
        assert!(!trusted_executable_locked(UF_IMMUTABLE));
        assert!(trusted_executable_locked(SF_IMMUTABLE));
        assert!(trusted_executable_locked(SF_IMMUTABLE | UF_IMMUTABLE));
    }

    /// A root-owned file in a directory this user can write is still
    /// replaceable through the name, so ownership alone cannot trust it.
    #[cfg(unix)]
    #[test]
    fn a_root_owned_file_in_a_user_writable_tree_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = dir("replaceable-exec");
        let binary = d.join("helper");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The fixture dir is user-owned, so the chain is replaceable even if
        // the file were chowned to root: ownership of an inode does not pin
        // the name a same-user process can swap.
        assert!(path_is_user_replaceable(&binary));
        assert!(
            !executable_is_trusted(&binary),
            "a binary a same-user process can rename over must not be trusted"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Group/other write bits let a non-root principal rewrite the inode in
    /// place without ever touching the name: an executable carrying them is
    /// untrusted even under a root-owned, unreplaceable chain.
    #[cfg(unix)]
    #[test]
    fn a_writable_executable_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = dir("writable-exec");
        let binary = d.join("helper");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        for (mode, writable) in [(0o755, false), (0o775, true), (0o757, true), (0o700, false)] {
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(mode)).unwrap();
            let meta = std::fs::metadata(&binary).unwrap();
            assert_eq!(file_is_untrusted_writable(&meta), writable, "mode {mode:o}");
        }
        // The mode bits say trusted while an ACL grants access anyway: an
        // extended entry must register on its own.
        #[cfg(target_os = "macos")]
        {
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(!has_extended_acl(&binary), "the fixture carries no ACL");
            let added = std::process::Command::new("chmod")
                .args(["+a", "everyone deny delete"])
                .arg(&binary)
                .status();
            if added.map(|s| s.success()).unwrap_or(false) {
                assert!(has_extended_acl(&binary), "an ACL entry must register");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The replaceability walk inspects ACLs on every ancestor, not only the
    /// file: an ACL granting add_file/delete_child on a directory is exactly
    /// how a non-root principal swaps a name the mode bits protect. The
    /// fixture proves the detection layer on a directory; the root-owned
    /// chain shape itself cannot be built inside a test.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_acl_on_a_parent_directory_registers() {
        let d = dir("acl-parent");
        assert!(
            !has_extended_acl(&d),
            "the fixture directory carries no ACL"
        );
        let added = std::process::Command::new("chmod")
            .args(["+a", "everyone deny delete_child"])
            .arg(&d)
            .status();
        if added.map(|s| s.success()).unwrap_or(false) {
            assert!(
                has_extended_acl(&d),
                "an ACL on a directory ancestor must register"
            );
            // The same probe failing closed is what makes the directory
            // untrusted; a directory carrying an ACL can never be a provably
            // protected ancestor.
        }
        let _ = std::process::Command::new("chmod")
            .args(["-a#", "0"])
            .arg(&d)
            .status();
        let _ = std::fs::remove_dir_all(&d);
    }
}
