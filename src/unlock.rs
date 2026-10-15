//! Unlock gate: a bounded window during which operations may proceed.
//!
//! Opening the window requires a biometric confirmation. That is the only part of
//! this design that an automated process cannot satisfy, which is what makes the
//! window mean something rather than being a self-imposed delay.
//!
//! Three properties, each with a reason:
//!
//! 1. **Bound to the boot session.** The window is recorded on disk, so without
//!    this it would survive a reboot. A window opened before a restart must not
//!    still be open after one.
//! 2. **Bounded in time.** A window that never closed would make the confirmation
//!    a one-time ceremony. `GITVAULT_UNLOCK_TTL` sets the length.
//! 3. **Integrity-bound to the vault key.** The record carries an HMAC keyed on
//!    the vault key, so a file nobody confirmed is void. Forging one requires
//!    silently reading the vault key - the same capability as reading the vault
//!    itself - which means a process that could forge the window no longer
//!    needs it.
//! 4. **Not inherited by children.** The in-process key cache is per process, so a
//!    process spawned by an agent starts empty and must go through the gate itself.
//!
//! What this does NOT do: identify the caller. Any process running as this user can
//! ask to open a window - it just cannot complete the biometric prompt, and it
//! cannot stamp a record the gate accepts without the vault key. The gate bounds
//! "how long after a human confirmed", not "who is asking".
//!
//! A note on the keychain item: it is created with `security add-generic-password`
//! and therefore has no biometric access control, so it can be read silently. The
//! gate below is what stands between a process and the vault contents; the keychain
//! item is storage, not a lock.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

/// Cache of the vault key, bound to this process.
static CACHED: std::sync::Mutex<Option<(Vec<u8>, SystemTime)>> = std::sync::Mutex::new(None);

pub fn default_ttl_secs() -> u64 {
    std::env::var("GITVAULT_UNLOCK_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(900)
}

pub fn state_path() -> PathBuf {
    // The state path is fixed in release builds: a path a caller could rewrite
    // is a window record the caller chose the location of. GITVAULT_UNLOCK_STATE
    // remains a test hook in debug builds only, like GITVAULT_TOUCHID.
    if cfg!(debug_assertions) {
        if let Ok(explicit) = std::env::var("GITVAULT_UNLOCK_STATE") {
            return PathBuf::from(explicit);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home)
        .join(".config")
        .join("gitvault")
        .join("unlock-until")
}

/// Seconds since the epoch at which this machine booted.
///
/// Read from `kern.boottime`. Returns None when unavailable, in which case a
/// window cannot be verified and is treated as closed - a missing signal must not
/// read as approval.
pub fn boot_time() -> Option<u64> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("kern.boottime")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Format: "{ sec = 1789311564, usec = 880805 } Sun Sep 13 ..."
    let after = text.split("sec =").nth(1)?;
    let digits: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The biometric helper's fixed location.
fn default_helper() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home)
        .join(".local")
        .join("bin")
        .join("gitvault-touchid")
}

/// Ask macOS for a biometric confirmation.
///
/// Returns Ok only on an explicit success. A missing helper, an unavailable sensor
/// and a cancelled prompt are all failures: none of them may be mistaken for
/// approval.
pub fn require_biometric(reason: &str) -> Result<()> {
    // The helper path is a fixed location in release builds: a helper path a
    // caller could rewrite is a confirmation the caller can self-answer, which
    // would reduce "a human was present" to a timer. GITVAULT_TOUCHID remains a
    // test hook in debug builds only.
    let helper = if cfg!(debug_assertions) {
        std::env::var("GITVAULT_TOUCHID")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_helper())
    } else {
        default_helper()
    };

    if !helper.exists() {
        bail!(
            "biometric helper not found at {}\n  \
             install it so the unlock gate can confirm a human is present",
            helper.display()
        );
    }

    let status = Command::new(&helper)
        .arg(reason)
        .status()
        .with_context(|| format!("failed to run {}", helper.display()))?;

    if !status.success() {
        bail!("biometric confirmation was not given");
    }
    Ok(())
}

/// Open a window, asking for a biometric confirmation if one is not already open.
///
/// Shared by `gitvault unlock` and by anything that needs the vault mid-operation, so
/// the two cannot drift into different definitions of "open". This is also what keeps
/// a commit from being refused for a reason the person committing can fix in the
/// moment: being asked to confirm is a prompt, not a refusal.
///
/// `reason` is shown in the biometric prompt, so it should say what the confirmation
/// is for. `announce` prints the resulting window; an operation that continues
/// immediately does not need to be told about it.
pub fn ensure_open(
    vault: &crate::vault::Vault,
    reason: &str,
    announce: bool,
    ttl_secs: Option<u64>,
) -> Result<SystemTime> {
    if is_unlocked(vault) {
        return Ok(SystemTime::now());
    }
    if !vault.exists() {
        bail!("no vault yet; run: gitvault auth init");
    }
    let secs = ttl_secs.unwrap_or_else(default_ttl_secs);
    // Biometric first. It is the only step an automated process cannot satisfy, which
    // is what makes this a gate rather than a timer.
    require_biometric(reason)?;
    // Then prove the key is readable, so a window never opens on a machine where every
    // later operation would fail somewhere less obvious.
    vault.verify_key()?;
    let key = vault
        .window_key()
        .context("vault key became unreadable between verification and stamping")?;
    let until = mark_unlocked(Duration::from_secs(secs), &key)?;
    if announce {
        let mins = secs / 60;
        if mins >= 1 {
            println!("vault open for {secs}s (~{mins} min); run `gitvault lock` to close it now");
        } else {
            println!("vault open for {secs}s; run `gitvault lock` to close it now");
        }
    }
    Ok(until)
}

/// The window record's integrity tag.
///
/// Bound to the vault key: minting a valid window requires the same capability
/// as reading the vault itself, so a process that could forge this file no
/// longer needs the window at all. An automated process that cannot reach the
/// vault key cannot produce a record this gate accepts.
fn window_mac(key: &[u8], expiry: u64, boot: u64) -> String {
    use hmac::{Hmac, Mac};
    use hmac::digest::KeyInit;
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts a key of any length");
    mac.update(format!("gitvault-unlock:{expiry}:{boot}").as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Record a window opened just now, tagged with the vault key.
pub fn mark_unlocked(ttl: Duration, key: &[u8]) -> Result<SystemTime> {
    let until = SystemTime::now() + ttl;
    let until_secs = until
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the epoch")?
        .as_secs();
    let boot = boot_time().unwrap_or(0);

    let path = state_path();
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            let _ = restrict(parent, 0o700);
        }
    }
    // "<expiry> <boot-time> <hmac>": the boot stamp makes a stale file
    // detectable; the tag makes a fabricated one detectable.
    std::fs::write(&path, format!("{until_secs} {boot} {}\n", window_mac(key, until_secs, boot)))?;
    restrict(&path, 0o600)?;
    Ok(until)
}

pub fn clear() -> Result<()> {
    if let Ok(mut cache) = CACHED.lock() {
        *cache = None;
    }
    let path = state_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Remaining seconds in the current window; 0 when locked, stale or forged.
pub fn remaining(vault: &crate::vault::Vault) -> u64 {
    let Ok(raw) = std::fs::read_to_string(state_path()) else {
        return 0;
    };
    let mut parts = raw.split_whitespace();
    let (Some(until), Some(stamp), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
        return 0;
    };
    let (Ok(until), Ok(stamp)) = (until.parse::<u64>(), stamp.parse::<u64>()) else {
        return 0;
    };

    // A window opened before this boot is void.
    match boot_time() {
        Some(current) if current == stamp => {}
        // No boot time to compare against: treat as locked rather than assume.
        _ => return 0,
    }

    // A record nobody confirmed is void: the tag is keyed on the vault key, so
    // forging it requires the same access as reading the vault directly. A
    // machine where the key cannot be read cannot verify the window either -
    // fail closed.
    let Some(key) = vault.window_key() else {
        return 0;
    };
    if window_mac(&key, until, stamp) != tag {
        return 0;
    }

    until.saturating_sub(now_secs())
}

pub fn is_unlocked(vault: &crate::vault::Vault) -> bool {
    remaining(vault) > 0
}

// ------------------------------------------------------------ in-process cache

pub fn cached_key() -> Option<Vec<u8>> {
    let cache = CACHED.lock().ok()?;
    match cache.as_ref() {
        Some((key, until)) if SystemTime::now() < *until => Some(key.clone()),
        _ => None,
    }
}

pub fn cache_key(key: &[u8], ttl: Duration) {
    if let Ok(mut cache) = CACHED.lock() {
        *cache = Some((key.to_vec(), SystemTime::now() + ttl));
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_state<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gv-unlock-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unlock-until");
        let previous = std::env::var("GITVAULT_UNLOCK_STATE").ok();
        // SAFETY: ENV_LOCK serialises every test that touches this variable.
        unsafe { std::env::set_var("GITVAULT_UNLOCK_STATE", &path) };
        let out = f();
        match previous {
            Some(v) => unsafe { std::env::set_var("GITVAULT_UNLOCK_STATE", v) },
            None => unsafe { std::env::remove_var("GITVAULT_UNLOCK_STATE") },
        }
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn seeded_vault(key: &[u8; 32]) -> crate::vault::Vault {
        // window_key() consults the in-process cache first, so a synthetic key
        // stands in for the keychain item without touching it. The key must be
        // 32 bytes like a real vault key: a sibling test can pick it up through
        // the same cache, and a wrong length would panic the cipher.
        crate::unlock::cache_key(key, Duration::from_secs(60));
        crate::vault::Vault::open().unwrap()
    }

    #[test]
    fn window_opens_and_closes() {
        with_state("open", || {
            clear().unwrap();
            let key = b"synthetic-window-key-01234567890";
            let vault = seeded_vault(key);
            assert_eq!(remaining(&vault), 0);
            assert!(!is_unlocked(&vault));

            mark_unlocked(Duration::from_secs(60), key).unwrap();
            assert!(is_unlocked(&vault));
            assert!(remaining(&vault) > 50);

            // A forged record — right shape, tag nobody minted — is still locked.
            let forged = format!("{} {} {}\n", now_secs() + 3600, boot_time().unwrap_or(0), "0".repeat(64));
            std::fs::write(state_path(), forged).unwrap();
            assert_eq!(remaining(&vault), 0, "a tag the vault key did not mint must lock");
            // A record minted under a different key is equally void.
            let boot = boot_time().unwrap_or(0);
            let expiry = now_secs() + 3600;
            let alien = window_mac(b"a-different-key-0123456789ab", expiry, boot);
            std::fs::write(state_path(), format!("{expiry} {boot} {alien}\n")).unwrap();
            assert_eq!(remaining(&vault), 0, "a tag under another key must lock");

            mark_unlocked(Duration::from_secs(60), key).unwrap();
            clear().unwrap();
            assert!(!is_unlocked(&vault));
        });
    }

    #[test]
    fn an_expired_window_is_locked() {
        with_state("expired", || {
            clear().unwrap();
            let key = b"synthetic-window-key-01234567890";
            let vault = seeded_vault(key);
            let boot = boot_time().unwrap_or(0);
            std::fs::write(state_path(), format!("1 {boot} {}\n", window_mac(key, 1, boot))).unwrap();
            assert_eq!(remaining(&vault), 0);
            assert!(!is_unlocked(&vault));
        });
    }

    #[test]
    fn a_window_from_a_previous_boot_is_void() {
        // The point of the boot stamp: a window that survived a restart must not
        // still be open.
        with_state("prior-boot", || {
            clear().unwrap();
            let key = b"synthetic-window-key-01234567890";
            let vault = seeded_vault(key);
            let current = boot_time().unwrap_or(1);
            let different = current.wrapping_sub(1);
            let expiry = now_secs() + 3600;

            std::fs::write(state_path(), format!("{expiry}\n")).unwrap();
            assert_eq!(remaining(&vault), 0, "a missing boot stamp must lock");

            let tag = window_mac(key, expiry, different);
            std::fs::write(state_path(), format!("{expiry} {different} {tag}\n")).unwrap();
            assert_eq!(remaining(&vault), 0, "a different boot session must lock");
        });
    }

    #[test]
    fn a_missing_or_malformed_state_file_is_locked() {
        with_state("missing", || {
            clear().unwrap();
            let vault = seeded_vault(b"synthetic-window-key-01234567890");
            let _ = std::fs::remove_file(state_path());
            assert_eq!(remaining(&vault), 0);
            std::fs::write(state_path(), "not a number\n").unwrap();
            assert_eq!(remaining(&vault), 0);
            std::fs::write(state_path(), "").unwrap();
            assert_eq!(remaining(&vault), 0);
            // The legacy two-field record predates the integrity tag; it cannot
            // stand in for a window nobody confirmed.
            std::fs::write(state_path(), format!("{} {}\n", now_secs() + 3600, boot_time().unwrap_or(0))).unwrap();
            assert_eq!(remaining(&vault), 0, "a record without an integrity tag must lock");
        });
    }

    #[test]
    fn a_missing_biometric_helper_is_a_failure_not_a_pass() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var("GITVAULT_TOUCHID").ok();
        unsafe { std::env::set_var("GITVAULT_TOUCHID", "/nonexistent/touchid") };
        let result = require_biometric("test");
        match previous {
            Some(v) => unsafe { std::env::set_var("GITVAULT_TOUCHID", v) },
            None => unsafe { std::env::remove_var("GITVAULT_TOUCHID") },
        }
        assert!(result.is_err(), "a missing helper must not read as approval");
    }
}
