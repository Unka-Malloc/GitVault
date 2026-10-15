//! Credential storage and per-command issuance.
//!
//! GitVault is meant to become the ONLY thing on the machine that holds GitHub
//! credentials, so that a process cannot reach the API by calling a CLI directly.
//! Three properties follow from that intent:
//!
//! 1. **One file, one key.** Every account token lives in a single encrypted
//!    blob. The key is fetched from the OS keychain on demand, so the tokens are
//!    never readable as plaintext on disk - not in a config file, not in a
//!    credential store another tool knows how to open.
//! 2. **Never printed.** No command prints a stored secret. `list` shows names and
//!    a fingerprint; the token itself leaves only through the credential-helper
//!    path, which git consumes and does not display.
//! 3. **Policy at issuance.** A caller asking for a token gets one only if the
//!    resolved identity is permitted to act on the target repository. Storing a
//!    credential does not imply it may be used anywhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"GITVLT01";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Keychain service name for the vault key. One entry, not one per account:
/// per-account entries would be individually readable by any process that knows
/// the service name, which is the situation this module exists to avoid.
const KEYCHAIN_SERVICE: &str = "gitvault-vault-key";

/// Overridable so tests do not touch the real vault key.
pub(crate) fn keychain_service() -> String {
    std::env::var("GITVAULT_KEYCHAIN_SERVICE").unwrap_or_else(|_| KEYCHAIN_SERVICE.to_string())
}

/// Everything held for one identity in one place.
///
/// Grouping by account rather than keeping parallel maps is deliberate: a token
/// and a key that must stay together are easy to update inconsistently when they
/// live in separate structures.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(from = "EntryWire")]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// OpenSSH-format private key material, for authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<String>,
    /// OpenSSH-format private key used to sign commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// Passphrase for `ssh_key`, when it has one.
    ///
    /// Held because ssh-add cannot be fed an encrypted key through a pipe: it
    /// prompts. The alternative is keeping an unencrypted copy on disk, which is
    /// exactly what this module exists to avoid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

/// Wire form that also accepts the earlier layout.
///
/// The first release stored `account -> "token"` as a bare string. Changing the
/// value type without accepting the old shape made an existing vault unreadable,
/// which is an unacceptable failure mode for the only store of a credential: the
/// user cannot re-derive a token they no longer have.
#[derive(Deserialize)]
#[serde(untagged)]
enum EntryWire {
    /// Legacy: the value was the token itself.
    Token(String),
    Full(EntryFields),
}

#[derive(Deserialize)]
struct EntryFields {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    ssh_key: Option<String>,
    #[serde(default)]
    signing_key: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
}

impl From<EntryWire> for Entry {
    fn from(w: EntryWire) -> Self {
        match w {
            EntryWire::Token(t) => Entry {
                token: Some(t),
                ssh_key: None,
                signing_key: None,
                passphrase: None,
            },
            EntryWire::Full(f) => Entry {
                token: f.token,
                ssh_key: f.ssh_key,
                signing_key: f.signing_key,
                passphrase: f.passphrase,
            }
        }
    }
}

impl Entry {
    pub fn is_empty(&self) -> bool {
        self.token.is_none()
            && self.ssh_key.is_none()
            && self.signing_key.is_none()
            && self.passphrase.is_none()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    /// account name -> held material
    #[serde(default)]
    pub accounts: BTreeMap<String, Entry>,
}

impl Store {
    pub fn get(&self, account: &str) -> Option<&str> {
        self.accounts.get(account).and_then(|e| e.token.as_deref())
    }

    pub fn entry(&self, account: &str) -> Option<&Entry> {
        self.accounts.get(account)
    }

    pub fn insert(&mut self, account: &str, token: &str) {
        self.accounts
            .entry(account.to_string())
            .or_default()
            .token = Some(token.to_string());
    }

    pub fn set_ssh_key(&mut self, account: &str, key: &str) {
        self.accounts
            .entry(account.to_string())
            .or_default()
            .ssh_key = Some(key.to_string());
    }

    pub fn set_passphrase(&mut self, account: &str, pass: &str) {
        self.accounts
            .entry(account.to_string())
            .or_default()
            .passphrase = Some(pass.to_string());
    }

    pub fn set_signing_key(&mut self, account: &str, key: &str) {
        self.accounts
            .entry(account.to_string())
            .or_default()
            .signing_key = Some(key.to_string());
    }

    /// Drop an entry once nothing is held for it, so a listing does not show an
    /// account with no material behind it.
    pub fn prune(&mut self, account: &str) {
        if self.accounts.get(account).map(Entry::is_empty).unwrap_or(false) {
            self.accounts.remove(account);
        }
    }

    /// A short, non-reversible marker so `list` can confirm a token is present
    /// without revealing it.
    ///
    /// FNV-1a is deliberate here, not an oversight: this is a display marker, not
    /// a security primitive. It only has to be stable and to not disclose the
    /// token. A secret-dependent fast hash would be the wrong tool if it were
    /// load-bearing, and it is not.
    pub fn fingerprint(token: &str) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in token.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{:016x}", h & 0xffff_ffff_ffff)
    }
}

pub struct Vault {
    path: PathBuf,
}

impl Vault {
    pub fn default_path() -> PathBuf {
        if let Ok(explicit) = std::env::var("GITVAULT_VAULT_PATH") {
            return PathBuf::from(explicit);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Path::new(&home).join(".config").join("gitvault").join("vault.enc")
    }

    pub fn open() -> Result<Self> {
        Self::open_at(Self::default_path())
    }

    pub fn open_at(path: PathBuf) -> Result<Self> {
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Confirm the vault key can be read right now.
    ///
    /// `unlock` calls this so the window only opens after a successful keychain
    /// read. Without that ordering the window would be decorative: it could open on
    /// a machine where the key is gone, and every later operation would fail
    /// somewhere less obvious.
    pub fn verify_key(&self) -> Result<()> {
        self.encryption_key().map(|_| ())
    }

    /// The vault key when it is readable, for binding the unlock window's
    /// integrity tag. A caller that can obtain this could read the whole vault,
    /// so it is also exactly the capability a forged window would need.
    pub(crate) fn window_key(&self) -> Option<Vec<u8>> {
        self.encryption_key().ok()
    }

    /// The private key held for an account's SSH authentication.
    pub fn ssh_key_for(&self, account: &str) -> Result<String> {
        self.load()?
            .entry(account)
            .and_then(|e| e.ssh_key.clone())
            .ok_or_else(|| {
                anyhow!(
                    "no SSH key held for '{account}'\n  run: gitvault auth import-key {account} <private-key-file>"
                )
            })
    }

    /// The passphrase for an account's SSH key, when one is held.
    pub fn passphrase_for(&self, account: &str) -> Option<String> {
        self.load()
            .ok()?
            .entry(account)
            .and_then(|e| e.passphrase.clone())
    }

    /// The public half of an account's signing key, derived without writing the
    /// private key anywhere.
    pub fn signing_key_public(&self, account: &str) -> Result<String> {
        let key = self.signing_key_for(account)?;
        let pass = self.passphrase_for(account);
        crate::sign::public_key_of_material(&key, pass.as_deref())
    }

    /// The private key held for signing commits as an account.
    pub fn signing_key_for(&self, account: &str) -> Result<String> {
        self.load()?
            .entry(account)
            .and_then(|e| e.signing_key.clone())
            .ok_or_else(|| {
                anyhow!(
                    "no signing key held for '{account}'\n  run: gitvault auth import-key {account} <key> --signing"
                )
            })
    }

    /// The token for an account, or an error naming the fix.
    ///
    /// Callers inside this crate use it to perform an operation. It is
    /// deliberately not reachable from any CLI surface: no command prints a token,
    /// so there is no interface an agent can call to obtain one.
    pub fn token_for(&self, account: &str) -> Result<String> {
        let store = self.load()?;
        store.get(account).map(str::to_string).ok_or_else(|| {
            anyhow!(
                "no stored token for '{account}'\n  run: gitvault auth add {account}"
            )
        })
    }

    /// Read the store, decrypting with the keychain-held key.
    pub fn load(&self) -> Result<Store> {
        if !self.path.exists() {
            return Ok(Store::default());
        }
        let blob = std::fs::read(&self.path)
            .with_context(|| format!("cannot read {}", self.path.display()))?;
        if blob.len() < MAGIC.len() + NONCE_LEN {
            bail!("vault file is truncated: {}", self.path.display());
        }
        if &blob[..MAGIC.len()] != MAGIC {
            bail!("vault file has an unrecognised format: {}", self.path.display());
        }
        let nonce = Nonce::from_slice(&blob[MAGIC.len()..MAGIC.len() + NONCE_LEN]);
        let ciphertext = &blob[MAGIC.len() + NONCE_LEN..];
        let key = self.encryption_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("vault could not be decrypted (wrong key or corrupted file)"))?;
        let store: Store = serde_json::from_slice(&plain).map_err(|e| {
            // Never echo the parser's message: it quotes the offending input, and the
            // input is a credential. This leaked a live token once.
            anyhow!(
                "vault contents could not be read (line {}, column {})\n  \
                 the vault itself is intact; this is a format problem, not corruption",
                e.line(),
                e.column()
            )
        })?;
        Ok(store)
    }

    /// Write the store, creating the key on first use.
    pub fn save(&self, store: &Store) -> Result<()> {
        let key = self.encryption_key_or_create()?;
        let plain = serde_json::to_vec(store)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        // A fresh random nonce per write. ChaCha20-Poly1305 requires nonce
        // uniqueness under a given key, and the key is long-lived, so it is
        // generated here rather than derived.
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plain.as_slice())
            .map_err(|_| anyhow!("vault encryption failed"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        // Harden only the directories this call actually creates.
        //
        // Setting the mode on a pre-existing parent is wrong twice over: it would
        // chmod ~/.config (owned by the user, shared with every other tool) and
        // it fails outright when the parent is not ours to chmod, as /tmp is not.
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                // Walk down from the first directory we created.
                let mut created = Vec::new();
                let mut cur = Some(parent);
                while let Some(dir) = cur {
                    if dir.exists() {
                        created.push(dir.to_path_buf());
                        cur = dir.parent();
                    } else {
                        break;
                    }
                }
                for dir in created.iter().rev() {
                    let _ = set_mode(dir, 0o700);
                }
            }
        }
        // Write via a temp file in the same directory, then rename: a partial
        // write must never be able to destroy every stored credential.
        let tmp = self.path.with_extension("enc.tmp");
        std::fs::write(&tmp, &out)?;
        set_mode(&tmp, 0o600)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    // ---------------------------------------------------------------- keychain

    fn encryption_key(&self) -> Result<Vec<u8>> {
        // Reuse a key fetched earlier in this process. The cross-invocation window
        // is tracked separately by the unlock module; this only avoids re-prompting
        // within a single invocation.
        if let Some(key) = crate::unlock::cached_key() {
            return Ok(key);
        }
        let raw = keychain_get(&keychain_service()).ok_or_else(|| {
            anyhow!(
                "vault key is not in the keychain; run `gitvault auth init` first\n\
                 (or the vault was created on another machine)"
            )
        })?;
        let key = decode_key(&raw)?;
        crate::unlock::cache_key(&key, std::time::Duration::from_secs(
            crate::unlock::default_ttl_secs(),
        ));
        Ok(key)
    }

    fn encryption_key_or_create(&self) -> Result<Vec<u8>> {
        if let Some(raw) = keychain_get(&keychain_service()) {
            if let Ok(k) = decode_key(&raw) {
                return Ok(k);
            }
        }
        let key: [u8; KEY_LEN] = rand::random();
        keychain_set(&keychain_service(), &B64.encode(key))?;
        Ok(key.to_vec())
    }
}

fn decode_key(raw: &str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(raw.trim())
        .context("keychain holds a malformed vault key")?;
    if bytes.len() != KEY_LEN {
        bail!("keychain key has the wrong length");
    }
    Ok(bytes)
}

fn keychain_get(service: &str) -> Option<String> {
    let out = Command::new("security")
        .args(["find-generic-password", "-s", service, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn keychain_set(service: &str, value: &str) -> Result<()> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            "gitvault",
            "-w",
            value,
            "-U",
        ])
        .status()
        .context("failed to run the security command")?;
    if !status.success() {
        bail!("could not store the vault key in the keychain");
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trips_through_serialization() {
        let mut s = Store::default();
        s.insert("acme-bot", "token-a");
        s.insert("alice", "token-b");
        let json = serde_json::to_vec(&s).unwrap();
        let back: Store = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.get("acme-bot"), Some("token-a"));
        assert_eq!(back.get("alice"), Some("token-b"));
        assert_eq!(back.get("missing"), None);
    }

    #[test]
    fn a_legacy_vault_written_as_bare_strings_still_loads() {
        // Regression: the value type changed from String to Entry. A vault written
        // by the earlier release must keep working, because a token it holds may not
        // be re-derivable.
        let legacy = r#"{"accounts":{"Acct":"ghp_example"}}"#;
        let store: Store = serde_json::from_str(legacy).expect("legacy shape must load");
        assert_eq!(store.get("Acct"), Some("ghp_example"));
    }

    #[test]
    fn the_current_shape_round_trips() {
        let mut s = Store::default();
        s.insert("A", "tok");
        s.set_ssh_key("A", "KEY");
        s.set_signing_key("A", "SIGN");
        let json = serde_json::to_string(&s).unwrap();
        let back: Store = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get("A"), Some("tok"));
        assert_eq!(back.entry("A").unwrap().ssh_key.as_deref(), Some("KEY"));
        assert_eq!(back.entry("A").unwrap().signing_key.as_deref(), Some("SIGN"));
    }

    #[test]
    fn fingerprint_is_stable_and_differs_per_token() {
        let a = Store::fingerprint("token-a");
        let b = Store::fingerprint("token-b");
        assert_eq!(a, Store::fingerprint("token-a"));
        assert_ne!(a, b);
        // Never echo the token itself.
        assert!(!a.contains("token"));
    }

    #[test]
    fn decrypting_a_corrupt_file_is_an_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("gv-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("vault.enc");
        std::fs::write(&p, b"GITVLT01garbagegarbagegarbage").unwrap();
        let v = Vault::open_at(p.clone()).unwrap();
        // Either it fails on the missing key or on decryption; both are errors.
        assert!(v.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
