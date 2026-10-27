//! `gitvault auth` - manage stored GitHub credentials.
//!
//! This replaces `gh auth`. The commands exist so that GitVault can be the only
//! holder of GitHub tokens on the machine; once that is true, a process cannot
//! reach the API through a CLI, because there is no CLI holding a token.
//!
//! Token entry is always interactive on stdin. A token passed as an argument
//! would land in shell history and in the process list, which is how tokens leak
//! in practice.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::vault::{Store, Vault};

pub fn cmd_init(vault: &Vault) -> Result<()> {
    if vault.exists() {
        // Not an error: re-initialising must not silently discard stored tokens.
        println!(
            "vault already exists at {} ({} account(s) stored)",
            vault.path().display(),
            vault.load().map(|s| s.accounts.len()).unwrap_or(0)
        );
        return Ok(());
    }
    // Creating the key is the whole job; an empty encrypted blob proves the key
    // works before any credential depends on it.
    vault.save(&Store::default())?;
    println!("vault created at {}", vault.path().display());
    println!(
        "the key is in the keychain under service '{}'",
        crate::vault::keychain_service()
    );
    Ok(())
}

pub fn cmd_add(vault: &Vault, account: &str) -> Result<()> {
    if account.trim().is_empty() {
        bail!("account name must not be empty");
    }
    let token = read_token(account)?;
    if token.is_empty() {
        bail!("no token was provided");
    }

    let mut store = vault.load()?;
    let existed = store.get(account).is_some();
    store.insert(account, &token);
    vault.save(&store)?;

    println!(
        "{} token for '{account}' ({}, {} chars)",
        if existed { "replaced" } else { "stored" },
        Store::fingerprint(&token),
        token.len()
    );
    Ok(())
}

/// Read a token without echoing it and without putting it in argv.
fn read_token(account: &str) -> Result<String> {
    read_secret_line(
        &format!("token for {account} (input hidden): "),
        "the token",
    )
}

/// Read one secret line: prompt on stderr, no terminal echo, nothing in argv.
///
/// A terminal whose echo cannot be disabled refuses rather than leaking the
/// secret into scrollback; the restore guard puts the terminal back on every
/// exit path, including an interrupted or failed read. A non-terminal stdin is
/// the piped-input mode and reads plainly.
pub(crate) fn read_secret_line(prompt: &str, what: &str) -> Result<String> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .with_context(|| format!("could not read {what} from stdin"))?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let line = {
        let _hidden = HiddenEcho::engage()?;
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .with_context(|| format!("could not read {what}"))?;
        line
    };
    eprintln!();
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// The terminal with echo switched off; dropping restores the saved flags.
/// On a terminal, hidden input either holds or the read never happens.
#[cfg(unix)]
struct HiddenEcho {
    fd: i32,
    saved: libc::termios,
}

#[cfg(unix)]
impl HiddenEcho {
    fn engage() -> Result<Self> {
        use std::os::unix::io::AsRawFd as _;
        let fd = io::stdin().as_raw_fd();
        let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            anyhow::bail!("cannot read terminal state for hidden input");
        }
        let mut hidden = saved;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            anyhow::bail!("cannot disable terminal echo for hidden input");
        }
        Ok(Self { fd, saved })
    }
}

#[cfg(unix)]
impl Drop for HiddenEcho {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(not(unix))]
struct HiddenEcho;

#[cfg(not(unix))]
impl HiddenEcho {
    fn engage() -> Result<Self> {
        anyhow::bail!("hidden terminal input is not supported on this platform")
    }
}

/// Remove selected material for an account.
///
/// Scoped, not wholesale. The original version deleted the entire entry, so
/// removing a key in order to re-import it also discarded the account's token - a
/// token that may not be re-derivable. Verified by doing exactly that to a live
/// PAT. Removal now names what is being removed, and an unscoped removal of an
/// entry holding more than one kind of material requires `--all`.
pub fn cmd_remove(vault: &Vault, account: &str, what: RemoveWhat) -> Result<()> {
    let mut store = vault.load()?;
    let Some(entry) = store.entry(account) else {
        println!("nothing stored for '{account}'");
        return Ok(());
    };

    let holds = [
        entry.token.is_some().then_some("token"),
        entry.ssh_key.is_some().then_some("ssh-key"),
        entry.signing_key.is_some().then_some("signing-key"),
        entry.passphrase.is_some().then_some("passphrase"),
        entry
            .signing_passphrase
            .is_some()
            .then_some("signing-passphrase"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    let remove_token = matches!(what, RemoveWhat::Token | RemoveWhat::All);
    let remove_keys = matches!(what, RemoveWhat::Keys | RemoveWhat::All);

    // Refuse an ambiguous removal rather than guessing. Silently discarding a token
    // alongside a key is the failure this guards against.
    if matches!(what, RemoveWhat::Token) && holds.len() > 1 {
        bail!(
            "'{account}' also holds {}; \
             removing only the token would leave them\n  \
             use --keys to remove the keys, or --all to remove everything",
            holds
                .iter()
                .filter(|h| **h != "token")
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut removed = Vec::new();
    if let Some(e) = store.accounts.get_mut(account) {
        if remove_token && e.token.take().is_some() {
            removed.push("token");
        }
        if remove_keys {
            if e.ssh_key.take().is_some() {
                removed.push("ssh-key");
            }
            if e.signing_key.take().is_some() {
                removed.push("signing-key");
            }
            if e.passphrase.take().is_some() {
                removed.push("passphrase");
            }
            if e.signing_passphrase.take().is_some() {
                removed.push("signing-passphrase");
            }
        }
    }
    store.prune(account);
    vault.save(&store)?;

    if removed.is_empty() {
        println!("nothing matched for '{account}'");
    } else {
        println!("removed {} from '{account}'", removed.join(", "));
    }
    Ok(())
}

/// Remove just the authentication key, or just the signing key.
pub fn cmd_remove_key(vault: &Vault, account: &str, signing: bool) -> Result<()> {
    let mut store = vault.load()?;
    let label = if signing { "signing-key" } else { "ssh-key" };
    let mut found = false;
    if let Some(e) = store.accounts.get_mut(account) {
        let slot = if signing {
            &mut e.signing_key
        } else {
            &mut e.ssh_key
        };
        found = slot.take().is_some();
        // A passphrase with no key left to unlock is dead weight.
        if signing {
            if e.signing_key.is_none() {
                e.signing_passphrase = None;
            }
        } else if e.ssh_key.is_none() {
            e.passphrase = None;
        }
    }
    store.prune(account);
    vault.save(&store)?;
    println!(
        "{} {label} for '{account}'",
        if found { "removed" } else { "no" }
    );
    Ok(())
}

/// Which part of an entry to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveWhat {
    Token,
    Keys,
    All,
}

pub fn cmd_list(vault: &Vault, cfg: &Config, json: bool) -> Result<()> {
    let store = vault.load()?;

    // Which identities reference each account, so the listing answers the question
    // a reader actually has: what can this material act as?
    let mut used_by: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for (key, id) in &cfg.identities {
        if let Some(acct) = &id.account {
            used_by.entry(acct.as_str()).or_default().push(key.as_str());
        }
    }

    // Report kinds and fingerprints, never material. An agent needs to know
    // whether it can act; it never needs the secret to find that out.
    let describe = |e: &crate::vault::Entry| -> Vec<String> {
        let mut kinds = Vec::new();
        if let Some(t) = &e.token {
            kinds.push(format!("token:{}", Store::fingerprint(t)));
        }
        if let Some(k) = &e.ssh_key {
            kinds.push(format!("ssh-key:{}", Store::fingerprint(k)));
        }
        if let Some(k) = &e.signing_key {
            kinds.push(format!("signing-key:{}", Store::fingerprint(k)));
        }
        if e.passphrase.is_some() {
            kinds.push("passphrase".to_string());
        }
        if e.signing_passphrase.is_some() {
            kinds.push("signing-passphrase".to_string());
        }
        kinds
    };

    if json {
        let rows: Vec<_> = store
            .accounts
            .iter()
            .map(|(acct, e)| {
                serde_json::json!({
                    "account": acct,
                    "holds": describe(e),
                    "identities": used_by.get(acct.as_str()).cloned().unwrap_or_default(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if store.accounts.is_empty() {
        println!("nothing stored");
        return Ok(());
    }
    for (acct, e) in &store.accounts {
        let ids = used_by
            .get(acct.as_str())
            .map(|v| v.join(", "))
            .unwrap_or_else(|| "(unreferenced by any identity)".to_string());
        println!("{acct:<24} {}  identities: {ids}", describe(e).join("  "));

        if !used_by.contains_key(acct.as_str()) {
            println!(
                "{:<24} ^ stored but unreachable: no identity names this account",
                ""
            );
        }
    }
    Ok(())
}

/// Import a private key from a file into the vault.
///
/// The point is to be able to delete the file afterwards: while a key exists on
/// disk, any process can read it and use it as that identity anywhere.
pub fn cmd_import_key(
    vault: &Vault,
    account: &str,
    file: &std::path::Path,
    signing: bool,
    passphrase: Option<String>,
) -> Result<()> {
    let material =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    if !material.contains("PRIVATE KEY") {
        bail!(
            "{} does not look like a private key (no PRIVATE KEY marker)",
            file.display()
        );
    }

    let mut store = vault.load()?;
    if signing {
        store.set_signing_key(account, &material);
    } else {
        store.set_ssh_key(account, &material);
    }
    if let Some(pass) = passphrase
        && !pass.is_empty()
    {
        if signing {
            store.set_signing_passphrase(account, &pass);
        } else {
            store.set_passphrase(account, &pass);
        }
    }
    vault.save(&store)?;

    println!(
        "imported {} for '{account}' from {}",
        if signing { "signing key" } else { "ssh key" },
        file.display()
    );
    println!("  fingerprint: {}", Store::fingerprint(&material));
    println!("  the file on disk is now redundant; deleting it is the point of importing");
    Ok(())
}

/// Report presence, never content. An agent needs to know whether it can act;
/// it never needs the token to find that out.
pub fn cmd_status(vault: &Vault, cfg: &Config, account: Option<&str>, json: bool) -> Result<()> {
    let store = vault.load()?;

    let wanted: Vec<String> = match account {
        Some(a) => vec![a.to_string()],
        None => {
            let mut v: Vec<String> = cfg
                .identities
                .values()
                .filter_map(|i| i.account.clone())
                .collect();
            v.sort();
            v.dedup();
            v
        }
    };

    if wanted.is_empty() {
        println!("no accounts are referenced by any identity");
        return Ok(());
    }

    if json {
        let rows: Vec<_> = wanted
            .iter()
            .map(|acct| {
                serde_json::json!({
                    "account": acct,
                    "stored": store.get(acct).is_some(),
                    "fingerprint": store.get(acct).map(Store::fingerprint),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    for acct in &wanted {
        match store.get(acct) {
            Some(t) => println!("{acct:<24} stored  {}", Store::fingerprint(t)),
            None => println!("{acct:<24} MISSING (run: gitvault auth add {acct})"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A vault on a temporary path, backed by a process-cached key: no
    /// keychain, no real vault file. All tests cache the same 32-byte key so
    /// parallel runs never see each other's key material.
    fn vault(tag: &str) -> (Vault, PathBuf) {
        let dir = std::env::temp_dir().join(format!("gv-auth-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::unlock::cache_key(&[7u8; 32], std::time::Duration::from_secs(60));
        (Vault::open_at(dir.join("vault.enc")).unwrap(), dir)
    }

    fn store_with(token: bool, ssh: bool, signing: bool) -> Store {
        let mut store = Store::default();
        if token {
            store.insert("acct", "tok");
        }
        if ssh {
            store.set_ssh_key("acct", "SSH-KEY");
        }
        if signing {
            store.set_signing_key("acct", "SIGN-KEY");
        }
        store
    }

    #[test]
    fn removing_a_token_from_a_mixed_entry_is_refused() {
        // The failure this scoped delete exists to prevent: a token that may
        // not be re-derivable must never ride along with a key removal.
        let (v, dir) = vault("mixed");
        v.save(&store_with(true, true, false)).unwrap();
        assert!(cmd_remove(&v, "acct", RemoveWhat::Token).is_err());
        let e = v.load().unwrap().entry("acct").unwrap().clone();
        assert!(
            e.token.is_some() && e.ssh_key.is_some(),
            "a refused removal must change nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_removal_keeps_the_token() {
        let (v, dir) = vault("keys");
        v.save(&store_with(true, true, true)).unwrap();
        cmd_remove(&v, "acct", RemoveWhat::Keys).unwrap();
        let e = v.load().unwrap().entry("acct").unwrap().clone();
        assert!(e.token.is_some());
        assert!(e.ssh_key.is_none() && e.signing_key.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_everything_prunes_the_entry() {
        let (v, dir) = vault("all");
        v.save(&store_with(true, true, false)).unwrap();
        cmd_remove(&v, "acct", RemoveWhat::All).unwrap();
        assert!(v.load().unwrap().entry("acct").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_a_lone_token_prunes_the_entry() {
        let (v, dir) = vault("lone");
        v.save(&store_with(true, false, false)).unwrap();
        cmd_remove(&v, "acct", RemoveWhat::Token).unwrap();
        assert!(v.load().unwrap().entry("acct").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_the_last_auth_key_drops_the_passphrase() {
        let (v, dir) = vault("pass");
        let mut store = store_with(true, true, false);
        store.set_passphrase("acct", "pw");
        v.save(&store).unwrap();
        cmd_remove_key(&v, "acct", false).unwrap();
        let e = v.load().unwrap().entry("acct").unwrap().clone();
        assert!(e.ssh_key.is_none() && e.passphrase.is_none());
        assert!(e.token.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_rejects_a_file_with_no_private_key_marker() {
        let (v, dir) = vault("import");
        let file = dir.join("not-a-key.txt");
        std::fs::write(&file, "just some text").unwrap();
        assert!(cmd_import_key(&v, "acct", &file, false, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
