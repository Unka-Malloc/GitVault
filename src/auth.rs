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
    println!("the key is in the keychain under service '{}'", crate::vault::keychain_service());
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
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("token for {account} (input hidden): ");
        io::stderr().flush().ok();
        let token = rpassword_fallback()?;
        eprintln!();
        Ok(token.trim().to_string())
    } else {
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .context("could not read the token from stdin")?;
        Ok(line.trim().to_string())
    }
}

/// Minimal hidden-input reader. Avoids a dependency for one prompt; falls back to
/// a plain read when the terminal cannot be put in no-echo mode.
fn rpassword_fallback() -> Result<String> {
    let status = std::process::Command::new("stty")
        .arg("-echo")
        .status();
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);
    if status.map(|s| s.success()).unwrap_or(false) {
        let _ = std::process::Command::new("stty").arg("echo").status();
    }
    read.context("could not read the token")?;
    Ok(line)
}

/// Remove selected material for an account.
///
/// Scoped, not wholesale. The original version deleted the entire entry, so
/// removing a key in order to re-import it also discarded the account's token - a
/// token that may not be re-derivable. Verified by doing exactly that to a live
/// PAT. Removal now names what is being removed, and an unscoped removal of an
/// entry holding more than one kind of material requires `--all`.
pub fn cmd_remove(
    vault: &Vault,
    account: &str,
    what: RemoveWhat,
) -> Result<()> {
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
        let slot = if signing { &mut e.signing_key } else { &mut e.ssh_key };
        found = slot.take().is_some();
        // A passphrase with no key left to unlock is dead weight.
        if !signing && e.ssh_key.is_none() && e.signing_key.is_none() {
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
    let material = std::fs::read_to_string(file)
        .with_context(|| format!("cannot read {}", file.display()))?;
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
    if let Some(pass) = passphrase {
        if !pass.is_empty() {
            store.set_passphrase(account, &pass);
        }
    }
    vault.save(&store)?;

    println!(
        "imported {} for '{account}' from {}",
        if signing { "signing key" } else { "ssh key" },
        file.display()
    );
    println!(
        "  fingerprint: {}",
        Store::fingerprint(&material)
    );
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

