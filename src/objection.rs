//! Operator-ruled objections to checker findings.
//!
//! A blocking checker verdict is evidence, not law: the operator may rule
//! that a finding does not apply. The ruling channel is a signed ledger at
//! `~/.config/gitvault/objections.toml`, blessed by the same configuration
//! signing key that certifies the routing table — so a waiver is as hard to
//! forge as the configuration itself. An unsigned or tampered ledger waives
//! nothing. Probator verifies this ledger when it evaluates a gate finding;
//! GitVault only files, rules on and signs it.
//!
//! Two kinds of rulings:
//!
//! - `finding`: waives one blocking finding, matched by checker, repository
//!   and file, optionally narrowed by line or by the finding's fingerprint
//!   (a hash of its evidence text). A location-level ruling persists while
//!   the checker's wording drifts; a fingerprint ruling lapses as soon as
//!   the finding text changes.
//! - `verdict`: accepts a whole non-pass outcome — including an
//!   `incomplete` that produced no findings at all — for one candidate:
//!   the ruling binds the exact head sha and lapses when it moves.
//!
//! Objections are filed into `objections.pending.toml` (unsigned, inert)
//! and become effective only when the operator rules on them through
//! `gitvault objection rule`, which requires the biometric vault
//! confirmation every credential-bearing operation requires.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// `~/.config/gitvault` — shared by both binaries that include this
/// module (`gitvault` also exposes it as `config::config_dir()`).
fn gitvault_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home).join(".config")
        })
        .join("gitvault")
}

/// `~/.config/gitvault/objections.toml` — the signed rulings ledger.
pub fn ledger_path() -> PathBuf {
    gitvault_dir().join("objections.toml")
}

/// `~/.config/gitvault/objections.pending.toml` — filed, not yet ruled.
pub fn pending_path() -> PathBuf {
    gitvault_dir().join("objections.pending.toml")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ruling {
    pub id: String,
    /// Repository slug (`owner/name`) the ruling is scoped to; empty means
    /// the ruling holds for any repository the finding appears in.
    #[serde(default)]
    pub repo: String,
    /// Checker contract name, e.g. `money-saver`.
    pub checker: String,
    /// `finding` waives one finding; `verdict` accepts a whole non-pass
    /// outcome for the bound head.
    pub kind: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: Option<u64>,
    /// sha256 of the finding's normalized evidence text; set at filing so
    /// the ruling lapses if the finding is reworded.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// The candidate head a `verdict` ruling covers.
    #[serde(default)]
    pub head: String,
    /// `overruled` waives; `sustained` records that the finding stands.
    pub verdict: String,
    /// Why the objection was filed.
    #[serde(default)]
    pub objection: String,
    /// The operator's adjudication note.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ruled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub id: String,
    #[serde(default)]
    pub repo: String,
    pub checker: String,
    pub kind: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: Option<u64>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub head: String,
    pub reason: String,
    #[serde(default)]
    pub filed_at: String,
}

/// A finding's stable identity for one checker report.
pub fn fingerprint(checker: &str, file: &str, line: u64, evidence: &str) -> String {
    let normalized = evidence.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = Sha256::new();
    for part in [checker, file, &line.to_string(), &normalized] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn load_list(path: &Path, key: &str) -> Result<Vec<toml::Value>, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let doc: toml::Value =
                toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(doc
                .get(key)
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub fn load_pending() -> Result<Vec<Pending>, String> {
    load_list(&pending_path(), "pending")?
        .into_iter()
        .map(|v| v.try_into().map_err(|e| format!("pending objection: {e}")))
        .collect()
}

pub fn write_pending(entries: &[Pending]) -> Result<(), String> {
    let doc = toml::to_string(
        &toml::Value::try_from(serde_json::json!({
            "pending": entries
        }))
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(pending_path(), doc).map_err(|e| e.to_string())
}

/// The signed rulings, or empty when the ledger does not exist, cannot be
/// read, or fails signature verification. Waivers only ever come from a
/// certified ledger.
pub fn load_rulings() -> Vec<Ruling> {
    load_rulings_at(&ledger_path())
}

fn load_rulings_at(path: &Path) -> Vec<Ruling> {
    if !path.is_file() {
        return Vec::new();
    }
    // One buffer, verified and parsed: a ledger swapped between a path-level
    // verify and a second read would waive findings it never proved.
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("gitvault: objections ledger unreadable - {e}");
            return Vec::new();
        }
    };
    match crate::configsig::signature_state_for(path, &raw) {
        crate::configsig::SigState::Valid | crate::configsig::SigState::Inactive => {}
        crate::configsig::SigState::Invalid(reason) => {
            eprintln!("gitvault: objections ledger is not certified - {reason}");
            return Vec::new();
        }
    }
    let entries = match String::from_utf8(raw) {
        Ok(text) => match toml::from_str::<toml::Value>(&text) {
            Ok(doc) => doc
                .get("ruling")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default(),
            Err(e) => {
                eprintln!("gitvault: objections ledger unreadable - {e}");
                return Vec::new();
            }
        },
        Err(_) => {
            eprintln!("gitvault: objections ledger is not text - no ruling applies");
            return Vec::new();
        }
    };
    entries
        .into_iter()
        .filter_map(|v| v.try_into().ok())
        .collect()
}

/// Write the rulings ledger and sign it with the configuration key.
pub fn write_rulings(rulings: &[Ruling], key: &str) -> Result<(), String> {
    let path = ledger_path();
    let mut body = String::from(
        "# Rulings on checker findings. Waivers count only while the\n\
         # signature verifies; edit through `gitvault objection rule`,\n\
         # never by hand.\n",
    );
    for ruling in rulings {
        let text = toml::to_string(
            &toml::Value::try_from(serde_json::json!({
                "ruling": [ruling]
            }))
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // toml emits `[[ruling]]` per entry; strip the leading key line of
        // every block after the first so entries share one array.
        let body_lines: Vec<&str> = text.lines().skip(1).collect();
        body.push_str("[[ruling]]\n");
        body.push_str(&body_lines.join("\n"));
        body.push('\n');
    }
    // Sign exactly the approved bytes, then land the pair atomically. Writing
    // the ledger in place before signing would let a same-user process swap
    // the path between the write and the sign, certifying bytes the operator
    // never saw.
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no directory", path.display()))?;
    let tmp = dir.join(format!(
        ".rulings-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&tmp, &body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let outcome = (|| -> Result<(), String> {
        crate::configsig::sign(&tmp, key).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::rename(
            crate::configsig::sig_path(&tmp),
            crate::configsig::sig_path(&path),
        )
        .map_err(|e| format!("ledger signature rename: {e}"))?;
        // The bytes that landed must be the bytes that were signed; a final
        // path cannot be a different file swapped in behind the rename.
        let landed = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if landed != body.as_bytes() {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(crate::configsig::sig_path(&path));
            return Err("the signed ledger on disk is not the approved buffer - removed".into());
        }
        Ok(())
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(crate::configsig::sig_path(&tmp));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_normalize_evidence_whitespace() {
        assert_eq!(
            fingerprint("c", "f", 1, "a   b\n\tc"),
            fingerprint("c", "f", 1, "a b c")
        );
        assert_ne!(
            fingerprint("c", "f", 1, "a b c"),
            fingerprint("c", "f", 2, "a b c")
        );
    }

    #[test]
    fn pending_objections_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "gitvault-objection-pending-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("objections.pending.toml");
        let entry = Pending {
            id: "ob-1".into(),
            repo: "owner/repo".into(),
            checker: "c".into(),
            kind: "finding".into(),
            file: "src/a.rs".into(),
            line: Some(4),
            fingerprint: Some("ff".into()),
            head: "h".into(),
            reason: "why".into(),
            filed_at: "t".into(),
        };
        let body = toml::to_string(
            &toml::Value::try_from(serde_json::json!({
                "pending": [&entry]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, body).unwrap();
        let loaded: Vec<Pending> = load_list(&path, "pending")
            .unwrap()
            .into_iter()
            .map(|v| v.try_into().unwrap())
            .collect();
        assert_eq!(loaded, vec![entry]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsigned_ledger_waives_nothing() {
        // A hand-written objections.toml without a verifying signature must
        // fail closed: load_rulings returns empty rather than trusting it.
        let dir = std::env::temp_dir().join(format!(
            "gitvault-objection-test-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = dir.join("objections.toml");
        std::fs::write(
            &ledger,
            "[[ruling]]\nid = \"ob-x\"\nchecker = \"c\"\nkind = \"verdict\"\nverdict = \"overruled\"\nhead = \"h\"\n",
        )
        .unwrap();
        assert!(load_rulings_at(&ledger).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
