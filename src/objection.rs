//! Operator-ruled objections to checker findings.
//!
//! A blocking checker verdict is evidence, not law: the operator may rule
//! that a finding does not apply. The ruling channel is a signed ledger at
//! `~/.config/gitvault/objections.toml`, blessed by the same configuration
//! signing key that certifies `checkers.toml` — so a waiver is as hard to
//! forge as the audit policy itself. An unsigned or tampered ledger waives
//! nothing.
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
    if crate::configsig::verify(path).is_err() {
        eprintln!("gitvault: objections ledger is not signed - no ruling applies");
        return Vec::new();
    }
    let entries = match load_list(path, "ruling") {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("gitvault: objections ledger unreadable - {e}");
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
    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    crate::configsig::sign(&path, key).map_err(|e| e.to_string())?;
    Ok(())
}

/// Which blocking findings a certified ledger waives for this run, and
/// whether a verdict-level ruling accepts a non-pass outcome for `head`.
/// Returns `(waived_finding_indexes, verdict_waived)`.
///
/// Consumed by `gitvault-review` at the verdict-to-exit-code decision; the
/// gate binary never waives anything itself.
#[allow(dead_code)]
pub fn waivers(
    report: &serde_json::Value,
    checker: &str,
    repo_slug: &str,
    head: &str,
) -> (Vec<usize>, bool) {
    waivers_with(&load_rulings(), report, checker, repo_slug, head)
}

/// The pure matching half of `waivers`, separated so the ledger load and its
/// signature verification stay untestable-free while every match rule is
/// exercised directly.
#[allow(dead_code)]
fn waivers_with(
    rulings: &[Ruling],
    report: &serde_json::Value,
    checker: &str,
    repo_slug: &str,
    head: &str,
) -> (Vec<usize>, bool) {
    let mut waived = Vec::new();
    let mut verdict_waived = false;
    if rulings.is_empty() {
        return (waived, verdict_waived);
    }
    let findings = report["findings"].as_array();
    for ruling in rulings.iter().filter(|r| {
        r.checker == checker
            && r.verdict == "overruled"
            && (r.repo.is_empty() || r.repo == repo_slug)
    }) {
        match ruling.kind.as_str() {
            "verdict" => {
                if ruling.head == head {
                    verdict_waived = true;
                }
            }
            _ => {
                if let Some(findings) = findings {
                    for (index, finding) in findings.iter().enumerate() {
                        if finding["severity"].as_str() != Some("blocking") {
                            continue;
                        }
                        if finding["file"].as_str() != Some(ruling.file.as_str()) {
                            continue;
                        }
                        if let Some(line) = ruling.line
                            && finding["line"].as_u64() != Some(line)
                        {
                            continue;
                        }
                        if let Some(expected) = &ruling.fingerprint {
                            let actual = fingerprint(
                                checker,
                                ruling.file.as_str(),
                                finding["line"].as_u64().unwrap_or(0),
                                finding["evidence"].as_str().unwrap_or(""),
                            );
                            if &actual != expected {
                                continue;
                            }
                        }
                        if !waived.contains(&index) {
                            waived.push(index);
                        }
                    }
                }
            }
        }
    }
    (waived, verdict_waived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "verdict": "fail",
            "findings": findings,
        })
    }

    fn blocking(file: &str, line: u64, evidence: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "blocking",
            "file": file,
            "line": line,
            "evidence": evidence,
            "impact": "x",
            "remedy": "y",
        })
    }

    fn ruling(checker: &str, kind: &str) -> Ruling {
        Ruling {
            id: "ob-test".into(),
            repo: "owner/repo".into(),
            checker: checker.into(),
            kind: kind.into(),
            file: String::new(),
            line: None,
            fingerprint: None,
            head: String::new(),
            verdict: "overruled".into(),
            objection: "why".into(),
            reason: "because".into(),
            ruled_at: "now".into(),
        }
    }

    #[test]
    fn a_finding_ruling_waives_the_exact_finding() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        r.fingerprint = Some(fingerprint("checker", "src/a.rs", 12, "the evidence"));
        let rep = report(serde_json::json!([
            blocking("src/a.rs", 12, "the evidence"),
            blocking("src/b.rs", 3, "other"),
        ]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert_eq!(waived, vec![0]);
    }

    #[test]
    fn a_location_ruling_without_fingerprint_still_waives() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        let rep = report(serde_json::json!([blocking("src/a.rs", 12, "reworded")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert_eq!(waived, vec![0]);
    }

    #[test]
    fn a_fingerprint_ruling_lapses_when_the_finding_is_reworded() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        r.fingerprint = Some(fingerprint("checker", "src/a.rs", 12, "old evidence"));
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "new evidence"
        )]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_repo_scoped_ruling_does_not_cross_repositories() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "other/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_ruling_for_another_checker_waives_nothing() {
        let mut r = ruling("other-checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_sustained_ruling_never_waives() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.verdict = "sustained".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, verdict_waived) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty() && !verdict_waived);
    }

    #[test]
    fn an_advisory_finding_is_never_waived_by_matching() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([serde_json::json!({
            "severity": "advisory", "file": "src/a.rs", "line": 1, "evidence": "e"
        })]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_verdict_ruling_binds_the_filed_head() {
        let mut r = ruling("checker", "verdict");
        r.head = "deadbeef".into();
        let rep = report(serde_json::json!([]));
        let (_, waived) = waivers_with(&[r.clone()], &rep, "checker", "owner/repo", "deadbeef");
        assert!(waived);
        let (_, waived) = waivers_with(&[r], &rep, "checker", "owner/repo", "cafe");
        assert!(!waived);
    }

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
