//! Run records: what each gate actually did, kept where an operator can read it.
//!
//! The verdict of a checker run is printed to stderr and then gone. Observing
//! the registered agents therefore needs a store, and this is it: one directory
//! per run under the run directory, holding the event, the range, every
//! checker's outcome and what it printed.
//!
//! Four deliberate limits:
//!
//! * **A record never blocks the action.** Recording is observation. If the
//!   store cannot be written, the run still decides - a gate that refused
//!   because it could not write a log would be trading a real decision for a
//!   diagnostic.
//! * **The machine's layout stays out.** stdout and stderr are captured, and a
//!   checker may print a home or temporary path. Those are replaced with
//!   `[LOCAL_PATH]` before anything is written, so the store - and any page
//!   that reads it - cannot describe this machine.
//! * **The repository path is not stored**, only the `Owner/Repo` slug. A path
//!   is a fact about this machine; the slug is a fact about the repository.
//! * **Evidence still belongs to the checker.** Nothing is copied out of a
//!   checker's own store: the record keeps what the engine saw on the pipes.
//!   A receipt a checker sanitized for its own reasons stays its own.
//!
//! Runs that invoke no registered checker are not recorded. The identity gate
//! alone runs on every local commit, and a record of "nothing was asked" would
//! bury the runs that were.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::checkers::{Context, OutcomeKind, Report};
use crate::config::Config;

/// Captured output per stream. Long enough for a checker's findings, short
/// enough that the store stays a store rather than an archive.
pub const MAX_CAPTURE: usize = 64 * 1024;
/// Most recent runs kept, and the age beyond which a run is dropped.
pub const MAX_RUNS: usize = 200;
pub const MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;

pub fn run_dir(cfg: &Config) -> PathBuf {
    cfg.record_dir.clone().unwrap_or_else(|| {
        let base = std::env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                Path::new(&home).join(".local").join("state")
            });
        base.join("gitvault").join("runs")
    })
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// A UTC timestamp for humans, without a date dependency.
///
/// The civil-date arithmetic is Howard Hinnant's `civil_from_days`: 719468 days
/// from 0000-03-01 to 1970-01-01, then a 400-year era of 146097 days. Records
/// store the epoch second; only the operator's view needs it readable.
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Replace this machine's home and temporary prefixes with a marker.
///
/// Checkers already keep matched values out of their output, but they do print
/// where their own receipts live. That path describes the machine, not the
/// work, so it is replaced before it reaches the store.
pub fn redact(text: &str) -> String {
    const MARKERS: [&str; 5] = [
        "/Users/",
        "/home/",
        "/var/folders/",
        "C:\\Users\\",
        "C:/Users/",
    ];
    const STOPS: [char; 8] = [' ', '\t', '\n', '\r', '"', '\'', '`', '<'];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        // The EARLIEST match wins, not the first marker in this array: taking a
        // later one would copy the text before it verbatim, and an earlier
        // match inside that copy would never be looked at again.
        let earliest = MARKERS
            .iter()
            .filter_map(|marker| rest.find(marker).map(|at| (at, at + marker.len())))
            .min();
        let Some((at, after)) = earliest else {
            out.push_str(rest);
            break;
        };
        let end = rest[after..]
            .find(|c| STOPS.contains(&c))
            .map(|i| after + i)
            .unwrap_or(rest.len());
        out.push_str(&rest[..at]);
        out.push_str("[LOCAL_PATH]");
        rest = &rest[end..];
    }
    out
}

fn capture(raw: &str) -> String {
    let text = redact(raw);
    if text.len() <= MAX_CAPTURE {
        return text;
    }
    let mut end = MAX_CAPTURE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated at {MAX_CAPTURE} bytes]", &text[..end])
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Range {
    /// The ref lines a push carried, verbatim: they name refs, not paths.
    pub refs: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_commit: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub name: String,
    pub severity: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub created_at: u64,
    pub duration_ms: u64,
    pub event: String,
    /// `Owner/Repo` when the repository has an origin remote, else empty. The
    /// work tree's path is deliberately not part of the record.
    pub repository: String,
    pub identity: String,
    pub account: String,
    pub range: Range,
    pub passed: bool,
    pub blocking_failures: usize,
    pub outcomes: Vec<Outcome>,
}

impl Record {
    /// The list projection: the same run without the captured output. A list of
    /// two hundred runs does not need two hundred transcripts to be read.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "created_at": self.created_at,
            "duration_ms": self.duration_ms,
            "event": self.event,
            "repository": self.repository,
            "identity": self.identity,
            "account": self.account,
            "passed": self.passed,
            "blocking_failures": self.blocking_failures,
            // The same key as the full record, so one reader sees one shape.
            "outcomes": self.outcomes.iter().map(|o| serde_json::json!({
                "name": o.name,
                "severity": o.severity,
                "outcome": o.outcome,
                "duration_ms": o.duration_ms,
            })).collect::<Vec<_>>(),
        })
    }
}

/// A run in flight: the id and the instant it started.
pub struct Run {
    id: String,
    dir: PathBuf,
    started_ms: u128,
}

/// Start a record for a run that will invoke at least one registered checker.
/// Returns None when nothing will run, or when the store cannot be created.
pub fn begin(cfg: &Config, selected: usize) -> Option<Run> {
    if selected == 0 {
        return None;
    }
    let dir = run_dir(cfg).join(format!(
        "{:010}-{:04x}",
        epoch_secs(),
        rand::random::<u16>()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    restrict(&dir, 0o700);
    Some(Run {
        id: dir.file_name()?.to_string_lossy().into_owned(),
        dir,
        started_ms: now_ms(),
    })
}

fn exit_of(kind: &OutcomeKind) -> Option<i32> {
    match kind {
        OutcomeKind::Failed(code) => Some(*code),
        _ => None,
    }
}

/// Write the record and prune the store. A failure is reported on stderr at
/// most, never as a refusal: a run that decided must stay decided.
pub fn finish(cfg: &Config, run: Run, ctx: &Context, report: &Report) {
    let record = Record {
        id: run.id,
        created_at: epoch_secs(),
        duration_ms: (now_ms().saturating_sub(run.started_ms)) as u64,
        event: ctx.event.clone(),
        repository: ctx.repo_slug.clone().unwrap_or_default(),
        identity: ctx.identity.clone(),
        account: ctx.account.clone().unwrap_or_default(),
        range: Range {
            refs: ctx.stdin.clone().unwrap_or_default(),
            pr_base: ctx.pr_base.clone(),
            pr_head: ctx.pr_head.clone(),
            pr_number: ctx.pr_number.clone(),
            release_tag: ctx.release_tag.clone(),
            release_commit: ctx.release_commit.clone(),
        },
        passed: report.blocking_failures() == 0,
        blocking_failures: report.blocking_failures(),
        outcomes: report
            .outcomes
            .iter()
            .map(|o| Outcome {
                name: o.name.clone(),
                severity: o.severity.to_string(),
                outcome: o.outcome.label(),
                exit_code: exit_of(&o.outcome),
                duration_ms: o.duration_ms,
                stdout: capture(&o.stdout),
                stderr: capture(&o.stderr),
            })
            .collect(),
    };
    let path = run.dir.join("engine.json");
    let written = serde_json::to_string_pretty(&record)
        .map_err(anyhow::Error::from)
        .and_then(|text| std::fs::write(&path, text + "\n").map_err(anyhow::Error::from));
    match written {
        Ok(()) => {
            restrict(&path, 0o600);
            prune(&run_dir(cfg));
        }
        Err(error) => eprintln!("gitvault: run record not written: {error}"),
    }
}

/// Keep the newest runs and drop the rest. Ordering is the id's, which starts
/// with the start time, so no directory metadata is needed.
fn prune(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    ids.sort();
    let cutoff = epoch_secs().saturating_sub(MAX_AGE_SECS);
    let keep_from = ids.len().saturating_sub(MAX_RUNS);
    for (index, id) in ids.iter().enumerate() {
        let expired = id
            .split('-')
            .next()
            .and_then(|stamp| stamp.parse::<u64>().ok())
            .map(|stamp| stamp < cutoff)
            .unwrap_or(false);
        if index < keep_from || expired {
            let _ = std::fs::remove_dir_all(dir.join(id));
        }
    }
}

fn read(dir: &Path) -> Vec<Record> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("engine.json")).ok())
        .filter_map(|raw| serde_json::from_str::<Record>(&raw).ok())
        .collect()
}

/// Every recorded run, newest first.
pub fn list(cfg: &Config) -> Result<Vec<Record>> {
    let dir = run_dir(cfg);
    let mut records = read(&dir);
    records.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
    Ok(records)
}

pub fn show(cfg: &Config, id: &str) -> Result<Record> {
    if id.is_empty() || id.contains('/') || id.contains("..") {
        bail!("'{id}' is not a run id");
    }
    let dir = run_dir(cfg);
    let raw = std::fs::read_to_string(dir.join(id).join("engine.json"))
        .with_context(|| format!("no run '{id}' in {}", dir.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::{MAX_AGE_SECS, MAX_CAPTURE, MAX_RUNS, capture, iso8601, prune, redact};

    #[test]
    fn pruning_keeps_the_newest_runs_and_drops_expired_ones() {
        let dir = std::env::temp_dir().join(format!("gv-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = super::epoch_secs();
        let expired = format!("{:010}-0000", now.saturating_sub(MAX_AGE_SECS + 60));
        std::fs::create_dir_all(dir.join(&expired)).unwrap();
        let newest = MAX_RUNS as u64 + 4;
        for index in 0..=newest {
            std::fs::create_dir_all(dir.join(format!(
                "{:010}-{:04x}",
                now - 10_000 + index,
                index
            )))
            .unwrap();
        }
        prune(&dir);
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(
            left.len(),
            MAX_RUNS,
            "the store holds exactly {MAX_RUNS} runs"
        );
        assert!(!left.contains(&expired), "an expired run is dropped");
        // The newest run survives: pruning must never trade today for history.
        assert!(left.contains(&format!("{:010}-{:04x}", now - 10_000 + newest, newest)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamps_read_as_utc() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day, which the era arithmetic has to get right.
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn home_and_temporary_paths_are_redacted() {
        let text = "report: /Users/someone/.hermes/profiles/x/runs/r/report.json\n\
                    tmp: /var/folders/ab/cd/T/gitvault-checker-1\n\
                    linux: /home/other/notes.txt\n\
                    windows: C:\\Users\\who\\AppData\\x\n";
        let redacted = redact(text);
        for leaked in [
            "/Users/someone",
            "/var/folders/ab",
            "/home/other",
            "C:\\Users\\who",
        ] {
            assert!(!redacted.contains(leaked), "leaked {leaked} in {redacted}");
        }
        // The whole path goes, exactly as the checkers' own sanitizer renders
        // it, so one concept has one rendering. The line's own text survives.
        assert!(redacted.contains("report: [LOCAL_PATH]"));
        assert!(redacted.contains("tmp: [LOCAL_PATH]"));
        assert!(redacted.contains("linux: [LOCAL_PATH]"));
        assert!(redacted.contains("windows: [LOCAL_PATH]"));
    }

    #[test]
    fn a_path_ends_even_without_a_following_space() {
        assert_eq!(redact("see /Users/x/y\""), "see [LOCAL_PATH]\"");
        assert_eq!(redact("/Users/x/y"), "[LOCAL_PATH]");
        assert_eq!(redact("no paths here"), "no paths here");
    }

    #[test]
    fn capture_truncates_on_a_character_boundary() {
        let long = "é".repeat(MAX_CAPTURE);
        let text = capture(&long);
        assert!(text.contains("[truncated at"));
        assert!(text.len() < long.len() + 64);
    }
}
