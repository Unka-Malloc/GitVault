//! The orchestration layer: snapshot resolution in, one review per target,
//! receipts out. Ported from the retired Python engine's run machinery -
//! receipt reuse, the resume keys, the retention window, the audit-agent
//! review process and the full-audit lifecycle - so a review is never paid for twice
//! and an interrupted run continues instead of replaying.
//!
//! The receipt identity names the engine that produced it: receipts written
//! by the Python engine are not reused, because the deterministic stage and
//! the tool surface now live here.

use crate::contract::{self, Contract};
use crate::credential;
use crate::evidence;
use crate::fullservice;
use crate::sanitize::sanitize;
use crate::util::sha256;
use crate::{ranges, stage1};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The retention window for review-run directories, the same convention the
/// run-record store applies (src/records.rs): newest 200 survive, and nothing
/// older than 90 days. Unfinished reviews retain their paid progress until
/// finalized; only settled receipts and abandoned directories use the bounds.
pub const MAX_RUNS: usize = 200;
pub const MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// the installed profile's settings and the sync contract
// ---------------------------------------------------------------------------

/// The checker installation record: paths and pins written by the installer.
pub struct Settings {
    pub agent_runner: Option<String>,
    pub profile: PathBuf,
    pub skill_dir: PathBuf,
    pub synced: Option<Value>,
    pub payload: Map<String, Value>,
}

pub fn load_settings(contract_dir: &Path) -> Result<Settings, String> {
    let raw = std::fs::read_to_string(contract_dir.join("installation.json"))
        .map_err(|error| format!("installation.json: {error}"))?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|error| format!("installation.json: {error}"))?;
    let text = |key: &str| value[key].as_str().unwrap_or("").to_string();
    Ok(Settings {
        agent_runner: value["agent_runner"].as_str().map(str::to_string),
        profile: PathBuf::from(text("profile")),
        skill_dir: PathBuf::from(text("skill_dir")),
        synced: value.get("synced").cloned(),
        payload: value["payload"].as_object().cloned().unwrap_or_default(),
    })
}

/// The synced-document drift check: a local edit the registry never saw
/// refuses the operation, so "the registry is the only source" stays
/// executable. The payload pin does the same for the contract itself.
pub fn assert_synced(settings: &Settings, contract_dir: &Path) -> Result<(), String> {
    let mut changed = Vec::new();
    if let Some(synced) = &settings.synced
        && let Some(files) = synced["files"].as_object()
    {
        for (name, expected) in files {
            let path = settings.skill_dir.join(name);
            let matches = std::fs::read_to_string(&path)
                .map(|text| sha256(&text) == expected.as_str().unwrap_or(""))
                .unwrap_or(false);
            if !matches {
                changed.push(name.clone());
            }
        }
    }
    if !changed.is_empty() {
        return Err(format!(
            "the local prompt copy no longer matches what the registry published ({}); \
             run `gitvault-review install --source {}` to sync",
            changed.join(", "),
            contract_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        ));
    }
    let mut drifted = Vec::new();
    for (name, expected) in &settings.payload {
        let path = contract_dir.join(name);
        let matches = std::fs::read_to_string(&path)
            .map(|text| sha256(&text) == expected.as_str().unwrap_or(""))
            .unwrap_or(false);
        if !matches {
            drifted.push(name.clone());
        }
    }
    if !drifted.is_empty() {
        return Err(format!(
            "the installed payload no longer matches what the installer wrote ({})",
            drifted.join(", ")
        ));
    }
    Ok(())
}

/// The runtime this review runs on — the synced profile.json's declared
/// `runtime` block, held to inert labels and the declared provider's
/// namespace. A profile that declares no runtime refuses the audit: a
/// provider, model or effort is never invented, and which agent or catalog
/// the declaration names is the profile's business, not the engine's.
pub fn declared_runtime(settings: &Settings) -> Result<Map<String, Value>, String> {
    let declared = std::fs::read_to_string(settings.skill_dir.join("profile.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|profile| profile["runtime"].as_object().cloned())
        .ok_or_else(|| "The synced profile declares no audit runtime".to_string())?;
    let mut runtime = Map::new();
    for key in ["harness", "provider"] {
        let Some(value) = declared
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| contract::is_runtime_label(value))
        else {
            return Err(format!(
                "The audit runtime must declare {key} as an inert label"
            ));
        };
        runtime.insert(key.to_string(), json!(value));
    }
    // Every declared model must sit in the runtime's own provider
    // namespace — provider-relative, never a pinned vendor.
    let prefix = format!("{}/", runtime["provider"].as_str().unwrap_or(""));
    let model = declared["model"].as_str().unwrap_or("");
    if !contract::RUNTIME_VALUE.is_match(model) || !model.starts_with(&prefix) {
        return Err(format!(
            "The audit runtime's model must sit in its declared provider's namespace \
             ({prefix}…), not {model:?}"
        ));
    }
    runtime.insert("model".to_string(), json!(model));
    if let Some(effort) = declared.get("effort") {
        let Some(effort) = effort
            .as_str()
            .filter(|value| contract::RUNTIME_VALUE.is_match(value))
        else {
            return Err("runtime.effort must be an inert label".to_string());
        };
        runtime.insert("effort".to_string(), json!(effort));
    }
    if let Some(fallbacks) = declared.get("fallback_models") {
        let fallbacks = fallbacks
            .as_array()
            .ok_or_else(|| "runtime.fallback_models must be a list".to_string())?
            .iter()
            .map(|entry| entry.as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>();
        if let Some(bad) = fallbacks.iter().find(|entry| !entry.starts_with(&prefix)) {
            return Err(format!(
                "runtime.fallback_models entry {bad:?} must sit in the declared provider's \
                 namespace ({prefix}…)"
            ));
        }
        runtime.insert("models".to_string(), json!(fallbacks));
    }
    if let Some(windows) = declared.get("windows") {
        let windows = windows
            .as_array()
            .ok_or_else(|| "runtime.windows must be a list".to_string())?;
        for (index, window) in windows.iter().enumerate() {
            let bounds = [window["from"].as_str(), window["to"].as_str()];
            if bounds
                .iter()
                .flatten()
                .any(|b| !contract::is_window_bound(b))
                || bounds.iter().any(Option::is_none)
            {
                return Err(format!("runtime.windows[{index}] bounds must be \"HH:MM\""));
            }
            let timezone = window["timezone"].as_str().unwrap_or("");
            if timezone.is_empty()
                || !timezone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/_-".contains(c))
            {
                return Err(format!(
                    "runtime.windows[{index}].timezone must be an IANA zone name"
                ));
            }
            let model_entries = window["model"].as_str().into_iter().chain(
                window["models"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str),
            );
            for entry in model_entries {
                if !entry.starts_with(&prefix) {
                    return Err(format!(
                        "runtime.windows[{index}] model {entry:?} must sit in the declared \
                         provider's namespace ({prefix}…)"
                    ));
                }
            }
        }
        runtime.insert("windows".to_string(), json!(windows));
    }
    if let Some(retry) = declared.get("retry") {
        let object = retry
            .as_object()
            .ok_or_else(|| "runtime.retry must be an object".to_string())?;
        // The contract's snake_case `reset_grace` projects into the
        // role's camelCase `resetGrace` — the AwP document shape.
        let mut projected = Map::new();
        for (key, value) in object {
            if !value.is_string() {
                return Err(format!(
                    "runtime.retry.{key} must be a duration string (\"30m\", \"PT3H1M\")"
                ));
            }
            let key = match key.as_str() {
                "interval" => "interval",
                "reset_grace" | "resetGrace" => "resetGrace",
                other => {
                    return Err(format!("runtime.retry.{other} is not a declared field"));
                }
            };
            projected.insert(key.to_string(), value.clone());
        }
        runtime.insert("retry".to_string(), Value::Object(projected));
    }
    Ok(runtime)
}

/// Stable role identity: the checker name and the registry's version tag.
fn role_identity(settings: &Settings, contract: &Contract) -> Value {
    json!({
        "id": contract.name,
        "revision": settings.synced.as_ref().and_then(|s| s["tag"].as_str()),
    })
}

// ---------------------------------------------------------------------------
// run directories: retention, resume keys, receipt reuse
// ---------------------------------------------------------------------------

fn unfinished_run(path: &Path) -> bool {
    // Submission is not completion: only a finalized receipt settles a run.
    if !path.join("resume.json").is_file() {
        return false;
    }
    match std::fs::read_to_string(path.join("report.json")) {
        Err(_) => true,
        Ok(raw) => serde_json::from_str::<Value>(&raw)
            .map(|report| report.get("review_head").is_none())
            .unwrap_or(false),
    }
}

pub fn prune_runs(runs_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(runs_dir) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .collect();
    let mtime = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH)
    };
    dirs.sort_by_key(|b| std::cmp::Reverse(mtime(b)));
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(MAX_AGE_SECS);
    for (rank, path) in dirs.iter().enumerate() {
        if unfinished_run(path) {
            continue;
        }
        let expired = mtime(path)
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() < cutoff)
            .unwrap_or(false);
        if expired || rank >= MAX_RUNS {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// A previous passing review of exactly this target. The judged items are part
/// of the key: a receipt written under an earlier contract did not answer the
/// questions this run asks.
fn audited(
    settings: &Settings,
    contract: &Contract,
    base: Option<&str>,
    head: &str,
    runtime: &Map<String, Value>,
) -> bool {
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    let Ok(entries) = std::fs::read_dir(&runs) else {
        return false;
    };
    let identity = role_identity(settings, contract);
    for report_path in entries.flatten().map(|e| e.path().join("report.json")) {
        let Ok(raw) = std::fs::read_to_string(&report_path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let same_identity = ["id", "revision"]
            .iter()
            .all(|key| report["agent_profile"][key] == identity[key]);
        if report["review_base"].as_str().unwrap_or("") == base.unwrap_or("")
            && report["review_head"].as_str() == Some(head)
            && report["review_items"] == json!(contract.domains)
            && report["gate_status"] == "passed"
            && report["engine"] == concat!("gitvault-review ", env!("CARGO_PKG_VERSION"))
            && same_identity
            && report["harness"] == runtime["harness"]
            && report["provider"] == runtime["provider"]
            && report["model"] == runtime["model"]
            && report["reasoning"] == runtime.get("effort").cloned().unwrap_or(Value::Null)
            && crate::seal::valid(&report)
        {
            return true;
        }
    }
    false
}

/// `commit` is an ancestor of (or equal to) `head` in `repo`.
fn ancestor_of(repo: &str, commit: &str, head: &str) -> bool {
    if commit == head {
        return true;
    }
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", commit, head])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The repository's review identity: its `owner/name` slug, or the canonical
/// checkout path when no usable remote names it. Two checkouts of one remote
/// share coverage; a path-identified local tree never shares it with another.
fn repo_identity(repo: &str) -> String {
    let slug = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| crate::git::slug_from_remote(String::from_utf8_lossy(&o.stdout).trim()));
    slug.or_else(|| {
        std::fs::canonicalize(repo)
            .ok()
            .map(|p| format!("local:{}", p.display()))
    })
    .unwrap_or_default()
}

/// The head this checker last completed a review of — the coverage cursor.
/// A settled report covered its head regardless of verdict: a pass is clean
/// coverage, and a refusal carries its blocking findings forward until they
/// are fixed or an operator ruling overrules them. A report qualifies only
/// under the same repository identity and the same contract questions,
/// sealed, settled, and on this head's ancestry line; anything else is not
/// coverage of this target.
fn cursor(
    repo: &str,
    runs: &Path,
    contract: &Contract,
    repo_id: &str,
    head: &str,
) -> Option<(String, Value)> {
    let mut newest: Option<(std::time::SystemTime, String, Value)> = None;
    for entry in std::fs::read_dir(runs).ok()?.flatten() {
        let report_path = entry.path().join("report.json");
        let Ok(raw) = std::fs::read_to_string(&report_path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let review_head = report["review_head"].as_str().unwrap_or("");
        let settled = matches!(report["gate_status"].as_str(), Some("passed" | "refused"));
        if review_head.is_empty()
            || !settled
            || repo_id.is_empty()
            || report["repo"].as_str() != Some(repo_id)
            || report["review_items"] != json!(contract.domains)
            || !crate::seal::valid(&report)
            || !ancestor_of(repo, review_head, head)
        {
            continue;
        }
        let mtime = std::fs::metadata(&report_path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if newest.as_ref().is_none_or(|(t, _, _)| mtime > *t) {
            newest = Some((mtime, review_head.to_string(), report));
        }
    }
    newest.map(|(_, head, report)| (head, report))
}

/// The commit this review may start from: the descendant of the target's own
/// base and the checker's coverage cursor — content at or below either was
/// already published or already reviewed, and is never reviewed twice. When
/// the two are unrelated (a rewritten history line) the target's own base
/// stands and the whole outgoing range is reviewed again.
fn effective_base(repo: &str, base: Option<&str>, cursor_head: Option<&str>) -> Option<String> {
    match (base, cursor_head) {
        (_, None) => base.map(str::to_string),
        (None, Some(cursor)) => Some(cursor.to_string()),
        (Some(base), Some(cursor)) => {
            if ancestor_of(repo, base, cursor) {
                Some(cursor.to_string())
            } else {
                Some(base.to_string())
            }
        }
    }
}

/// The blocking findings a report still stands on for a range that never
/// opened their files: its fresh findings plus the ones it inherited from
/// its own cursor. A finding on a path the range touched was re-reviewed,
/// and the new verdict speaks for it.
fn carried_blockers(
    report: Option<&Value>,
    changed: &std::collections::HashSet<&str>,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let Some(report) = report else {
        return out;
    };
    for key in ["findings", "carried_findings"] {
        for f in report[key].as_array().into_iter().flatten() {
            let blocking = f["severity"].as_str() == Some("blocking");
            let untouched = f["file"]
                .as_str()
                .is_none_or(|file| !changed.contains(file));
            let duplicate = out.iter().any(|e: &Value| {
                e["file"] == f["file"] && e["line"] == f["line"] && e["evidence"] == f["evidence"]
            });
            if blocking && untouched && !duplicate {
                out.push(f.clone());
            }
        }
    }
    out
}

/// Whether the audit's outcome stands: a pass verdict carries no blocking
/// findings — fresh or inherited from the coverage cursor — or every
/// blocking finding is overruled by a signature-verified operator ruling.
/// The sealed report keeps the checker's own verdict; the waiver record
/// lands beside it so run history shows which operator decision stood in
/// for a fix.
fn outcome(
    report: &Value,
    contract: &Contract,
    repo_id: &str,
    head: &str,
    run_dir: Option<&Path>,
) -> i32 {
    let mut merged = report.clone();
    let mut findings = merged["findings"].as_array().cloned().unwrap_or_default();
    for f in report["carried_findings"].as_array().into_iter().flatten() {
        let duplicate = findings.iter().any(|e| {
            e["file"] == f["file"] && e["line"] == f["line"] && e["evidence"] == f["evidence"]
        });
        if !duplicate {
            let mut f = f.clone();
            f["carried"] = json!(true);
            findings.push(f);
        }
    }
    merged["findings"] = json!(findings);
    let blocking = merged["findings"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter(|f| f["severity"].as_str() == Some("blocking"))
                .count()
        })
        .unwrap_or(0);
    let slug = repo_id.strip_prefix("local:").map_or(repo_id, |_| "");
    if report["verdict"].as_str() == Some("pass") && blocking == 0 {
        return 0;
    }
    let (waived, verdict_waived) = crate::objection::waivers(&merged, &contract.name, slug, head);
    let standing = merged["findings"]
        .as_array()
        .map(|f| {
            f.iter()
                .enumerate()
                .filter(|(i, f)| f["severity"].as_str() == Some("blocking") && !waived.contains(i))
                .count()
        })
        .unwrap_or(0);
    if !verdict_waived && (standing != 0 || waived.is_empty()) {
        return 1;
    }
    let mut note = Vec::new();
    for i in &waived {
        let f = &merged["findings"][*i];
        note.push(format!(
            "{}:{}",
            f["file"].as_str().unwrap_or(""),
            f["line"].as_u64().unwrap_or(0)
        ));
    }
    if let Some(dir) = run_dir {
        let _ = evidence::write_json(
            &dir.join("waivers.json"),
            &serde_json::json!({
                "objection_waived": note,
                "verdict_waived": verdict_waived,
                "ledger": crate::objection::ledger_path(),
            }),
        );
    }
    println!(
        "{}: outcome waived by signed operator ruling{}",
        contract.title,
        if note.is_empty() {
            String::new()
        } else {
            format!(" — waived findings: {}", note.join(", "))
        }
    );
    0
}

/// An unfinished run of exactly this target under this runtime, waiting to
/// continue. resume.json is the lookup key; scope.json cannot serve because
/// it is removed when a run ends.
fn resume_dir(runs: &Path, key: &Value) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(runs)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("resume.json"))
        .filter(|path| path.is_file())
        .collect();
    candidates.sort();
    for path in candidates {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(candidate) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if candidate == *key && unfinished_run(path.parent().unwrap()) {
            return Some(path.parent().unwrap().to_path_buf());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// the audit review process
// ---------------------------------------------------------------------------

/// Drive one review through the A4AA-backed audit runner: the agent owns
/// only the conversation, this runtime owns the tools, the evidence and the
/// receipt. Returns (usage, duration_ms, profile identity). No wall-clock
/// kill, no second reviewer.
fn agent_review(
    run_dir: &Path,
    settings: &Settings,
    runtime: &Map<String, Value>,
    contract: &Contract,
) -> Result<(Value, u128, Value), String> {
    let runner = settings
        .agent_runner
        .clone()
        .filter(|runner| !runner.is_empty())
        .or_else(|| {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join("gitvault-audit-agent"))
                    .find(|candidate| candidate.is_file())
                    .map(|candidate| candidate.to_string_lossy().into_owned())
            })
        })
        .ok_or("The A4AA audit runner is not installed; update the checker installation")?;
    let completion_path = run_dir.join("completion.json");
    let saved: Option<Value> = std::fs::read_to_string(&completion_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let cached = saved.as_ref().is_some_and(|saved| {
        saved["completed"] == true
            && saved["runtime"] == Value::Object(runtime.clone())
            && saved["outcome"].is_object()
    });
    let (outcome, returncode, duration_ms) = if let Some(saved) = saved.filter(|_| cached) {
        (
            saved["outcome"].clone(),
            0,
            saved["duration_ms"].as_u64().unwrap_or(0) as u128,
        )
    } else {
        // The runner owns the conversation: fire the task with the contract
        // and the run directory, inherit the operator's environment
        // verbatim, and read back the settled outcome on stdout.
        let started = std::time::Instant::now();
        let result = Command::new(&runner)
            .arg("--contract")
            .arg(contract.dir.join("contract.json"))
            .arg("--run")
            .arg(run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .current_dir(run_dir)
            .output()
            .map_err(|error| format!("The A4AA audit runner could not start: {error}"))?;
        let duration_ms = started.elapsed().as_millis();
        let outcome = serde_json::from_str::<Value>(&String::from_utf8_lossy(&result.stdout))
            .unwrap_or(Value::Null);
        (outcome, result.status.code().unwrap_or(1), duration_ms)
    };
    let usage = &outcome["usage"];
    let valid_usage = [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    ]
    .iter()
    .all(|key| usage[key].as_u64().is_some());
    let identity = role_identity(settings, contract);
    let selected = &outcome["profile"];
    let valid_profile = ["id", "revision"]
        .iter()
        .all(|key| selected[key] == identity[key])
        && selected["principal"].is_string();
    let settled = outcome["completed"] == true && valid_usage && valid_profile;
    let has_report = run_dir.join("report.json").exists();
    evidence::write_json(
        &completion_path,
        &json!({
            "completed": settled && has_report && returncode == 0,
            "has_report": has_report,
            "runtime": runtime,
            "duration_ms": duration_ms as u64,
            "outcome": {
                "completed": outcome["completed"],
                "usage": outcome["usage"],
                "profile": outcome["profile"],
                "served": outcome["served"],
                "failure": outcome["failure"],
            },
            "failure_reason": if settled && has_report && returncode == 0 {
                Value::Null
            } else {
                json!("A4AA audit review did not complete")
            },
        }),
    )?;
    if returncode != 0 || !settled || !has_report {
        return Err(
            "The audit agent did not complete a valid review; publication refused".to_string(),
        );
    }
    Ok((outcome["usage"].clone(), duration_ms, selected.clone()))
}

// ---------------------------------------------------------------------------
// one target, then the gate
// ---------------------------------------------------------------------------

/// The per-hit detail lines under a refused stage-one report.
fn stage1_lines(contract: &Contract, summary: &stage1::Summary) -> Vec<String> {
    if contract
        .stage1
        .as_ref()
        .is_some_and(|stage1| stage1.surfaces)
    {
        let mut lines: Vec<String> = summary
            .hits
            .iter()
            .map(|hit| {
                format!(
                    "{}:{} {} → {}",
                    hit.path,
                    hit.line,
                    hit.rule,
                    hit.remedy.unwrap_or("")
                )
            })
            .collect();
        if let Some(surfaces) = &summary.surfaces {
            lines.extend(surfaces.iter().map(|surface| {
                format!("notice {}:{} {}", surface.path, surface.line, surface.rule)
            }));
        }
        return lines;
    }
    summary
        .hits
        .iter()
        .map(|hit| {
            let suffix = if hit.line > 0 {
                format!(":{}", hit.line)
            } else {
                String::new()
            };
            format!("{}{} {}", hit.path, suffix, hit.rule)
        })
        .collect()
}

/// Run one review of one resolved target. Returns the exit code.
#[allow(clippy::too_many_arguments)]
fn review_target(
    repo: &str,
    settings: &Settings,
    target: &stage1::Target,
    base: Option<&str>,
    cursor_report: Option<&Value>,
    repo_id: &str,
    summary: Option<&stage1::Summary>,
    summaries: &[stage1::Summary],
    runtime: &Map<String, Value>,
    contract: &Contract,
) -> Result<i32, String> {
    let tree = {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", &format!("{}^{{tree}}", target.head)])
            .output()
            .map_err(|error| format!("Git could not read the review snapshot: {error}"))?;
        if !output.status.success() {
            return Err("Git could not read the review snapshot".to_string());
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    // With a review base the range's own diff is the whole review surface —
    // content at or below it was published or already covered by the cursor;
    // only a base-less target inventories the whole tree.
    let changed = match base {
        Some(base) => stage1::outgoing_paths_range(repo, Some(base), &target.head)?,
        None => stage1::outgoing_paths_snapshot(repo, &tree)?,
    };
    // A path the tool surface refuses is a review that can never complete.
    // Refuse it before the review costs a token - naming the path, never its
    // content.
    for path in &changed {
        if evidence::safe_path(path).is_err() {
            return Err(format!(
                "The snapshot contains '{path}', a path the review contract excludes; \
                 no review could ever pass it, so the publication is refused locally"
            ));
        }
    }
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    std::fs::create_dir_all(&runs).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&runs, std::fs::Permissions::from_mode(0o700));
    }
    let identity = role_identity(settings, contract);
    let resume_key = json!({
        "base": base,
        "head": target.head,
        "items": contract.domains,
        "agent_profile": identity,
        "harness": runtime["harness"],
        "provider": runtime["provider"],
        "model": runtime["model"],
        "effort": runtime.get("effort").cloned().unwrap_or(Value::Null),
    });
    let run_dir = match resume_dir(&runs, &resume_key) {
        Some(existing) => existing,
        None => {
            let created = runs.join(format!(
                "review-{}-{:04x}",
                std::process::id(),
                rand_suffix()
            ));
            std::fs::create_dir_all(&created).map_err(|error| error.to_string())?;
            evidence::write_json(&created.join("resume.json"), &resume_key)?;
            created
        }
    };
    // The conceal sweep skips directories whose `live` pid is still running;
    // a resumed directory gets its marker refreshed either way.
    let _ = std::fs::write(run_dir.join("live"), std::process::id().to_string());
    // The scope the evidence server reads; kind and surfaces ride along for
    // the checkers whose contracts carry them.
    let mut scope = json!({
        "repo": repo,
        "tree": tree,
        "base": base,
        "changed": changed.clone(),
        "runtime": runtime,
    });
    if let Some(report) = cursor_report {
        scope["coverage_cursor"] = json!(report["review_head"]);
    }
    if contract.stage1.is_some() {
        scope["kind"] = json!(target.kind);
        if contract
            .stage1
            .as_ref()
            .is_some_and(|stage1| stage1.surfaces)
        {
            let surfaces: Vec<Value> = summary
                .and_then(|summary| summary.surfaces.as_ref())
                .map(|surfaces| {
                    surfaces
                        .iter()
                        .map(|surface| {
                            json!({"path": surface.path, "line": surface.line, "rule": surface.rule})
                        })
                        .collect()
                })
                .unwrap_or_default();
            scope["surfaces"] = json!(surfaces);
        }
    }
    evidence::write_json(&run_dir.join("scope.json"), &scope)?;
    // The run's verdict credential: minted (or reused after an unfinished
    // attempt) before the reviewer starts, held here for the receipt check
    // and consumed once a verdict seals it.
    let key = credential::issue(&run_dir)?;
    let result = (|| -> Result<i32, String> {
        println!(
            "{}: reviewing {} with {}/{} ({})…",
            contract.title,
            target.label,
            runtime["provider"].as_str().unwrap_or(""),
            runtime["model"].as_str().unwrap_or(""),
            runtime
                .get("effort")
                .and_then(|v| v.as_str())
                .unwrap_or("default"),
        );
        let (usage, duration_ms, identity) = agent_review(&run_dir, settings, runtime, contract)?;
        let report_path = run_dir.join("report.json");
        let mut report: Value = serde_json::from_str(
            &std::fs::read_to_string(&report_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // The verdict must carry this run's signature: a receipt that never
        // went through the review server's submit channel - hand-written,
        // replayed from another run, or left by a crashed attempt - is not a
        // review at all.
        if !credential::verify(&key, &report) {
            return Err(
                "the audit report carries no valid verdict credential; publication refused"
                    .to_string(),
            );
        }
        if let Some(reference) = &target.ref_ {
            let moved = Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "--verify", &format!("{reference}^{{commit}}")])
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
                .unwrap_or_default();
            if moved != target.head {
                return Err("The pushed ref moved during review; publication refused".to_string());
            }
        }
        // Blocking findings the coverage cursor proved on content this range
        // did not touch keep standing — the file was never re-opened, so the
        // sealed evidence is still the live one. They join this receipt before
        // it seals, so the next cursor inherits the same standing findings
        // and a hand-edited history cannot silently drop one.
        let changed_set: std::collections::HashSet<&str> =
            changed.iter().map(String::as_str).collect();
        let carried = carried_blockers(cursor_report, &changed_set);
        report["carried_findings"] = json!(carried);
        // The receipt's standing result, not the checker's bare verdict: a
        // pass that still stands on blocking findings — fresh or carried —
        // is a refusal, so the reuse path never waves it through and the
        // next cursor inherits the same blockers.
        let standing = report["findings"]
            .as_array()
            .map(|f| {
                f.iter()
                    .filter(|f| f["severity"].as_str() == Some("blocking"))
                    .count()
            })
            .unwrap_or(0)
            + report["carried_findings"].as_array().map_or(0, Vec::len);
        report["gate_status"] = json!(if report["verdict"] == "pass" && standing == 0 {
            "passed"
        } else {
            "refused"
        });
        report["review_usage"] = json!({"tokens": usage, "duration_ms": duration_ms as u64});
        report["agent_profile"] = identity;
        report["review_base"] = json!(base);
        report["review_head"] = json!(target.head);
        report["repo"] = json!(repo_id);
        report["review_kind"] = json!(target.kind);
        // What this pass answered, so a later run under a wider contract does
        // not reuse it (see `audited`).
        report["review_items"] = json!(contract.domains);
        report["stage1"] =
            json!({"ranges": summaries.iter().map(stage1::Summary::to_json).collect::<Vec<_>>()});
        if !target.fallback.is_empty() {
            report["fallback"] = json!(target.fallback);
        }
        // Seal the receipt into the run history's chain: `audited` reuses a
        // receipt only when the seal recomputes, so a hand-written
        // `report.json` must at least join the chain honestly - and a receipt
        // deleted from the middle leaves a dangling `seal_prev` an operator
        // can see. Tamper-evidence, not tamper-proofing: the unforgeable
        // attestation is the `gitvault/audited` status the push hook posts.
        let seal_prev = crate::seal::latest(&runs, "report.json", Some(&run_dir));
        report["seal_prev"] = json!(seal_prev);
        report["seal"] = json!(crate::seal::seal(&seal_prev, &report));
        evidence::write_json(&report_path, &report)?;
        // The verdict is finalized on disk; its credential is spent. Doing
        // this only now keeps an unfinalized attempt resumable under the
        // same key.
        credential::consume(&run_dir);
        println!(
            "{}: {} — {}",
            contract.title,
            report["verdict"].as_str().unwrap_or(""),
            sanitize(report["summary"].as_str().unwrap_or(""))
        );
        if let Some(findings) = report["findings"].as_array() {
            for finding in findings {
                println!(
                    "  {}:{} [{}] {} → {}",
                    sanitize(finding["file"].as_str().unwrap_or("")),
                    finding["line"].as_i64().unwrap_or(0),
                    finding["severity"].as_str().unwrap_or(""),
                    sanitize(finding["impact"].as_str().unwrap_or("")),
                    sanitize(finding["remedy"].as_str().unwrap_or("")),
                );
            }
        }
        println!("{} report: {}", contract.title, report_path.display());
        let carried_count = report["carried_findings"].as_array().map_or(0, Vec::len);
        if carried_count > 0 {
            evidence::write_json(
                &run_dir.join("carried.json"),
                &json!({
                    "cursor": cursor_report
                        .map(|r| r["review_head"].clone())
                        .unwrap_or(Value::Null),
                    "findings": report["carried_findings"],
                }),
            )?;
            println!(
                "{}: {} blocking finding(s) carried from the previous covered head",
                contract.title, carried_count
            );
        }
        Ok(outcome(
            &report,
            contract,
            repo_id,
            &target.head,
            Some(&run_dir),
        ))
    })();
    let _ = std::fs::remove_file(run_dir.join("scope.json"));
    // A run that never finalized its receipt is refused, never pending.
    // The reworded receipt is re-signed only when it was authentic to begin
    // with — re-signing an unverifiable receipt would launder a forged
    // report into a signature a resume would accept.
    if let Ok(raw) = std::fs::read_to_string(run_dir.join("report.json"))
        && let Ok(mut receipt) = serde_json::from_str::<Value>(&raw)
        && receipt["gate_status"] == "pending"
    {
        let authentic = credential::verify(&key, &receipt);
        receipt["gate_status"] = json!("refused");
        if authentic {
            receipt["receipt_mac"] = json!(credential::mac(&key, &receipt));
        }
        let _ = evidence::write_json(&run_dir.join("report.json"), &receipt);
    }
    result
}

fn rand_suffix() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 0xffff) as u16
}

/// The checker entry point. Refuses on the first stage that finds a problem;
/// a refused audit never touches the working tree.
pub fn run(repo: &str, contract_path: &Path) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    let settings = load_settings(contract.dir.as_path())?;
    assert_synced(&settings, contract.dir.as_path())?;
    let runtime = declared_runtime(&settings)?;
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    let result = review_gate(repo, &contract, &settings, &runtime);
    for entry in std::fs::read_dir(&runs).into_iter().flatten().flatten() {
        let marker = entry.path().join("live");
        if std::fs::read_to_string(&marker)
            .ok()
            .and_then(|pid| pid.trim().parse::<u32>().ok())
            == Some(std::process::id())
        {
            let _ = std::fs::remove_file(&marker);
        }
    }
    // Housekeeping follows the audit, never precedes it: a recorded session
    // is concealed only once its run has finished — flagging a conversation
    // while its agent is still prompting breaks the turn. The sweep covers
    // every checker's runs root, since a checker skipped by an earlier
    // phase's refusal never reaches its own sweep. It must also precede
    // pruning, since a removed run directory takes its session id evidence
    // with it.
    if let Some(profiles) = settings.profile.parent() {
        crate::conceal::run_sessions(profiles);
    }
    prune_runs(&runs);
    result
}

fn review_gate(
    repo: &str,
    contract: &Contract,
    settings: &Settings,
    runtime: &Map<String, Value>,
) -> Result<i32, String> {
    let targets = ranges::ranges(repo)?;
    if targets.is_empty() {
        println!(
            "{}: nothing unpublished in this operation; no review needed",
            contract.title
        );
        return Ok(0);
    }
    let mut summaries = Vec::new();
    if let Some(stage1_contract) = &contract.stage1 {
        let opts = stage1::Opts {
            withheld_path: None,
        };
        let (ok, found) = stage1::audit_all(
            repo,
            &targets,
            &stage1_contract.rules,
            &opts,
            stage1_contract.surfaces,
        )?;
        let stage_label = stage1_contract.label.as_deref().unwrap_or("deterministic");
        for summary in &found {
            let state = if summary.refused.is_empty() {
                summary.status.clone()
            } else {
                format!("refused: {}", summary.refused)
            };
            let surfaces = summary
                .surfaces
                .as_ref()
                .map(|surfaces| format!(", surfaces={}", surfaces.len()))
                .unwrap_or_default();
            println!(
                "{}: {} {} — {} ({}, findings={}{})",
                contract.title,
                stage_label,
                state,
                summary.label,
                summary.scope,
                summary.hits.len(),
                surfaces,
            );
            for line in stage1_lines(contract, summary) {
                println!("  {line}");
            }
        }
        summaries = found;
        if !ok {
            return Err(stage1_contract.refusal.clone().unwrap_or_else(|| {
                "The deterministic audit refused this operation; nothing was published".to_string()
            }));
        }
    }
    let repo_id = repo_identity(repo);
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    for (index, target) in targets.iter().enumerate() {
        // The coverage cursor: this checker's newest settled review on this
        // head's ancestry line. Content at or below it — or at or below the
        // target's own base — is never reviewed twice.
        let (cursor_head, cursor_report) =
            match cursor(repo, &runs, contract, &repo_id, &target.head) {
                Some((head, report)) => (Some(head), Some(report)),
                None => (None, None),
            };
        // The identical head already carries this checker's verdict; the
        // sealed outcome stands as-is — a signed ruling may still waive it.
        if cursor_head.as_deref() == Some(target.head.as_str())
            && let Some(report) = &cursor_report
        {
            if report["gate_status"].as_str() == Some("passed") {
                println!(
                    "{}: {} already passed its semantic review ({}); reusing that verdict",
                    contract.title,
                    target.label,
                    &target.head[..12.min(target.head.len())],
                );
                continue;
            }
            println!(
                "{}: {} was already refused at {}; the sealed verdict stands",
                contract.title,
                target.label,
                &target.head[..12.min(target.head.len())],
            );
            return Ok(outcome(report, contract, &repo_id, &target.head, None));
        }
        let base = effective_base(repo, target.base.as_deref(), cursor_head.as_deref());
        if cursor_head.is_some() && base.as_deref() != target.base.as_deref() {
            println!(
                "{}: {} reviews the increment since {} ({} paths)",
                contract.title,
                target.label,
                &cursor_head.as_deref().unwrap_or_default()
                    [..12.min(cursor_head.as_deref().unwrap_or_default().len())],
                stage1::outgoing_paths_range(repo, base.as_deref(), &target.head)
                    .map(|p| p.len())
                    .unwrap_or(0),
            );
        }
        if audited(settings, contract, base.as_deref(), &target.head, runtime) {
            println!(
                "{}: {} already passed its semantic review ({}); reusing that verdict",
                contract.title,
                target.label,
                &target.head[..12.min(target.head.len())],
            );
            continue;
        }
        let summary = summaries.get(index);
        if review_target(
            repo,
            settings,
            target,
            base.as_deref(),
            cursor_report.as_ref(),
            &repo_id,
            summary,
            &summaries,
            runtime,
            contract,
        )? != 0
        {
            return Ok(1);
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// the full-audit lifecycle
// ---------------------------------------------------------------------------

/// Build a full-service run directory: the sanitized snapshot, the original
/// request, the scope and the bare object store the evidence server reads.
pub fn build_snapshot_dir(
    contract: &Contract,
    manifest_path: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let selected: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest_path).map_err(|e| format!("manifest: {e}"))?,
    )
    .map_err(|e| format!("manifest: {e}"))?;
    let projects = selected["projects"]
        .as_object()
        .ok_or("manifest: expected a projects object")?;
    let reuse = selected["reuse"].as_object();
    let snapshot = fullservice::snapshot_projects(contract, projects, reuse)?;
    std::fs::create_dir_all(output).map_err(|e| format!("output: {e}"))?;
    evidence::write_json(&output.join("snapshot.json"), &snapshot)?;
    let request: Value = serde_json::from_str(
        &std::fs::read_to_string(request_path).map_err(|e| format!("request: {e}"))?,
    )
    .map_err(|e| format!("request: {e}"))?;
    evidence::write_json(&output.join("request.json"), &request)?;
    let objects = output.join("objects.git");
    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&objects)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !init.status.success() {
        return Err("git: could not create the run's object store".to_string());
    }
    let tree = Command::new("git")
        .arg("-C")
        .arg(&objects)
        .args(["hash-object", "-t", "tree", "--stdin", "-w"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    let tree = String::from_utf8_lossy(&tree.stdout).trim().to_string();
    evidence::write_json(
        &output.join("scope.json"),
        &json!({
            "mode": "full-service",
            "repo": objects.to_string_lossy(),
            "tree": tree,
            "base": tree,
            "changed": [],
        }),
    )?;
    Ok(())
}

/// Snapshot the selected projects and run one full audit over them.
pub fn start_full_audit(
    contract_path: &Path,
    manifest_path: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    if !contract.tools.full_service {
        return Err("This contract offers no full-service mode".to_string());
    }
    if output.exists() {
        return Err("The output directory must not already exist".to_string());
    }
    build_snapshot_dir(&contract, manifest_path, request_path, output)?;
    resume_full_audit(contract_path, output)
}

/// Continue or finalize an existing full-audit directory.
pub fn resume_full_audit(contract_path: &Path, output: &Path) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    if !contract.tools.full_service {
        return Err("This contract offers no full-service mode".to_string());
    }
    let output = output
        .canonicalize()
        .map_err(|error| format!("output: {error}"))?;
    if output.join("report.json").exists() {
        return Err("An existing submitted report must not be re-audited".to_string());
    }
    let snapshot: Value = serde_json::from_str(
        &std::fs::read_to_string(output.join("snapshot.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let status_path = output.join("status.json");
    if let Ok(raw) = std::fs::read_to_string(&status_path) {
        let previous: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if previous["state"] == "running" {
            return Err(
                "Review is already marked running; inspect the owning process first".to_string(),
            );
        }
        let history_path = output.join("attempts.json");
        let mut attempts: Vec<Value> = std::fs::read_to_string(&history_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        attempts.push(previous);
        evidence::write_json(&history_path, &json!(attempts))?;
    }
    let settings = load_settings(contract.dir.as_path())?;
    assert_synced(&settings, contract.dir.as_path())?;
    let runtime = declared_runtime(&settings)?;
    // Keep the declared runtime in the scope so the receipt labels the engine
    // that actually produced the verdict, even on a resumed directory.
    let scope_path = output.join("scope.json");
    let mut scope: Value =
        serde_json::from_str(&std::fs::read_to_string(&scope_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    scope["runtime"] = Value::Object(runtime.clone());
    evidence::write_json(&scope_path, &scope)?;
    evidence::write_json(
        &status_path,
        &json!({
            "state": "running",
            "projects": snapshot["projects"].as_object().map(|p| p.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
            "files": snapshot["files"].as_object().map(|f| f.len()).unwrap_or_default(),
        }),
    )?;
    // Same one-shot credential the gate path issues: the full audit's
    // verdict is signed by the session that produced it and the key dies
    // with it.
    let key = credential::issue(&output)?;
    match agent_review(&output, &settings, &runtime, &contract) {
        Err(error) => {
            evidence::write_json(
                &status_path,
                &json!({"state": "failed", "report_exists": output.join("report.json").exists()}),
            )?;
            eprintln!("{} full audit failed: {}", contract.title, sanitize(&error));
            Ok(1)
        }
        Ok((usage, duration_ms, identity)) => {
            let report_path = output.join("report.json");
            let mut report: Value = serde_json::from_str(
                &std::fs::read_to_string(&report_path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if !credential::verify(&key, &report) {
                evidence::write_json(
                    &status_path,
                    &json!({"state": "failed", "report_exists": true}),
                )?;
                return Err("the audit report carries no valid verdict credential".to_string());
            }
            report["gate_status"] = json!("full-audit-complete");
            report["review_usage"] = json!({"tokens": usage, "duration_ms": duration_ms as u64});
            report["agent_profile"] = identity;
            evidence::write_json(&report_path, &report)?;
            credential::consume(&output);
            evidence::write_json(
                &status_path,
                &json!({"state": "completed", "report_exists": true}),
            )?;
            Ok(0)
        }
    }
}
