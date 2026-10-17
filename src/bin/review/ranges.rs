//! Resolve what a push, a pull request or a release is about to publish.
//!
//! Every event judges the whole tree at its head commit: the auditors hold the
//! same global view from the first review on, so no later event can widen the
//! review object after an earlier one passed. Three properties matter:
//!
//! * the review object is the immutable whole-tree snapshot at `head` - one
//!   target per distinct head commit, with no base to compare against;
//! * a merge request whose head is not local is fetched into FETCH_HEAD only;
//! * a release is judged as the whole tree it publishes, exactly like a push.

use crate::stage1::Target;
use std::process::Command;

fn git(repo: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|error| format!("Git could not read the review snapshot: {error}"))?;
    if !output.status.success() {
        return Err("Git could not read the review snapshot".to_string());
    }
    Ok(output)
}

fn rev(repo: &str, spec: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", spec])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => String::new(),
    }
}

fn short_ref(name: &str) -> &str {
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// True when a remote-tracking ref already contains the commit.
fn published_elsewhere(repo: &str, commit: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--count=1",
            "--contains",
            commit,
            "--format=%(refname)",
            "refs/remotes",
        ])
        .output()
        .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Fetch a merge request's head into FETCH_HEAD; creates no ref.
fn fetch_pull_head(repo: &str, number: &str) -> Result<(), String> {
    git(
        repo,
        &[
            "fetch",
            "--no-tags",
            "--quiet",
            "origin",
            &format!("refs/pull/{number}/head"),
        ],
    )
    .map(|_| ())
    .map_err(|_| "The merge request head could not be fetched for review".to_string())
}

/// One whole-snapshot target at the resolved head commit.
fn snapshot(kind: &str, label: String, head: String, ref_: Option<String>) -> Target {
    Target {
        kind: kind.to_string(),
        label,
        base: None,
        head,
        ref_,
        scope: "snapshot".to_string(),
        fallback: String::new(),
    }
}

/// The whole tree a release publishes, at its resolved commit.
fn release_target(repo: &str, tag: &str, commit: &str) -> Result<Target, String> {
    let mut head = if commit.is_empty() {
        String::new()
    } else {
        rev(repo, &format!("{commit}^{{commit}}"))
    };
    if head.is_empty() && !tag.is_empty() {
        head = rev(repo, &format!("{tag}^{{commit}}"));
    }
    if head.is_empty() {
        return Err("The release commit is not in this checkout; publish this release from the tagged working tree".to_string());
    }
    let label = format!(
        "release {}",
        if tag.is_empty() {
            &head[..12.min(head.len())]
        } else {
            tag
        }
    );
    Ok(snapshot("release", label, head, None))
}

/// The push refs, pull request or release to audit. `vars` carries the
/// GITVAULT_* environment, injected so tests never mutate process state.
pub fn ranges_from(
    repo: &str,
    event: &str,
    vars: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<Target>, String> {
    let var = |name: &str| {
        vars.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    if event == "release" {
        return Ok(vec![release_target(
            repo,
            &var("GITVAULT_RELEASE_TAG"),
            &var("GITVAULT_RELEASE_COMMIT"),
        )?]);
    }
    if event == "pr" {
        let head_ref = var("GITVAULT_PR_HEAD");
        let base_ref = var("GITVAULT_PR_BASE");
        let number = var("GITVAULT_PR_NUMBER");
        let (head, label);
        if !number.is_empty() {
            fetch_pull_head(repo, &number)?;
            head = rev(repo, "FETCH_HEAD^{commit}");
            label = format!(
                "merge request #{number} → {}",
                if base_ref.is_empty() {
                    "default"
                } else {
                    &base_ref
                }
            );
        } else {
            let mut found = rev(repo, &format!("{head_ref}^{{commit}}"));
            if found.is_empty() {
                found = rev(
                    repo,
                    &format!("refs/remotes/origin/{}^{{commit}}", short_ref(&head_ref)),
                );
            }
            head = found;
            label = format!(
                "pull request {head_ref} → {}",
                if base_ref.is_empty() {
                    "default"
                } else {
                    &base_ref
                }
            );
        }
        if head.is_empty() {
            return Err("The pull request head is not available locally; push the branch through GitVault first".to_string());
        }
        return Ok(vec![snapshot("pr", label, head, None)]);
    }
    let mut found = Vec::new();
    for line in var("GITVAULT_PUSH_REFS").lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            continue;
        }
        let (local_ref, local_sha) = (fields[0], fields[1]);
        if local_sha.trim_matches('0').is_empty() {
            continue; // a deletion publishes nothing
        }
        let head = rev(repo, &format!("{local_sha}^{{commit}}"));
        if head.is_empty() || published_elsewhere(repo, &head) {
            continue; // already-published tips add no unreviewed content
        }
        found.push(snapshot(
            "push",
            format!("push {local_ref}"),
            head,
            Some(local_ref.to_string()),
        ));
    }
    // One target per distinct head commit.
    let mut seen = std::collections::HashSet::new();
    found.retain(|target| seen.insert(target.head.clone()));
    Ok(found)
}

/// The live form: the GITVAULT_* environment, read once.
pub fn ranges(repo: &str) -> Result<Vec<Target>, String> {
    let mut vars = serde_json::Map::new();
    for name in [
        "GITVAULT_EVENT",
        "GITVAULT_RELEASE_TAG",
        "GITVAULT_RELEASE_COMMIT",
        "GITVAULT_PR_HEAD",
        "GITVAULT_PR_BASE",
        "GITVAULT_PR_NUMBER",
        "GITVAULT_PUSH_REFS",
    ] {
        if let Ok(value) = std::env::var(name) {
            vars.insert(name.to_string(), serde_json::Value::String(value));
        }
    }
    let event = vars
        .get("GITVAULT_EVENT")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    ranges_from(repo, &event, &vars)
}
