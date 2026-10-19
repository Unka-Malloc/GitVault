//! The AI-attribution gate: a built-in, deterministic scan of the commit
//! messages a publication event would send out.
//!
//! The commit-msg and prepare-commit-msg scrubbers strip attribution from the
//! message being *written*. This gate is the other half: pre-push, `pr` and
//! `release` all release commits already in history, which may carry
//! `Co-authored-by:` bot trailers, "Generated with" badges or agent signature
//! lines from before the scrubber existed - or from work done outside it. A
//! hit is blocking: the answer is to rewrite the range and strip the lines,
//! never to publish them.
//!
//! The pattern catalogue is a port of `~/.git-hooks/ai_attribution.py` and
//! keeps its matching rules exactly:
//!
//! * every pattern is anchored to the whole line - a line must *be* an
//!   attribution line, not merely mention a name;
//! * single-word brands (Jules, Cursor, Cline, ...) only count with a vendor
//!   address or in a "Generated with" badge, so a human named Jules survives;
//! * indented lines never match (a body quoting a trailer keeps it);
//! * known humans and non-AI bots are outside every pattern.
//!
//! Conservative by design: when the catalogue changes, change it here and in
//! `ai_attribution.py` together.

use std::collections::HashSet;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;

use crate::checkers::{CheckerOutcome, Context, OutcomeKind};
use crate::config::Severity;

// --------------------------------------------------------------- addresses

/// Vendor addresses that are always an agent: devin.ai/cognition domains with
/// any local part, plus the exact noreply mailbox devin-ai-integration uses.
const DEVIN_ADDR: &str = r"(?:[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9.\-]*\.)?(?:devin\.ai|cognition\.ai|cognition-labs\.com)|158243242\+devin-ai-integration\[bot\]@users\.noreply\.github\.com|(?:[0-9]+\+)?devin-ai-integration(?:\[bot\])?@users\.noreply\.github\.com)";
const ANTHROPIC_ADDR: &str = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]*anthropic\.com";
const COMMANDCODE_ADDR: &str = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]*commandcode\.ai";

/// GitHub renders agent accounts as `<id>+<name>[bot]@users.noreply.github.com`.
/// Only accounts AI agents actually use are listed; a bare `[bot]` is not
/// enough - dependabot and friends stay out.
const GITHUB_AGENT_BOT: &str = r"(?:[0-9]+\+)?(?:copilot|copilot-swe-agent|devin-ai-integration|cursor(?:agent)?|codex|claude|jules|sweep-ai|codegen-sh|openhands|aider|gemini[^@<>]*|qwen[^@<>]*|kimi|glm|lingma|trae[^@<>]*|factory-droid)(?:\[bot\])?@users\.noreply\.github\.com";

/// Domains where any local part is an agent address.
const OTHER_DOMAINS: &str = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]*(?:openai\.com|cursor\.com|cursor\.sh|nousresearch\.com|stably\.ai|happy\.engineering|agentmail\.to|factory\.ai|augmentcode\.com|sourcegraph\.com|codeium\.com|windsurf\.com|tabnine\.com|qodo\.ai|codium\.ai|aider\.chat|zed\.dev|all-hands\.dev|continue\.dev|cline\.ai|trae\.ai|sweep\.dev|charm\.land|oh-my-codex\.dev|habibilabs\.dev|z\.ai|minimax\.io|moonshot\.cn|kimi\.com)";

/// Exact addresses on domains shared with humans; these need the agent's
/// display name in the trailer as well (`Jules ... <jules@google.com>`).
const OTHER_PAIR_ADDR: &str = r"(?:jules@google\.com|gemini(?:-code-assist)?@google\.com|bard@google\.com|(?:q-developer|amazonq|amazon-q)@amazon\.com|lingma@alibaba\.com|qwen[\w.\-]*@alibabacloud\.com|mimo@xiaomi\.com|service@deepseek\.com)";
const OTHER_PAIR_NAMES: &str = r"(?:Jules|Gemini(?:\s+Code\s+Assist)?|Bard|Amazon\s+Q(?:\s+Developer)?|Lingma|Qwen[\s\-]*(?:Code|Coder)?|MiMo|DeepSeek[\w.\-]*)";

// ------------------------------------------------------------------- names

/// Multi-word or otherwise unmistakable agent names: accepted with any address.
const NAMED_AGENTS: &str = r"(?:OpenAI\s+Codex|GPT-[\d.]+\s*Codex|CommandCode(?:Bot)?|GitHub\s+Copilot|Copilot\s+swe-?agent|CursorAgent|Cursor\s+Agent|Hermes\s+(?:Agent|Audit)|Factory[\s\-]*Droid|Augment\s+Code|Qwen[\s\-]*(?:Code|Coder)|Gemini\s+(?:CLI|Code\s+Assist)|Trae\s+(?:Agent|Work|AI)|WorkBuddy|Kilo\s+Code|Rovo\s+Dev|Roo\s+Code|Amazon\s+Q(?:\s+Developer)?|Lingma|OpenHands|OpenCode|sweep-ai|codegen-sh|continue-agent|cline-bot|oh-my-codex|MiniMax|MiMo|ChatGPT|Blut-?Agent)";

/// Single-word brands: only count with a vendor address, or in a badge.
const SINGLE_WORD_BRANDS: &str = r"(?:Copilot|Cursor|Codex|Jules|Gemini|Crush|Kiro|Junie|Windsurf|Codeium|Tabnine|CodeGeeX|Aider|Cline|Continue|Goose|Droid|Amp|Zed|GLM|DeepSeek|Qwen|Kimi|Bard|Trae)";

/// Families whose names live in their own patterns too.
const FAMILY_NAMES: &str = r"(?:Claude(?:\s+Code)?|Devin(?:\s+AI)?|CommandCode(?:Bot)?)";

/// Model ids used by `Assisted-by:` / `Generated-by:` trailers.
const MODEL_IDS: &str = r"(?:GPT-[\w.\-]+|ChatGPT|o[1-9][\w.\-]*|Claude[\w.\-]*|Gemini[\w.\-]*|GLM[\w.\-]*|DeepSeek[\w.\-]*|Qwen[\w.\-]*|Kimi[\w.\-]*|Grok[\w.\-]*|Mistral[\w.\-]*|Codestral[\w.\-]*|Llama[\w.\-]*|MiniMax[\w.\-]*|MiMo[\w.\-]*|Doubao[\w.\-]*|Ernie[\w.\-]*|Hunyuan[\w.\-]*|Phi-[\w.\-]+|Command[\s\-]?R[\w.\-]*)";

// ----------------------------------------------------------------- patterns

struct Pattern {
    /// The agent family the pattern belongs to: devin | claude | commandcode |
    /// other. Reported as the match's category.
    tag: &'static str,
    /// What shape the line has, for the refusal message. The line itself is
    /// never printed.
    kind: &'static str,
    regex: Regex,
}

fn trailer(name: &str, address: &str) -> String {
    format!(r"(?i)^Co-authored-by:\s*{name}\s*<{address}>\s*$")
}

/// A "Generated with" badge as the whole line, behind at most a small prefix
/// (emoji): `[name](url)` when a url is required, otherwise any link plus the
/// bare-name form some agents emit.
fn badge(name: &str, url: Option<&str>, plain: bool) -> String {
    let bracketed = match url {
        Some(u) => format!(r"\[{name}\]\({u}\)"),
        None => format!(r"\[{name}\](?:\([^)]*\))?"),
    };
    let forms = if plain {
        format!("{bracketed}|{name}")
    } else {
        bracketed
    };
    format!(r"(?i)^[^\w\s]{{0,3}}\s*Generated with (?:{forms})\s*$")
}

fn pattern(tag: &'static str, kind: &'static str, raw: String) -> Pattern {
    Pattern {
        tag,
        kind,
        regex: Regex::new(&raw).expect("attribution pattern must compile"),
    }
}

const CO_TRAILER: &str = "co-authored-by trailer";
const GEN_BADGE: &str = "generated-with badge";
const STRUCTURED: &str = "assisted/generated-by trailer";

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let other_addr = format!("(?:{GITHUB_AGENT_BOT}|{OTHER_DOMAINS}|copilot@github\\.com)");
    let badge_names = format!("(?:{NAMED_AGENTS}|{SINGLE_WORD_BRANDS})");
    let structured_names = format!("(?:{badge_names}|{FAMILY_NAMES})");
    vec![
        pattern("devin", CO_TRAILER, trailer(r"Devin\s+AI", r"[^<>]+")),
        pattern("devin", CO_TRAILER, trailer(r"[^<>]*", DEVIN_ADDR)),
        pattern(
            "devin",
            GEN_BADGE,
            badge(
                r"Devin(?:\s+AI)?",
                Some(r"https?://[^)]*devin\.ai[^)]*"),
                false,
            ),
        ),
        pattern("devin", GEN_BADGE, badge(r"Devin\s+AI", None, true)),
        pattern("claude", CO_TRAILER, trailer(r"Claude\s+Code", r"[^<>]+")),
        pattern("claude", CO_TRAILER, trailer(r"[^<>]*", ANTHROPIC_ADDR)),
        pattern(
            "claude",
            GEN_BADGE,
            badge(
                r"Claude(?:\s+Code)?",
                Some(r"https?://[^)]*(?:claude\.(?:com|ai)|anthropic\.com)[^)]*"),
                false,
            ),
        ),
        pattern("claude", GEN_BADGE, badge(r"Claude\s+Code", None, true)),
        pattern(
            "claude",
            "claude-session trailer",
            r"(?i)^Claude-Session:\s*\S.*$".to_string(),
        ),
        pattern(
            "commandcode",
            CO_TRAILER,
            trailer(r"CommandCode(?:Bot)?", r"[^<>]+"),
        ),
        pattern(
            "commandcode",
            CO_TRAILER,
            trailer(r"[^<>]*", COMMANDCODE_ADDR),
        ),
        pattern(
            "commandcode",
            GEN_BADGE,
            badge(r"CommandCode(?:Bot)?", None, true),
        ),
        pattern("other", CO_TRAILER, trailer(NAMED_AGENTS, r"[^<>]+")),
        pattern("other", CO_TRAILER, trailer(r"[^<>]*", &other_addr)),
        pattern(
            "other",
            CO_TRAILER,
            trailer(OTHER_PAIR_NAMES, OTHER_PAIR_ADDR),
        ),
        pattern("other", GEN_BADGE, badge(&badge_names, None, true)),
        pattern(
            "other",
            STRUCTURED,
            format!(
                r"(?i)^(?:Assisted|Generated)-by:\s*(?:{structured_names}|{MODEL_IDS})(?::\s*(?:{structured_names}|{MODEL_IDS}))?\s*$"
            ),
        ),
    ]
});

/// The (tag, kind) of the first pattern that makes `line` an attribution line.
/// Indented lines never match: a body quoting a trailer as an example keeps it.
fn attribution_match(line: &str) -> Option<(&'static str, &'static str)> {
    if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    PATTERNS
        .iter()
        .find(|p| p.regex.is_match(line))
        .map(|p| (p.tag, p.kind))
}

// ------------------------------------------------------------------ ranges

/// One revision-set spec for `git log`: the outgoing commits for a single ref
/// or boundary, expressed as arguments (`a..b`, or `sha --not <refs>`).
type RangeSpec = Vec<String>;

fn run_git(repo: &std::path::Path, args: &[String]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn all_zeros(sha: &str) -> bool {
    !sha.is_empty() && sha.chars().all(|c| c == '0')
}

/// The outgoing commits for each event, as `git log` argument sets. Derived
/// from the same boundary the event already computes: stdin ref lines for
/// pre-push, base/head (or the request's fetched head) for `pr`, the tagged
/// commit minus existing releases for `release`.
fn outgoing_ranges(ctx: &Context) -> Result<Vec<RangeSpec>, String> {
    match ctx.event.as_str() {
        "pre-push" => push_ranges(ctx),
        "pr" => pr_ranges(ctx),
        "release" => release_ranges(ctx),
        _ => Ok(vec![]),
    }
}

/// pre-push stdin lines are `<local ref> <local sha> <remote ref> <remote sha>`.
/// A new remote ref scans everything the local sha has that no remote-tracking
/// ref does (first push included); a deletion contributes nothing.
fn push_ranges(ctx: &Context) -> Result<Vec<RangeSpec>, String> {
    let mut ranges = vec![];
    for line in ctx.stdin.as_deref().unwrap_or("").lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (local_sha, remote_sha) = (fields[1], fields[3]);
        if all_zeros(local_sha) {
            continue;
        }
        if all_zeros(remote_sha) {
            ranges.push(vec![
                local_sha.to_string(),
                "--not".into(),
                "--remotes".into(),
            ]);
        } else {
            // The remote sha normally resolves locally. When it does not (a
            // remote this checkout never fetched, or a tip the remote moved
            // since), fall back to the wider set.
            let mut spec = vec![format!("{remote_sha}..{local_sha}")];
            if run_git(
                &ctx.repo_root,
                &[
                    "rev-parse".into(),
                    "--verify".into(),
                    format!("{remote_sha}^{{commit}}"),
                ],
            )
            .is_err()
            {
                spec = vec![local_sha.to_string(), "--not".into(), "--remotes".into()];
            }
            ranges.push(spec);
        }
    }
    Ok(ranges)
}

fn merge_base(repo: &std::path::Path, a: &str, b: &str) -> Result<String, String> {
    run_git(repo, &["merge-base".into(), a.into(), b.into()]).map(|s| s.trim().to_string())
}

/// `pr create` scans the commits the request would add to its base;
/// `pr merge` fetches the request's head and scans what it carries into the
/// checked-out branch. An event without either boundary has no defined range
/// and is skipped by the caller before this is reached.
fn pr_ranges(ctx: &Context) -> Result<Vec<RangeSpec>, String> {
    if let Some(number) = &ctx.pr_number {
        run_git(
            &ctx.repo_root,
            &[
                "fetch".into(),
                "-q".into(),
                "origin".into(),
                format!("pull/{number}/head"),
            ],
        )
        .map_err(|e| format!("cannot fetch pull/{number}/head for review: {e}"))?;
        let base = merge_base(&ctx.repo_root, "FETCH_HEAD", "HEAD")?;
        return Ok(vec![vec![format!("{base}..FETCH_HEAD")]]);
    }

    let head = ctx.pr_head.clone().unwrap_or_default();
    let base = ctx.pr_base.clone().unwrap_or_default();
    // An empty base means the repository's default branch, which locally is
    // what origin/HEAD points at.
    let base_ref = if base.is_empty() {
        run_git(
            &ctx.repo_root,
            &["rev-parse".into(), "--verify".into(), "origin/HEAD".into()],
        )
        .map(|_| "origin/HEAD".to_string())
        .unwrap_or_else(|_| "HEAD".to_string())
    } else {
        base
    };
    let base_sha = merge_base(&ctx.repo_root, &base_ref, &head).or_else(|_| {
        run_git(
            &ctx.repo_root,
            &["rev-parse".into(), "--verify".into(), base_ref.clone()],
        )
        .map(|s| s.trim().to_string())
    })?;
    Ok(vec![vec![format!("{base_sha}..{head}")]])
}

/// A release publishes the commits on the tagged commit that no earlier tag
/// already released. The release tag itself is excluded from the exclusion
/// set - it is the thing being published, not a boundary.
fn release_ranges(ctx: &Context) -> Result<Vec<RangeSpec>, String> {
    let commit = match &ctx.release_commit {
        Some(c) => c.clone(),
        None => return Ok(vec![]),
    };
    let tags = run_git(&ctx.repo_root, &["tag".into(), "--list".into()])
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|t| !t.is_empty() && Some(*t) != ctx.release_tag.as_deref())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut spec = vec![commit];
    if !tags.is_empty() {
        spec.push("--not".into());
        spec.extend(tags);
    }
    Ok(vec![spec])
}

// -------------------------------------------------------------------- gate

/// Scan `(sha, message)` pairs out of one `git log` call. NUL is the record
/// separator because git does not allow it inside a commit message.
fn log_messages(repo: &std::path::Path, spec: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut args = vec!["log".into(), "--format=%H%x00%B%x00".into()];
    args.extend(spec.iter().cloned());
    let out = run_git(repo, &args)?;
    let mut commits = vec![];
    let parts: Vec<&str> = out.split('\x00').collect();
    for pair in parts.chunks(2) {
        let sha = pair[0].trim();
        if sha.is_empty() {
            continue;
        }
        commits.push((
            sha.to_string(),
            pair.get(1).copied().unwrap_or("").to_string(),
        ));
    }
    Ok(commits)
}

/// The built-in attribution gate, registered beside `identity-actual`.
///
/// Runs for the publication events that release history: pre-push, pr,
/// release. A hit is always blocking - unlike the identity gate it owes
/// nothing to the routing table, so there is no advisory form. A repository
/// state the gate cannot read refuses closed: a push it cannot inspect must
/// not sail through.
pub fn gate(ctx: &Context) -> Option<CheckerOutcome> {
    if !matches!(ctx.event.as_str(), "pre-push" | "pr" | "release") {
        return None;
    }
    // A `pr` event with neither a create boundary (base/head) nor a merge
    // boundary (number) has no defined outgoing range.
    if ctx.event == "pr" && ctx.pr_number.is_none() && ctx.pr_head.is_none() {
        return None;
    }

    let started = std::time::Instant::now();
    let outcome = |outcome: OutcomeKind, stdout: String| {
        Some(CheckerOutcome {
            name: "attribution-history".to_string(),
            severity: Severity::Blocking,
            outcome,
            duration_ms: started.elapsed().as_millis() as u64,
            stdout,
            stderr: String::new(),
        })
    };

    let ranges = match outgoing_ranges(ctx) {
        Ok(r) => r,
        Err(why) => return outcome(OutcomeKind::CouldNotRun(why), String::new()),
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut scanned = 0usize;
    let mut hits: Vec<String> = vec![];
    for spec in &ranges {
        let commits = match log_messages(&ctx.repo_root, spec) {
            Ok(c) => c,
            Err(why) => return outcome(OutcomeKind::CouldNotRun(why), String::new()),
        };
        for (sha, body) in commits {
            if !seen.insert(sha.clone()) {
                continue;
            }
            scanned += 1;
            let mut tags: Vec<&str> = vec![];
            let mut kinds: Vec<&str> = vec![];
            for line in body.lines() {
                if let Some((tag, kind)) = attribution_match(line) {
                    if !tags.contains(&tag) {
                        tags.push(tag);
                    }
                    if !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
            }
            if !tags.is_empty() {
                hits.push(format!(
                    "  {}  {} ({})",
                    &sha[..sha.len().min(12)],
                    tags.join(", "),
                    kinds.join(", ")
                ));
            }
        }
    }

    if !hits.is_empty() {
        // A long tainted range still names every hit's class of line, but the
        // listing itself is capped - the remediation is the same either way.
        let shown = hits.len().min(50);
        let mut detail = hits[..shown].join("\n");
        if hits.len() > shown {
            detail.push_str(&format!("\n  … and {} more", hits.len() - shown));
        }
        return outcome(
            OutcomeKind::Failed(-1),
            format!(
                "{} of {scanned} outgoing commit(s) carry AI attribution:\n{detail}\n  \
                 strip it before publishing: rewrite the range \
                 (git rebase -i / git filter-repo / git filter-branch) so the \
                 trailers are removed, then push the rewritten history",
                hits.len(),
            ),
        );
    }
    if scanned == 0 {
        return outcome(OutcomeKind::Passed, "no outgoing commits to scan".into());
    }
    outcome(
        OutcomeKind::Passed,
        format!("{scanned} outgoing commit(s) scanned - no AI attribution"),
    )
}

#[cfg(test)]
mod tests {
    use super::attribution_match;

    fn tag_of(line: &str) -> Option<&'static str> {
        attribution_match(line).map(|(tag, _)| tag)
    }

    #[test]
    fn bot_trailers_match() {
        assert_eq!(
            tag_of(
                "Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>"
            ),
            Some("devin")
        );
        assert_eq!(
            tag_of("Co-authored-by: Devin <devin-ai-integration[bot]@users.noreply.github.com>"),
            Some("devin")
        );
        assert_eq!(
            tag_of("Co-Authored-By: Claude Code <noreply@anthropic.com>"),
            Some("claude")
        );
        assert_eq!(
            tag_of("Co-Authored-By: github-actions <copilot@github.com>"),
            Some("other")
        );
        assert_eq!(
            tag_of("Co-Authored-By: Jules <jules@google.com>"),
            Some("other")
        );
        assert_eq!(
            tag_of("Assisted-by: Claude Code:claude-sonnet-4-6"),
            Some("other")
        );
        assert_eq!(tag_of("Generated-by: glm-4-5"), Some("other"));
        assert_eq!(tag_of("Claude-Session: abc-123"), Some("claude"));
    }

    #[test]
    fn badges_match() {
        assert_eq!(
            tag_of("Generated with [Devin](https://devin.ai)"),
            Some("devin")
        );
        assert_eq!(
            tag_of("🤖 Generated with [Claude Code](https://claude.com/claude-code)"),
            Some("claude")
        );
        assert_eq!(tag_of("Generated with Claude Code"), Some("claude"));
        assert_eq!(
            tag_of("Generated with [Cursor](https://cursor.sh)"),
            Some("other")
        );
    }

    #[test]
    fn humans_and_mentions_do_not_match() {
        assert_eq!(tag_of("Co-Authored-By: Jane Doe <jane@example.com>"), None);
        // A human named Jules on a non-vendor address survives.
        assert_eq!(tag_of("Co-Authored-By: Jules <jules@example.com>"), None);
        assert_eq!(tag_of("Assisted-by: Jane Doe"), None);
        assert_eq!(
            tag_of(
                "Co-Authored-By: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
            ),
            None
        );
        // Prose mentions are not attribution lines.
        assert_eq!(tag_of("Claude reviewed the diff"), None);
        assert_eq!(
            tag_of("Generated with [Devin](https://devin.ai) was the tool we discussed"),
            None
        );
    }

    #[test]
    fn indented_lines_never_match() {
        assert_eq!(
            tag_of("  Co-Authored-By: Devin <devin-ai-integration[bot]@users.noreply.github.com>"),
            None
        );
        assert_eq!(tag_of("\tGenerated with Claude Code"), None);
    }
}
