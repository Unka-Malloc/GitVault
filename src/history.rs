//! The history-integrity gate: a built-in, deterministic verdict on what a
//! push does to published refs - separate from what the pushed content is.
//!
//! The audit registry judges content: the snapshot a ref's head carries. This
//! gate judges the *act* on the ref itself, which no content review can see:
//!
//! * **Non-fast-forward.** A remote tip that is not an ancestor of the pushed
//!   head means already-published commits are being rewritten. That is an
//!   irreversible act on the public record, never something a diff review
//!   should wave through.
//! * **Tag re-pointing.** A tag whose remote object differs from the pushed
//!   one moved the release anchor; even an ancestor move is a re-point, and
//!   tags do not move.
//! * **Ref deletion.** Deleting a published ref publishes nothing new but can
//!   orphan content: when the deleted tip is no longer contained in any local
//!   or remote-tracking ref, the deletion is blocking. When the commits are
//!   still reachable elsewhere the deletion removes only the name - reported
//!   advisory, and the operation proceeds.
//!
//! All three facts are already on stdin (`<local ref> <local sha> <remote ref>
//! <remote sha>`), so the gate costs a few `merge-base`/`merge-base
//! --is-ancestor` calls and no token.

use std::process::Command;

use crate::checkers::{CheckerOutcome, Context, OutcomeKind};
use crate::config::Severity;

fn is_zero(sha: &str) -> bool {
    sha.trim_matches('0').is_empty()
}

fn is_ancestor(repo: &std::path::Path, old: &str, new: &str) -> Option<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", old, new])
        .output()
        .ok()?;
    match out.status.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        // The remote tip is not in this object store, so ancestry cannot be
        // proven at all - treated like a rewrite below.
        _ => None,
    }
}

/// Whether the commit a deleted ref pointed at still lives somewhere the
/// deletion does not remove it: any local ref, or a remote-tracking ref that
/// is not the one being deleted. A tip nothing else reaches would be orphaned
/// by the deletion.
fn still_reachable(
    repo: &std::path::Path,
    commit: &str,
    deleted_remote: &str,
    remote: Option<&str>,
) -> bool {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--contains",
            commit,
            "--format=%(refname)",
            "refs/heads",
            "refs/remotes",
            "refs/tags",
        ])
        .output();
    let Ok(out) = out else {
        return false;
    };
    // The remote-tracking mirror of the ref being deleted contains the tip by
    // definition; counting it would make every deletion "reachable". A remote
    // ref `refs/heads/<b>` mirrors locally as `refs/remotes/<remote>/<b>`.
    // Only the pushed remote's own mirror is excluded: `upstream/tmp` survives
    // a deletion of `origin`'s `tmp` and rightly counts as reachability. When
    // the remote is unknown the conservative suffix match stays - wrongly
    // blocking a legitimate delete beats wrongly passing an orphaning one.
    let suffix = deleted_remote
        .strip_prefix("refs/heads/")
        .or_else(|| deleted_remote.strip_prefix("refs/tags/"))
        .map(|short| format!("/{short}"));
    String::from_utf8_lossy(&out.stdout).lines().any(|r| {
        let excluded = match (remote, &suffix) {
            (Some(remote), Some(short)) => r == format!("refs/remotes/{remote}{short}"),
            (None, Some(s)) => r.starts_with("refs/remotes/") && r.ends_with(s.as_str()),
            (_, None) => false,
        };
        !excluded
    })
}

fn hit(name: &str, line: String) -> CheckerOutcome {
    CheckerOutcome {
        name: name.to_string(),
        severity: Severity::Blocking,
        outcome: OutcomeKind::Failed(-1),
        duration_ms: 0,
        stdout: line,
        stderr: String::new(),
    }
}

/// The gate body. Runs for `pre-push` only; other events have no ref lines to
/// judge. Returns one outcome per finding so every violation is named.
pub fn gates(ctx: &Context) -> Vec<CheckerOutcome> {
    if ctx.event != "pre-push" {
        return Vec::new();
    }
    let Some(stdin) = &ctx.stdin else {
        return Vec::new();
    };
    let mut outcomes = Vec::new();
    for line in stdin.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            continue;
        }
        let (local_ref, local_sha, remote_ref, remote_sha) =
            (fields[0], fields[1], fields[2], fields[3]);
        if is_zero(local_sha) {
            // A deletion. Blocking only when the tip would be orphaned; a
            // ref being removed while its commits stay reachable elsewhere
            // loses the name, not the content - reported advisory, because a
            // published ref disappearing is a fact the record should carry.
            if is_zero(remote_sha) {
                continue;
            }
            if still_reachable(
                &ctx.repo_root,
                remote_sha,
                remote_ref,
                ctx.push_remote.as_deref(),
            ) {
                outcomes.push(CheckerOutcome {
                    name: "history-delete".to_string(),
                    severity: Severity::Advisory,
                    outcome: OutcomeKind::Passed,
                    duration_ms: 0,
                    stdout: format!(
                        "{remote_ref} is deleted while {remote_sha} stays reachable \
                         through other refs - the name goes, the commits survive"
                    ),
                    stderr: String::new(),
                });
            } else {
                outcomes.push(hit(
                    "history-delete",
                    format!(
                        "{remote_ref} deletes the only ref reaching {remote_sha} - \
                         those commits would be orphaned on the remote\n\
                         keep them reachable first (push another ref containing them), \
                         or accept the loss through a different, reviewed path"
                    ),
                ));
            }
            continue;
        }
        if is_zero(remote_sha) {
            continue; // a new ref publishes new content; nothing is rewritten
        }
        // A tag never re-points: forward or divergent, the verdict names the
        // real offense rather than advice to rebase a ref that cannot.
        if local_ref.starts_with("refs/tags/") {
            outcomes.push(hit(
                "history-tag-repoint",
                format!(
                    "{remote_ref} re-points tag {local_ref} (remote {remote_sha} → {local_sha}); \
                     tags do not move - push a new tag instead"
                ),
            ));
            continue;
        }
        match is_ancestor(&ctx.repo_root, remote_sha, local_sha) {
            Some(true) => {}
            // The remote tip is not in this object store at all: ancestry
            // cannot be judged until the remote is fetched. The remedy is
            // fetch + rebase - the same command reports a real rewrite or
            // makes the push a fast-forward.
            None => outcomes.push(hit(
                "history-nonff",
                format!(
                    "{remote_ref}'s tip {remote_sha} is not in this checkout; \
                     fetch it and rebase `{local_ref}` onto it \
                     (git fetch {} && git rebase {remote_ref}), then push again",
                    ctx.push_remote.as_deref().unwrap_or("<remote>"),
                ),
            )),
            // The tip is present but not an ancestor: integrating it turns
            // the push back into a fast-forward.
            Some(false) => outcomes.push(hit(
                "history-nonff",
                format!(
                    "{local_ref} does not contain {remote_ref}'s tip (remote {remote_sha} → {local_sha}); \
                     integrate it with git pull --rebase{} and push again - \
                     deliberately different history needs a new ref name",
                    ctx.push_remote
                        .as_deref()
                        .map(|remote| format!(" {remote}"))
                        .unwrap_or_default(),
                ),
            )),
        }
    }
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::Context;
    use std::path::{Path, PathBuf};

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Synthetic")
            .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
            .env("GIT_COMMITTER_NAME", "Synthetic")
            .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A scratch repository whose only purpose is giving the gate real objects
    /// to reason over; the tree is deleted when the wrapper drops.
    struct Repo(PathBuf);

    impl Repo {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "gv-history-{}-{:04x}",
                std::process::id(),
                rand::random::<u16>()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            git(&dir, &["init", "-b", "main"]);
            Self(dir)
        }

        fn commit(&self, file: &str) -> String {
            std::fs::write(self.0.join(file), file).unwrap();
            git(&self.0, &["add", file]);
            git(&self.0, &["commit", "-m", file]);
            git(&self.0, &["rev-parse", "HEAD"])
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ctx(repo: &Repo, stdin: String) -> Context {
        Context {
            event: "pre-push".into(),
            repo_root: repo.0.clone(),
            repo_slug: None,
            identity: "synthetic".into(),
            account: None,
            via_default: false,
            expected_email: None,
            actual_email: None,
            stdin: Some(stdin),
            push_remote: Some("origin".into()),
            pr_base: None,
            pr_base_sha: None,
            pr_head: None,
            pr_number: None,
            release_tag: None,
            release_commit: None,
            release_assets: Vec::new(),
            inherited_fds: Vec::new(),
            commit_message_file: None,
            commit_message_source: None,
        }
    }

    fn names(outcomes: &[CheckerOutcome]) -> Vec<&str> {
        outcomes.iter().map(|o| o.name.as_str()).collect()
    }

    #[test]
    fn a_fast_forward_push_is_not_a_history_event() {
        let repo = Repo::new();
        let a = repo.commit("a");
        let b = repo.commit("b");
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/main {b} refs/heads/main {a}"),
        ));
        assert!(out.is_empty(), "a fast-forward draws no verdict: {out:?}");
    }

    #[test]
    fn rewriting_a_published_tip_is_refused() {
        let repo = Repo::new();
        let a = repo.commit("a");
        let b = repo.commit("b");
        // A divergent sibling: the remote tip is not an ancestor of the head.
        git(&repo.0, &["checkout", "-b", "side", &a]);
        let c = repo.commit("c");
        git(&repo.0, &["checkout", "main"]);
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/main {b} refs/heads/main {c}"),
        ));
        assert_eq!(names(&out), ["history-nonff"]);
    }

    #[test]
    fn a_remote_tip_missing_from_the_checkout_still_refuses_with_guidance() {
        let repo = Repo::new();
        let b = repo.commit("b");
        // The remote advertises a tip this object store has never fetched:
        // ancestry cannot be proven, so the push is held for fetch+rebase.
        let missing = "1".repeat(40);
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/main {b} refs/heads/main {missing}"),
        ));
        assert_eq!(names(&out), ["history-nonff"]);
        assert!(
            out[0].stdout.contains("fetch"),
            "the remedy names the fetch first: {}",
            out[0].stdout
        );
    }

    #[test]
    fn a_tag_never_moves_even_forward() {
        let repo = Repo::new();
        let a = repo.commit("a");
        let b = repo.commit("b");
        let out = gates(&ctx(&repo, format!("refs/tags/v1 {b} refs/tags/v1 {a}")));
        assert_eq!(names(&out), ["history-tag-repoint"]);
        // A brand-new tag publishes content, it does not rewrite any.
        let out = gates(&ctx(
            &repo,
            format!("refs/tags/v2 {b} refs/tags/v2 {}", "0".repeat(40)),
        ));
        assert!(out.is_empty());
        // A divergent re-point is the same offense with the same name -
        // telling the operator to rebase a tag would be no help at all.
        git(&repo.0, &["checkout", "-b", "side", &a]);
        let c = repo.commit("c");
        let out = gates(&ctx(&repo, format!("refs/tags/v1 {b} refs/tags/v1 {c}")));
        assert_eq!(names(&out), ["history-tag-repoint"]);
    }

    #[test]
    fn deleting_an_orphaned_tip_is_refused_but_a_reachable_one_passes() {
        let repo = Repo::new();
        repo.commit("a");
        git(&repo.0, &["checkout", "-b", "tmp"]);
        let x = repo.commit("x");
        git(&repo.0, &["checkout", "main"]);
        git(&repo.0, &["branch", "-D", "tmp"]);
        let zero = "0".repeat(40);

        // Nothing reaches x now: deleting its remote ref orphans the commits.
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/tmp {zero} refs/heads/tmp {x}"),
        ));
        assert_eq!(names(&out), ["history-delete"]);

        // The remote-tracking mirror of the deleted ref contains the tip by
        // definition; it must not count toward reachability.
        git(&repo.0, &["update-ref", "refs/remotes/origin/tmp", &x]);
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/tmp {zero} refs/heads/tmp {x}"),
        ));
        assert_eq!(
            names(&out),
            ["history-delete"],
            "the ref's own mirror cannot vouch for its reachability"
        );

        // A different remote's same-named mirror is not the one being
        // deleted: in the origin+upstream fork layout its reachability is
        // real, so the deletion is advisory rather than refused.
        git(&repo.0, &["update-ref", "refs/remotes/upstream/tmp", &x]);
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/tmp {zero} refs/heads/tmp {x}"),
        ));
        assert_eq!(names(&out), ["history-delete"]);
        assert_eq!(
            out[0].severity,
            Severity::Advisory,
            "upstream/tmp still reaches the tip origin/tmp loses"
        );

        // The same tip reachable from another ref deletes the name, not the
        // content: the advisory row records the fact without blocking it.
        let head = git(&repo.0, &["rev-parse", "main"]);
        let out = gates(&ctx(
            &repo,
            format!("refs/heads/feature {zero} refs/heads/feature {head}"),
        ));
        assert_eq!(names(&out), ["history-delete"]);
        assert_eq!(out[0].severity, Severity::Advisory);
    }

    #[test]
    fn other_events_carry_no_ref_lines_to_judge() {
        let repo = Repo::new();
        let a = repo.commit("a");
        let mut c = ctx(&repo, format!("refs/heads/main {0} refs/heads/main {0}", a));
        c.event = "commit".into();
        assert!(gates(&c).is_empty());
    }
}
