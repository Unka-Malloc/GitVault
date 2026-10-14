//! Read-only git probing.
//!
//! Everything here shells out to `git` and parses its output. Nothing in this
//! module executes repository content: `git remote get-url`, `git rev-parse` and
//! `git diff --cached --name-only` read metadata only.
//!
//! Routing on the remote's owner (rather than on the local path) is deliberate:
//! it survives cloning the same repository to a different directory, and it
//! keeps working for a fresh clone that has never been configured locally.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct Repo {
    pub root: PathBuf,
    remote: Option<String>,
}

impl Repo {
    /// Locate the working tree containing `directory`.
    pub fn discover(directory: &Path) -> Result<Self> {
        if !directory.exists() {
            bail!("path does not exist: {}", directory.display());
        }
        let root = git(directory, &["rev-parse", "--show-toplevel"])
            .context("not inside a git working tree")?;
        let root = PathBuf::from(root.trim());
        let remote = git(&root, &["remote", "get-url", "origin"])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(Self { root, remote })
    }

    /// Build a Repo handle for a known `Owner/Name` slug, without a checkout.
    ///
    /// Used when an operation names its target explicitly instead of running
    /// inside the working tree. Owner-based routing is what makes this safe: the
    /// rules key off the owner, not off a local path, so a slug is enough.
    pub fn for_slug(slug: &str) -> Self {
        Self {
            root: PathBuf::from("."),
            remote: Some(format!("git@github.com:{slug}.git")),
        }
    }

    /// Test-only: build a Repo without touching the filesystem.
    #[cfg(test)]
    pub fn for_test(root: &str, remote: Option<&str>) -> Self {
        Self {
            root: PathBuf::from(root),
            remote: remote.map(str::to_string),
        }
    }

    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// Owning account parsed out of the origin remote.
    ///
    /// Handles the forms that actually occur in the wild:
    ///   https://github.com/acme/launcher.git
    ///   git@github.com:acme/launcher.git
    ///   ssh://git@ssh.github.com:443/acme/launcher.git
    ///   git@github.com-acme:acme/launcher.git   (ssh host alias)
    pub fn owner(&self) -> Option<String> {
        parse_owner(self.remote.as_deref()?)
    }

    /// `Owner/Repo` slug parsed from the origin remote, which is what external
    /// tooling (the audit scanner, for one) expects as a repository identifier.
    pub fn slug(&self) -> Option<String> {
        let remote = self.remote.as_deref()?;
        let s = remote.trim();
        let s = s.strip_suffix(".git").unwrap_or(s);
        let path = if let Some(rest) = s.split_once("://").map(|(_, r)| r) {
            rest.split_once('/').map(|(_, p)| p)?
        } else if let Some((_, rest)) = s.split_once(':') {
            rest
        } else {
            return None;
        };
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() < 2 {
            return None;
        }
        Some(format!("{}/{}", parts[0], parts[1]))
    }

    /// Short name of the checked-out branch, or None when detached.
    pub fn current_branch(&self) -> Option<String> {
        git(&self.root, &["rev-parse", "--abbrev-ref", "HEAD"])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "HEAD")
    }

    /// Path of every file staged for the next commit. Used by pre-commit so the
    /// decision matches the index, not the working tree the developer sees.
    pub fn staged_paths(&self) -> Result<Vec<String>> {
        let out = git(
            &self.root,
            &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        )?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Every object id the current branch would introduce relative to base.
    pub fn commits_in_range(&self, base: &str, head: &str) -> Result<Vec<String>> {
        let out = git(&self.root, &["rev-list", &format!("{base}..{head}")])?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// The email git will actually stamp on a commit here.
    ///
    /// This is the value that decides GitHub attribution, and it is NOT
    /// necessarily the identity the rules resolve to: `git -c user.email=...`,
    /// a repo-local override, or a stray `includeIf` can all make them differ.
    /// Comparing the two is what turns "the policy is right" into "the commit
    /// will actually be attributed correctly".
    pub fn configured_email(&self) -> Option<String> {
        git(&self.root, &["config", "user.email"])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn configured_name(&self) -> Option<String> {
        git(&self.root, &["config", "user.name"])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn is_ancestor(&self, maybe_ancestor: &str, descendant: &str) -> bool {
        git(
            &self.root,
            &["merge-base", "--is-ancestor", maybe_ancestor, descendant],
        )
        .is_ok()
    }

    /// Resolve a revision to a commit id; refuses when it does not exist. Used
    /// by the release boundary, where a tag that is not in this checkout means
    /// the content cannot be reviewed from here.
    pub fn resolve_commit(&self, revision: &str) -> Result<String> {
        let out = git(
            &self.root,
            &["rev-parse", "--verify", &format!("{revision}^{{commit}}")],
        )?;
        Ok(out.trim().to_string())
    }

    /// The zero object id git uses for "this ref does not exist remotely yet".
    pub const NULL_SHA: &'static str = "0000000000000000000000000000000000000000";

    /// Root commit of a history, used when pushing a branch that is new remotely.
    pub fn root_commit(&self, head: &str) -> Result<String> {
        let out = git(&self.root, &["rev-list", "--max-parents=0", head])?;
        let last = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .next_back()
            .unwrap_or(head);
        Ok(last.to_string())
    }
}

pub fn parse_owner(remote: &str) -> Option<String> {
    let s = remote.trim();
    let s = s.strip_suffix(".git").unwrap_or(s);
    if s.is_empty() {
        return None;
    }

    // Split into "<prefix>:<path>" for scp-like, or take the URL path.
    let path = if let Some(rest) = s.split_once("://").map(|(_, r)| r) {
        // scheme://[user@]host[:port]/owner/repo
        rest.split_once('/').map(|(_, p)| p)?
    } else if let Some((_, rest)) = s.split_once(':') {
        rest
    } else {
        return None;
    };

    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?;
    // Require a repository component: "github.com/foo" alone is not owner/repo.
    parts.next()?;
    Some(owner.to_string())
}

fn git(directory: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{Repo, parse_owner};
    use std::path::PathBuf;

    fn repo_for(remote: &str) -> Repo {
        Repo {
            root: PathBuf::from("/tmp/x"),
            remote: Some(remote.to_string()),
        }
    }

    #[test]
    fn parses_every_remote_form_that_occurs_in_practice() {
        let cases = [
            ("https://github.com/acme/launcher.git", "acme"),
            ("https://github.com/acme/launcher", "acme"),
            ("git@github.com:acme/launcher.git", "acme"),
            ("git@github.com-acme:acme/launcher.git", "acme"),
            ("ssh://git@ssh.github.com:443/acme/launcher.git", "acme"),
            ("https://github.com/platform-org/engine.git", "platform-org"),
            ("git@github.com:alice/better-plan.git", "alice"),
        ];
        for (remote, expected) in cases {
            assert_eq!(
                parse_owner(remote).as_deref(),
                Some(expected),
                "remote: {remote}"
            );
        }
    }

    #[test]
    fn refuses_to_guess_an_owner_from_an_ambiguous_remote() {
        // No repository component: not an owner/repo pair.
        assert_eq!(parse_owner("https://github.com/acme"), None);
        assert_eq!(parse_owner("git@github.com:acme"), None);
        assert_eq!(parse_owner(""), None);
        assert_eq!(parse_owner("not-a-remote"), None);
    }

    #[test]
    fn slug_is_owner_slash_repo() {
        assert_eq!(
            repo_for("git@github.com-acme:acme/launcher.git").slug().as_deref(),
            Some("acme/launcher")
        );
        assert_eq!(
            repo_for("https://github.com/platform-org/engine.git").slug().as_deref(),
            Some("platform-org/engine")
        );
        assert_eq!(repo_for("https://github.com/acme").slug(), None);
    }
}
