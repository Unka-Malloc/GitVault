//! A file that deletes itself, on success or on any early return.
//!
//! `ssh-keygen` and the askpass helper both need a filesystem path, so a secret
//! has to touch the disk briefly. Two properties bound that exposure: the file
//! is created atomically at its final mode (`O_EXCL`, so nothing else could
//! have planted the predictable name first), and the deletion is guaranteed by
//! Drop rather than by a call an error path could skip.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub struct TempSecret {
    path: PathBuf,
}

/// The boundary git reports for `probe`: the worktree top-level and the git
/// common directory, canonicalized. A probe outside any checkout has no
/// boundary; a git answer that cannot be produced at all fails closed rather
/// than let a scratch root land in an unmeasured tree.
fn checkout_boundary(probe: &Path, flag: &str) -> Result<Option<PathBuf>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(probe)
        .args(["rev-parse", flag])
        .output()
        .with_context(|| format!("git rev-parse {flag} could not run"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not a git repository") || stderr.contains("work tree") {
            return Ok(None);
        }
        anyhow::bail!(
            "git rev-parse {flag} failed at {}: {}",
            probe.display(),
            stderr.trim()
        );
    }
    let reported = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if reported.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(&reported);
    let path = if path.is_absolute() {
        path
    } else {
        probe.join(path)
    };
    path.canonicalize()
        .map(Some)
        .with_context(|| format!("git rev-parse {flag} resolved to an unreadable path {reported}"))
}

/// The private scratch root every secret file lives under: the account's state
/// directory, never `std::env::temp_dir()`. TMPDIR is caller-controlled and can
/// point inside a checkout, which would put key material in the reviewed tree
/// where abnormal termination or a broad `git add` could publish it.
///
/// `probe` is where the reviewed checkout is discovered: the repository root
/// when the caller knows it, otherwise the process's own directory. The root
/// is refused when it resolves inside the checkout's worktree or git common
/// directory - an account home planted under a worktree root must not defeat
/// the boundary from a nested invocation directory either.
pub(crate) fn private_temp_root() -> Result<PathBuf> {
    private_temp_root_at(None)
}

/// `repo` names the checkout whose boundary matters - the repository under
/// review when the caller has one, or `None` to probe the process's own
/// directory.
pub(crate) fn private_temp_root_at(repo: Option<&Path>) -> Result<PathBuf> {
    let probe = match repo {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .context("cannot resolve the process directory for the scratch boundary")?,
    };
    scratch_root(&crate::configsig::account_home()?, &probe)
}

fn scratch_root(home: &Path, probe: &Path) -> Result<PathBuf> {
    let root = home.join(".local/state/gitvault/tmp");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&root)
        .with_context(|| format!("cannot create the secret scratch root {}", root.display()))?;
    let root = root
        .canonicalize()
        .with_context(|| format!("cannot resolve the secret scratch root {}", root.display()))?;
    for flag in ["--show-toplevel", "--git-common-dir"] {
        if let Some(boundary) = checkout_boundary(probe, flag)? {
            anyhow::ensure!(
                !root.starts_with(&boundary),
                "the secret scratch root {} resolves inside the checkout boundary {} - refusing",
                root.display(),
                boundary.display()
            );
        }
    }
    Ok(root)
}

impl TempSecret {
    /// Create a uniquely named file under the private scratch root,
    /// atomically, at `mode`.
    ///
    /// `create_new` makes this fail rather than follow a planted symlink or
    /// inherit a pre-created file's permissions: a same-user attacker who raced
    /// the name ahead of us gets an error, not our contents.
    pub fn write(contents: &str, mode: u32) -> Result<Self> {
        let path = private_temp_root()?.join(format!(
            "gitvault-secret-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        use std::io::Write;
        if let Err(why) = opts
            .open(&path)
            .and_then(|mut f| f.write_all(contents.as_bytes()))
        {
            // A failed write must not leave a partial secret on disk: the
            // name is gone before the error surfaces.
            let _ = std::fs::remove_file(&path);
            return Err(why).with_context(|| format!("could not create {}", path.display()));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempSecret {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A scratch root planted under the worktree root must refuse even when
    /// the probe runs from a nested directory: cwd alone is not the boundary.
    /// A home outside the checkout remains usable.
    #[test]
    fn a_scratch_root_inside_the_reviewed_checkout_refuses() {
        let base = std::env::temp_dir().join(format!(
            "gv-scratch-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        let nested = repo.join("deep/down");
        std::fs::create_dir_all(&nested).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join("a"), "a").unwrap();
        git(&repo, &["add", "a"]);
        git(&repo, &["commit", "-qm", "a"]);

        // HOME at the worktree root, invoked from a nested directory: the
        // scratch root would land inside the reviewed tree, so it refuses.
        let refused = scratch_root(&repo, &nested);
        assert!(refused.is_err(), "an in-checkout scratch root must refuse");

        // HOME outside the checkout probes cleanly.
        let outside = base.join("home");
        let root = scratch_root(&outside, &nested).unwrap();
        assert!(root.starts_with(outside.canonicalize().unwrap()));

        let _ = std::fs::remove_dir_all(&base);
    }
}
