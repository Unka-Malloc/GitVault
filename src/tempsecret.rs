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
    /// The pinned scratch-root descriptor and the file's name inside it:
    /// Drop's `unlinkat` removes the name from the directory the boundary
    /// check judged, wherever the scratch path happens to resolve by then.
    #[cfg(unix)]
    dir_fd: std::fs::File,
    #[cfg(unix)]
    name: std::ffi::OsString,
}

/// The boundaries `dir` can sit inside, discovered on the filesystem alone:
/// an ancestor containing `.git` - a directory or a `gitdir:` link file -
/// names a worktree top, and the gitdir it resolves to (plus a recorded
/// commondir) bounds the git side too. A directory that itself carries a
/// gitdir's shape - `HEAD`, `objects/`, `refs/` - is a bare repository and
/// bounds anything beneath it. No git child runs and no repository-
/// controlled configuration is consulted: a hostile `core.bare` or
/// `core.worktree` entry in `.git/config` changes nothing on disk, and an
/// unreadable or unparseable `.git` still counts as a boundary rather than
/// as proof that no worktree exists.
fn checkout_boundaries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut cursor = dir
        .canonicalize()
        .context("cannot resolve the checkout probe directory")?;
    let mut out = Vec::new();
    loop {
        let dotgit = cursor.join(".git");
        if dotgit.symlink_metadata().is_ok() {
            // Any `.git` entry makes `cursor` a worktree top - even one we
            // cannot read - so it bounds the scratch root by itself.
            out.push(cursor.clone());
            if let Some(gitdir) = resolve_gitdir(&dotgit, &cursor) {
                out.push(gitdir.clone());
                // A worktree .git file's gitdir records its common dir; the
                // shared object store bounds the same way.
                if let Ok(commondir) = std::fs::read_to_string(gitdir.join("commondir")) {
                    let shared = gitdir.join(commondir.trim());
                    if let Ok(shared) = shared.canonicalize() {
                        out.push(shared);
                    }
                }
            }
        } else if is_gitdir(&cursor) {
            out.push(cursor.clone());
        }
        if !cursor.pop() {
            break;
        }
    }
    Ok(out)
}

/// Where a `.git` entry points: a directory is the gitdir itself (a symlink
/// resolves through canonicalization), and a link file carries `gitdir: <p>`
/// relative to the worktree it sits beside. An entry that resolves nowhere
/// yields no gitdir boundary - the worktree top was already counted.
fn resolve_gitdir(dotgit: &Path, beside: &Path) -> Option<PathBuf> {
    if dotgit.is_dir() {
        return dotgit.canonicalize().ok();
    }
    let link = std::fs::read_to_string(dotgit).ok()?;
    let target = link.strip_prefix("gitdir:")?.trim();
    let resolved = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        beside.join(target)
    };
    resolved.canonicalize().ok()
}

/// A bare repository or gitdir carries this shape: `HEAD`, an `objects`
/// directory and a `refs` directory.
fn is_gitdir(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir()
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
/// The validated scratch root plus - on unix - the directory pinned open
/// on a descriptor: files are created relative to the descriptor, so a
/// same-user swap or rename of a path component after validation cannot
/// move a secret file somewhere the boundary never judged.
pub(crate) struct ScratchRoot {
    pub path: PathBuf,
    #[cfg(unix)]
    fd: std::fs::File,
}

pub(crate) fn private_temp_root_at(repo: Option<&Path>) -> Result<PathBuf> {
    Ok(private_scratch_at(repo)?.path)
}

/// `repo` names the checkout whose boundary matters - the repository under
/// review when the caller has one, or `None` to probe the process's own
/// directory.
pub(crate) fn private_scratch_at(repo: Option<&Path>) -> Result<ScratchRoot> {
    let probe = match repo {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .context("cannot resolve the process directory for the scratch boundary")?,
    };
    scratch_root(&crate::configsig::account_home()?, &probe)
}

fn scratch_root(home: &Path, probe: &Path) -> Result<ScratchRoot> {
    let root = home.join(".local/state/gitvault/tmp");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&root).with_context(|| {
        format!(
            "cannot create the secret scratch root {}",
            crate::records::redact(&root.display().to_string())
        )
    })?;
    let root = root.canonicalize().with_context(|| {
        format!(
            "cannot resolve the secret scratch root {}",
            crate::records::redact(&root.display().to_string())
        )
    })?;
    // Both the probe's checkout and the root's own hosting checkout bound
    // the root: an account home planted under ANY worktree puts secret
    // material in a tree some push can publish, whether or not it is the
    // repository under review right now. The boundaries come from the
    // filesystem alone - `.git` entries, gitdir links, bare-repository
    // shape - so hostile repository config cannot falsify them, and a probe
    // whose directory cannot be resolved fails closed above.
    for dir in [probe, root.as_path()] {
        for boundary in checkout_boundaries(dir)? {
            anyhow::ensure!(
                !root.starts_with(&boundary),
                "the secret scratch root {} resolves inside the checkout boundary {} - refusing",
                crate::records::redact(&root.display().to_string()),
                crate::records::redact(&boundary.display().to_string())
            );
        }
    }
    // Pin the validated root on a descriptor: a swap between the boundary
    // check and here makes the descriptor's own path differ from the one
    // that was judged, and the refusal lands instead of the pin.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let croot = std::ffi::CString::new(root.as_os_str().as_bytes())
            .context("the scratch root is not an encodable path")?;
        let fd = crate::open_pinned_dir(libc::AT_FDCWD, &croot).with_context(|| {
            format!(
                "cannot pin the scratch root {}",
                crate::records::redact(&root.display().to_string())
            )
        })?;
        anyhow::ensure!(
            crate::fd_canonical_path(&fd)? == root,
            "the scratch root pinned on a descriptor is not the validated \
             directory - the path was swapped; refusing"
        );
        Ok(ScratchRoot { path: root, fd })
    }
    #[cfg(not(unix))]
    Ok(ScratchRoot { path: root })
}

impl TempSecret {
    /// Create a uniquely named file under the pinned private scratch root,
    /// atomically, at `mode`.
    ///
    /// `O_EXCL` makes this fail rather than follow a planted symlink or
    /// inherit a pre-created file's permissions: a same-user attacker who raced
    /// the name ahead of us gets an error, not our contents. On unix the
    /// create is `openat` relative to the pinned root descriptor with
    /// `O_NOFOLLOW`, and Drop removes the name through `unlinkat` on that
    /// same descriptor - a rename of the scratch path after validation can
    /// neither redirect the create nor strand the file in a checkout.
    pub fn write(contents: &str, mode: u32) -> Result<Self> {
        let root = private_scratch_at(None)?;
        let name = std::ffi::OsString::from(format!(
            "gitvault-secret-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = root.path.join(&name);
        #[cfg(unix)]
        let written = {
            use std::io::Write as _;
            let cname = std::ffi::CString::new(name.as_encoded_bytes())
                .context("the secret file name is not encodable")?;
            crate::create_pinned_file(&root.fd, &cname, mode).and_then(|mut file| {
                file.write_all(contents.as_bytes())
                    .map(|_| file)
                    .map_err(anyhow::Error::from)
            })
        };
        #[cfg(not(unix))]
        let written = {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            opts.open(&path)
                .and_then(|mut f| f.write_all(contents.as_bytes()))
        };
        if let Err(why) = written {
            // A failed write must not leave a partial secret on disk: the
            // name is gone before the error surfaces.
            let _ = std::fs::remove_file(&path);
            return Err(why).with_context(|| format!("could not create {}", path.display()));
        }
        Ok(Self {
            path,
            #[cfg(unix)]
            dir_fd: root.fd,
            #[cfg(unix)]
            name,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempSecret {
    fn drop(&mut self) {
        // The descriptor-relative unlink removes the name from the inode the
        // boundary check judged, wherever the scratch path resolves now.
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            if let Ok(name) = std::ffi::CString::new(self.name.as_encoded_bytes()) {
                unsafe {
                    libc::unlinkat(self.dir_fd.as_raw_fd(), name.as_ptr(), 0);
                }
            }
        }
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
        assert!(root.path.starts_with(outside.canonicalize().unwrap()));

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Hostile repository-LOCAL config - `core.bare`/`core.worktree` in
    /// `.git/config` - must not change the reported boundary: discovery reads
    /// `.git` entries on disk, not configuration a repository controls. An
    /// account home under that checkout still refuses through scratch_root.
    #[test]
    fn hostile_local_git_config_cannot_hide_the_checkout_boundary() {
        let base = std::env::temp_dir().join(format!(
            "gv-scratch-cfg-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        let nested = repo.join("deep/down");
        std::fs::create_dir_all(&nested).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);

        // The repo claims to be bare and to serve a worktree far away; both
        // claims live only in .git/config and cannot move the disk boundary.
        let config = repo.join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("\tbare = true\n\tworktree = /nonexistent/elsewhere\n");
        std::fs::write(&config, text).unwrap();

        let boundaries = checkout_boundaries(&nested).unwrap();
        let top = repo.canonicalize().unwrap();
        assert!(
            boundaries.contains(&top),
            "the worktree boundary must be found without trusting config: {boundaries:?}"
        );
        assert!(
            scratch_root(&repo, &nested).is_err(),
            "a scratch root inside the checkout refuses despite hostile local config"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
