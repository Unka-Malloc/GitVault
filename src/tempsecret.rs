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
    /// The pinned scratch-root descriptor, the canonical root it validated
    /// against, and the file's name inside it: `path()` re-resolves the
    /// descriptor at every use so a relocated root refuses, and Drop's
    /// `unlinkat` removes the name from the directory the boundary check
    /// judged, wherever the scratch path happens to resolve by then.
    #[cfg(unix)]
    dir_fd: std::fs::File,
    /// The secret's own descriptor, kept open: `fd_share` duplicates it for
    /// a child so the consumer's open binds this file, not a re-resolvable
    /// name.
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(unix)]
    root: PathBuf,
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
/// The pinned scratch root for consumers that need a filesystem path:
/// the guard pins the directory on a descriptor and `path()` re-verifies
/// it at every use, so the validated root is never reduced to a bare
/// pathname that a same-user rename could move into a checkout.
pub(crate) fn private_temp_root() -> Result<ScratchRoot> {
    private_temp_root_at(None)
}

/// `repo` names the checkout whose boundary matters - the repository under
/// review when the caller has one, or `None` to probe the process's own
/// directory.
/// The validated scratch root plus - on unix - the directory pinned open
/// on a descriptor: files are created relative to the descriptor, and the
/// path is never reduced to a bare string - `path()` re-resolves the
/// descriptor at every use, so a same-user rename or reparenting between
/// the boundary check and a consumer's write is caught rather than letting
/// a moved root put secrets somewhere the boundary never judged.
pub(crate) struct ScratchRoot {
    path: PathBuf,
    #[cfg(unix)]
    fd: std::fs::File,
}

impl ScratchRoot {
    /// Bind a child's working directory to the pinned root: `fchdir` in
    /// the child's `pre_exec` makes this descriptor - not a path spelling -
    /// the lookup root, so a reparented scratch tree cannot redirect what
    /// the child creates or opens.
    #[cfg(unix)]
    pub fn fchdir_child(&self, command: &mut std::process::Command) {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        let fd = self.fd.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// Create a subdirectory relative to the pinned descriptor itself:
    /// `mkdirat` binds the create to the inode the boundary check judged,
    /// so no path component - swapped, moved or replanted - can redirect
    /// where the key directory lands.
    #[cfg(unix)]
    pub fn mkdir_pinned(&self, leaf: &std::ffi::OsStr, mode: libc::mode_t) -> Result<PathBuf> {
        use std::os::fd::AsRawFd as _;
        let cname = std::ffi::CString::new(leaf.as_encoded_bytes())
            .context("leaf name is not encodable")?;
        anyhow::ensure!(
            unsafe { libc::mkdirat(self.fd.as_raw_fd(), cname.as_ptr(), mode) } == 0,
            "cannot create the pinned scratch leaf: {}",
            std::io::Error::last_os_error()
        );
        Ok(self.path.join(leaf))
    }

    /// Remove a leaf created by `mkdir_pinned` along with the file names
    /// `keygen` leaves in it - each `unlinkat` resolves inside the pinned
    /// inode, so a reparented scratch root cannot redirect the delete to
    /// names outside it.
    #[cfg(unix)]
    pub fn remove_leaf_pinned(&self, leaf: &std::ffi::OsStr, files: &[&str]) {
        use std::os::fd::AsRawFd as _;
        for file in files {
            let composite = Path::new(leaf).join(file);
            if let Ok(name) = std::ffi::CString::new(composite.as_os_str().as_encoded_bytes()) {
                unsafe {
                    libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0);
                }
            }
        }
        if let Ok(name) = std::ffi::CString::new(leaf.as_encoded_bytes()) {
            unsafe {
                libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
    }

    /// The validated root's path - re-verified against the pinned
    /// descriptor on every call. A relocation after the boundary check
    /// makes the descriptor's live path differ from the one that was
    /// judged, and the consumer refuses instead of writing through a
    /// moved path. A descriptor whose path cannot be re-established fails
    /// closed.
    pub fn path(&self) -> Result<&Path> {
        #[cfg(unix)]
        {
            let live = crate::fd_canonical_path(&self.fd)
                .context("cannot re-establish the scratch root's path - refusing")?;
            anyhow::ensure!(
                live == self.path,
                "the secret scratch root moved after the boundary check - refusing"
            );
        }
        Ok(&self.path)
    }
}

/// A scratch root handed to a child process, kept alive for the child's
/// whole run: on unix the child does not get a re-resolved path at all -
/// its `TMPDIR` is `/dev/fd/N` over an inheritable duplicate of the pinned
/// descriptor, so the scratch space it writes into is the inode the
/// boundary check judged, whatever the path does meanwhile. `reassert`
/// after the child finishes catches a mid-run relocation: a moved root
/// cannot have been the judged directory, and the run's result is refused
/// rather than trusted.
pub(crate) struct ScratchShare {
    root: ScratchRoot,
    /// The plain (non-close-on-exec) duplicate the child inherits; it is
    /// closed when the share drops, after the spawn boundary is crossed.
    #[cfg(unix)]
    _shared: std::fs::File,
}

impl ScratchShare {
    /// Fail when the pinned directory is no longer where the boundary
    /// check judged it: `path()` re-resolves the descriptor and refuses
    /// on any divergence.
    pub fn reassert(&self) -> Result<()> {
        self.root.path().map(|_| ())
    }
}

/// Prepare the private scratch root for a child process: the share guard
/// pins the directory (and, on unix, an inheritable duplicate descriptor)
/// until it is dropped, and the returned path is what the child's TMPDIR
/// should hold - `/dev/fd/N` on unix, so scratch writes resolve through
/// the pinned inode rather than a path a same-user rename could have
/// moved into the checkout since validation.
pub(crate) fn scratch_for_child(repo: Option<&Path>) -> Result<(ScratchShare, PathBuf)> {
    let root = private_scratch_at(repo)?;
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let fd = unsafe { libc::fcntl(root.fd.as_raw_fd(), libc::F_DUPFD, 300) };
        anyhow::ensure!(fd >= 0, "cannot share the scratch root with the child");
        let shared = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok((
            ScratchShare {
                root,
                _shared: shared,
            },
            PathBuf::from(format!("/dev/fd/{fd}")),
        ))
    }
    #[cfg(not(unix))]
    {
        let path = root.path()?.to_path_buf();
        Ok((ScratchShare { root }, path))
    }
}

/// The pinned scratch root for callers whose consumers need a filesystem
/// path: keep the guard for the whole write/use lifetime and take `path()`
/// at each use boundary so a relocation is always caught.
pub(crate) fn private_temp_root_at(repo: Option<&Path>) -> Result<ScratchRoot> {
    private_scratch_at(repo)
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
    // Canonicalize after creation: the boundary judges the directory as it
    // exists, not the spelling the caller's environment happened to give.
    let root = std::fs::canonicalize(&root).with_context(|| {
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
        let file = match written {
            Ok(file) => file,
            Err(why) => {
                // A failed write must not leave a partial secret on disk:
                // the name is gone before the error surfaces.
                let _ = std::fs::remove_file(&path);
                return Err(why).with_context(|| format!("could not create {}", path.display()));
            }
        };
        let secret = Self {
            path,
            #[cfg(unix)]
            dir_fd: root.fd,
            #[cfg(unix)]
            file,
            #[cfg(unix)]
            root: root.path,
            #[cfg(unix)]
            name,
        };
        secret.path()?;
        Ok(secret)
    }

    /// A `/dev/fd/N` spelling of the secret for a consumer inside a spawned
    /// child: the returned descriptor is a duplicate of the secret's own
    /// open file, rewound to its start, and the caller clears its
    /// close-on-exec flag in the child's `pre_exec` so the reference rides
    /// the exec boundary. What the tool opens is this description itself -
    /// no directory component exists between the check and the open for a
    /// same-user process to reparent or swap.
    ///
    /// The returned `File` owns the descriptor and must outlive the spawn;
    /// the path is only valid while it (and this guard) live.
    #[cfg(unix)]
    pub fn fd_share(&self) -> Result<(PathBuf, std::fs::File)> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let fd = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
        anyhow::ensure!(
            fd >= 0,
            "cannot share the secret descriptor: {}",
            std::io::Error::last_os_error()
        );
        // The duplicate shares the description, offset included: the
        // consumer's first read must meet the bytes, not their end.
        anyhow::ensure!(
            unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0,
            "cannot rewind the shared secret descriptor: {}",
            std::io::Error::last_os_error()
        );
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok((PathBuf::from(format!("/dev/fd/{fd}")), file))
    }

    /// Bind a child's working directory to this secret's pinned scratch
    /// directory: `fchdir` in the child's `pre_exec` makes the descriptor -
    /// not a path spelling - the lookup root, so a same-user reparent of
    /// the scratch tree cannot redirect the consumer's opens. Pair with
    /// `name()` for consumers that resolve a relative file name (as
    /// `ssh-keygen -f` does with its `.pub` sibling convention). The
    /// unguessable name inside a directory only this account can enter is
    /// the remaining surface.
    #[cfg(unix)]
    pub fn fchdir_child(&self, command: &mut std::process::Command) {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        let fd = self.dir_fd.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// The secret's own file name, for a consumer whose working directory
    /// was pinned by `fchdir_child`: a relative name stays inside the
    /// descriptor-bound directory where a path could have been reparented.
    #[cfg(unix)]
    pub fn name(&self) -> &std::ffi::OsStr {
        &self.name
    }

    /// The secret file's path for consumers that need one - re-validated
    /// on every call: on unix the pinned scratch descriptor is resolved
    /// again and must still name the directory the boundary check judged.
    /// A same-user rename or reparenting between the write and this use
    /// makes the descriptor's live path differ, and the consumer refuses
    /// rather than hand a moved path to a tool that re-resolves it. A
    /// descriptor whose path can no longer be established fails closed.
    /// Children that open the secret themselves take `fd_share` instead:
    /// a description reference carries no re-resolvable name at all.
    pub fn path(&self) -> Result<&Path> {
        #[cfg(unix)]
        {
            let live = crate::fd_canonical_path(&self.dir_fd)
                .context("cannot re-establish the scratch root's path - refusing")?;
            anyhow::ensure!(
                live == self.root,
                "the secret scratch root moved after the boundary check - refusing"
            );
        }
        Ok(&self.path)
    }
}

/// Wire a shared descriptor into `command` so the spawned child can open
/// its `/dev/fd/N` reference: the flag comes off inside the child's own
/// `pre_exec` - after fork, before exec - which is also what lets a tool
/// the child in turn runs (an askpass helper under ssh-add) inherit it.
/// Call once per share; the owning `File` must outlive the spawn.
#[cfg(unix)]
pub fn share_with_child(command: &mut std::process::Command, share: &std::fs::File) {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let fd = share.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
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

    /// A descriptor share must serve the secret's own bytes at /dev/fd/N:
    /// the child's open binds the description, not a re-resolvable name.
    #[cfg(unix)]
    #[test]
    fn a_fd_share_serves_the_secret_through_dev_fd() {
        let secret = TempSecret::write("the-secret-material", 0o600).unwrap();
        let (fd_path, share) = secret.fd_share().unwrap();
        assert!(
            fd_path.starts_with("/dev/fd/"),
            "the share names a descriptor, not a path: {fd_path:?}"
        );
        use std::io::Read as _;
        let mut contents = String::new();
        std::fs::File::open(&fd_path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "the-secret-material");
        drop(share);
        assert!(
            std::fs::File::open(&fd_path).is_err(),
            "a dead share's reference must not resolve"
        );
    }
}
