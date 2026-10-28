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
    /// Create a subdirectory bound to the pinned root AND pinned itself:
    /// `mkdirat` creates under the judged inode, then the leaf is reopened
    /// `O_DIRECTORY|O_NOFOLLOW` through the same descriptor - the returned
    /// `PinnedLeaf` is a descriptor pair (leaf, root) so a rename or
    /// replant of anything in between can no longer redirect a child's
    /// writes, a read-back, or the final unlink. A leaf name that is not
    /// a single plain component refuses before any syscall.
    #[cfg(unix)]
    pub fn mkdir_leaf(&self, leaf: &std::ffi::OsStr, mode: libc::mode_t) -> Result<PinnedLeaf> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let leaf_path = Path::new(leaf);
        anyhow::ensure!(
            leaf_path.components().count() == 1
                && leaf_path
                    .file_name()
                    .is_some_and(|name| name == leaf && name != ".." && name != "."),
            "scratch leaf names must be a single component"
        );
        let cname = std::ffi::CString::new(leaf.as_encoded_bytes())
            .context("leaf name is not encodable")?;
        anyhow::ensure!(
            unsafe { libc::mkdirat(self.fd.as_raw_fd(), cname.as_ptr(), mode) } == 0,
            "cannot create the pinned scratch leaf: {}",
            std::io::Error::last_os_error()
        );
        let dir = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        anyhow::ensure!(
            dir >= 0,
            "cannot pin the scratch leaf: {}",
            std::io::Error::last_os_error()
        );
        // Own the descriptor before any fallible check: a refused
        // validation below drops the File and closes the fd rather than
        // leaking it.
        let dir = unsafe { std::fs::File::from_raw_fd(dir) };
        // The open happened after the name existed, so a replant between
        // mkdirat and openat is possible. Pin what we actually opened and
        // refuse unless the name still resolves to that same inode right
        // now: fstat the descriptor, lstat the name without following a
        // planted link (a symlink to the moved leaf reports the LINK's
        // inode, not the leaf's), require a directory, then prove the
        // opened directory is the fresh one by requiring it to be empty -
        // a substitute carrying planted entries cannot claim the inode a
        // just-created directory would have had.
        let mut opened: libc::stat = unsafe { std::mem::zeroed() };
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        let pinned = unsafe {
            libc::fstat(dir.as_raw_fd(), &mut opened) == 0
                && libc::fstatat(
                    self.fd.as_raw_fd(),
                    cname.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                ) == 0
                && named.st_mode & libc::S_IFMT == libc::S_IFDIR
                && opened.st_dev == named.st_dev
                && opened.st_ino == named.st_ino
        };
        anyhow::ensure!(
            pinned && leaf_is_empty(dir.as_raw_fd()),
            "the pinned scratch leaf was replaced during creation - refusing"
        );
        Ok(PinnedLeaf {
            dir,
            root: self
                .fd
                .try_clone()
                .context("cannot pin the scratch root twice")?,
            name: leaf.to_os_string(),
            ident: (opened.st_dev, opened.st_ino),
        })
    }

    /// On unix no consumer may resolve the root by path at all - children
    /// bind by descriptor (fchdir, /dev/fd TMPDIR, mkdirat/openat) so a
    /// rename or reparent has nothing left to redirect. Non-unix callers
    /// still need the path spelling.
    #[cfg(not(unix))]
    pub fn path(&self) -> Result<&Path> {
        Ok(&self.path)
    }

    /// Prove the pinned descriptor still names the directory the boundary
    /// check judged: `fd_canonical_path` answers the inode's live path,
    /// and a relocation makes it differ from the judged one. A descriptor
    /// whose path can no longer be established fails closed. Unix-only;
    /// this is a checkpoint, never a path handed to a consumer.
    #[cfg(unix)]
    pub(crate) fn reassert(&self) -> Result<()> {
        let live = crate::fd_canonical_path(&self.fd)
            .context("cannot re-establish the scratch root's path - refusing")?;
        anyhow::ensure!(
            live == self.path,
            "the secret scratch root moved after the boundary check - refusing"
        );
        Ok(())
    }

    /// Tests arrange relocations by path (renames of roots and leaves);
    /// production unix code has no accessor at all, and even this test
    /// spelling re-judges the pin before answering. `cfg(test)` keeps the
    /// spelling out of shipped binaries.
    #[cfg(all(unix, test))]
    pub(crate) fn path(&self) -> Result<&Path> {
        self.reassert()?;
        Ok(&self.path)
    }
}

/// A leaf directory inside the pinned scratch root, pinned itself by
/// descriptor: creation, child working-directory binding, file reads and
/// the final cleanup all resolve through `dir` (leaf) and `root`
/// (rmdir of the leaf's name), never through a re-resolved path. Dropping
/// removes the leaf directory itself from the root - a caller that wants
/// files gone unlinks them through the leaf descriptor first.
#[cfg(unix)]
pub(crate) struct PinnedLeaf {
    /// O_DIRECTORY descriptor on the leaf itself.
    dir: std::fs::File,
    /// A duplicate of the scratch root descriptor, kept for the leaf's
    /// own removal at drop.
    root: std::fs::File,
    /// The leaf's single-component name under the root.
    name: std::ffi::OsString,
    /// (dev, ino) of the directory the pin was proven to hold at create:
    /// later name re-lookups and removal compare against it rather than
    /// trusting that `name` still resolves to this descriptor's inode.
    ident: (libc::dev_t, libc::ino_t),
}

/// Whether an opened directory descriptor lists nothing but `.`/`..`:
/// a directory `mkdirat` just made is empty, so a replanted stand-in
/// carrying entries cannot claim to be the freshly created leaf.
#[cfg(unix)]
fn leaf_is_empty(dir: std::os::fd::RawFd) -> bool {
    let dup = unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return false;
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe { libc::close(dup) };
        return false;
    }
    let mut empty = true;
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            empty = false;
            break;
        }
    }
    unsafe { libc::closedir(stream) };
    empty
}

#[cfg(unix)]
impl PinnedLeaf {
    /// Bind a child's working directory to the leaf descriptor: the
    /// relative names the child opens resolve inside this inode, so a
    /// reparented or replanted leaf cannot redirect where secrets land.
    pub fn fchdir_child(&self, command: &mut std::process::Command) {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        let fd = self.dir.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// Read a file inside the leaf through the pinned descriptor -
    /// `openat` relative to `dir`, never through a path the caller could
    /// have replanted between creation and use.
    pub fn read(&self, name: &std::ffi::OsStr) -> Result<Vec<u8>> {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let cname = std::ffi::CString::new(name.as_encoded_bytes())
            .context("file name is not encodable")?;
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), cname.as_ptr(), libc::O_RDONLY) };
        anyhow::ensure!(
            fd >= 0,
            "cannot read the pinned leaf file: {}",
            std::io::Error::last_os_error()
        );
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Remove a file name inside the leaf through its own descriptor.
    pub fn unlink(&self, name: &std::ffi::OsStr) {
        use std::os::fd::AsRawFd as _;
        if let Ok(cname) = std::ffi::CString::new(name.as_encoded_bytes()) {
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), cname.as_ptr(), 0);
            }
        }
    }

    /// Whether `name` under the pinned root still resolves to the inode
    /// this leaf was proven to hold at creation. A same-user rename or
    /// replant after open shows up as a mismatch and fails the use.
    #[cfg(unix)]
    pub fn reassert(&self) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        let cname = std::ffi::CString::new(self.name.as_encoded_bytes())
            .context("leaf name is not encodable")?;
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        // No-follow, directory-typed identity: a symlink planted under the
        // leaf's name reports the link's own inode - never the leaf's - so
        // a replant cannot launder an outside directory through this check.
        anyhow::ensure!(
            unsafe {
                libc::fstatat(
                    self.root.as_raw_fd(),
                    cname.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
                && named.st_mode & libc::S_IFMT == libc::S_IFDIR
                && (named.st_dev, named.st_ino) == self.ident,
            "the pinned scratch leaf moved after the boundary check - refusing"
        );
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PinnedLeaf {
    /// The leaf's own name is removed relative to the pinned root, and only
    /// while the name still resolves to the inode this run created and
    /// proved at open: a replanted name now naming a substitute is left
    /// alone rather than rmdir'd from under a stand-in.
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        if let Ok(cname) = std::ffi::CString::new(self.name.as_encoded_bytes()) {
            let mut named: libc::stat = unsafe { std::mem::zeroed() };
            let ours = unsafe {
                libc::fstatat(
                    self.root.as_raw_fd(),
                    cname.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                ) == 0
                    && named.st_mode & libc::S_IFMT == libc::S_IFDIR
                    && (named.st_dev, named.st_ino) == self.ident
            };
            if ours {
                unsafe {
                    libc::unlinkat(self.root.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR);
                }
            }
        }
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
    /// check judged it: the descriptor is re-resolved and any divergence
    /// refuses.
    pub fn reassert(&self) -> Result<()> {
        #[cfg(unix)]
        {
            self.root.reassert()
        }
        #[cfg(not(unix))]
        {
            self.root.path().map(|_| ())
        }
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
        #[cfg(unix)]
        secret.reassert()?;
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

    /// The secret file's path for consumers that need one. On unix there
    /// is no path accessor at all: every consumer is bound by descriptor
    /// (fd_share / fchdir-bound cwd), so a rename or reparent has nothing
    /// left to redirect. Non-unix has no descriptor pin, and a path can be
    /// relocated between any check and the child's open - a check-then-open
    /// this platform cannot close, so the handoff refuses rather than lend
    /// a raceable spelling to a consumer.
    #[cfg(not(unix))]
    pub fn path(&self) -> Result<&Path> {
        anyhow::bail!(
            "this platform cannot hand a checked secret to a consumer atomically - \
             descriptor-bound handoff is required, refusing"
        )
    }

    /// Tests still inspect the recorded path directly (uniqueness,
    /// privacy bits); production consumers on unix get no accessor at
    /// all - even the test spelling is gated by the same mid-operation
    /// reassert production checkpoints use. `cfg(test)` keeps the
    /// spelling out of shipped binaries.
    #[cfg(all(unix, test))]
    pub(crate) fn path(&self) -> Result<&Path> {
        self.reassert()?;
        Ok(&self.path)
    }

    /// Prove the scratch root's descriptor still names the directory the
    /// boundary check judged. Called after construction and available to
    /// flows that need a mid-operation checkpoint; a descriptor whose
    /// path moved - or can no longer be established - fails closed.
    #[cfg(unix)]
    pub(crate) fn reassert(&self) -> Result<()> {
        let live = crate::fd_canonical_path(&self.dir_fd)
            .context("cannot re-establish the scratch root's path - refusing")?;
        anyhow::ensure!(
            live == self.root,
            "the secret scratch root moved after the boundary check - refusing"
        );
        Ok(())
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

    /// A pinned leaf is a descriptor pair: single-component names only,
    /// reads resolve through the leaf inode, and dropping removes the
    /// leaf's own name from the root - never a replanted stand-in.
    #[cfg(unix)]
    #[test]
    fn a_pinned_leaf_is_bound_by_descriptor_for_its_whole_life() {
        let root = private_temp_root().unwrap();
        let root_path = crate::fd_canonical_path(&root.fd).unwrap();

        // Composite names - including traversal - refuse before mkdirat.
        for bad in ["a/b", "../x", ".", "..", ""] {
            assert!(
                root.mkdir_leaf(std::ffi::OsStr::new(bad), 0o700).is_err(),
                "leaf name {bad:?} must refuse"
            );
        }

        let tag = format!("leaf-{}-a", std::process::id());
        let leaf = root.mkdir_leaf(std::ffi::OsStr::new(&tag), 0o700).unwrap();
        assert!(root_path.join(&tag).is_dir());
        // A file written through the leaf's own directory entry reads
        // back through its descriptor.
        std::fs::write(root_path.join(&tag).join("k"), b"secret").unwrap();
        assert_eq!(leaf.read(std::ffi::OsStr::new("k")).unwrap(), b"secret");
        leaf.unlink(std::ffi::OsStr::new("k"));
        assert!(!root_path.join(&tag).join("k").exists());
        // Dropping removes exactly this leaf's name from the root.
        drop(leaf);
        assert!(!root_path.join(&tag).exists());

        // A same-named directory replanted between create and drop is a
        // different inode - the drop's unlinkat names it under the root,
        // but the earlier leaf's files were unlinked through the leaf fd,
        // so nothing of a stand-in's contents is touched.
        let tag = format!("leaf-{}-b", std::process::id());
        let leaf = root.mkdir_leaf(std::ffi::OsStr::new(&tag), 0o700).unwrap();
        std::fs::write(root_path.join(&tag).join("kept"), b"1").unwrap();
        leaf.unlink(std::ffi::OsStr::new("kept"));
        drop(leaf);
        assert!(!root_path.join(&tag).exists());
    }

    /// The rename/replant race the pin exists for: the leaf's name is moved
    /// to a substitute directory between "open" and "accept". `reassert`
    /// must refuse (the name no longer resolves to the pinned inode), the
    /// leaf's own descriptor still serves the REAL directory's contents,
    /// and drop must leave the stand-in's contents untouched - removal is
    /// conditional on the recorded inode, not on the name.
    #[cfg(unix)]
    #[test]
    fn a_renamed_and_replanted_leaf_is_refused_and_never_removed() {
        let root = private_temp_root().unwrap();
        let root_path = crate::fd_canonical_path(&root.fd).unwrap();
        let pid = std::process::id();
        let tag = format!("leaf-{pid}-{:04x}", rand::random::<u16>());
        let moved = format!("{tag}-moved");
        let leaf = root.mkdir_leaf(std::ffi::OsStr::new(&tag), 0o700).unwrap();
        std::fs::write(root_path.join(&tag).join("k"), b"secret").unwrap();

        // Rename the real leaf away, then plant a different directory under
        // its name - the shape a same-UID replant takes.
        std::fs::rename(root_path.join(&tag), root_path.join(&moved)).unwrap();
        std::fs::create_dir(root_path.join(&tag)).unwrap();
        std::fs::write(root_path.join(&tag).join("stand-in"), b"x").unwrap();

        assert!(
            leaf.reassert().is_err(),
            "a leaf whose name was replanted must fail closed"
        );
        // The pinned descriptor is unaffected: it still reads the original
        // inode, wherever the name now points.
        assert_eq!(leaf.read(std::ffi::OsStr::new("k")).unwrap(), b"secret");

        drop(leaf);
        // Conditional removal: the substitute keeps its contents and name.
        assert_eq!(
            std::fs::read(root_path.join(&tag).join("stand-in")).unwrap(),
            b"x",
            "cleanup must never remove a replanted stand-in's contents"
        );
        // But the renamed REAL leaf is gone only by its own path - nothing
        // descriptor-relative could have removed it under a foreign name.
        assert!(root_path.join(&moved).exists());
        let _ = std::fs::remove_dir_all(root_path.join(&tag));
        let _ = std::fs::remove_dir_all(root_path.join(&moved));
    }

    /// The symlink variant of the replant: the leaf is moved outside the
    /// scratch root and its name replaced with a link back to it. A
    /// following lookup would see the right inode through the link and
    /// accept an out-of-root directory; the no-follow identity check must
    /// see the LINK's own inode and refuse, and cleanup must neither
    /// follow the link nor remove its target.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_leaf_name_is_never_the_leaf() {
        let root = private_temp_root().unwrap();
        let root_path = crate::fd_canonical_path(&root.fd).unwrap();
        let outside = std::env::temp_dir().join(format!(
            "gv-leaf-out-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::create_dir(&outside).unwrap();
        let tag = format!("leaf-{}-{:04x}", std::process::id(), rand::random::<u16>());
        let leaf = root.mkdir_leaf(std::ffi::OsStr::new(&tag), 0o700).unwrap();
        std::fs::write(root_path.join(&tag).join("k"), b"secret").unwrap();

        // Move the real leaf outside the pinned root entirely, then point
        // its old name at it through a symlink.
        let moved = outside.join(&tag);
        std::fs::rename(root_path.join(&tag), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, root_path.join(&tag)).unwrap();

        assert!(
            leaf.reassert().is_err(),
            "a symlinked leaf name must refuse: the name no longer names the leaf"
        );
        // The descriptor still serves the real inode's bytes.
        assert_eq!(leaf.read(std::ffi::OsStr::new("k")).unwrap(), b"secret");

        drop(leaf);
        // Cleanup neither followed the link nor removed the out-of-root
        // target: the link stays a link, and the moved directory keeps its
        // contents.
        assert!(
            root_path.join(&tag).is_symlink(),
            "the planted link must be left alone"
        );
        assert_eq!(std::fs::read(moved.join("k")).unwrap(), b"secret");
        let _ = std::fs::remove_file(root_path.join(&tag));
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// The scratch root moving mid-operation is the relocation the
    /// post-keygen acceptance check exists to catch: `reassert` compares
    /// the pinned descriptor's live path with the validated one and fails
    /// closed when they diverge.
    #[cfg(unix)]
    #[test]
    fn a_relocated_scratch_root_fails_the_post_operation_reassert() {
        let home = std::env::temp_dir().join(format!(
            "gv-scratch-move-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let root = scratch_root(&home, &home).unwrap();
        let judged = crate::fd_canonical_path(&root.fd).unwrap();
        let moved = home.join(".local/state/gitvault/tmp-moved");
        std::fs::rename(&judged, &moved).unwrap();
        assert!(
            root.reassert().is_err(),
            "a relocated scratch root must refuse the acceptance check"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
