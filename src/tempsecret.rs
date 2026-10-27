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

/// The private scratch root every secret file lives under: the account's state
/// directory, never `std::env::temp_dir()`. TMPDIR is caller-controlled and can
/// point inside a checkout, which would put key material in the reviewed tree
/// where abnormal termination or a broad `git add` could publish it. The root
/// is also verified not to resolve inside the current working tree - a HOME
/// redirected into a checkout must not quietly defeat the boundary either.
pub(crate) fn private_temp_root() -> Result<PathBuf> {
    let root = crate::configsig::account_home()?.join(".local/state/gitvault/tmp");
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
    if let Ok(cwd) = std::env::current_dir().and_then(|c| c.canonicalize())
        && root.starts_with(&cwd)
    {
        anyhow::bail!(
            "the secret scratch root {} resolves inside the working tree {} - refusing",
            root.display(),
            cwd.display()
        );
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
