//! Files on disk: names derived from keychain keys, atomic writes, and the
//! private directories omnifob keeps its state in.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;

/// A file name for a key (a keychain key, a lock name, a profile id): every
/// byte outside `[A-Za-z0-9._-]` is written as `%XX`, and so is a leading
/// `.`, so `aws-sso/acme/token` is `aws-sso%2Facme%2Ftoken`. Distinct keys
/// always get distinct names, and a name is never `.`, `..` or hidden.
pub fn encode_key_filename(key: &str) -> String {
    let mut name = String::with_capacity(key.len());
    for (i, b) in key.bytes().enumerate() {
        let leading_dot = i == 0 && b == b'.';
        if !leading_dot && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) {
            name.push(b as char);
        } else {
            name.push_str(&format!("%{b:02X}"));
        }
    }
    name
}

/// Creates `dir` and any missing parents readable by their owner only on
/// Unix (`0700`), and narrows `dir` to `0700` if it exists more widely
/// open. For directories omnifob owns, such as the state directory; on
/// other platforms it does nothing more than `create_dir_all`.
pub fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .permissions()
            .mode();
        // Best effort: a directory someone else owns stays as it is.
        if mode & 0o077 != 0
            && let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        {
            tracing::warn!("could not make {} private: {e}", dir.display());
        }
    }
    Ok(())
}

/// Replaces `path` with `contents` through a temporary file in the same
/// directory and a rename, so a reader never sees half a file and a failed
/// write leaves the old one. An existing file keeps its permissions, a new
/// one is readable by its owner only on Unix (as botocore creates the AWS
/// config), and a symbolic link (a dotfiles manager's) stays a link: its
/// target is replaced. A missing directory is created with the default
/// permissions. For files the user owns, such as the omnifob and AWS
/// configs; omnifob's own state goes through [`write_private`].
pub fn write_atomically(path: &Path, contents: impl AsRef<[u8]>) -> anyhow::Result<()> {
    write(path, contents.as_ref(), Access::Keep)
}

/// Like [`write_atomically`], for omnifob's own state and secrets: the file
/// is readable by its owner only on Unix, from its creation and whatever it
/// was before, and its directory is made private with
/// [`create_private_dir`].
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> anyhow::Result<()> {
    write(path, contents.as_ref(), Access::Private)
}

#[derive(Clone, Copy, PartialEq)]
enum Access {
    /// An existing file's permissions, else the owner's only.
    Keep,
    /// The owner's only.
    Private,
}

fn write(path: &Path, contents: &[u8], access: Access) -> anyhow::Result<()> {
    let target = match std::fs::canonicalize(path) {
        Ok(target) => target,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let dir = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    match access {
        Access::Keep => {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?
        }
        Access::Private => create_private_dir(&dir)?,
    }
    let name = target
        .file_name()
        .with_context(|| format!("{} is not a file", path.display()))?
        .to_string_lossy();
    // Unique within this process, and the process id across them; the file
    // is created anew, never opened through a link left in its place.
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let n = WRITES.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.omnifob-{}-{n}.tmp", std::process::id()));
    let permissions = match access {
        Access::Keep => std::fs::metadata(&target).ok().map(|m| m.permissions()),
        Access::Private => None,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let written = (|| {
        // Before the contents on Unix, so they are never readable more widely
        // than the file they replace.
        #[cfg(unix)]
        if let Some(permissions) = &permissions {
            file.set_permissions(permissions.clone())?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        #[cfg(not(unix))]
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&tmp, permissions)?;
        }
        retry_busy(|| std::fs::rename(&tmp, &target))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

/// How often a file operation that a busy file can refuse is tried. On
/// Windows, a file another process is replacing, or that an antivirus or
/// indexer holds open, can refuse to be opened or replaced for a moment
/// ("Access is denied"), so two `fob` processes writing the same state at
/// once would otherwise fail. Elsewhere such a failure is final.
const BUSY_ATTEMPTS: u32 = if cfg!(windows) { 10 } else { 1 };
const BUSY_PAUSE: Duration = Duration::from_millis(50);

/// Runs `io`, trying again on Windows while it fails with anything but
/// `NotFound`, for up to half a second. [`write_atomically`] and
/// [`write_private`] replace their file through it; use it for reads of a
/// file other processes replace.
pub fn retry_busy<T>(io: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    retry(BUSY_ATTEMPTS, BUSY_PAUSE, io)
}

fn retry<T>(
    attempts: u32,
    pause: Duration,
    mut io: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut attempt = 1;
    loop {
        match io() {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound && attempt < attempts => {
                tracing::debug!("file busy ({e}); trying again");
                attempt += 1;
                std::thread::sleep(pause);
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system's temporary directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omnifob-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn key_file_names_are_distinct_and_safe() {
        assert_eq!(
            encode_key_filename("aws-sso/acme/token"),
            "aws-sso%2Facme%2Ftoken"
        );
        assert_eq!(encode_key_filename("a-b_c.d"), "a-b_c.d");
        // `_` once stood for every other character, so these shared a file.
        assert_ne!(
            encode_key_filename("a/b_c/d"),
            encode_key_filename("a/b/c_d")
        );
        assert_eq!(encode_key_filename("a b%"), "a%20b%25");
        assert_eq!(encode_key_filename("é"), "%C3%A9");
        assert_eq!(encode_key_filename("."), "%2E");
        assert_eq!(encode_key_filename(".."), "%2E.");
        assert_eq!(encode_key_filename(".hidden"), "%2Ehidden");
        assert_eq!(encode_key_filename("x.y."), "x.y.");
    }

    #[test]
    fn busy_files_are_tried_again_but_missing_ones_are_not() {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let mut calls = 0;
        let result = retry(3, Duration::ZERO, || {
            calls += 1;
            if calls < 3 { Err(denied()) } else { Ok(calls) }
        });
        assert_eq!(result.unwrap(), 3);

        let mut calls = 0;
        let result: std::io::Result<()> = retry(3, Duration::ZERO, || {
            calls += 1;
            Err(denied())
        });
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(calls, 3);

        let mut calls = 0;
        let result: std::io::Result<()> = retry(3, Duration::ZERO, || {
            calls += 1;
            Err(std::io::ErrorKind::NotFound.into())
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn atomic_writes_replace_the_file_and_leave_nothing_behind() {
        let dir = scratch("atomic");
        let path = dir.join("aws").join("config");
        write_atomically(&path, "first\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");
        write_atomically(&path, "second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        write_private(&path, b"third\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third\n");
        assert_eq!(entries(&dir.join("aws")), ["config"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Unix only: on Windows eight threads replacing one file can keep it
    // busy for longer than the writer's retries wait, which would make this
    // test flaky.
    #[cfg(unix)]
    #[test]
    fn concurrent_writes_never_share_a_temporary_file() {
        let dir = scratch("concurrent");
        let path = dir.join("state.json");
        std::thread::scope(|s| {
            for t in 0..8 {
                let path = &path;
                s.spawn(move || {
                    for i in 0..25 {
                        write_private(path, format!("{t}-{i}")).unwrap();
                    }
                });
            }
        });
        let last = std::fs::read_to_string(&path).unwrap();
        assert!(last.ends_with("-24"), "{last}");
        assert_eq!(entries(&dir), ["state.json"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_keep_permissions_and_symbolic_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("atomic-unix");
        let real = dir.join("dotfiles-config");
        std::fs::write(&real, "old\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.join("config");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomically(&link, "new\n").unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new\n");
        assert_eq!(mode(&real), 0o640);
        assert_eq!(entries(&dir), ["config", "dotfiles-config"]);

        // A new file is the owner's only.
        let fresh = dir.join("fresh");
        write_atomically(&fresh, "x\n").unwrap();
        assert_eq!(mode(&fresh), 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_writes_make_the_file_and_its_directory_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("private");

        // A new directory, and the missing ones above it, are private.
        let path = root.join("state").join("vault").join("key.dpapi");
        write_private(&path, "sealed").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&root.join("state")), 0o700);
        assert_eq!(mode(&root.join("state").join("vault")), 0o700);

        // A file and directory left readable by others are narrowed.
        let wide = root.join("wide");
        std::fs::create_dir(&wide).unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = wide.join("profiles.json");
        std::fs::write(&file, "{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&file, "{\"a\":1}").unwrap();
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&wide), 0o700);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"a\":1}");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
