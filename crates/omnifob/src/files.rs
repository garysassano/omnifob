//! Files fob writes outside its state directory: the omnifob config and the
//! AWS config.

use anyhow::Context;

pub(crate) fn aws_config_file(
    file: Option<std::path::PathBuf>,
) -> anyhow::Result<std::path::PathBuf> {
    file.or_else(|| std::env::var_os("AWS_CONFIG_FILE").map(Into::into))
        .or_else(|| std::env::home_dir().map(|h| h.join(".aws/config")))
        .context("cannot find the AWS config file; pass --file")
}

/// Replaces `path` with `contents` through a temporary file in the same
/// directory and a rename, so a reader never sees half a file and a failed
/// write leaves the old one. An existing file keeps its permissions, a new
/// one is readable by its owner only on Unix (as botocore creates the AWS
/// config), and a symbolic link (a dotfiles manager's) stays a link: its
/// target is replaced. The temporary file is created anew, never opened
/// through a link left in its place.
pub(crate) fn write_atomically(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let target = match std::fs::canonicalize(path) {
        Ok(target) => target,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let dir = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = target
        .file_name()
        .with_context(|| format!("{} is not a file", path.display()))?
        .to_string_lossy();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp = dir.join(format!(
        ".{name}.omnifob-{}-{nonce}.tmp",
        std::process::id()
    ));
    let permissions = std::fs::metadata(&target).ok().map(|m| m.permissions());
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
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        #[cfg(not(unix))]
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&tmp, permissions)?;
        }
        std::fs::rename(&tmp, &target)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system's temporary directory.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("omnifob-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn atomic_writes_replace_the_file_and_leave_nothing_behind() {
        let dir = scratch("atomic");
        let path = dir.join("aws").join("config");
        write_atomically(&path, "first\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");
        write_atomically(&path, "second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        assert_eq!(entries(&dir.join("aws")), ["config"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_keep_permissions_and_symbolic_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("atomic-unix");
        let real = dir.join("dotfiles-config");
        std::fs::write(&real, "old\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
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
        let mode = std::fs::metadata(&real).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(entries(&dir), ["config", "dotfiles-config"]);

        // A new file is the owner's only.
        let fresh = dir.join("fresh");
        write_atomically(&fresh, "x\n").unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
