//! Facts about the machine omnifob runs on.

use std::sync::OnceLock;

/// Whether this is Linux under WSL, where Windows programs such as
/// `powershell.exe` can be run. WSL's kernel names Microsoft in
/// `/proc/version`; checked once per process.
pub fn is_wsl() -> bool {
    static WSL: OnceLock<bool> = OnceLock::new();
    *WSL.get_or_init(|| {
        cfg!(target_os = "linux")
            && std::fs::read_to_string("/proc/version")
                .is_ok_and(|v| v.to_lowercase().contains("microsoft"))
    })
}

/// Whether WSL can start Windows programs: its interop handler is registered
/// with `binfmt_misc` (`WSLInterop`, or `WSLInterop-late` on newer WSL) and
/// enabled. Reading the entry is much faster than starting `powershell.exe`
/// to find out.
pub fn wsl_interop() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc/sys/fs/binfmt_misc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("WSLInterop")
            && std::fs::read_to_string(entry.path())
                .is_ok_and(|status| status.lines().next() == Some("enabled"))
    })
}

/// Whether an executable file named `program` is in a `PATH` directory, as
/// the shell would find it, without running it.
pub fn on_path(program: &str) -> bool {
    find_on_path(program).is_some()
}

/// The executable file named `program` in the first `PATH` directory that
/// has one, as the shell would find it, without running it. Empty and
/// relative `PATH` entries, which the shell reads as the current directory,
/// are skipped, so nothing in the directory a command runs in is picked up;
/// on Windows, `PATHEXT`'s extensions are tried as `cmd.exe` tries them.
pub fn find_on_path(program: &str) -> Option<std::path::PathBuf> {
    if program.is_empty() || program.contains(['/', '\\']) {
        return None;
    }
    let path = std::env::var_os("PATH")?;
    let names = program_names(program);
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| is_executable(candidate))
}

#[cfg(windows)]
fn program_names(program: &str) -> Vec<String> {
    if std::path::Path::new(program).extension().is_some() {
        return vec![program.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{program}{}", ext.to_ascii_lowercase()))
        .collect()
}

#[cfg(not(windows))]
fn program_names(program: &str) -> Vec<String> {
    vec![program.to_string()]
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn programs_are_found_on_path_without_running_them() {
        // `sh` is on every Unix PATH the tests run with.
        assert!(on_path("sh"));
        assert!(!on_path("omnifob-no-such-program"));
        assert!(!on_path("."));
        // A path is not a program name to look up.
        assert!(!on_path("/bin/sh"));
        assert!(!on_path("bin/sh"));
        assert!(!on_path(""));
    }
}
