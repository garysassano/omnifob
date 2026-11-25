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
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| is_executable(&dir.join(program)))
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn programs_are_found_on_path_without_running_them() {
        // `sh` is on every Unix PATH the tests run with.
        assert!(on_path("sh"));
        assert!(!on_path("omnifob-no-such-program"));
        assert!(!on_path("."));
    }
}
