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
