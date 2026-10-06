//! File locations. Like mise, omnifob uses XDG-style paths on every platform.

use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(fallback))
}

/// `$OMNIFOB_CONFIG`, else `$XDG_CONFIG_HOME/omnifob/config.toml`.
pub fn config_file() -> PathBuf {
    std::env::var_os("OMNIFOB_CONFIG")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| xdg("XDG_CONFIG_HOME", ".config").join("omnifob/config.toml"))
}

/// `$XDG_STATE_HOME/omnifob`: discovered profiles and other non-secret state.
pub fn state_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("omnifob")
}
