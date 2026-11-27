//! File locations. Like mise, omnifob uses XDG-style paths on every platform.
//!
//! Without a home directory there is no default location: omnifob does not
//! fall back to the current directory, where it would write its state into
//! whatever repository the command runs in. The variables then have to name
//! the locations. A relative `HOME` counts as none, for the same reason.

use std::path::PathBuf;

use anyhow::Context;

/// `$<var>`, else `<home>/<fallback>`. A relative value is ignored, as
/// the XDG Base Directory spec asks, since it would put files wherever the
/// command happens to run.
fn xdg(var: &str, fallback: &str) -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(var).filter(|v| std::path::Path::new(v).is_absolute()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::home_dir()
        .filter(|home| home.is_absolute())
        .with_context(|| {
            format!("there is no home directory, so set {var} to say where omnifob keeps its files")
        })?;
    Ok(home.join(fallback))
}

/// The current [`Context`](crate::Context)'s config file.
pub fn config_file() -> anyhow::Result<PathBuf> {
    Ok(crate::Context::current().config_file()?.to_path_buf())
}

/// The current [`Context`](crate::Context)'s state directory.
pub fn state_dir() -> anyhow::Result<PathBuf> {
    Ok(crate::Context::current().state_dir()?.to_path_buf())
}

/// `$OMNIFOB_CONFIG`, else `$XDG_CONFIG_HOME/omnifob/config.toml`. Fails
/// when neither is set and there is no home directory.
pub fn standard_config_file() -> anyhow::Result<PathBuf> {
    if let Some(file) = std::env::var_os("OMNIFOB_CONFIG").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(file));
    }
    xdg("XDG_CONFIG_HOME", ".config")
        .map(|dir| dir.join("omnifob/config.toml"))
        .context("set OMNIFOB_CONFIG or XDG_CONFIG_HOME")
}

/// `$XDG_STATE_HOME/omnifob`: discovered profiles and other non-secret
/// state. Fails when the variable is unset and there is no home directory.
pub fn standard_state_dir() -> anyhow::Result<PathBuf> {
    Ok(xdg("XDG_STATE_HOME", ".local/state")?.join("omnifob"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables_name_the_locations() {
        // Only reads: other tests set these variables for their own scratch
        // directories, so this checks the values whatever they are.
        if let Some(config) = std::env::var_os("OMNIFOB_CONFIG").filter(|v| !v.is_empty()) {
            assert_eq!(standard_config_file().unwrap(), PathBuf::from(config));
        }
        if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            assert_eq!(
                standard_state_dir().unwrap(),
                PathBuf::from(state).join("omnifob")
            );
        }
        // Unset, the location is under the home directory, never relative.
        if let Ok(dir) = xdg("OMNIFOB_TEST_UNSET_VARIABLE", ".x") {
            assert!(
                dir.is_absolute() && dir.ends_with(".x"),
                "{}",
                dir.display()
            );
        }
    }
}
