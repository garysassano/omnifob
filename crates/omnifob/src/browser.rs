//! Opening sign-in and console URLs in the browser an integration names.

use std::process::{Command, Stdio};

use anyhow::Context;
use omnifob_core::{Config, Profile};

/// Opens `url` in the browser that integration `name` names in `[browsers]`,
/// or in the system's default browser.
pub(crate) fn open(config: &Config, name: &str, url: &str) -> anyhow::Result<()> {
    match config.browser_for(name)? {
        Some(browser) => run(browser.command_for(url)?),
        None => open_default(url),
    }
}

/// Opens `url`, the console of `profile`, in its integration's browser,
/// isolated from other profiles' consoles as that browser's `isolate` says,
/// or in the system's default browser.
pub(crate) fn open_console(config: &Config, profile: &Profile, url: &str) -> anyhow::Result<()> {
    match config.browser_for(&profile.integration)? {
        Some(browser) => run(browser.console_command_for(url, profile)?),
        None => open_default(url),
    }
}

/// Opens `url` in the system's default browser without waiting for it. On
/// WSL without a Linux opener (`wslview`, `xdg-open`), Windows' default
/// browser opens it through `explorer.exe`, which takes the URL as one
/// argument (unlike `cmd.exe /c start`, which reads `&` as a command
/// separator).
fn open_default(url: &str) -> anyhow::Result<()> {
    match open::that_detached(url) {
        Ok(()) => Ok(()),
        Err(e) if omnifob_core::platform::is_wsl() => {
            tracing::debug!("no Linux browser opener ({e}); trying explorer.exe");
            run(("explorer.exe".to_string(), vec![url.to_string()]))
        }
        Err(e) => Err(e.into()),
    }
}

fn run((program, args): (String, Vec<String>)) -> anyhow::Result<()> {
    let mut command = Command::new(&program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // A browser that was not running yet stays up after fob exits, and
    // Ctrl-C at a sign-in prompt must not reach it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    command
        .spawn()
        .with_context(|| format!("running {program}"))?;
    Ok(())
}
