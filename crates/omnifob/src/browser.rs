//! Opening sign-in and console URLs in the browser an integration names.

use std::process::{Command, Stdio};

use anyhow::Context;
use omnifob_core::Config;

/// Opens `url` in the browser that integration `name` names in `[browsers]`,
/// or in the system's default browser.
pub(crate) fn open(config: &Config, name: &str, url: &str) -> anyhow::Result<()> {
    let Some(browser) = config.browser_for(name)? else {
        return Ok(open::that(url)?);
    };
    let (program, args) = browser.command_for(url);
    let mut command = Command::new(program);
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
