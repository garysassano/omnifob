//! Background renewal: `fob renew`, which fob starts detached when cached
//! credentials near their end.

use omnifob_core::{providers, store};

use crate::App;

impl App {
    /// Fetches new credentials for a profile, unless another renewal of the
    /// same profile is already running. Never prompts.
    pub(crate) async fn renew(&self, id: &str) -> anyhow::Result<()> {
        let Some(profile) = self.cache.all().find(|p| p.id == id).cloned() else {
            return Ok(());
        };
        let Some(_lock) = RenewalLock::acquire(id)? else {
            return Ok(());
        };
        providers::credentials(&self.config, &profile, false, None).await?;
        Ok(())
    }
}

/// Starts `fob renew <profile>` detached from the terminal, so the next
/// command finds fresh credentials instead of waiting for them.
pub(crate) fn spawn_renewal(profile_id: &str) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["renew", profile_id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: Ctrl-C in the terminal does not reach it.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    match cmd.spawn() {
        Ok(_) => tracing::debug!("renewing {profile_id} in the background"),
        Err(e) => tracing::debug!("could not start a background renewal: {e}"),
    }
}

/// A lock file per profile so concurrent commands start one renewal only.
/// A lock older than two minutes is considered abandoned.
pub(crate) struct RenewalLock(std::path::PathBuf);

impl RenewalLock {
    fn acquire(profile_id: &str) -> anyhow::Result<Option<Self>> {
        let path = store::lock_dir()?.join(store::lock_file_name(&format!("renew-{profile_id}")));
        for _ in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Some(Self(path))),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let age = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok());
                    if age.is_some_and(|a| a < std::time::Duration::from_secs(120)) {
                        return Ok(None);
                    }
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }
}

impl Drop for RenewalLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
