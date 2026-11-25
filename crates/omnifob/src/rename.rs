//! `fob rename`: renaming an integration, keeping its sign-in and profiles.

use anyhow::Context;
use omnifob_core::{paths, providers};

use crate::files::{aws_config_file, write_atomically};
use crate::{App, profiles_file};

impl App {
    pub(crate) fn rename(&mut self, old: &str, new: &str) -> anyhow::Result<()> {
        let path = paths::config_file();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let renamed = omnifob_core::config::rename_integration(&text, old, new)?;
        let integration = self.config.integration(old)?.clone();

        if let Some(synced) = self.cache.integrations.get(old) {
            providers::forget_credentials(&synced.profiles);
        }
        let moved = providers::rename_sign_in(old, new, &integration)?;
        if let Err(e) = write_atomically(&path, &renamed) {
            // Put the sign-in back so nothing is left half renamed.
            let _ = providers::rename_sign_in(new, old, &integration);
            return Err(e);
        }
        self.cache.rename_integration(old, new);
        self.cache.save(&profiles_file())?;

        let kept = if moved {
            "kept the sign-in"
        } else {
            "no sign-in to keep"
        };
        eprintln!("fob: renamed '{old}' to '{new}' ({kept}); profiles are now {new}/...");
        let aws_config = aws_config_file(None)
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        if aws_config.is_some_and(|t| t.contains(&format!(" creds {old}/"))) {
            eprintln!(
                "fob: ~/.aws/config still has profiles for '{old}'; run `fob export aws-config --write` to update them"
            );
        }
        let stale: Vec<&str> = self
            .config
            .agent
            .profiles
            .iter()
            .flatten()
            .filter(|p| p.starts_with(&format!("{old}/")))
            .map(String::as_str)
            .collect();
        if !stale.is_empty() {
            eprintln!(
                "fob: [agent] profiles in {} still names '{old}' ({}); rename it there so agents keep these profiles",
                path.display(),
                stale.join(", ")
            );
        }
        Ok(())
    }
}
