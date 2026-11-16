//! Commands run by a coding agent (Claude Code, Codex, Gemini CLI and the
//! like). Their output goes into the agent's context and its transcripts, and
//! each command starts in a new shell with no one at a terminal, so under an
//! agent fob does not print credentials, never prompts, and wants a profile
//! named by its full id.
//!
//! This guards against accidents, not against the agent: it runs as the user
//! and can read what the user can. The harness's sandbox and permission rules
//! are the boundary.

use std::ffi::OsString;
use std::sync::OnceLock;

use anyhow::anyhow;

/// Variables coding agents set in the commands they run. `OMNIFOB_AGENT`
/// covers the others, and turns detection off with `0`.
const MARKERS: &[&str] = &[
    // Claude Code
    "CLAUDECODE",
    // Gemini CLI
    "GEMINI_CLI",
    // Cursor's agent
    "CURSOR_AGENT",
    // Codex, when it runs commands in its sandbox
    "CODEX_SANDBOX",
    // GitHub Copilot's coding agent (the Azure CLI reads it too)
    "COPILOT_AGENT_SESSION_ID",
];

/// Whether a coding agent runs this command.
pub(crate) fn active() -> bool {
    static ACTIVE: OnceLock<bool> = OnceLock::new();
    *ACTIVE.get_or_init(|| detect(|name| std::env::var_os(name)))
}

fn detect(var: impl Fn(&str) -> Option<OsString>) -> bool {
    match var("OMNIFOB_AGENT")
        .as_ref()
        .and_then(|v| v.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("1" | "true" | "yes") => return true,
        Some("0" | "false" | "no") => return false,
        _ => {}
    }
    MARKERS
        .iter()
        .any(|marker| var(marker).is_some_and(|v| !v.is_empty()))
}

/// The error for a command that would print credentials into the agent's
/// output.
pub(crate) fn refuse_to_print(profile_id: &str) -> anyhow::Error {
    anyhow!(
        "not printing credentials into an agent's output; run the command as `fob exec {profile_id} -- <command>`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_with(vars: &[(&str, &str)]) -> bool {
        detect(|name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        })
    }

    #[test]
    fn markers_and_the_override() {
        assert!(!detect_with(&[]));
        assert!(detect_with(&[("CLAUDECODE", "1")]));
        assert!(detect_with(&[("CODEX_SANDBOX", "seatbelt")]));
        assert!(!detect_with(&[("CLAUDECODE", "")]));
        assert!(detect_with(&[("OMNIFOB_AGENT", "1")]));
        assert!(detect_with(&[("OMNIFOB_AGENT", "TRUE")]));
        assert!(!detect_with(&[("OMNIFOB_AGENT", "0"), ("CLAUDECODE", "1")]));
        // Anything else leaves it to the markers.
        assert!(detect_with(&[
            ("OMNIFOB_AGENT", "maybe"),
            ("CLAUDECODE", "1")
        ]));
    }
}
