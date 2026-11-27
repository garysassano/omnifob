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

/// Variables coding agents set in the commands they run, each checked
/// against the agent's documentation or source on 2026-11-25.
/// `OMNIFOB_AGENT` covers the others, and turns detection off with `0`.
/// Aider, Windsurf, Amp and Kiro document none, so they need it.
const MARKERS: &[&str] = &[
    // The cross-agent marker proposed in agents.md, which Claude Code,
    // OpenCode, Crush and Pi set.
    "AI_AGENT",
    // Claude Code
    "CLAUDECODE",
    // Gemini CLI (`shellExecutionService.ts`)
    "GEMINI_CLI",
    // Cursor's agent (its terminal documentation)
    "CURSOR_AGENT",
    // Codex: in its sandbox, and the thread of every command it runs
    // (`codex-rs/protocol/src/shell_environment.rs`)
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    // GitHub Copilot's coding agent (the Azure CLI reads it too)
    "COPILOT_AGENT_SESSION_ID",
    // GitHub Copilot CLI (its changelog)
    "COPILOT_CLI",
    // OpenCode (anomalyco/opencode#51975)
    "OPENCODE",
    // Crush (`internal/shell/shell.go`)
    "CRUSH",
    // Qwen Code (`shellExecutionService.ts`)
    "QWEN_CODE",
    // Cline, in the terminals it opens (`VscodeTerminalRegistry.ts`)
    "CLINE_ACTIVE",
    // Goose's developer shell (aaif-goose/goose#13598)
    "GOOSE_TERMINAL",
    // Pi (`docs/environment-variables.md`)
    "PI_CODING_AGENT",
    // Antigravity (set by its `agy` binary)
    "ANTIGRAVITY_AGENT",
];

/// Whether a coding agent runs this command.
pub(crate) fn active() -> bool {
    marker().is_some()
}

/// The variable that says a coding agent runs this command: its marker,
/// or `OMNIFOB_AGENT`.
pub(crate) fn marker() -> Option<&'static str> {
    static MARKER: OnceLock<Option<&'static str>> = OnceLock::new();
    *MARKER.get_or_init(|| detect(|name| std::env::var_os(name)))
}

/// The library's view of the agent: its Copilot session, which Entra ID
/// records in tokens, when it has one.
pub(crate) fn context_agent() -> Option<omnifob_core::Agent> {
    active().then(|| omnifob_core::Agent {
        session_id: std::env::var("COPILOT_AGENT_SESSION_ID")
            .ok()
            .filter(|v| !v.is_empty()),
    })
}

fn detect(var: impl Fn(&str) -> Option<OsString>) -> Option<&'static str> {
    match var("OMNIFOB_AGENT")
        .as_ref()
        .and_then(|v| v.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("1" | "true" | "yes") => return Some("OMNIFOB_AGENT"),
        Some("0" | "false" | "no") => return None,
        _ => {}
    }
    // `CLAUDECODE=0` or `CLINE_ACTIVE=false` says no agent.
    MARKERS.iter().copied().find(|marker| {
        var(marker).is_some_and(|v| {
            let v = v.to_string_lossy().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false" && v != "no"
        })
    })
}

/// The error for a command that would print credentials into the agent's
/// output.
pub(crate) fn refuse_to_print(profile_id: &str) -> anyhow::Error {
    omnifob_core::Coded::new(
        omnifob_core::Code::UseExec,
        format!(
            "not printing credentials into an agent's output; run the command as `fob exec {profile_id} -- <command>`"
        ),
    )
    .with("profile", profile_id)
    .with("run", format!("fob exec {profile_id} -- <command>"))
    .into()
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
        .is_some()
    }

    #[test]
    fn markers_and_the_override() {
        assert!(!detect_with(&[]));
        assert!(detect_with(&[("CLAUDECODE", "1")]));
        assert!(detect_with(&[("CODEX_SANDBOX", "seatbelt")]));
        assert!(!detect_with(&[("CLAUDECODE", "")]));
        // A marker turned off is no marker.
        assert!(!detect_with(&[("CLAUDECODE", "0")]));
        assert!(!detect_with(&[("CLINE_ACTIVE", "false")]));
        assert!(detect_with(&[("OMNIFOB_AGENT", "1")]));
        assert!(detect_with(&[("OMNIFOB_AGENT", "TRUE")]));
        assert!(!detect_with(&[("OMNIFOB_AGENT", "0"), ("CLAUDECODE", "1")]));
        // Anything else leaves it to the markers.
        assert!(detect_with(&[
            ("OMNIFOB_AGENT", "maybe"),
            ("CLAUDECODE", "1")
        ]));
        for marker in [
            "AI_AGENT",
            "OPENCODE",
            "GOOSE_TERMINAL",
            "CLINE_ACTIVE",
            "COPILOT_CLI",
        ] {
            assert!(detect_with(&[(marker, "1")]), "{marker}");
        }
        let found = detect(|name| (name == "CODEX_THREAD_ID").then(|| OsString::from("t")));
        assert_eq!(found, Some("CODEX_THREAD_ID"));
    }
}
