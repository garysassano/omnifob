//! The local audit log: one JSON line per credential handed out, appended
//! to `audit.jsonl` in the state directory when `[audit] enabled = true`.
//! It records what was handed to whom and until when, never a secret.

use std::io::Write;

use jiff::Timestamp;
use serde::Serialize;

/// One handout.
#[derive(Debug, Clone, Serialize)]
pub struct Entry<'a> {
    pub timestamp: Timestamp,
    /// The fob command (`exec`, `creds`, `env`, `console`).
    pub command: &'a str,
    pub profile: &'a str,
    pub integration: &'a str,
    /// The coding agent's marker variable, when an agent ran the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<&'a str>,
    /// How the credentials were handed over (`env`, `aws-container`,
    /// `azure-identity`, `gcp-adc`, `credential-process`, ...).
    pub via: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The provider's ID of a token that can be revoked (a minted
    /// Cloudflare token), which is not a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<&'a str>,
}

/// The log's path: `<state>/audit.jsonl`.
pub fn file() -> anyhow::Result<std::path::PathBuf> {
    Ok(crate::paths::state_dir()?.join("audit.jsonl"))
}

/// Appends `entry` as one line. The file is created private, and each line
/// is written in one call to a file opened for appending, so lines from
/// parallel commands do not interleave.
pub fn record(entry: &Entry<'_>) -> anyhow::Result<()> {
    let path = file()?;
    if let Some(dir) = path.parent() {
        crate::files::create_private_dir(dir)?;
    }
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&path)?;
    file.write_all(&line)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_append_and_leave_out_what_is_unknown() {
        let dir = std::env::temp_dir().join(format!("omnifob-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let context = crate::Context::builder().state_dir(&dir).build();
        let _entered = context.enter();
        let entry = Entry {
            timestamp: Timestamp::from_second(0).unwrap(),
            command: "exec",
            profile: "a/b/c",
            integration: "a",
            agent: Some("CLAUDECODE"),
            via: "env",
            expires_at: None,
            token_id: None,
        };
        record(&entry).unwrap();
        record(&Entry {
            agent: None,
            token_id: Some("t1"),
            ..entry
        })
        .unwrap();
        let text = std::fs::read_to_string(file().unwrap()).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["agent"], "CLAUDECODE");
        assert!(lines[0].get("token_id").is_none());
        assert!(lines[1].get("agent").is_none());
        assert_eq!(lines[1]["token_id"], "t1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(file().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
