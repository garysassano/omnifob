//! The keys of the `command` integration.

use jiff::SignedDuration;
use serde::Deserialize;

use super::{opt_duration, parse_url};

/// An external program that prints credentials (`type = "command"`), such
/// as saml2aws, gimme-aws-creds, okta-aws-cli, AWS IAM Roles Anywhere's
/// `credential_process` helper or an in-house script. It is run without a
/// shell, its stderr passes through to the terminal (so it can prompt or
/// report), and its stdout is read as credentials: omnifob's own JSON
/// (`{"env": {...}, "expires_at": "<RFC 3339>"}`, as `fob creds` prints)
/// or the AWS `credential_process` format. Credentials with an expiry are
/// cached until then; credentials without one are fetched for each use.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CommandConfig {
    /// The program and its arguments, run without a shell. The program is a
    /// name looked up on `PATH`, an absolute path or one under `~/`.
    /// `{ttl_seconds}` in an argument becomes the lifetime asked for, which
    /// needs `ttl`.
    pub command: Vec<String>,
    /// What the program prints: `omnifob` (the default) or
    /// `credential-process`.
    #[serde(default)]
    pub format: CommandFormat,
    /// Middle segment of the profile id; defaults to "default".
    #[serde(default)]
    pub account: Option<String>,
    /// Last segment of the profile id; defaults to the program's file name.
    #[serde(default)]
    pub name: Option<String>,
    /// How long the program may run before it is stopped, 1 second to 10
    /// minutes; defaults to 2 minutes, enough for a browser sign-in.
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub timeout: Option<SignedDuration>,
    /// The lifetime to ask the program for, which makes it take `--ttl` and
    /// `[agent] max_ttl`: passed as `{ttl_seconds}` in `command` and as
    /// `OMNIFOB_TTL_SECONDS` in its environment. Unset, the program picks
    /// the lifetime and `--ttl` is refused.
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub ttl: Option<SignedDuration>,
    /// Exported as `AWS_REGION` and `AWS_DEFAULT_REGION` with
    /// `credential-process` output.
    #[serde(default)]
    pub region: Option<String>,
    /// URL `fob console` opens; there is none by default.
    #[serde(default)]
    pub console: Option<String>,
    /// The browser in `[browsers]` that this integration's consoles open in;
    /// by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

/// What a `command` integration's program prints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum CommandFormat {
    /// `{"env": {"NAME": "value", ...}, "expires_at": "<RFC 3339>"}`, with
    /// `expires_at` optional; other keys are ignored.
    #[default]
    Omnifob,
    /// The AWS `credential_process` format (`Version` 1, `AccessKeyId`,
    /// `SecretAccessKey`, optional `SessionToken`, `Expiration` and
    /// `AccountId`), exported as the AWS variables.
    CredentialProcess,
}

/// `{ttl_seconds}` in an argument.
pub const TTL_PLACEHOLDER: &str = "{ttl_seconds}";

impl CommandConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        let Some(program) = self.command.first() else {
            return Err("command must name a program".to_string());
        };
        if program.trim().is_empty() {
            return Err("command must name a program".to_string());
        }
        if program.contains(TTL_PLACEHOLDER) {
            return Err(format!(
                "{TTL_PLACEHOLDER} belongs in an argument, not in the program"
            ));
        }
        let path = std::path::Path::new(program);
        let bare = path.components().count() == 1 && !program.contains(['/', '\\']);
        if !bare && !path.is_absolute() && !program.starts_with("~/") {
            return Err(format!(
                "command: '{program}' must be a program name on PATH, an absolute path or one under ~/, not relative to wherever fob runs"
            ));
        }
        if self.ttl.is_none() && self.command.iter().any(|a| a.contains(TTL_PLACEHOLDER)) {
            return Err(format!(
                "command uses {TTL_PLACEHOLDER}, which needs `ttl` to say what to ask for"
            ));
        }
        if let Some(timeout) = self.timeout
            && !(SignedDuration::from_secs(1)..=SignedDuration::from_mins(10)).contains(&timeout)
        {
            return Err("timeout must be between 1s and 10m".to_string());
        }
        if let Some(ttl) = self.ttl
            && ttl < SignedDuration::from_mins(1)
        {
            return Err("ttl must be at least 1m".to_string());
        }
        if let Some(region) = &self.region {
            if self.format != CommandFormat::CredentialProcess {
                return Err("region is exported with format = \"credential-process\" only; put it in the program's env output otherwise".to_string());
            }
            super::aws::check_region("region", region)?;
        }
        if let Some(name) = &self.name
            && crate::profile::slug(name) != *name
        {
            return Err(format!(
                "name '{name}' must be a profile id segment: lowercase letters, digits, '.', '_' and '-' (such as \"{}\")",
                crate::profile::slug(name)
            ));
        }
        if let Some(url) = &self.console {
            parse_url("console", url)?;
        }
        Ok(())
    }

    /// How long the program may run.
    pub fn timeout(&self) -> SignedDuration {
        self.timeout.unwrap_or(SignedDuration::from_mins(2))
    }

    /// The last segment of the profile id.
    pub fn leaf(&self) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => {
                let program = self.command.first().map(String::as_str).unwrap_or_default();
                let file = program.rsplit(['/', '\\']).next().unwrap_or(program);
                let stem = file.strip_suffix(".exe").unwrap_or(file);
                crate::profile::slug(stem)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::*;

    #[test]
    fn command_keys_are_checked() {
        let command = |extra: &str| {
            Config::parse(&format!("[integrations.c]\ntype = \"command\"\n{extra}\n"))
                .map_err(|e| format!("{e:#}"))
        };
        let parsed = command("command = [\"/opt/bin/Get Creds.exe\", \"--json\"]").unwrap();
        let Integration::Command(c) = &parsed.integrations["c"] else {
            panic!()
        };
        assert_eq!(c.leaf(), "get-creds");
        assert_eq!(c.timeout(), jiff::SignedDuration::from_mins(2));
        assert!(command("command = [\"saml2aws\", \"--duration={ttl_seconds}\"]\nttl = \"1h\"\nformat = \"credential-process\"\nregion = \"eu-west-1\"").is_ok());
        assert!(command("command = [\"~/bin/creds\"]\nname = \"ci\"\ntimeout = \"30s\"").is_ok());
        for (extra, message) in [
            ("command = []", "command must name a program"),
            ("command = [\" \"]", "command must name a program"),
            (
                "command = [\"./creds\"]",
                "not relative to wherever fob runs",
            ),
            (
                "command = [\"bin/creds\"]",
                "not relative to wherever fob runs",
            ),
            ("command = [\"x\", \"{ttl_seconds}\"]", "needs `ttl`"),
            (
                "command = [\"{ttl_seconds}\"]\nttl = \"1h\"",
                "belongs in an argument",
            ),
            (
                "command = [\"x\"]\ntimeout = \"11m\"",
                "timeout must be between 1s and 10m",
            ),
            (
                "command = [\"x\"]\nttl = \"30s\"",
                "ttl must be at least 1m",
            ),
            (
                "command = [\"x\"]\nregion = \"eu-west-1\"",
                "credential-process\" only",
            ),
            (
                "command = [\"x\"]\nname = \"Two Words\"",
                "must be a profile id segment",
            ),
            (
                "command = [\"x\"]\nformat = \"yaml\"",
                "unknown variant `yaml`",
            ),
            (
                "command = [\"x\"]\nconsole = \"ftp://x\"",
                "must be an http:// or https:// URL",
            ),
            ("command = \"saml2aws script\"", "invalid type: string"),
        ] {
            let error = command(extra).unwrap_err();
            assert!(error.contains(message), "{extra}: {error}");
        }
    }
}
