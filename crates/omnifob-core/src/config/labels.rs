//! `[[labels]]`: the environment and access level of profiles, by pattern.

use serde::Deserialize;

use crate::labels::Access;

/// Labels for the profiles matching `profiles`. For each label, the first
/// entry that matches a profile and sets it wins; profiles no entry labels
/// get what fob can tell or guess from their id.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Label {
    /// Profile ids this applies to, as patterns in which `*` stands for any
    /// characters within one `/`-separated segment, e.g. `"acme/*-prd/*"`.
    pub profiles: Vec<String>,
    /// The environment, e.g. "prod", "staging" or "dev". `fob list` marks
    /// "prod" and "production", and agents ask before using them.
    #[serde(default)]
    pub env: Option<String>,
    /// What the profiles may do: "read", "write" or "admin".
    #[serde(default)]
    pub access: Option<Access>,
}

impl Label {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.profiles.is_empty() {
            return Err("profiles must name at least one profile pattern".to_string());
        }
        if let Some(pattern) = self
            .profiles
            .iter()
            .find(|p| p.is_empty() || p.split('/').any(str::is_empty))
        {
            return Err(format!(
                "profiles: '{pattern}' has an empty segment; write a profile id such as \"*/prod/*\""
            ));
        }
        match (&self.env, self.access) {
            (Some(env), _) if env.trim().is_empty() => Err("env must not be empty".to_string()),
            (None, None) => Err("set env, access or both".to_string()),
            _ => Ok(()),
        }
    }
}
