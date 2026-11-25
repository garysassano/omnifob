//! `[agent]`: what commands run by a coding agent may use.

use jiff::SignedDuration;
use serde::Deserialize;

use super::opt_duration;

/// Limits on what a coding agent can get, under `[agent]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Profile ids agents may get credentials for, as patterns in which `*`
    /// stands for any characters within one `/`-separated segment, e.g.
    /// `"acme/dev/*"` or `"*/*/ReadOnly"`. Unset, agents may use every profile.
    #[serde(default)]
    pub profiles: Option<Vec<String>>,
    /// The longest lifetime of credentials an agent gets, e.g. "15m", for
    /// profiles whose lifetime omnifob chooses (Cloudflare tokens, chained
    /// and IAM users' roles, cross-partition roles, Google service
    /// accounts). Longer ones are asked for with this lifetime and not
    /// cached. At least 15 minutes, the shortest AWS session.
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub max_ttl: Option<SignedDuration>,
    /// Whether `fob exec` mints a Cloudflare token for each command an
    /// agent runs and deletes it when the command ends, as `--revoke` does.
    #[serde(default)]
    pub auto_revoke: bool,
}

impl AgentConfig {
    /// Whether an agent may get credentials for `profile_id`.
    pub fn allows(&self, profile_id: &str) -> bool {
        self.profiles
            .as_ref()
            .is_none_or(|patterns| patterns.iter().any(|p| matches_pattern(p, profile_id)))
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if let Some(ttl) = self.max_ttl
            && ttl < SignedDuration::from_mins(15)
        {
            return Err(
                "max_ttl: at least 15 minutes, the shortest session AWS hands out".to_string(),
            );
        }
        for pattern in self.profiles.iter().flatten() {
            if pattern.is_empty() || pattern.split('/').any(str::is_empty) {
                return Err(format!(
                    "profiles: '{pattern}' has an empty segment; write a profile id such as \"acme/dev/*\""
                ));
            }
        }
        Ok(())
    }
}

/// The local audit log, under `[audit]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Append a line to `audit.jsonl` in the state directory for every
    /// credential handed out: when, which profile, which command, which
    /// agent, until when. Never the credentials.
    #[serde(default)]
    pub enabled: bool,
}

/// Whether `id` matches `pattern`, in which `*` matches any run of characters
/// other than `/`: both have the same number of `/`-separated segments, and
/// each segment matches its pattern segment.
pub(crate) fn matches_pattern(pattern: &str, id: &str) -> bool {
    let (mut patterns, mut segments) = (pattern.split('/'), id.split('/'));
    loop {
        match (patterns.next(), segments.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if matches_segment(p.as_bytes(), s.as_bytes()) => {}
            _ => return false,
        }
    }
}

/// Wildcard matching of one segment in at most `pattern × segment` steps,
/// never exponential: on a mismatch only the last `*` seen takes one more
/// character, since letting an earlier one take more cannot help. Comparing bytes is
/// the same as comparing characters, since `*` is ASCII and a literal never
/// starts inside another character's UTF-8 encoding.
fn matches_segment(pattern: &[u8], segment: &[u8]) -> bool {
    let (mut p, mut s) = (0, 0);
    // The last `*` seen, and where in the segment its match ends.
    let mut star: Option<(usize, usize)> = None;
    while s < segment.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, s));
                p += 1;
            }
            Some(&c) if c == segment[s] => {
                p += 1;
                s += 1;
            }
            _ => match star {
                Some((star_p, star_s)) => {
                    star = Some((star_p, star_s + 1));
                    p = star_p + 1;
                    s = star_s + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn agent_profiles_match_patterns_within_segments() {
        let agent = |patterns: &[&str]| AgentConfig {
            profiles: Some(patterns.iter().map(|p| p.to_string()).collect()),
            ..AgentConfig::default()
        };
        assert!(AgentConfig::default().allows("acme/prod/Admin"));
        let dev = agent(&["acme/dev/*", "*/*/ReadOnly"]);
        assert!(dev.allows("acme/dev/Admin"));
        assert!(dev.allows("other/prod/ReadOnly"));
        assert!(!dev.allows("acme/prod/Admin"));
        assert!(!dev.allows("acme/dev"));
        // `*` stays within its segment.
        assert!(!agent(&["acme/*"]).allows("acme/dev/Admin"));
        assert!(agent(&["acme/*/*"]).allows("acme/dev/Admin"));
        assert!(agent(&["acme/d*v/Ad*"]).allows("acme/dev/Admin"));
        assert!(agent(&["acme/dév/*"]).allows("acme/dév/Admin"));
        assert!(!agent(&[]).allows("acme/dev/Admin"));
        assert!(agent(&["*"]).allows("x"));
        assert!(!agent(&["*"]).allows("x/y"));
        assert!(agent(&["a/**/c"]).allows("a//c"));
        assert!(agent(&["a/*b*/c"]).allows("a/abba/c"));
        assert!(!agent(&["a/*b*/c"]).allows("a/aaa/c"));
        assert!(!agent(&["a/b"]).allows("a/b/c"));
        assert!(!agent(&["a/b/c"]).allows("a/b"));
    }

    #[test]
    fn max_ttl_is_at_least_an_aws_session() {
        let config = |ttl: &str| {
            crate::Config::parse(&format!(
                "[agent]\nmax_ttl = \"{ttl}\"\nauto_revoke = true\n"
            ))
        };
        let parsed = config("15m").unwrap();
        assert_eq!(
            parsed.agent.max_ttl,
            Some(jiff::SignedDuration::from_mins(15))
        );
        assert!(parsed.agent.auto_revoke);
        let e = config("10m").unwrap_err().to_string();
        assert!(e.contains("at least 15 minutes"), "{e}");
    }

    /// A pattern with many `*`s against a long near-miss would take years
    /// with backtracking that tries every split.
    #[test]
    fn agent_patterns_never_backtrack_exponentially() {
        let pattern = format!("{}b/x", "*a".repeat(30));
        let id = format!("{}/x", "a".repeat(5000));
        let agent = AgentConfig {
            profiles: Some(vec![pattern.clone()]),
            ..AgentConfig::default()
        };
        let started = std::time::Instant::now();
        assert!(!agent.allows(&id));
        assert!(agent.allows(&format!("{}b/x", "a".repeat(5000))));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn agent_section_is_parsed_and_checked() {
        let config = Config::parse("[agent]\nprofiles = [\"acme/dev/*\"]\n").unwrap();
        assert!(config.agent.allows("acme/dev/Admin"));
        assert!(!config.agent.allows("acme/prod/Admin"));
        assert!(Config::parse("").unwrap().agent.profiles.is_none());
        let error = Config::parse("[agent]\nprofiles = [\"acme//x\"]\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("empty segment"), "{error}");
        assert!(Config::parse("[agent]\nother = 1\n").is_err());
    }
}
