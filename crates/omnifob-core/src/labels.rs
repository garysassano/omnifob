//! A profile's environment (production, staging...) and access level (read,
//! write, admin): set by `[[labels]]` in the config, else worked out where
//! fob can tell (a Cloudflare template's permissions) or guessed from the
//! words of the profile's id. `fob list` shows them, so a person sees which
//! profile is production and an agent picks the least-privileged one, and
//! each says where it came from, so a guess is never taken for a fact.

use serde::{Deserialize, Serialize};

use crate::config::{Integration, matches_pattern};
use crate::{Config, Profile, Target};

/// What a profile may do, from least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
    Admin,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Admin => "admin",
        }
    }
}

/// Where a label came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// `[[labels]]` in the config.
    Config,
    /// The permissions fob hands out for the profile (a Cloudflare template).
    Permissions,
    /// Guessed from words of the profile's id, such as `prd` or `ReadOnly`.
    Name,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Config => "config",
            Source::Permissions => "permissions",
            Source::Name => "name",
        }
    }
}

/// A profile's labels, each with where it came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    pub env: Option<(String, Source)>,
    pub access: Option<(Access, Source)>,
}

/// The labels of `profile`: for each, the first `[[labels]]` entry that
/// matches and sets it, else what fob can tell or guess.
pub fn of(config: &Config, profile: &Profile) -> Labels {
    let matching = || {
        config
            .labels
            .iter()
            .filter(|l| l.profiles.iter().any(|p| matches_pattern(p, &profile.id)))
    };
    let env = matching()
        .find_map(|l| l.env.clone())
        .map(|env| (env, Source::Config))
        .or_else(|| guess_env(&profile.id).map(|env| (env.to_string(), Source::Name)));
    let access = matching()
        .find_map(|l| l.access)
        .map(|access| (access, Source::Config))
        .or_else(|| template_access(config, profile).map(|a| (a, Source::Permissions)))
        .or_else(|| guess_access(leaf(&profile.id)).map(|a| (a, Source::Name)));
    Labels { env, access }
}

/// The last segment of an id: the role or template.
fn leaf(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

/// The words of `text` in lower case, split at anything but letters and
/// digits and where a capital follows a lower-case letter or digit:
/// `itv-brdcst-ac-prd` gives `itv brdcst ac prd`, `AdministratorAccess`
/// gives `administrator access`.
fn words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous: Option<char> = None;
    for c in text.chars() {
        if !c.is_alphanumeric() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            let boundary = c.is_uppercase()
                && previous.is_some_and(|p| p.is_lowercase() || p.is_ascii_digit());
            if boundary && !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            word.extend(c.to_lowercase());
        }
        previous = Some(c);
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// The environment a profile's id names, when it names exactly one: words
/// such as `prod`, `prd`, `staging`, `uat` or `dev` in any segment.
fn guess_env(id: &str) -> Option<&'static str> {
    let mut found: Option<&'static str> = None;
    for word in words(id) {
        let env = match word.as_str() {
            "prod" | "prd" | "production" => "prod",
            "staging" | "stage" | "stg" | "preprod" => "staging",
            "test" | "tst" | "qa" | "uat" => "test",
            "dev" | "development" | "sandbox" => "dev",
            _ => continue,
        };
        match found {
            Some(other) if other != env => return None,
            _ => found = Some(env),
        }
    }
    found
}

/// The access a role's or template's name suggests, the highest when it
/// suggests several (`ReadWrite` is write): AWS's managed job roles
/// (`AdministratorAccess`, `PowerUserAccess`, `ReadOnlyAccess`,
/// `ViewOnlyAccess`, `SecurityAudit`), Azure's and Google's basic roles
/// (owner, contributor or editor, reader or viewer), and the usual words.
fn guess_access(name: &str) -> Option<Access> {
    let words = words(name);
    let has = |w: &str| words.iter().any(|word| word == w);
    let mut access = None;
    for word in &words {
        let found = match word.as_str() {
            "admin" | "administrator" | "administrators" | "owner" => Access::Admin,
            "write" | "edit" | "editor" | "deploy" | "deployer" | "developer" | "contributor"
            | "operator" | "rw" => Access::Write,
            "power" if has("user") => Access::Write,
            "poweruser" => Access::Write,
            "read" | "readonly" | "reader" | "view" | "viewer" | "viewonly" | "audit"
            | "auditor" | "ro" => Access::Read,
            _ => continue,
        };
        access = access.max(Some(found));
    }
    access
}

/// A Cloudflare profile's access from its template's permissions: write
/// when any required permission writes or edits, read when all read.
fn template_access(config: &Config, profile: &Profile) -> Option<Access> {
    let Target::Cloudflare { template, .. } = &profile.target else {
        return None;
    };
    let Some(Integration::Cloudflare(cloudflare)) = config.integrations.get(&profile.integration)
    else {
        return None;
    };
    let templates = crate::providers::cloudflare::templates(cloudflare);
    let permissions = &templates.get(template)?.permissions;
    if permissions.is_empty() {
        return None;
    }
    if permissions
        .iter()
        .any(|p| p.ends_with(" Write") || p.ends_with(" Edit"))
    {
        Some(Access::Write)
    } else if permissions.iter().all(|p| p.ends_with(" Read")) {
        Some(Access::Read)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_split_at_separators_and_case() {
        assert_eq!(words("itv-brdcst-ac-prd"), ["itv", "brdcst", "ac", "prd"]);
        assert_eq!(words("AdministratorAccess"), ["administrator", "access"]);
        assert_eq!(words("acme/dev/ReadOnly"), ["acme", "dev", "read", "only"]);
        assert_eq!(words("S3FullAccess"), ["s3", "full", "access"]);
        assert_eq!(words("PROD_EU"), ["prod", "eu"]);
    }

    #[test]
    fn environments_are_guessed_only_when_the_id_names_one() {
        assert_eq!(guess_env("itv/itv-brdcst-ac-prd/itv-pe"), Some("prod"));
        assert_eq!(guess_env("acme/production/Admin"), Some("prod"));
        assert_eq!(guess_env("gary/test/AdministratorAccess"), Some("test"));
        assert_eq!(guess_env("acme/StagingEu/Deploy"), Some("staging"));
        assert_eq!(guess_env("cf/personal/workers"), None);
        // Two environments: no guess rather than a wrong one.
        assert_eq!(guess_env("acme/dev-to-prod/Admin"), None);
        // Words, not substrings.
        assert_eq!(guess_env("acme/product/Admin"), None);
    }

    #[test]
    fn access_is_guessed_from_role_names() {
        assert_eq!(guess_access("AdministratorAccess"), Some(Access::Admin));
        assert_eq!(guess_access("PowerUserAccess"), Some(Access::Write));
        assert_eq!(guess_access("ReadOnlyAccess"), Some(Access::Read));
        assert_eq!(guess_access("ViewOnlyAccess"), Some(Access::Read));
        assert_eq!(guess_access("SecurityAudit"), Some(Access::Read));
        assert_eq!(guess_access("itv-readonly"), Some(Access::Read));
        assert_eq!(guess_access("itv-read-only"), Some(Access::Read));
        assert_eq!(guess_access("Contributor"), Some(Access::Write));
        assert_eq!(guess_access("Owner"), Some(Access::Admin));
        assert_eq!(guess_access("dns-edit"), Some(Access::Write));
        assert_eq!(guess_access("ReadWrite"), Some(Access::Write));
        assert_eq!(guess_access("itv-pe"), None);
        assert_eq!(guess_access("workers"), None);
    }

    fn profile(id: &str, target: Target) -> Profile {
        Profile {
            id: id.into(),
            integration: id.split('/').next().unwrap().into(),
            target,
        }
    }

    fn aws(id: &str) -> Profile {
        profile(
            id,
            Target::Aws {
                account_id: "111111111111".into(),
                account_name: "x".into(),
                role_name: leaf(id).into(),
            },
        )
    }

    #[test]
    fn the_config_wins_over_guesses_field_by_field() {
        let config = Config::parse(
            r#"
            [[labels]]
            profiles = ["acme/*-prd/*"]
            env = "production"

            [[labels]]
            profiles = ["*/*/itv-pe", "acme/*/*"]
            access = "write"
            env = "ignored, the first entry set it"
            "#,
        )
        .unwrap();
        let labels = of(&config, &aws("acme/core-prd/ReadOnly"));
        assert_eq!(labels.env, Some(("production".into(), Source::Config)));
        assert_eq!(labels.access, Some((Access::Write, Source::Config)));
        let labels = of(&config, &aws("other/core-dev/ReadOnly"));
        assert_eq!(labels.env, Some(("dev".into(), Source::Name)));
        assert_eq!(labels.access, Some((Access::Read, Source::Name)));
        assert_eq!(of(&config, &aws("other/core/x")), Labels::default());
    }

    #[test]
    fn label_entries_are_checked() {
        let error = |text: &str| Config::parse(text).unwrap_err().to_string();
        assert!(error("[[labels]]\nprofiles = []\nenv = \"prod\"\n").contains("at least one"));
        assert!(
            error("[[labels]]\nprofiles = [\"a//b\"]\nenv = \"prod\"\n").contains("empty segment")
        );
        assert!(error("[[labels]]\nprofiles = [\"a/*/*\"]\n").contains("set env, access or both"));
        assert!(error("[[labels]]\nprofiles = [\"a/*/*\"]\naccess = \"root\"\n").contains("root"));
        assert!(error("[[labels]]\nprofiles = [\"a/*/*\"]\nenv = \" \"\n").contains("empty"));
    }

    #[test]
    fn cloudflare_access_comes_from_the_template() {
        let config = Config::parse(
            r#"
            [integrations.cf]
            type = "cloudflare-token"

            [integrations.cf.templates.mixed]
            permissions = ["Zone Read", "Cache Purge"]
            "#,
        )
        .unwrap();
        let cf = |template: &str| {
            profile(
                &format!("cf/acct/{template}"),
                Target::Cloudflare {
                    account_id: "a".into(),
                    account_name: "acct".into(),
                    template: template.into(),
                },
            )
        };
        let access = |template: &str| of(&config, &cf(template)).access;
        assert_eq!(
            access("workers"),
            Some((Access::Write, Source::Permissions))
        );
        assert_eq!(
            access("dns-read"),
            Some((Access::Read, Source::Permissions))
        );
        assert_eq!(access("read"), Some((Access::Read, Source::Permissions)));
        // Neither all reads nor any write: no answer from the permissions,
        // and none from the name.
        assert_eq!(access("mixed"), None);
    }
}
