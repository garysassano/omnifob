//! Git's credential helper protocol: git asks for a host's credentials, and
//! omnifob answers with the token of the profile that serves that host in the
//! current directory.
//!
//! A host omnifob has no profile for is left to the next helper. A host it
//! does serve but cannot pick one profile for is refused with `quit=1`, so
//! git does not fall through to another helper and act as a different account.

use std::collections::BTreeMap;

use crate::config::{Config, Integration};
use crate::providers::token;
use crate::{Credentials, Profile};

/// The attributes git sends, one `key=value` per line up to a blank line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub username: Option<String>,
}

pub fn parse_request(text: &str) -> Request {
    let attrs: BTreeMap<&str, &str> = text
        .lines()
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once('='))
        .collect();
    let get = |k: &str| {
        attrs
            .get(k)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
    };
    Request {
        protocol: get("protocol"),
        host: get("host"),
        username: get("username"),
    }
}

/// The git host a profile's token signs in to, if any.
pub fn host_of(config: &Config, profile: &Profile) -> Option<String> {
    match config.integrations.get(&profile.integration)? {
        Integration::Token(c) => token::git_host(c).ok().flatten().map(str::to_lowercase),
        _ => None,
    }
}

/// Which profile answers a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Choice<'a> {
    /// omnifob has no profile for this host; let other helpers answer.
    NotOurs,
    Use(&'a Profile),
    /// omnifob serves this host but cannot tell which profile to use.
    Refuse(String),
}

/// Picks the profile for `host`: among the current directory's profiles
/// when the directory is configured, else the only profile serving it.
pub fn choose<'a>(
    config: &Config,
    all: impl IntoIterator<Item = &'a Profile>,
    here: Option<(&str, &[&'a Profile])>,
    host: &str,
) -> Choice<'a> {
    let host = host.to_lowercase();
    let serves = |p: &Profile| host_of(config, p).as_deref() == Some(host.as_str());
    let serving: Vec<&Profile> = all.into_iter().filter(|p| serves(p)).collect();
    if serving.is_empty() {
        return Choice::NotOurs;
    }
    let ids = |ps: &[&Profile]| {
        ps.iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match here {
        Some((dir, profiles)) => {
            let listed: Vec<&Profile> = profiles.iter().copied().filter(|p| serves(p)).collect();
            match listed.as_slice() {
                [one] => Choice::Use(one),
                [] => Choice::Refuse(format!(
                    "directory '{dir}' lists no profile for {host}; add one of: {}",
                    ids(&serving)
                )),
                several => Choice::Refuse(format!(
                    "directory '{dir}' lists several profiles for {host}: {}",
                    ids(several)
                )),
            }
        }
        None => match serving.as_slice() {
            [one] => Choice::Use(one),
            several => Choice::Refuse(format!(
                "several profiles serve {host} ({}); list one for this directory under [directories]",
                ids(several)
            )),
        },
    }
}

/// The reply to git: the username it asked about (or a placeholder; hosts
/// such as GitHub ignore the username when the password is a token) and
/// the token.
pub fn response(
    config: &Config,
    profile: &Profile,
    creds: &Credentials,
    request: &Request,
) -> anyhow::Result<String> {
    let Some(Integration::Token(c)) = config.integrations.get(&profile.integration) else {
        anyhow::bail!("{} has no git credentials", profile.id);
    };
    let var = token::git_password_var(c)?;
    let password = creds
        .env
        .get(&var)
        .ok_or_else(|| anyhow::anyhow!("{} has no {var}", profile.id))?;
    let username = request.username.as_deref().unwrap_or("x-access-token");
    Ok(format!("username={username}\npassword={password}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;

    fn config() -> Config {
        Config::parse(
            r#"
            [integrations.gh-me]
            type = "token"
            preset = "github"

            [integrations.gh-acme]
            type = "token"
            preset = "github"

            [integrations.ghe]
            type = "token"
            preset = "github"
            git_host = "GHE.example.com"

            [integrations.hz]
            type = "token"
            preset = "hetzner"
            "#,
        )
        .unwrap()
    }

    fn profile(integration: &str) -> Profile {
        Profile::new(integration, "default", "github", Target::Token {})
    }

    #[test]
    fn parses_requests() {
        let r = parse_request("protocol=https\nhost=github.com\nusername=me\n\nignored=1\n");
        assert_eq!(r.protocol.as_deref(), Some("https"));
        assert_eq!(r.host.as_deref(), Some("github.com"));
        assert_eq!(r.username.as_deref(), Some("me"));
        assert_eq!(parse_request(""), Request::default());
        assert_eq!(parse_request("username=\n").username, None);
    }

    #[test]
    fn chooses_by_directory_then_by_host() {
        let config = config();
        let (me, acme, ghe, hz) = (
            profile("gh-me"),
            profile("gh-acme"),
            profile("ghe"),
            profile("hz"),
        );
        let all = [&me, &acme, &ghe, &hz];
        let pick = |here: Option<(&str, &[&Profile])>, host: &str| match choose(
            &config, all, here, host,
        ) {
            Choice::Use(p) => Ok(p.integration.clone()),
            Choice::NotOurs => Err("not ours".to_string()),
            Choice::Refuse(why) => Err(why),
        };
        assert_eq!(
            pick(Some(("~/git-acme", &[&acme, &hz])), "github.com").unwrap(),
            "gh-acme"
        );
        assert_eq!(
            pick(None, "ghe.example.com").unwrap(),
            "ghe",
            "case-insensitive"
        );
        assert_eq!(pick(None, "gitlab.com").unwrap_err(), "not ours");
        assert!(
            pick(None, "github.com")
                .unwrap_err()
                .contains("several profiles serve")
        );
        assert!(
            pick(Some(("~/x", &[&hz])), "github.com")
                .unwrap_err()
                .contains("lists no profile for github.com")
        );
        assert!(
            pick(Some(("~/x", &[&me, &acme])), "github.com")
                .unwrap_err()
                .contains("lists several")
        );
    }

    #[test]
    fn responds_with_the_token() {
        let config = config();
        let creds = Credentials {
            env: [("GH_TOKEN".to_string(), "secret".to_string())].into(),
            ..Default::default()
        };
        let request = parse_request("protocol=https\nhost=github.com\n");
        assert_eq!(
            response(&config, &profile("gh-me"), &creds, &request).unwrap(),
            "username=x-access-token\npassword=secret\n"
        );
        let request = parse_request("protocol=https\nhost=github.com\nusername=me\n");
        assert!(
            response(&config, &profile("gh-me"), &creds, &request)
                .unwrap()
                .starts_with("username=me\n")
        );
    }
}
