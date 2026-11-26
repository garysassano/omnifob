//! `[browsers]`: the browsers integrations open in, and console isolation.

use serde::Deserialize;

use crate::Profile;

/// How to open a URL in one browser, or one profile of a browser, so that
/// each integration's sign-in sessions stay in the profile it belongs to.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Browser {
    /// The program and its arguments, run without a shell; `{url}` in an
    /// argument is replaced by the URL, e.g.
    /// `["firefox", "-P", "work", "{url}"]`.
    pub command: Vec<String>,
    /// Opens each AWS profile's console apart from the others, so that
    /// signing in as one does not sign the console out of another.
    #[serde(default)]
    pub isolate: Option<Isolation>,
}

/// How a browser keeps AWS consoles apart, one per profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// A Chromium profile per fob profile (`--profile-directory`), in place
    /// of any the command names; Chrome creates it on first use.
    ChromiumProfile,
    /// A Firefox container per fob profile, opened through the Granted
    /// Containers extension's `ext+granted-containers:` URLs.
    FirefoxContainer,
}

impl Browser {
    /// The program and its arguments for opening `url`.
    pub fn command_for(&self, url: &str) -> (&str, Vec<String>) {
        let args = self.command[1..]
            .iter()
            .map(|arg| arg.replace("{url}", url))
            .collect();
        (&self.command[0], args)
    }

    /// The program and its arguments for opening `url`, the console of
    /// `profile`. AWS consoles open in the profile's own Chromium profile or
    /// Firefox container when `isolate` says so: their URL is a federation
    /// link that signs in by itself. Other consoles rely on the sign-in
    /// already in the browser, so they open as [`Self::command_for`] does.
    pub fn console_command_for(&self, url: &str, profile: &Profile) -> (&str, Vec<String>) {
        if !profile.target.is_aws() {
            return self.command_for(url);
        }
        match self.isolate {
            None => self.command_for(url),
            Some(Isolation::FirefoxContainer) => {
                let container = form_urlencoded::Serializer::new(String::new())
                    .append_pair("name", &profile.id)
                    .append_pair("url", url)
                    .finish();
                self.command_for(&format!("ext+granted-containers:{container}"))
            }
            Some(Isolation::ChromiumProfile) => {
                // Chromium takes switch values only after `=`.
                let (program, args) = self.command_for(url);
                let profile_dir = format!(
                    "--profile-directory={}",
                    chromium_profile_directory(&profile.id)
                );
                let isolated = [profile_dir, "--no-first-run".to_string()]
                    .into_iter()
                    .chain(args.into_iter().filter(|arg| {
                        !arg.starts_with("--profile-directory=") && arg != "--no-first-run"
                    }))
                    .collect();
                (program, isolated)
            }
        }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        match self.command.split_first() {
            None => Err("command must name a program".to_string()),
            Some((program, _)) if program.is_empty() => {
                Err("command must name a program".to_string())
            }
            Some((program, _)) if program.contains("{url}") => {
                Err("{url} belongs in an argument, not in the program".to_string())
            }
            Some((_, args)) if !args.iter().any(|arg| arg.contains("{url}")) => {
                Err("command must pass the URL: put {url} in an argument".to_string())
            }
            Some(_) => Ok(()),
        }
    }
}

/// The Chromium profile folder for fob profile `id`: `fob` and the id's
/// segments, separated by spaces. Characters a Windows folder name cannot
/// hold become `_`, and trailing dots and spaces, which Windows drops from a
/// folder name, are left out.
fn chromium_profile_directory(id: &str) -> String {
    let mut dir = String::from("fob");
    for segment in id.split('/') {
        dir.push(' ');
        dir.extend(segment.chars().map(|c| {
            if c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        }));
    }
    dir.trim_end_matches(['.', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn integrations_open_in_the_browser_they_name() {
        let config = Config::parse(
            r#"
            [browsers.work]
            command = ["chrome", "--profile-directory=Profile 1", "{url}"]

            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-central-1"
            browser = "work"

            [integrations.google]
            type = "gcp"
            "#,
        )
        .unwrap();
        let browser = config.browser_for("acme").unwrap().unwrap();
        assert_eq!(
            browser.command_for("https://x.test/?a=1&b={url}"),
            (
                "chrome",
                vec![
                    "--profile-directory=Profile 1".to_string(),
                    "https://x.test/?a=1&b={url}".to_string()
                ]
            )
        );
        assert!(config.browser_for("google").unwrap().is_none());
        assert!(config.browser_for("nope").is_err());
    }

    #[test]
    fn a_browser_must_exist_and_pass_the_url() {
        let error = |text: &str| Config::parse(text).unwrap_err().to_string();
        let integration = "[integrations.c]\ntype = \"cloudflare-token\"\nbrowser = \"work\"\n";
        assert_eq!(
            error(integration),
            "integration 'c' opens in browser 'work', which [browsers] does not define (defined: none)"
        );
        for (command, message) in [
            ("[]", "command must name a program"),
            ("[\"\", \"{url}\"]", "command must name a program"),
            (
                "[\"firefox\"]",
                "command must pass the URL: put {url} in an argument",
            ),
            (
                "[\"{url}\"]",
                "{url} belongs in an argument, not in the program",
            ),
        ] {
            let text = format!("[browsers.work]\ncommand = {command}\n{integration}");
            assert_eq!(
                error(&text),
                format!("browser 'work': {message}"),
                "{command}"
            );
        }
        assert!(
            Config::parse(&format!(
                "[browsers.work]\ncommand = [\"firefox\", \"--url={{url}}\"]\n{integration}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn aws_consoles_open_isolated_per_profile() {
        let config = Config::parse(
            r#"
            [browsers.chrome]
            command = ["chrome", "--profile-directory=Profile 1", "--no-first-run", "--new-window", "{url}"]
            isolate = "chromium-profile"

            [browsers.firefox]
            command = ["firefox", "-P", "work", "{url}"]
            isolate = "firefox-container"
            "#,
        )
        .unwrap();
        let aws = Profile {
            id: "acme/prod-eu/Admin:Access".into(),
            integration: "acme".into(),
            target: crate::Target::Aws {
                account_id: "123456789012".into(),
                account_name: "prod eu".into(),
                role_name: "Admin:Access".into(),
            },
        };
        let url = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=a+b/c";
        assert_eq!(
            config.browsers["chrome"].console_command_for(url, &aws),
            (
                "chrome",
                vec![
                    "--profile-directory=fob acme prod-eu Admin_Access".to_string(),
                    "--no-first-run".to_string(),
                    "--new-window".to_string(),
                    url.to_string(),
                ]
            )
        );
        // Windows drops trailing dots and spaces from folder names.
        assert_eq!(
            chromium_profile_directory("acme/prod/Ops. "),
            "fob acme prod Ops"
        );
        let (_, args) = config.browsers["firefox"].console_command_for(url, &aws);
        assert_eq!(&args[..2], ["-P", "work"]);
        let container = args[2].strip_prefix("ext+granted-containers:").unwrap();
        let params: Vec<(String, String)> = form_urlencoded::parse(container.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            params,
            [
                ("name".to_string(), aws.id.clone()),
                ("url".to_string(), url.to_string())
            ]
        );

        // Other consoles rely on the browser's own sign-in, so they stay put.
        let gcp = Profile {
            id: "g/proj/user".into(),
            integration: "g".into(),
            target: crate::Target::Gcp {
                project_id: "proj".into(),
                project_name: "proj".into(),
            },
        };
        for browser in config.browsers.values() {
            assert_eq!(
                browser.console_command_for("https://x.test/", &gcp),
                browser.command_for("https://x.test/")
            );
        }
        assert!(
            Config::parse("[browsers.b]\ncommand = [\"b\", \"{url}\"]\nisolate = \"tabs\"\n")
                .is_err()
        );
    }
}
