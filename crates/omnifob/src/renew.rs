//! Background renewal: `fob renew`, which fob starts detached when cached
//! credentials near their end.

use std::time::Duration;

use omnifob_core::{Config, Integration, Profile, Target, providers, store};

use crate::App;

impl App {
    /// Fetches new credentials for a profile, unless another renewal of the
    /// same profile is already running. Never prompts.
    pub(crate) async fn renew(&self, id: &str) -> anyhow::Result<()> {
        let Some(profile) = self.cache.all().find(|p| p.id == id).cloned() else {
            return Ok(());
        };
        // Taken at once or not at all: a renewal already running will do.
        // The OS lets go of it when this process ends, however it ends.
        let Some(_lock) = store::lock(&format!("renew-{id}"), Duration::ZERO).await? else {
            return Ok(());
        };
        providers::credentials(&self.config, &profile, false, None).await?;
        Ok(())
    }
}

/// Whether renewing `profile` needs someone at a terminal: a role whose
/// trust policy wants an MFA code asks for one each session (a chained or
/// console sign-in's role with `mfa_serial`, and an IAM user's `no_session`
/// role when the user has `mfa_serial`), so a renewal in the background
/// always fails.
fn needs_a_person(config: &Config, profile: &Profile) -> bool {
    match (config.integration(&profile.integration), &profile.target) {
        (Ok(Integration::AwsSso(c)), Target::AwsChained { label, account_id }) => c
            .chained_role(label, account_id.as_deref())
            .is_some_and(|role| role.mfa_serial.is_some()),
        (Ok(Integration::AwsIam(c)), Target::AwsIamRole { label, .. }) => {
            c.mfa_serial.is_some() && c.roles.get(label).is_some_and(|role| role.no_session)
        }
        // A new session asks for a code.
        (Ok(Integration::AwsIam(c)), Target::AwsIamSession { .. }) => c.mfa_serial.is_some(),
        (Ok(Integration::AwsLogin(c)), Target::AwsLoginRole { label, .. }) => c
            .roles
            .get(label)
            .is_some_and(|role| role.mfa_serial.is_some()),
        _ => false,
    }
}

/// Starts `fob renew <profile>` detached from the terminal, so the next
/// command finds fresh credentials instead of waiting for them. Profiles
/// that cannot be renewed without a person are left for the next command.
pub(crate) fn spawn_renewal(config: &Config, profile: &Profile) {
    if needs_a_person(config, profile) {
        return;
    }
    let profile_id = profile.id.as_str();
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["renew", profile_id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: Ctrl-C in the terminal does not reach it.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    match cmd.spawn() {
        Ok(_) => tracing::debug!("renewing {profile_id} in the background"),
        Err(e) => tracing::debug!("could not start a background renewal: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chained_roles_with_mfa_are_not_renewed_in_the_background() {
        let config = Config::parse(
            r#"
[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
sso_region = "eu-west-1"

[integrations.acme.chained.deploy]
via_account_id = "111111111111"
via_role = "Admin"
role_arn = "arn:aws:iam::222222222222:role/Deploy"

[integrations.acme.chained.guarded]
via_account_id = "111111111111"
via_role = "Admin"
role_arn = "arn:aws:iam::222222222222:role/Guarded"
mfa_serial = "arn:aws:iam::111111111111:mfa/me"
"#,
        )
        .unwrap();
        let chained = |label: &str| Profile {
            id: format!("acme/x/{label}"),
            integration: "acme".into(),
            target: Target::AwsChained {
                label: label.into(),
                account_id: None,
            },
        };
        assert!(!needs_a_person(&config, &chained("deploy")));
        assert!(needs_a_person(&config, &chained("guarded")));
    }

    #[test]
    fn roles_assumed_with_an_mfa_code_are_not_renewed_in_the_background() {
        let config = Config::parse(
            r#"
[integrations.user]
type = "aws-iam"
mfa_serial = "arn:aws:iam::111111111111:mfa/me"

[integrations.user.roles.session]
role_arn = "arn:aws:iam::222222222222:role/S"

[integrations.user.roles.key]
role_arn = "arn:aws:iam::222222222222:role/K"
no_session = true

[integrations.console]
type = "aws-login"
login_region = "eu-west-1"

[integrations.console.roles.plain]
role_arn = "arn:aws:iam::222222222222:role/P"

[integrations.console.roles.guarded]
role_arn = "arn:aws:iam::222222222222:role/G"
mfa_serial = "arn:aws:iam::111111111111:mfa/me"
"#,
        )
        .unwrap();
        let profile = |integration: &str, target: Target| Profile {
            id: format!("{integration}/x/y"),
            integration: integration.into(),
            target,
        };
        let iam = |label: &str| {
            profile(
                "user",
                Target::AwsIamRole {
                    label: label.into(),
                    account_id: None,
                },
            )
        };
        let login = |label: &str| {
            profile(
                "console",
                Target::AwsLoginRole {
                    label: label.into(),
                    account_id: None,
                },
            )
        };
        assert!(!needs_a_person(&config, &iam("session")));
        assert!(needs_a_person(&config, &iam("key")));
        assert!(!needs_a_person(&config, &login("plain")));
        assert!(needs_a_person(&config, &login("guarded")));
    }
}
