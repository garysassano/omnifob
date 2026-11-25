//! `fob import aws` and `fob export aws-config`: moving configuration between
//! omnifob and the AWS config file.

use anyhow::Context;
use omnifob_core::profile::slug;
use omnifob_core::{Config, Integration, Profile, paths};

use crate::App;
use crate::files::{aws_config_file, write_atomically};

/// `fob export gcp-adc`: an `external_account` ADC file whose subject
/// token comes from `fob creds <profile> --format gcp-executable`. It holds
/// no token, so it may be written anywhere.
pub(crate) fn export_gcp_adc(
    app: &App,
    profile: &Profile,
    audience: &str,
    absolute: bool,
    write: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use omnifob_core::provision::{check_wif_audience, gcp_executable_adc};
    check_wif_audience(audience)?;
    let impersonate = match (
        &profile.target,
        app.config.integration(&profile.integration)?,
    ) {
        (omnifob_core::Target::Gcp { .. }, _) => None,
        (omnifob_core::Target::GcpServiceAccount { label, .. }, Integration::Gcp(c)) => Some(
            c.service_accounts
                .get(label)
                .with_context(|| format!("no service account '{label}'; run `fob sync`"))?
                .email
                .clone(),
        ),
        _ => anyhow::bail!("{} is not a Google Cloud profile", profile.id),
    };
    let program = fob_program(absolute)?;
    let command = format!("{program} creds {} --format gcp-executable", profile.id);
    let adc = gcp_executable_adc(&command, audience, impersonate.as_deref());
    let text = serde_json::to_string_pretty(&adc)? + "\n";
    match write {
        Some(path) => {
            write_atomically(path, text)?;
            eprintln!(
                "fob: wrote {}; set GOOGLE_APPLICATION_CREDENTIALS to it, and GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 so the client libraries run fob",
                path.display()
            );
        }
        None => {
            print!("{text}");
            eprintln!(
                "fob: the client libraries run fob only with GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1"
            );
        }
    }
    Ok(())
}

/// How generated configuration runs fob: `fob`, or this binary's full path.
fn fob_program(absolute: bool) -> anyhow::Result<String> {
    if !absolute {
        return Ok("fob".to_string());
    }
    let exe = std::env::current_exe().context("finding the path of this fob binary")?;
    let exe = exe
        .to_str()
        .with_context(|| format!("the path {} is not valid Unicode", exe.display()))?;
    omnifob_core::import::credential_process_program(exe, cfg!(windows))
}

pub(crate) fn export_aws_config(
    app: &App,
    prefix: &str,
    absolute: bool,
    write: bool,
    file: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    use omnifob_core::import::{aws_config_block, replace_aws_block};
    let program = fob_program(absolute)?;
    let profiles: Vec<&Profile> = app.cache.all().filter(|p| p.target.is_aws()).collect();
    let regions: std::collections::BTreeMap<String, String> = profiles
        .iter()
        .filter_map(|p| {
            let integration = app.config.integration(&p.integration).ok()?;
            if let Integration::AwsIam(c) = integration {
                let region = match &p.target {
                    omnifob_core::Target::AwsIamRole { label, .. } => c
                        .roles
                        .get(label)
                        .and_then(|r| r.region.clone())
                        .or_else(|| c.region.clone()),
                    _ => c.region.clone(),
                }?;
                return Some((p.id.clone(), region));
            }
            if let Integration::AwsLogin(c) = integration {
                let region = match &p.target {
                    omnifob_core::Target::AwsLoginRole { label, .. } => {
                        c.roles.get(label).and_then(|r| r.region.clone())
                    }
                    _ => None,
                }
                .or_else(|| c.default_region.clone())
                .unwrap_or_else(|| c.region.clone());
                return Some((p.id.clone(), region));
            }
            if let Integration::Command(c) = integration {
                return Some((p.id.clone(), c.region.clone()?));
            }
            let Integration::AwsSso(c) = integration else {
                return None;
            };
            let region = match &p.target {
                omnifob_core::Target::AwsChained { label, .. } => c
                    .chained
                    .get(label)
                    .and_then(|r| r.region.clone())
                    .or_else(|| c.default_region.clone()),
                // Always set: the destination partition's Region, which the
                // portal's default_region cannot be.
                omnifob_core::Target::AwsCrossPartition { label, .. } => {
                    c.cross_partition.get(label).map(|r| r.region.clone())
                }
                _ => c.default_region.clone(),
            }?;
            Some((p.id.clone(), region))
        })
        .collect();
    let (block, clashes) = aws_config_block(&profiles, prefix, &regions, &program);
    for clash in &clashes {
        eprintln!(
            "fob: left out {}: its AWS profile name {} is {}'s already; rename one of the integrations or accounts to tell them apart",
            clash.left_out, clash.name, clash.kept
        );
    }
    let written = profiles.len() - clashes.len();
    if !write {
        print!("{block}");
        return Ok(());
    }
    let path = aws_config_file(file)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let updated = replace_aws_block(&existing, &block);
    if updated == existing {
        eprintln!("fob: {} is up to date", path.display());
        return Ok(());
    }
    if !existing.is_empty() {
        // A new file with the config's permissions, so a config holding keys
        // is not copied somewhere more readable.
        let backup = backup_path(&path);
        match std::fs::remove_file(&backup) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("replacing {}", backup.display()));
            }
            _ => {}
        }
        write_atomically(&backup, &existing)?;
        if let Ok(meta) = std::fs::metadata(&path) {
            std::fs::set_permissions(&backup, meta.permissions())
                .with_context(|| format!("writing {}", backup.display()))?;
        }
        eprintln!("fob: backed up the previous file to {}", backup.display());
    }
    write_atomically(&path, &updated)?;
    eprintln!(
        "fob: wrote {written} profile(s) to omnifob's block in {}; use them with --profile {prefix}<integration>-<account>-<role>",
        path.display()
    );
    Ok(())
}

/// `<file>.omnifob-backup` next to the file: the suffix is appended, so
/// `--file work.ini` backs up to `work.ini.omnifob-backup` rather than
/// replacing the extension.
fn backup_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".omnifob-backup");
    name.into()
}

pub(crate) fn import_aws(
    config: &Config,
    file: Option<std::path::PathBuf>,
    write: bool,
) -> anyhow::Result<()> {
    use omnifob_core::import::{
        aws_iam_user_toml, aws_import, aws_login_toml, aws_portal_toml, chained_toml,
        iam_roles_toml, normalize_start_url,
    };
    let file = aws_config_file(file)?;
    let text =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;

    // Configured portals, by normalised start URL.
    let configured: std::collections::BTreeMap<
        String,
        (&String, &omnifob_core::config::AwsSsoConfig),
    > = config
        .integrations
        .iter()
        .filter_map(|(name, i)| match i {
            Integration::AwsSso(c) => Some((normalize_start_url(&c.start_url), (name, c))),
            _ => None,
        })
        .collect();
    let mut taken: Vec<String> = config.integrations.keys().cloned().collect();
    let mut unique = |name: &mut String| {
        let base = name.clone();
        let mut n = 1;
        while taken.contains(name) {
            n += 1;
            *name = format!("{base}-{n}");
        }
        taken.push(name.clone());
    };
    let mut sections = Vec::new();
    let (mut new_portals, mut new_chained) = (0, 0);
    let mut new_users = Vec::new();
    let import = aws_import(&text);
    for skipped in &import.skipped {
        eprintln!(
            "fob: skipped profile '{}': {}",
            skipped.profile, skipped.reason
        );
    }
    for mut portal in import.portals {
        if let Some((name, existing)) = configured.get(&portal.start_url) {
            // Labels become lowercase in ids, so `Prod` there is `prod` here.
            let labels: Vec<String> = existing.chained.keys().map(|l| slug(l)).collect();
            portal.chained.retain(|label, _| !labels.contains(label));
            if portal.chained.is_empty() {
                eprintln!(
                    "fob: {} is already configured as '{name}'",
                    portal.start_url
                );
            } else {
                eprintln!(
                    "fob: {} is configured as '{name}'; {} chained role(s) to add",
                    portal.start_url,
                    portal.chained.len()
                );
                new_chained += portal.chained.len();
                sections.push(chained_toml(name, &portal.chained).trim_start().to_string());
            }
            continue;
        }
        unique(&mut portal.name);
        eprintln!(
            "fob: {} as '{}': {} profile(s), {} chained role(s)",
            portal.start_url,
            portal.name,
            portal.profiles,
            portal.chained.len()
        );
        new_portals += 1;
        new_chained += portal.chained.len();
        sections.push(aws_portal_toml(&portal));
    }
    for mut user in import.iam_users {
        // An aws-iam integration named after the profile is taken to be the
        // same user, so importing again adds only new roles.
        if let Some(Integration::AwsIam(existing)) = config.integrations.get(&user.name) {
            let labels: Vec<String> = existing.roles.keys().map(|l| slug(l)).collect();
            user.roles.retain(|label, _| !labels.contains(label));
            if user.roles.is_empty() {
                eprintln!(
                    "fob: profile '{}' (an access key) is already configured as '{}'",
                    user.profile, user.name
                );
            } else {
                eprintln!(
                    "fob: profile '{}' (an access key) is configured as '{}'; {} role(s) to add",
                    user.profile,
                    user.name,
                    user.roles.len()
                );
                new_chained += user.roles.len();
                sections.push(
                    iam_roles_toml(&user.name, &user.roles)
                        .trim_start()
                        .to_string(),
                );
            }
            continue;
        }
        unique(&mut user.name);
        eprintln!(
            "fob: profile '{}' (an access key) as aws-iam '{}': {} role(s)",
            user.profile,
            user.name,
            user.roles.len()
        );
        new_chained += user.roles.len();
        sections.push(aws_iam_user_toml(&user));
        new_users.push(user.name);
    }
    let mut new_logins = Vec::new();
    for mut login in import.logins {
        // An aws-login integration named after the profile is taken to be
        // the same sign-in.
        if let Some(Integration::AwsLogin(_)) = config.integrations.get(&login.name) {
            eprintln!(
                "fob: profile '{}' (an `aws login` sign-in) is already configured as '{}'",
                login.profile, login.name
            );
            continue;
        }
        unique(&mut login.name);
        eprintln!(
            "fob: profile '{}' (an `aws login` sign-in) as aws-login '{}' in {}",
            login.profile, login.name, login.region
        );
        sections.push(aws_login_toml(&login));
        new_logins.push(login.name);
    }
    if sections.is_empty() {
        eprintln!("fob: nothing new to import");
        return Ok(());
    }
    let mut key_hint = if new_users.is_empty() {
        String::new()
    } else {
        let logins: Vec<String> = new_users
            .iter()
            .map(|n| format!("`fob login {n}`"))
            .collect();
        format!(
            "; the access keys were not imported: run {} to store each one in the keychain",
            logins.join(", ")
        )
    };
    if !new_logins.is_empty() {
        let logins: Vec<String> = new_logins
            .iter()
            .map(|n| format!("`fob login {n}`"))
            .collect();
        key_hint.push_str(&format!(
            "; the `aws login` sessions stay with the AWS CLI: run {} to sign in through omnifob",
            logins.join(", ")
        ));
    }
    let toml = sections.join("\n");
    if !write {
        print!("{toml}");
        eprintln!(
            "fob: review the names, then run again with --write to append them to {}{key_hint}",
            paths::config_file()?.display()
        );
        return Ok(());
    }
    let path = paths::config_file()?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let separator = if existing.is_empty() || existing.ends_with("\n\n") {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let updated = format!("{existing}{separator}{toml}");
    Config::parse(&updated).context("the result would not be a valid config; nothing written")?;
    write_atomically(&path, &updated)?;
    eprintln!(
        "fob: added {} integration(s) and {new_chained} role(s) to {}; run `fob sync`, or `fob login <name>` for new integrations{key_hint}",
        new_portals + new_users.len() + new_logins.len(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backups_append_their_suffix() {
        assert_eq!(
            backup_path(std::path::Path::new("/home/me/.aws/config")),
            std::path::PathBuf::from("/home/me/.aws/config.omnifob-backup")
        );
        assert_eq!(
            backup_path(std::path::Path::new("work.ini")),
            std::path::PathBuf::from("work.ini.omnifob-backup")
        );
    }
}
