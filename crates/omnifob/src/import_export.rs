//! `fob import aws` and `fob export aws-config`: moving configuration between
//! omnifob and the AWS config file.

use anyhow::{Context, bail};
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
                omnifob_core::Target::AwsChained { label, account_id } => c
                    .chained_role(label, account_id.as_deref())
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

/// Leaves out of imported or discovered tables and rules what a configured
/// portal already has: chained roles with a configured table's label or
/// role, chained roles one of its rules gives, including the accounts of an
/// imported rule for the same permission set, role name and path (the rest
/// of that rule's accounts come in as tables, since the configured rule is
/// not rewritten). What remains gets labels of its own where theirs is
/// taken by a configured table or rule, so the config still parses once it
/// is added.
fn keep_new(
    existing: &omnifob_core::config::AwsSsoConfig,
    chained: &mut std::collections::BTreeMap<String, omnifob_core::config::ChainedRole>,
    chained_rules: &mut std::collections::BTreeMap<String, omnifob_core::config::ChainedRule>,
) {
    let Ok(partition) = existing.partition() else {
        return;
    };
    // A rule matching a configured one may name accounts that one does not
    // cover; it comes in as a table per account, filtered with the rest.
    let rules = std::mem::take(chained_rules);
    for (label, rule) in rules {
        if !existing.chained_rules.values().any(|r| {
            r.via_role == rule.via_role && r.role_name == rule.role_name && r.path == rule.path
        }) {
            chained_rules.insert(label, rule);
            continue;
        }
        for account in &rule.accounts {
            chained.insert(
                format!("{label}-{account}"),
                rule.role_for(account, partition),
            );
        }
    }
    // Labels become lowercase in ids, so `Prod` there is `prod` here.
    let tables: Vec<String> = existing.chained.keys().map(|l| slug(l)).collect();
    chained.retain(|label, role| {
        let given_by_rule = existing.chained_rules.values().any(|rule| {
            rule.via_role == role.via_role
                && rule.applies_to(&role.via_account_id)
                && rule.role_for(&role.via_account_id, partition).role_arn == role.role_arn
        });
        let configured = existing.chained.values().any(|c| {
            c.via_account_id == role.via_account_id
                && c.via_role == role.via_role
                && c.role_arn == role.role_arn
        });
        !given_by_rule && !configured && !tables.contains(&slug(label))
    });
    let configured: Vec<String> = existing
        .chained
        .keys()
        .chain(existing.chained_rules.keys())
        .map(|l| slug(l))
        .collect();
    for (label, role) in std::mem::take(chained) {
        let taken = |l: &str| {
            configured.contains(&slug(l))
                || chained.contains_key(l)
                || chained_rules.contains_key(l)
        };
        chained.insert(unique_label(&label, taken), role);
    }
    for (label, rule) in std::mem::take(chained_rules) {
        let taken = |l: &str| {
            configured.contains(&slug(l))
                || chained.contains_key(l)
                || chained_rules.contains_key(l)
        };
        chained_rules.insert(unique_label(&label, taken), rule);
    }
}

/// `label`, or `label-2`, `label-3`, ... until `taken` refuses none.
fn unique_label(label: &str, taken: impl Fn(&str) -> bool) -> String {
    let mut unique = label.to_string();
    let mut n = 1;
    while taken(&unique) {
        n += 1;
        unique = format!("{label}-{n}");
    }
    unique
}

/// Appends `toml` to the config file, after checking that the result is a
/// valid config; returns the file's path.
fn append_to_config(toml: &str) -> anyhow::Result<std::path::PathBuf> {
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
    Ok(path)
}

/// `fob discover aws`: searches the integration's Identity Center roles (or
/// those of the `via` permission sets) for IAM roles they may assume in
/// their own account, and prints what is not configured yet as chained
/// tables, folding a role found in several accounts into a rule, as
/// `fob import aws` does. Under an agent, only profiles open to it search.
pub(crate) async fn discover_aws(
    app: &App,
    integration: &str,
    via: &[String],
    write: bool,
) -> anyhow::Result<()> {
    use omnifob_core::import::{chained_rules_toml, chained_toml, fold_chained};
    use omnifob_core::providers::aws::discover::{Source, discover};
    let Integration::AwsSso(config) = app.config.integration(integration)? else {
        bail!(
            "'{integration}' is not an aws-sso integration; discovery searches Identity Center roles"
        );
    };
    let agent_limits = crate::agent::active() && app.config.agent.profiles.is_some();
    let sources: Vec<Source> = app
        .cache
        .all()
        .filter(|p| p.integration == integration)
        .filter(|p| !agent_limits || app.config.agent.allows(&p.id))
        .filter_map(|p| match &p.target {
            omnifob_core::Target::Aws {
                account_id,
                role_name,
                ..
            } if via.is_empty() || via.contains(role_name) => Some(Source {
                account_id: account_id.clone(),
                segment: p.id.split('/').nth(1)?.to_string(),
                via_role: role_name.clone(),
            }),
            _ => None,
        })
        .collect();
    if sources.is_empty() {
        bail!(
            "no Identity Center role of '{integration}' to search{}; see `fob list {integration}`",
            if via.is_empty() {
                String::new()
            } else {
                format!(" named {}", via.join(" or "))
            }
        );
    }
    eprintln!(
        "fob: searching {} role(s) of '{integration}' with iam:ListRoles and the policy simulator",
        sources.len()
    );
    let discovery = discover(integration, config, sources).await;
    for skipped in &discovery.skipped {
        eprintln!(
            "fob: skipped {}/{}/{}: {}",
            integration, skipped.source.segment, skipped.source.via_role, skipped.reason
        );
    }
    let mut chained = std::collections::BTreeMap::new();
    for found in &discovery.found {
        // Already a table, under any label.
        if config
            .chained
            .values()
            .any(|c| c.role_arn == found.role.role_arn)
        {
            continue;
        }
        if found.conditional {
            eprintln!(
                "fob: {} ({}): its trust policy has conditions fob did not check",
                found.label, found.role.role_arn
            );
        }
        chained.insert(found.label.clone(), found.role.clone());
    }
    let (mut chained, mut rules) = fold_chained(chained);
    keep_new(config, &mut chained, &mut rules);
    if chained.is_empty() && rules.is_empty() {
        eprintln!("fob: nothing new found");
        return Ok(());
    }
    let mut toml = String::from(
        "# Found by `fob discover aws`: the policy simulator lets the permission set assume\n\
         # these roles. Trust-policy conditions and resource control policies are not checked,\n\
         # so a role can still refuse.\n",
    );
    toml.push_str(chained_toml(integration, &chained).trim_start());
    toml.push_str(&chained_rules_toml(integration, &rules));
    eprintln!(
        "fob: found {} chained role(s) and {} chained rule(s)",
        chained.len(),
        rules.len()
    );
    if !write {
        print!("{toml}");
        eprintln!(
            "fob: review them, then run again with --write to append them to {}",
            paths::config_file()?.display()
        );
        return Ok(());
    }
    let path = append_to_config(&toml)?;
    eprintln!(
        "fob: added them to {}; run `fob sync {integration}`",
        path.display()
    );
    Ok(())
}

pub(crate) fn import_aws(
    config: &Config,
    file: Option<std::path::PathBuf>,
    write: bool,
) -> anyhow::Result<()> {
    use omnifob_core::import::{
        aws_iam_user_toml, aws_import, aws_login_toml, aws_portal_toml, chained_rules_toml,
        chained_toml, iam_roles_toml, normalize_start_url,
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
            keep_new(existing, &mut portal.chained, &mut portal.chained_rules);
            if portal.chained.is_empty() && portal.chained_rules.is_empty() {
                eprintln!(
                    "fob: {} is already configured as '{name}'",
                    portal.start_url
                );
            } else {
                eprintln!(
                    "fob: {} is configured as '{name}'; {} chained role(s) and {} chained rule(s) to add",
                    portal.start_url,
                    portal.chained.len(),
                    portal.chained_rules.len()
                );
                new_chained += portal.chained.len() + portal.chained_rules.len();
                let mut toml = chained_toml(name, &portal.chained);
                toml.push_str(&chained_rules_toml(name, &portal.chained_rules));
                sections.push(toml.trim_start().to_string());
            }
            continue;
        }
        unique(&mut portal.name);
        eprintln!(
            "fob: {} as '{}': {} profile(s), {} chained role(s), {} chained rule(s)",
            portal.start_url,
            portal.name,
            portal.profiles,
            portal.chained.len(),
            portal.chained_rules.len()
        );
        new_portals += 1;
        new_chained += portal.chained.len() + portal.chained_rules.len();
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
    let path = append_to_config(&toml)?;
    eprintln!(
        "fob: added {} integration(s) and {new_chained} role(s) or rule(s) to {}; run `fob sync`, or `fob login <name>` for new integrations{key_hint}",
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
