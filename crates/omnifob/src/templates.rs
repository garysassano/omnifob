//! `fob cloudflare`: permissions and token templates.

use anyhow::{Context, bail};
use dialoguer::console::Term;
use omnifob_core::providers::cloudflare;
use omnifob_core::{Config, Integration, paths};

use crate::cli::CloudflareCommand;
use crate::files::write_atomically;
use crate::{App, interactive};

impl App {
    pub(crate) async fn cloudflare(&self, command: CloudflareCommand) -> anyhow::Result<()> {
        let cloudflare_config = |name: &str| match self.config.integration(name)? {
            Integration::Cloudflare(c) => Ok(c.clone()),
            other => bail!(
                "'{name}' is an {} integration, not cloudflare",
                other.kind()
            ),
        };
        match command {
            CloudflareCommand::Permissions {
                integration,
                filter,
            } => {
                let config = cloudflare_config(&integration)?;
                let groups = self
                    .with_login(|| cloudflare::permission_groups(&integration, &config))
                    .await?;
                let filter = filter.map(|f| f.to_lowercase());
                for group in groups {
                    if filter
                        .as_ref()
                        .is_none_or(|f| group.name.to_lowercase().contains(f))
                    {
                        let scope = group
                            .scopes
                            .first()
                            .map_or("", |s| s.rsplit('.').next().unwrap_or(s));
                        println!("{:<50} {scope}", group.name);
                    }
                }
            }
            CloudflareCommand::Templates { integration } => {
                let config = cloudflare_config(&integration)?;
                let mut templates = cloudflare::builtin_templates();
                templates.extend(config.templates.clone());
                for (name, template) in templates {
                    let ttl = template.ttl.unwrap_or(config.ttl);
                    println!("{name} ({ttl:#}): {}", template.permissions.join(", "));
                    if !template.optional.is_empty() {
                        println!("  when available: {}", template.optional.join(", "));
                    }
                    if !template.r2_buckets.is_empty() {
                        println!("  R2 buckets: {}", template.r2_buckets.join(", "));
                    }
                    if template.s3 {
                        println!("  with R2 S3 credentials");
                    }
                    let ips = template.ips.as_ref().unwrap_or(&config.ips);
                    if !ips.is_empty() {
                        println!("  usable from: {}", ips.join(", "));
                    }
                }
            }
            CloudflareCommand::AddTemplate { .. } => unreachable!("handled in run"),
        }
        Ok(())
    }

    /// Writes a new Cloudflare template to the config and syncs, so its
    /// profiles can be used at once. `template` holds what the command line
    /// gave; without permissions, they are picked interactively.
    pub(crate) async fn add_template(
        &mut self,
        integration: &str,
        name: &str,
        mut template: omnifob_core::config::CloudflareTemplate,
        replace: bool,
    ) -> anyhow::Result<()> {
        // Before signing in or picking permissions, which the name would waste.
        omnifob_core::config::check_name("template name", name)?;
        let config = match self.config.integration(integration)? {
            Integration::Cloudflare(c) => c.clone(),
            other => bail!(
                "'{integration}' is an {} integration, not cloudflare",
                other.kind()
            ),
        };
        if config.templates.contains_key(name) && !replace {
            bail!(
                "'{integration}' already has a template named '{name}'; add --replace to overwrite it"
            );
        }
        let groups = self
            .with_login(|| cloudflare::permission_groups(integration, &config))
            .await?;
        let permissions = if template.permissions.is_empty() {
            if !interactive() {
                bail!(
                    "name the permissions with --permission, or run this in a terminal to pick them"
                );
            }
            pick_permissions(&cloudflare::services(&groups, config.minting()))?
        } else {
            // Check the names now rather than at the first mint, and store
            // them as Cloudflare spells them.
            cloudflare::resolve_permissions(&template.permissions, &groups)?
                .into_iter()
                .map(|g| g.name.clone())
                .collect()
        };
        if permissions.is_empty() {
            bail!("no permissions picked; nothing was saved");
        }
        if cloudflare::builtin_templates().contains_key(name) {
            eprintln!(
                "fob: '{name}' replaces the built-in template of that name for '{integration}'"
            );
        }

        // Optional permissions are kept as given: an account that does not
        // offer one now may later, which is what they are for.
        template.permissions = permissions;
        let path = paths::config_file();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let text = omnifob_core::config::add_cloudflare_template(
            &text,
            integration,
            name,
            &template,
            replace,
        )?;
        write_atomically(&path, &text)?;
        self.config = Config::parse(&text)?;
        eprintln!(
            "fob: added template '{name}' to '{integration}' ({}):",
            path.display()
        );
        for permission in &template.permissions {
            eprintln!("       {permission}");
        }
        for permission in &template.optional {
            eprintln!("       {permission} (when available)");
        }
        self.sync(&[integration.to_string()]).await
    }
}

/// Lets the user pick services and an access level for each, the way the
/// dashboard's token form does, but searchable. Returns permission names.
pub(crate) fn pick_permissions(services: &[cloudflare::Service]) -> anyhow::Result<Vec<String>> {
    // Index of the chosen permission per service: read, write or another.
    let mut chosen: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
    let mut cursor = 0;
    let term = Term::stderr();
    eprintln!("fob: pick a service, then its access; pick \"Done\" to save.");
    loop {
        let mut items = vec![match chosen.len() {
            0 => "Done (cancel: nothing picked yet)".to_string(),
            n => format!("Done: save {n} permission{}", if n == 1 { "" } else { "s" }),
        }];
        items.extend(services.iter().enumerate().map(|(i, s)| {
            let picked = chosen.get(&i).map_or(String::new(), |p| format!("  [{p}]"));
            format!("{:<44} {:<8}{picked}", s.name, s.scope())
        }));
        let Some(picked) = dialoguer::FuzzySelect::new()
            .with_prompt(format!("Services ({} picked)", chosen.len()))
            .items(&items)
            .default(cursor)
            .interact_on_opt(&term)?
        else {
            bail!("cancelled; nothing was saved");
        };
        if picked == 0 {
            return Ok(chosen.into_values().collect());
        }
        cursor = picked;
        let index = picked - 1;
        let service = &services[index];
        let mut options: Vec<(String, Option<String>)> = Vec::new();
        if let Some(g) = &service.read {
            options.push(("Read".into(), Some(g.name.clone())));
        }
        if let Some(g) = &service.write {
            options.push(("Edit (read and write)".into(), Some(g.name.clone())));
        }
        for g in &service.other {
            options.push((g.name.clone(), Some(g.name.clone())));
        }
        if chosen.contains_key(&index) {
            options.push(("None (remove)".into(), None));
        }
        let labels: Vec<&str> = options.iter().map(|(label, _)| label.as_str()).collect();
        let Some(level) = dialoguer::Select::new()
            .with_prompt(service.name.as_str())
            .items(&labels)
            .default(0)
            .interact_on_opt(&term)?
        else {
            continue;
        };
        match &options[level].1 {
            Some(name) => chosen.insert(index, name.clone()),
            None => chosen.remove(&index),
        };
    }
}
