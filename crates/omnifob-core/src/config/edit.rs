//! Changes to `config.toml` that keep its comments and layout.

use anyhow::{Context, bail};

use super::{CloudflareTemplate, Config, check_name};

/// Renames an integration in the text of a config file, keeping comments,
/// layout and its sub-tables (chained roles, templates).
pub fn rename_integration(text: &str, old: &str, new: &str) -> anyhow::Result<Renamed> {
    check_name("integration name", new)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let integrations = doc
        .get_mut("integrations")
        .and_then(|i| i.as_table_mut())
        .context("the config has no [integrations] table")?;
    if integrations.contains_key(new) {
        bail!("an integration named '{new}' already exists");
    }
    let (key, item) = integrations
        .remove_entry(old)
        .with_context(|| format!("no integration named '{old}'"))?;
    let renamed = toml_edit::Key::new(new)
        .with_leaf_decor(key.leaf_decor().clone())
        .with_dotted_decor(key.dotted_decor().clone());
    integrations.insert_formatted(&renamed, item);
    let references = rename_references(&mut doc, old, new);
    let text = doc.to_string();
    // Other integrations may still have names to fix, one rename at a time.
    Config::parse_allowing_any_names(&text).context("the renamed config is not valid")?;
    Ok(Renamed { text, references })
}

/// A config renamed by [`rename_integration`].
#[derive(Debug)]
pub struct Renamed {
    /// The config's new text.
    pub text: String,
    /// Where profile ids or patterns under the old name were rewritten, as
    /// `[agent] profiles`, `[directories]`, `labels[0].profiles` or
    /// `browsers.<name>.containers[0].profiles`.
    pub references: Vec<String>,
}

/// Rewrites profile ids and patterns that start with `<old>/` to start with
/// `<new>/`, in `[agent] profiles`, `[directories]`, `[[labels]]` and
/// `[[browsers.*.containers]]`, keeping comments; returns where.
fn rename_references(doc: &mut toml_edit::DocumentMut, old: &str, new: &str) -> Vec<String> {
    let prefix = format!("{old}/");
    let rewrite = |value: &mut toml_edit::Value| -> bool {
        let Some(rest) = value.as_str().and_then(|s| s.strip_prefix(&prefix)) else {
            return false;
        };
        let decor = value.decor().clone();
        let mut renamed = toml_edit::Value::from(format!("{new}/{rest}"));
        *renamed.decor_mut() = decor;
        *value = renamed;
        true
    };
    let rewrite_array = |item: Option<&mut toml_edit::Item>| -> bool {
        let Some(array) = item.and_then(|i| i.as_array_mut()) else {
            return false;
        };
        let mut changed = false;
        for value in array.iter_mut() {
            changed |= rewrite(value);
        }
        changed
    };
    let mut references = Vec::new();
    if rewrite_array(doc.get_mut("agent").and_then(|a| a.get_mut("profiles"))) {
        references.push("[agent] profiles".to_string());
    }
    if let Some(dirs) = doc
        .get_mut("directories")
        .and_then(|d| d.as_table_like_mut())
    {
        let mut changed = false;
        for (_, item) in dirs.iter_mut() {
            if let Some(value) = item.as_value_mut() {
                changed |= rewrite(value);
            }
        }
        if changed {
            references.push("[directories]".to_string());
        }
    }
    if let Some(labels) = doc
        .get_mut("labels")
        .and_then(|l| l.as_array_of_tables_mut())
    {
        for (i, label) in labels.iter_mut().enumerate() {
            if rewrite_array(label.get_mut("profiles")) {
                references.push(format!("labels[{i}].profiles"));
            }
        }
    }
    if let Some(browsers) = doc.get_mut("browsers").and_then(|b| b.as_table_like_mut()) {
        for (name, browser) in browsers.iter_mut() {
            let Some(styles) = browser
                .get_mut("containers")
                .and_then(|c| c.as_array_of_tables_mut())
            else {
                continue;
            };
            for (i, style) in styles.iter_mut().enumerate() {
                if rewrite_array(style.get_mut("profiles")) {
                    references.push(format!("browsers.{name}.containers[{i}].profiles"));
                }
            }
        }
    }
    references
}

/// Adds a template to a Cloudflare integration in the config text, keeping
/// the rest of the file as it is. An existing template of that name is
/// replaced only with `replace`.
pub fn add_cloudflare_template(
    text: &str,
    integration: &str,
    name: &str,
    template: &CloudflareTemplate,
    replace: bool,
) -> anyhow::Result<String> {
    check_name("template name", name)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let table = doc
        .get_mut("integrations")
        .and_then(|i| i.get_mut(integration))
        .and_then(|i| i.as_table_mut())
        .with_context(|| format!("no integration named '{integration}'"))?;
    if table
        .get("type")
        .and_then(|t| t.as_str())
        .is_none_or(|t| !t.starts_with("cloudflare-"))
    {
        bail!("'{integration}' is not a cloudflare integration");
    }
    let templates = table
        .entry("templates")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut()
        .context("`templates` must be a table")?;
    if templates.contains_key(name) && !replace {
        bail!("integration '{integration}' already has a template named '{name}'");
    }
    let mut new = toml_edit::Table::new();
    new["permissions"] =
        toml_edit::value(template.permissions.iter().collect::<toml_edit::Array>());
    if !template.optional.is_empty() {
        new["optional"] = toml_edit::value(template.optional.iter().collect::<toml_edit::Array>());
    }
    if let Some(ttl) = template.ttl {
        new["ttl"] = toml_edit::value(format!("{ttl:#}"));
    }
    if !template.r2_buckets.is_empty() {
        new["r2_buckets"] =
            toml_edit::value(template.r2_buckets.iter().collect::<toml_edit::Array>());
    }
    if template.s3 {
        new["s3"] = toml_edit::value(true);
    }
    if !template.zones.is_empty() {
        new["zones"] = toml_edit::value(template.zones.iter().collect::<toml_edit::Array>());
    }
    if let Some(ips) = &template.ips {
        new["ips"] = toml_edit::value(ips.iter().collect::<toml_edit::Array>());
    }
    templates.insert(name, toml_edit::Item::Table(new));
    let text = doc.to_string();
    Config::parse(&text).context("the new template does not make a valid config")?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn renames_keep_comments_order_and_subtables() {
        let text = "# mine\n[integrations.mine] # personal\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n\n[integrations.mine.chained.lab]\nvia_account_id = \"111111111111\"\nvia_role = \"A\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\n\n[integrations.cf]\ntype = \"cloudflare-token\"\n";
        let renamed = rename_integration(text, "mine", "aws").unwrap();
        assert_eq!(
            renamed.text,
            text.replace("integrations.mine", "integrations.aws")
        );
        assert!(renamed.references.is_empty());
        assert!(
            rename_integration(text, "mine", "cf")
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert!(
            rename_integration(text, "nope", "x")
                .unwrap_err()
                .to_string()
                .contains("no integration")
        );
        for bad in ["a/b", "a b", "", "a\"b"] {
            assert!(
                rename_integration(text, "mine", bad).is_err(),
                "{bad:?} is refused"
            );
        }
    }

    #[test]
    fn renames_rewrite_profile_references_and_keep_their_comments() {
        let text = r#"[integrations.mine]
type = "aws-sso"
start_url = "https://a.awsapps.com/start"
region = "eu-west-1"

[agent]
profiles = ["mine/dev/*", # dev
  "other/*/*"]

[directories]
"~/code/a" = "mine/dev/Admin" # a
"~/code/b" = "other/x/Y"

[[labels]]
profiles = ["mine/*-prd/*"]
env = "prod"

[[labels]]
profiles = ["*/dev/*"]
env = "dev"

[browsers.ff]
type = "firefox"

[[browsers.ff.containers]]
profiles = ["mine/prod/*"]
color = "red"
"#;
        let renamed = rename_integration(text, "mine", "aws").unwrap();
        assert_eq!(
            renamed.references,
            [
                "[agent] profiles",
                "[directories]",
                "labels[0].profiles",
                "browsers.ff.containers[0].profiles"
            ]
        );
        assert_eq!(
            renamed.text,
            text.replace("integrations.mine", "integrations.aws")
                .replace("\"mine/", "\"aws/")
        );
    }

    #[test]
    fn adds_cloudflare_templates() {
        let text = "# mine\n[integrations.cf] # work\ntype = \"cloudflare-token\"\n\n[integrations.mine]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n";
        let template = CloudflareTemplate {
            permissions: vec!["Pages Write".into(), "Zone Read".into()],
            optional: vec![],
            ttl: Some(SignedDuration::from_mins(90)),
            ..Default::default()
        };
        let added = add_cloudflare_template(text, "cf", "pages", &template, false).unwrap();
        assert!(
            added.starts_with("# mine\n[integrations.cf] # work\n"),
            "{added}"
        );
        let config = Config::parse(&added).unwrap();
        let Integration::Cloudflare(cf) = config.integration("cf").unwrap() else {
            panic!("not cloudflare");
        };
        assert_eq!(cf.templates["pages"], template);
        let err = |r: anyhow::Result<String>| r.unwrap_err().to_string();
        assert!(
            err(add_cloudflare_template(
                &added, "cf", "pages", &template, false
            ))
            .contains("already has")
        );
        assert!(add_cloudflare_template(&added, "cf", "pages", &template, true).is_ok());
        assert!(
            err(add_cloudflare_template(text, "mine", "x", &template, false))
                .contains("not a cloudflare")
        );
        assert!(
            err(add_cloudflare_template(text, "nope", "x", &template, false))
                .contains("no integration")
        );
        for bad in ["a/b", "my pages", ""] {
            assert!(
                add_cloudflare_template(text, "cf", bad, &template, false).is_err(),
                "{bad:?} is refused"
            );
        }
    }
}
