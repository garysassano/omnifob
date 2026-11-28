//! `fob add`: writes a new integration to the config, from options or from
//! a few questions, so a first setup needs no hand-written TOML.

use anyhow::{Context, bail};
use dialoguer::console::Term;
use omnifob_core::config::{NewValue, add_integration, check_name, integration_toml};
use omnifob_core::providers::aws::partition::check_region_name;
use omnifob_core::providers::token::{self, AuthScheme, Preset};
use omnifob_core::{Config, paths};

use crate::cli::AddTokenType;
use crate::files::write_atomically;
use crate::{App, interactive};

/// The integration types `fob add` writes, with what each signs in to.
pub(crate) const KINDS: &[(&str, &str)] = &[
    ("aws-sso", "AWS IAM Identity Center"),
    ("aws-login", "AWS console sign-in, as `aws login`"),
    ("aws-iam", "AWS IAM user with an access key"),
    ("gcp", "Google Cloud"),
    ("azure", "Azure (Entra ID)"),
    ("cloudflare-token", "Cloudflare, with a bootstrap token"),
    ("cloudflare-oauth", "Cloudflare, with a browser sign-in"),
];

/// The options of `fob add`, as the command line gave them.
#[derive(Default)]
pub(crate) struct AddArgs {
    pub(crate) kind: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) start_url: Option<String>,
    pub(crate) sso_region: Option<String>,
    pub(crate) login_region: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) mfa_serial: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) projects: Vec<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) token_type: Option<AddTokenType>,
    pub(crate) account_id: Option<String>,
    pub(crate) vars: Vec<String>,
    pub(crate) login: bool,
    pub(crate) print: bool,
}

/// What is being added: an integration type, or `token` with a preset.
#[derive(Clone, Copy)]
enum Kind {
    Type(&'static str),
    Token(&'static Preset),
}

impl Kind {
    fn parse(kind: &str) -> anyhow::Result<Self> {
        if let Some((name, _)) = KINDS.iter().find(|(k, _)| *k == kind) {
            return Ok(Kind::Type(name));
        }
        if let Some(preset) = token::PRESETS.iter().find(|p| p.name == kind) {
            return Ok(Kind::Token(preset));
        }
        match kind {
            "token" => bail!(
                "name the provider's preset instead of `token`, e.g. `fob add hetzner`; presets: {}. \
                 A provider without one goes in the config by hand (docs/guides/configuration.md#token-only-providers-token)",
                preset_names()
            ),
            "command" => bail!(
                "a command integration runs a program you name, so it goes in the config by hand \
                 (docs/guides/configuration.md#any-program-command)"
            ),
            other => bail!(
                "unknown type '{other}'; types: {}; token presets: {}",
                KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", "),
                preset_names()
            ),
        }
    }

    /// The `type` written to the config.
    fn type_name(self) -> &'static str {
        match self {
            Kind::Type(name) => name,
            Kind::Token(_) => "token",
        }
    }

    /// The name suggested for a new integration of this kind.
    fn suggested_name(self, start_url: Option<&str>) -> String {
        match self {
            Kind::Type("aws-sso") => start_url
                .map(omnifob_core::import::portal_name)
                .unwrap_or_else(|| "aws".into()),
            Kind::Type("aws-login") => "console".into(),
            Kind::Type("aws-iam") => "iam".into(),
            Kind::Type("gcp") => "google".into(),
            Kind::Type("azure") => "azure".into(),
            Kind::Type(_) => "cloudflare".into(),
            Kind::Token(preset) => preset.name.into(),
        }
    }
}

fn preset_names() -> String {
    token::PRESETS
        .iter()
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Which options apply to which types, so one given to another type is
/// refused rather than dropped.
fn check_options(kind: Kind, args: &AddArgs) -> anyhow::Result<()> {
    let ty = kind.type_name();
    let given = [
        ("--start-url", args.start_url.is_some(), &["aws-sso"][..]),
        ("--sso-region", args.sso_region.is_some(), &["aws-sso"]),
        (
            "--login-region",
            args.login_region.is_some(),
            &["aws-login"],
        ),
        (
            "--region",
            args.region.is_some(),
            &["aws-sso", "aws-login", "aws-iam"],
        ),
        ("--mfa-serial", args.mfa_serial.is_some(), &["aws-iam"]),
        ("--tenant", args.tenant.is_some(), &["azure"]),
        ("--project", !args.projects.is_empty(), &["gcp"]),
        (
            "--client-id",
            args.client_id.is_some(),
            &["cloudflare-oauth"],
        ),
        (
            "--token-type",
            args.token_type.is_some(),
            &["cloudflare-token"],
        ),
        (
            "--account-id",
            args.account_id.is_some(),
            &["cloudflare-token"],
        ),
        ("--var", !args.vars.is_empty(), &["token"]),
    ];
    for (option, set, types) in given {
        if set && !types.contains(&ty) {
            bail!("{option} applies only to {}, not {ty}", types.join(" and "));
        }
    }
    if args.account_id.is_some() && args.token_type != Some(AddTokenType::Account) {
        bail!("--account-id needs --token-type account");
    }
    Ok(())
}

/// Asks for a value, or fails naming the option when no one can answer.
struct Asker {
    interactive: bool,
    kind: &'static str,
}

impl Asker {
    /// A required value: the option's, else asked for.
    fn required(
        &self,
        given: Option<String>,
        option: &str,
        prompt: &str,
        default: Option<String>,
        check: fn(&str) -> Result<(), String>,
    ) -> anyhow::Result<String> {
        if let Some(value) = given {
            return Ok(value);
        }
        if !self.interactive {
            return default.with_context(|| {
                format!(
                    "{} needs {option} ({prompt}), or run this in a terminal to be asked",
                    self.kind
                )
            });
        }
        let mut input = dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .validate_with(|v: &String| check(v.trim()));
        if let Some(default) = default {
            input = input.default(default);
        }
        Ok(input.interact_text_on(&Term::stderr())?.trim().to_string())
    }

    /// An optional value: the option's, else asked for when someone can
    /// answer (Enter leaves it out).
    fn optional(
        &self,
        given: Option<String>,
        prompt: &str,
        check: fn(&str) -> Result<(), String>,
    ) -> anyhow::Result<Option<String>> {
        if given.is_some() || !self.interactive {
            return Ok(given);
        }
        let value = dialoguer::Input::<String>::new()
            .with_prompt(format!("{prompt} (Enter to leave out)"))
            .allow_empty(true)
            .validate_with(|v: &String| match v.trim() {
                "" => Ok(()),
                v => check(v),
            })
            .interact_text_on(&Term::stderr())?;
        Ok(Some(value.trim().to_string()).filter(|v| !v.is_empty()))
    }
}

fn region(value: &str) -> Result<(), String> {
    check_region_name(value).map_err(|e| format!("{e:#}"))
}

fn start_url(value: &str) -> Result<(), String> {
    if value.starts_with("https://") && value.len() > "https://".len() {
        Ok(())
    } else {
        Err("the portal URL starts with https://, e.g. https://acme.awsapps.com/start".into())
    }
}

fn not_blank(value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err("must not be empty".into())
    } else {
        Ok(())
    }
}

fn anything(_: &str) -> Result<(), String> {
    Ok(())
}

/// The integration's keys, from the options and answers.
fn keys(
    kind: Kind,
    args: &mut AddArgs,
    ask: &Asker,
) -> anyhow::Result<Vec<(&'static str, NewValue)>> {
    let mut keys: Vec<(&'static str, NewValue)> = Vec::new();
    let mut push = |key: &'static str, value: Option<String>| {
        if let Some(value) = value {
            keys.push((key, value.into()));
        }
    };
    match kind {
        Kind::Type("aws-sso") => {
            let url = ask.required(
                args.start_url.take(),
                "--start-url",
                "AWS access portal URL",
                None,
                start_url,
            )?;
            let from_url = omnifob_core::import::portal_region(&url);
            let sso_region = ask.required(
                args.sso_region.take(),
                "--sso-region",
                "Region IAM Identity Center runs in",
                from_url,
                region,
            )?;
            args.start_url = Some(url.clone());
            push("start_url", Some(url));
            push("sso_region", Some(sso_region));
            push(
                "region",
                ask.optional(args.region.take(), "Region exported as AWS_REGION", region)?,
            );
        }
        Kind::Type("aws-login") => {
            push(
                "login_region",
                Some(ask.required(
                    args.login_region.take(),
                    "--login-region",
                    "Region to sign in through",
                    None,
                    region,
                )?),
            );
            push("region", args.region.take());
        }
        Kind::Type("aws-iam") => {
            push(
                "region",
                ask.optional(args.region.take(), "Region for STS and AWS_REGION", region)?,
            );
            push(
                "mfa_serial",
                ask.optional(args.mfa_serial.take(), "MFA device ARN", anything)?,
            );
        }
        Kind::Type("gcp") => {
            if !args.projects.is_empty() {
                keys.push(("projects", NewValue::Strings(args.projects.clone())));
            }
        }
        Kind::Type("azure") => push("tenant", args.tenant.take()),
        Kind::Type("cloudflare-oauth") => {
            if args.client_id.is_none() && ask.interactive {
                eprintln!(
                    "fob: a browser sign-in needs an OAuth client registered in your Cloudflare \
                     account once; docs/guides/cloudflare.md#the-oauth-client shows how"
                );
            }
            push(
                "client_id",
                Some(ask.required(
                    args.client_id.take(),
                    "--client-id",
                    "OAuth client ID",
                    None,
                    not_blank,
                )?),
            );
        }
        Kind::Type("cloudflare-token") => {
            let token_type = match args.token_type {
                Some(t) => t,
                None if ask.interactive => {
                    let picked = dialoguer::Select::new()
                        .with_prompt("Who owns the bootstrap token?")
                        .items([
                            "You (user-owned): reaches every account you belong to",
                            "One account (account-owned)",
                        ])
                        .default(0)
                        .interact_on(&Term::stderr())?;
                    if picked == 0 {
                        AddTokenType::User
                    } else {
                        AddTokenType::Account
                    }
                }
                None => AddTokenType::User,
            };
            if token_type == AddTokenType::Account {
                push("token_type", Some("account".into()));
                push(
                    "account_id",
                    Some(ask.required(
                        args.account_id.take(),
                        "--account-id",
                        "Cloudflare account ID",
                        None,
                        not_blank,
                    )?),
                );
            }
        }
        Kind::Type(other) => unreachable!("no keys for {other}"),
        Kind::Token(preset) => {
            push("preset", Some(preset.name.into()));
            let mut vars: Vec<(String, String)> = Vec::new();
            for var in &args.vars {
                let (name, value) = var
                    .split_once('=')
                    .with_context(|| format!("--var {var}: write it as NAME=VALUE"))?;
                vars.push((name.trim().to_string(), value.to_string()));
            }
            // A preset that checks the token with a variable as the user
            // (Upstash's email) needs it.
            if let Some(token::Verify {
                scheme: AuthScheme::Basic { user_var },
                ..
            }) = preset.verify
                && !vars.iter().any(|(name, _)| name == user_var)
            {
                let value = ask.required(
                    None,
                    &format!("--var {user_var}=..."),
                    user_var,
                    None,
                    not_blank,
                )?;
                vars.push((user_var.to_string(), value));
            }
            if !vars.is_empty() {
                keys.push(("vars", NewValue::Map(vars)));
            }
        }
    }
    Ok(keys)
}

impl App {
    /// `fob add`: works out the kind, name and keys, writes the integration
    /// (or prints it), and signs in when asked.
    pub(crate) async fn add(&mut self, mut args: AddArgs) -> anyhow::Result<()> {
        let interactive = interactive();
        let kind = match args.kind.take() {
            Some(kind) => Kind::parse(&kind)?,
            None if interactive => pick_kind()?,
            None => bail!(
                "name the type or token preset to add, e.g. `fob add gcp` or `fob add hetzner`, \
                 or run this in a terminal to pick one; types: {}; token presets: {}",
                KINDS.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", "),
                preset_names()
            ),
        };
        check_options(kind, &args)?;
        // A name given up front is checked before any question.
        if let Some(name) = &args.name {
            self.check_new_name(name)?;
        }
        let ask = Asker {
            interactive,
            kind: kind.type_name(),
        };
        let keys = keys(kind, &mut args, &ask)?;
        let name = match args.name.take() {
            Some(name) => name,
            None => self.new_name(kind.suggested_name(args.start_url.as_deref()), interactive)?,
        };

        if args.print {
            print!("{}", integration_toml(&name, kind.type_name(), &keys));
            return Ok(());
        }
        let path = paths::config_file()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let text = add_integration(&text, &name, kind.type_name(), &keys)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        write_atomically(&path, &text)?;
        self.config = Config::parse(&text)?;
        eprintln!(
            "fob: added '{name}' ({}) to {}",
            kind.type_name(),
            path.display()
        );

        let sign_in = args.login
            || (interactive
                && dialoguer::Confirm::new()
                    .with_prompt(format!("Sign in to '{name}' now?"))
                    .default(true)
                    .interact_on(&Term::stderr())?);
        if sign_in {
            self.login(&name, false, false, false, false, false).await?;
            self.sync(std::slice::from_ref(&name)).await?;
        } else {
            eprintln!("fob: run `fob login {name}` to sign in");
        }
        Ok(())
    }

    fn check_new_name(&self, name: &str) -> anyhow::Result<()> {
        check_name("integration name", name)?;
        if self.config.integrations.contains_key(name) {
            bail!("an integration named '{name}' already exists");
        }
        Ok(())
    }

    /// The suggested name when it is free and no one can be asked; else
    /// asks, offering it.
    fn new_name(&self, suggested: String, interactive: bool) -> anyhow::Result<String> {
        if !interactive {
            return match self.check_new_name(&suggested) {
                Ok(()) => Ok(suggested),
                Err(e) => Err(e.context("name the integration: `fob add <type> <name>`")),
            };
        }
        let taken = |name: &str| self.config.integrations.contains_key(name);
        let mut default = suggested.clone();
        let mut n = 1;
        while taken(&default) {
            n += 1;
            default = format!("{suggested}-{n}");
        }
        let name = dialoguer::Input::<String>::new()
            .with_prompt("Name (the first part of its profile ids)")
            .default(default)
            .validate_with(|v: &String| self.check_new_name(v.trim()).map_err(|e| e.to_string()))
            .interact_text_on(&Term::stderr())?;
        Ok(name.trim().to_string())
    }
}

/// Lets the user pick the type or token preset to add.
fn pick_kind() -> anyhow::Result<Kind> {
    let mut items: Vec<String> = KINDS
        .iter()
        .map(|(kind, title)| format!("{title} ({kind})"))
        .collect();
    items.extend(
        token::PRESETS
            .iter()
            .map(|p| format!("{} (token, preset {})", p.title, p.name)),
    );
    let picked = dialoguer::FuzzySelect::new()
        .with_prompt("What to add (type to search)")
        .items(&items)
        .default(0)
        .interact_on_opt(&Term::stderr())?
        .context("nothing picked; nothing was added")?;
    Ok(match KINDS.get(picked) {
        Some((kind, _)) => Kind::Type(kind),
        None => Kind::Token(&token::PRESETS[picked - KINDS.len()]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> AddArgs {
        AddArgs::default()
    }

    const NO_ONE: Asker = Asker {
        interactive: false,
        kind: "aws-sso",
    };

    #[test]
    fn kinds_are_types_or_presets() {
        assert!(matches!(
            Kind::parse("aws-sso").unwrap(),
            Kind::Type("aws-sso")
        ));
        assert!(matches!(Kind::parse("hetzner").unwrap(), Kind::Token(p) if p.name == "hetzner"));
        for (kind, hint) in [
            ("token", "name the provider's preset"),
            ("command", "by hand"),
            ("aws", "unknown type 'aws'"),
        ] {
            let err = Kind::parse(kind).err().unwrap().to_string();
            assert!(err.contains(hint), "{kind}: {err}");
        }
    }

    #[test]
    fn options_for_another_type_are_refused() {
        let mut a = args();
        a.tenant = Some("contoso".into());
        let err = check_options(Kind::Type("gcp"), &a)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "--tenant applies only to azure, not gcp");
        let mut a = args();
        a.account_id = Some("x".into());
        let err = check_options(Kind::Type("cloudflare-token"), &a).unwrap_err();
        assert!(err.to_string().contains("--token-type account"), "{err}");
        let mut a = args();
        a.region = Some("eu-west-1".into());
        assert!(check_options(Kind::Type("aws-iam"), &a).is_ok());
    }

    #[test]
    fn keys_come_from_the_options() {
        // A regional portal URL gives the Region it runs in.
        let mut a = args();
        a.start_url = Some("https://ssoins-1111aaaa2222bbbb.portal.eu-west-1.app.aws".into());
        let written = keys(Kind::Type("aws-sso"), &mut a, &NO_ONE).unwrap();
        let text = integration_toml("x", "aws-sso", &written);
        assert!(text.contains("sso_region = \"eu-west-1\"\n"), "{text}");
        assert!(!text.contains("\nregion"), "{text}");

        // An awsapps.com URL does not, so the option is needed.
        let mut a = args();
        a.start_url = Some("https://acme.awsapps.com/start".into());
        let err = keys(Kind::Type("aws-sso"), &mut a, &NO_ONE).unwrap_err();
        assert!(err.to_string().contains("--sso-region"), "{err}");

        let mut a = args();
        a.token_type = Some(AddTokenType::Account);
        a.account_id = Some("0123456789abcdef0123456789abcdef".into());
        let ask = Asker {
            interactive: false,
            kind: "cloudflare-token",
        };
        let written = keys(Kind::Type("cloudflare-token"), &mut a, &ask).unwrap();
        let text = integration_toml("cf", "cloudflare-token", &written);
        assert!(
            text.contains("token_type = \"account\"\naccount_id = "),
            "{text}"
        );

        // Upstash checks its key with the account email, so it is required.
        let upstash = Kind::parse("upstash").unwrap();
        let ask = Asker {
            interactive: false,
            kind: "token",
        };
        let err = keys(upstash, &mut args(), &ask).unwrap_err();
        assert!(err.to_string().contains("--var UPSTASH_EMAIL"), "{err}");
        let mut a = args();
        a.vars = vec!["UPSTASH_EMAIL=me@example.com".into()];
        let written = keys(upstash, &mut a, &ask).unwrap();
        let text = integration_toml("upstash", "token", &written);
        assert!(
            text.contains("preset = \"upstash\"\nvars = { UPSTASH_EMAIL = \"me@example.com\" }"),
            "{text}"
        );
    }

    #[test]
    fn suggested_names_follow_the_kind() {
        assert_eq!(
            Kind::Type("aws-sso").suggested_name(Some("https://acme.awsapps.com/start")),
            "acme"
        );
        assert_eq!(Kind::Type("gcp").suggested_name(None), "google");
        assert_eq!(Kind::parse("fly").unwrap().suggested_name(None), "fly");
    }
}
