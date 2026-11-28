//! The command line's arguments, and shell completion of their values.

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::{ArgValueCandidates, CompletionCandidate};
use omnifob_core::history::{self, History};
use omnifob_core::profile::ProfileCache;
use omnifob_core::{Config, Profile, paths};

use crate::profiles_file;
use crate::shell::Shell;

#[derive(Parser)]
#[command(
    name = "fob",
    version,
    about = "One sign-in for every cloud: short-lived credentials for AWS (Identity Center, IAM users and console sign-in), Google Cloud, Azure and Cloudflare, and stored tokens for the rest",
    after_help = "Config: --config, $OMNIFOB_CONFIG or ~/.config/omnifob/config.toml"
)]
pub(crate) struct Cli {
    /// The config file, instead of $OMNIFOB_CONFIG or
    /// ~/.config/omnifob/config.toml (passed on to the commands fob runs)
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Sign in to an integration, then discover its profiles
    Login {
        /// The integration; without it, pick one from a list
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: Option<String>,
        /// Print the sign-in URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Sign in from a browser on any device instead of this machine's:
        /// AWS IAM Identity Center and Azure show a code to enter there (the
        /// device flow), AWS console sign-in and Google a code to paste back
        /// here. Chosen on its own over SSH and in containers.
        #[arg(long)]
        device_code: bool,
        /// Read the token (a Cloudflare bootstrap token, a token integration's
        /// single secret, or an IAM user's access key ID and secret separated by
        /// whitespace) from stdin instead of prompting
        #[arg(long, conflicts_with = "from_clipboard")]
        token_stdin: bool,
        /// Read the token (a Cloudflare bootstrap token or a token integration's
        /// single secret) from the clipboard instead of prompting
        #[arg(long)]
        from_clipboard: bool,
        /// Sign in again even when the stored browser sign-in (AWS IAM Identity
        /// Center, AWS console sign-in, Google, Azure, Cloudflare OAuth) still works
        #[arg(long)]
        force: bool,
        /// Start a device sign-in and return at once, after printing where to
        /// approve it and the code; `--wait` then finishes it. For agents and
        /// scripts, which see a command's output only when it ends (AWS IAM
        /// Identity Center and Azure)
        #[arg(
            long,
            conflicts_with_all = ["wait", "token_stdin", "from_clipboard", "device_code"]
        )]
        start: bool,
        /// Wait until the sign-in `--start` began is approved, then keep it and
        /// discover profiles
        #[arg(
            long,
            conflicts_with_all = ["token_stdin", "from_clipboard", "device_code", "force", "no_browser"]
        )]
        wait: bool,
    },
    /// Forget an integration's sign-in and cached credentials
    Logout {
        /// The integration; without it, pick one from a list
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: Option<String>,
        /// Sign out of every configured integration
        #[arg(long, conflicts_with = "integration")]
        all: bool,
    },
    /// Show integrations and whether you are signed in
    Status {
        /// Print JSON, for scripts and status bars
        #[arg(long)]
        json: bool,
        /// Also ask each provider whether the sign-in still works, as `fob
        /// check` does; the stored state alone cannot tell whether a session
        /// that renews (an Identity Center portal session) has ended
        #[arg(long)]
        check: bool,
    },
    /// Check that sign-ins work, or that a profile's credentials do (never signs in)
    Check {
        /// The profile whose credentials to check, by its id or words of it;
        /// without it, every integration's sign-in
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        /// Check this integration's sign-in only; repeat for more
        #[arg(
            long,
            conflicts_with = "profile",
            add = ArgValueCandidates::new(integration_candidates)
        )]
        integration: Vec<String>,
        /// Print nothing; only the exit status tells whether everything works
        #[arg(long, short)]
        quiet: bool,
        /// Print the results as JSON
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    /// Rename an integration, keeping its sign-in and discovered profiles
    Rename {
        /// The integration's current name
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        old: String,
        /// Its new name: letters, digits, `.`, `_` and `-`
        new: String,
    },
    /// Discover profiles (every integration when none is given)
    Sync {
        /// The integrations to discover; without them, every one
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integrations: Vec<String>,
    },
    /// List profiles, optionally filtered
    #[command(visible_alias = "ls")]
    List {
        /// Words that the profiles must match, as other commands take them
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        query: Vec<String>,
        /// Print JSON with each profile's account and role, for scripts and agents
        #[arg(long)]
        json: bool,
        /// Only the profiles in one account (an account ID, or a profile in it),
        /// from least to most access: where to look when a role is denied
        #[arg(
            long,
            value_name = "ACCOUNT_OR_PROFILE",
            add = ArgValueCandidates::new(account_candidates)
        )]
        account: Option<String>,
    },
    /// Print shell code exporting a profile's credentials (pick one when omitted)
    Env {
        /// The profile, by its id or words of it; without it, the working
        /// directory's default from `[directories]`, else pick one from a list
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[command(flatten)]
        by: ByAccount,
        /// The shell the code is for (default: the one running fob)
        #[arg(long, value_enum, default_value_t = Shell::detect())]
        shell: Shell,
        /// Print code that removes the variables of the active profile instead
        #[arg(long, conflicts_with_all = ["profile", "account_id", "role", "no_cache", "ttl"])]
        unset: bool,
        /// Get new credentials even if cached ones are still valid
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of new credentials instead of the configured one, e.g. "4h";
        /// not cached (Cloudflare tokens, assumed AWS roles, IAM users, Google
        /// service accounts)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
    },
    /// Run a command with a profile's credentials
    Exec {
        /// The profile; without it, the working directory's default from
        /// `[directories]`, else pick one from a list
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[command(flatten)]
        by: ByAccount,
        /// Get new credentials even if cached ones are still valid
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of new credentials instead of the configured one, e.g. "4h";
        /// not cached (Cloudflare tokens, assumed AWS roles, IAM users, Google
        /// service accounts)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
        /// Mint a token for this command only and revoke it when the command
        /// ends (Cloudflare)
        #[arg(long, conflicts_with = "no_cache")]
        revoke: bool,
        /// Serve the credentials from a loopback container credentials
        /// endpoint (AWS_CONTAINER_CREDENTIALS_FULL_URI) instead of
        /// variables, renewed while the command runs (AWS)
        #[arg(long)]
        server: bool,
        /// Run no managed identity endpoint (Azure) or ADC token endpoint
        /// (Google Cloud) for the command
        #[arg(long, conflicts_with = "server")]
        no_server: bool,
        /// Give gcloud its token in a private file (CLOUDSDK_AUTH_ACCESS_TOKEN_FILE),
        /// renewed while the command runs, instead of CLOUDSDK_AUTH_ACCESS_TOKEN
        /// (Google Cloud)
        #[arg(long)]
        token_file: bool,
        /// The command and its arguments, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Open the provider's web console as a profile
    Console {
        /// The profile, by its id or words of it; without it, pick one from a list
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[command(flatten)]
        by: ByAccount,
        /// Print the URL instead of opening it
        #[arg(long)]
        print: bool,
        /// Copy the URL to the clipboard instead of opening it (over SSH,
        /// to your local terminal's clipboard)
        #[arg(long, conflicts_with = "print")]
        copy: bool,
        /// How long the console session lasts, 15m to 12h, e.g. "8h"
        /// (Identity Center roles and IAM users' roles; overrides
        /// `console_duration`)
        #[arg(long, value_parser = parse_ttl)]
        duration: Option<jiff::SignedDuration>,
        /// The console page to open, e.g. "ec2", "s3" or "cloudformation"
        /// (AWS)
        #[arg(long)]
        service: Option<String>,
        /// The Region the console opens in (AWS)
        #[arg(long)]
        region: Option<String>,
    },
    /// Print credentials for other tools (fnox, AWS credential_process, scripts)
    Creds {
        /// The profile, by its id or words of it
        #[arg(
            required_unless_present_any = ["account_id", "role"],
            add = ArgValueCandidates::new(profile_candidates)
        )]
        profile: Vec<String>,
        #[command(flatten)]
        by: ByAccount,
        /// What to print, for the tool that reads it
        #[arg(long, value_enum, default_value_t = CredsFormat::Json)]
        format: CredsFormat,
        /// The EKS cluster's name, for `--format k8s-exec` with an AWS profile
        #[arg(long)]
        cluster: Option<String>,
        /// The Region of the EKS cluster's STS endpoint, for `--format
        /// k8s-exec` (default: the profile's, else us-east-1)
        #[arg(long)]
        region: Option<String>,
        /// Get new credentials even if cached ones are still valid
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of new credentials instead of the configured one, e.g. "4h";
        /// not cached (Cloudflare tokens, assumed AWS roles, IAM users, Google
        /// service accounts)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
    },
    /// Revoke the credentials omnifob handed out for a profile (Cloudflare
    /// tokens are deleted; AWS role credentials can only be forgotten)
    Revoke {
        /// The profile, by its id or words of it
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        /// Every profile: deletes every token omnifob minted and clears every
        /// cached credential
        #[arg(long, conflicts_with = "profile")]
        all: bool,
    },
    /// Switch the current shell to a profile (needs the shell integration from `fob activate`)
    Use {
        /// The profile, by its id or words of it; without it, the working
        /// directory's default from `[directories]`, else pick one from a list
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
    },
    /// Remove the active profile's variables from the current shell (needs `fob activate`)
    Unuse,
    /// Print shell integration: adds `fob use <profile>` and `fob unuse`
    Activate {
        /// The shell to print the integration for
        shell: Shell,
    },
    /// Create integrations from other tools' configuration
    #[command(subcommand)]
    Import(ImportCommand),
    /// Find roles your sign-ins may assume that the provider does not list
    #[command(subcommand)]
    Discover(DiscoverCommand),
    /// Write configuration for other tools
    #[command(subcommand)]
    Export(ExportCommand),
    /// Cloudflare helpers
    #[command(subcommand, visible_alias = "cf")]
    Cloudflare(CloudflareCommand),
    /// Get replacement credentials for a profile (started by fob in the background)
    #[command(hide = true)]
    Renew { profile: String },
}

/// Picks a profile by its account and role instead of words of its id, so
/// a command written down works for colleagues whose integrations and
/// accounts are named differently.
#[derive(clap::Args)]
pub(crate) struct ByAccount {
    /// The account of the profile instead of naming it: an AWS account ID,
    /// Azure subscription ID, Google Cloud project ID or Cloudflare account ID
    #[arg(long, conflicts_with = "profile", value_name = "ID")]
    pub(crate) account_id: Option<String>,
    /// The role of the profile instead of naming it, e.g.
    /// "AdministratorAccess" (the last part of its id: an AWS role, a
    /// Cloudflare template)
    #[arg(long, conflicts_with = "profile")]
    pub(crate) role: Option<String>,
}

impl ByAccount {
    /// The profile `words` name, or this account and role.
    pub(crate) fn pick<'a>(&'a self, words: &'a Option<String>) -> crate::sync::Pick<'a> {
        crate::sync::Pick {
            query: words.as_deref(),
            account_id: self.account_id.as_deref(),
            role: self.role.as_deref(),
            directory_default: false,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum ImportCommand {
    /// IAM Identity Center portals used by profiles in ~/.aws/config
    /// (standard sso_* keys, sso-session sections and granted's keys)
    Aws {
        /// The AWS config file; defaults to $AWS_CONFIG_FILE or ~/.aws/config
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Append the new integrations to the omnifob config instead of printing them
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum DiscoverCommand {
    /// IAM roles an Identity Center role, an IAM user or a console sign-in
    /// may assume, in its account or another one of the integration, found
    /// with iam:ListRoles and the policy simulator (or the source's own
    /// policies when the simulator is refused); assumes nothing
    Aws {
        /// The aws-sso, aws-iam or aws-login integration to search
        #[arg(add = ArgValueCandidates::new(aws_candidates))]
        integration: String,
        /// Search with this permission set only (repeatable); every one when left out
        #[arg(long = "via", value_name = "PERMISSION_SET")]
        via: Vec<String>,
        /// Append what was found to the config instead of printing it
        #[arg(long)]
        write: bool,
        /// Include CDK bootstrap and other roles tooling assumes for itself,
        /// left out by default
        #[arg(long)]
        all: bool,
        /// Print what was found, skipped and left out as JSON, for scripts
        /// and agents, instead of config
        #[arg(long, conflicts_with = "write")]
        json: bool,
        /// When neither the simulator nor the source's policies can be read,
        /// list the roles whose trust policy lets the source in, unchecked
        /// (printed for review, never written)
        #[arg(long)]
        trust_only: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ExportCommand {
    /// AWS CLI profiles that get credentials from `fob creds`, for tools that
    /// want --profile or AWS_PROFILE (needs `fob` on PATH, or --absolute)
    AwsConfig {
        /// Prefix for the generated profile names
        #[arg(long, default_value = "fob-")]
        prefix: String,
        /// Write the full path of this fob binary instead of `fob`, for editors
        /// and GUI tools that run without your shell's PATH
        #[arg(long)]
        absolute: bool,
        /// Replace omnifob's marked block in the AWS config file instead of printing it
        #[arg(long)]
        write: bool,
        /// The AWS config file; defaults to $AWS_CONFIG_FILE or ~/.aws/config
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
    /// Google Application Default Credentials that run `fob creds --format
    /// gcp-executable` and exchange the account's ID token through a
    /// workload identity pool; holds no token
    GcpAdc {
        /// The Google profile whose account the file signs in as
        #[arg(required = true, add = ArgValueCandidates::new(gcp_profile_candidates))]
        profile: Vec<String>,
        /// The workload identity pool provider that trusts
        /// https://accounts.google.com, as
        /// //iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
        #[arg(long)]
        audience: String,
        /// Write the full path of this fob binary instead of `fob`
        #[arg(long)]
        absolute: bool,
        /// Write the file here instead of printing it
        #[arg(long, value_name = "PATH")]
        write: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum CloudflareCommand {
    /// List the permission names templates can use
    Permissions {
        /// The Cloudflare integration
        #[arg(add = ArgValueCandidates::new(cloudflare_candidates))]
        integration: String,
        /// Only show permissions whose name contains this
        filter: Option<String>,
    },
    /// List templates and their permissions
    Templates {
        /// The Cloudflare integration
        #[arg(add = ArgValueCandidates::new(cloudflare_candidates))]
        integration: String,
    },
    /// Create a template: pick services and their access level from the
    /// account's permissions, or name the permissions with --permission
    AddTemplate {
        /// The Cloudflare integration
        #[arg(add = ArgValueCandidates::new(cloudflare_candidates))]
        integration: String,
        /// Template name; profiles become <integration>/<account>/<name>
        name: String,
        /// A permission, as `fob cf permissions` lists it ("Pages Write");
        /// repeat for more. Without it, fob asks interactively.
        #[arg(long = "permission", short)]
        permissions: Vec<String>,
        /// A permission added when the account offers it and skipped
        /// otherwise; repeat for more
        #[arg(long = "optional")]
        optional: Vec<String>,
        /// An R2 bucket that bucket-level permissions apply to ("eu/name" in
        /// a jurisdiction); repeat for more
        #[arg(long = "r2-bucket")]
        r2_buckets: Vec<String>,
        /// A zone that zone-level permissions apply to, as a domain name or
        /// zone ID; repeat for more (default: every zone in the account)
        #[arg(long = "zone")]
        zones: Vec<String>,
        /// Also hand out R2's S3-compatible credentials
        #[arg(long)]
        s3: bool,
        /// An IP address or CIDR range the tokens work from, instead of the
        /// integration's `ips`; repeat for more
        #[arg(long = "ip")]
        ips: Vec<String>,
        /// Lifetime of the template's tokens, e.g. "30m" (default: the integration's)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
        /// Replace a template of that name in the config
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum CredsFormat {
    /// `{"profile", "env", "expires_at"}`
    Json,
    /// The output a fnox `command` lease expects
    Fnox,
    /// The output AWS `credential_process` expects
    CredentialProcess,
    /// The response of Google's executable-sourced credentials: the
    /// account's ID token (see `fob export gcp-adc`)
    GcpExecutable,
    /// A kubectl exec plugin's `ExecCredential`: an EKS token (with
    /// --cluster), a GKE access token or an AKS Entra ID token
    K8sExec,
}

pub(crate) fn parse_ttl(s: &str) -> anyhow::Result<jiff::SignedDuration> {
    omnifob_core::config::parse_duration(s)
}

/// Profile ids for shell completion, recently used ones first, with the
/// provider kind as a hint.
pub(crate) fn profile_candidates() -> Vec<CompletionCandidate> {
    profiles_where(|_| true)
}

/// Google profiles for shell completion.
fn gcp_profile_candidates() -> Vec<CompletionCandidate> {
    profiles_where(|p| matches!(p.target, omnifob_core::Target::Gcp { .. }))
}

/// Account IDs for shell completion, with the profiles' integration and
/// account name as a hint.
fn account_candidates() -> Vec<CompletionCandidate> {
    let Ok(cache) = profiles_file().and_then(|file| ProfileCache::load(&file)) else {
        return Vec::new();
    };
    let mut accounts = std::collections::BTreeMap::new();
    for profile in cache.all() {
        if let Some(account) = profile.target.account_id() {
            let hint = profile
                .id
                .rsplit_once('/')
                .map_or(profile.id.as_str(), |(head, _)| head);
            accounts
                .entry(account.to_string())
                .or_insert_with(|| hint.to_string());
        }
    }
    accounts
        .into_iter()
        .map(|(account, hint)| CompletionCandidate::new(account).help(Some(hint.into())))
        .collect()
}

/// Profile ids matching `keep` for shell completion, recently used ones
/// first, with the provider kind as a hint.
fn profiles_where(keep: impl Fn(&Profile) -> bool) -> Vec<CompletionCandidate> {
    let Ok(cache) = profiles_file().and_then(|file| ProfileCache::load(&file)) else {
        return Vec::new();
    };
    let mut profiles: Vec<_> = cache.all().filter(|p| keep(p)).collect();
    if let Ok(file) = history::file() {
        History::load(&file).sort_recent_first(&mut profiles, |p| p.id.as_str());
    }
    profiles
        .into_iter()
        .map(|p| {
            let kind = match p.target {
                omnifob_core::Target::Aws { .. } => "aws",
                omnifob_core::Target::AwsChained { .. } => "aws (chained)",
                omnifob_core::Target::AwsCrossPartition { .. } => "aws (cross-partition)",
                omnifob_core::Target::AwsIamSession { .. } => "aws (iam user)",
                omnifob_core::Target::AwsIamRole { .. } => "aws (iam role)",
                omnifob_core::Target::AwsLogin { .. } => "aws (console sign-in)",
                omnifob_core::Target::AwsLoginRole { .. } => "aws (console sign-in role)",
                omnifob_core::Target::Command { aws: true } => "aws (command)",
                omnifob_core::Target::Command { aws: false } => "command",
                omnifob_core::Target::Gcp { .. } => "gcp",
                omnifob_core::Target::Azure { .. } => "azure",
                omnifob_core::Target::GcpServiceAccount { .. } => "gcp (service account)",
                omnifob_core::Target::Cloudflare { .. } => "cloudflare",
                omnifob_core::Target::Token {} => "token",
            };
            CompletionCandidate::new(&p.id).help(Some(kind.into()))
        })
        .collect()
}

/// Integration names for shell completion.
pub(crate) fn integration_candidates() -> Vec<CompletionCandidate> {
    integrations_where(|_| true)
}

/// Names of the AWS integrations `fob discover aws` searches, for shell
/// completion.
fn aws_candidates() -> Vec<CompletionCandidate> {
    integrations_where(|i| {
        matches!(
            i,
            omnifob_core::Integration::AwsSso(_)
                | omnifob_core::Integration::AwsIam(_)
                | omnifob_core::Integration::AwsLogin(_)
        )
    })
}

/// Cloudflare integration names for shell completion.
fn cloudflare_candidates() -> Vec<CompletionCandidate> {
    integrations_where(|i| matches!(i, omnifob_core::Integration::Cloudflare(_)))
}

fn integrations_where(
    keep: impl Fn(&omnifob_core::Integration) -> bool,
) -> Vec<CompletionCandidate> {
    let Ok(config) = paths::config_file().and_then(|file| Config::load_allowing_any_names(&file))
    else {
        return Vec::new();
    };
    config
        .integrations
        .iter()
        .filter(|(_, i)| keep(i))
        .map(|(name, i)| CompletionCandidate::new(name).help(Some(i.kind().into())))
        .collect()
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    /// Every argument says what it is for in `--help`, which is how agents
    /// and people learn a command.
    #[test]
    fn every_argument_has_help() {
        fn walk(command: &clap::Command, path: &str, missing: &mut Vec<String>) {
            if command.is_hide_set() {
                return;
            }
            let path = format!("{path} {}", command.get_name());
            for arg in command.get_arguments() {
                let id = arg.get_id().as_str();
                if arg.is_hide_set() || id == "help" || id == "version" {
                    continue;
                }
                if arg.get_help().is_none() && arg.get_long_help().is_none() {
                    missing.push(format!("{path} {id}"));
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, &path, missing);
            }
        }
        let mut missing = Vec::new();
        walk(&Cli::command(), "", &mut missing);
        assert!(missing.is_empty(), "arguments without help: {missing:?}");
    }
}
