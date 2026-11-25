//! The command line's arguments, and shell completion of their values.

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::{ArgValueCandidates, CompletionCandidate};
use omnifob_core::history::{self, History};
use omnifob_core::profile::ProfileCache;
use omnifob_core::{Config, paths};

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
    },
    /// Check that sign-ins work, or that a profile's credentials do (never signs in)
    Check {
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
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        old: String,
        new: String,
    },
    /// Discover profiles (every integration when none is given)
    Sync {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integrations: Vec<String>,
    },
    /// List profiles, optionally filtered
    #[command(visible_alias = "ls")]
    List {
        /// Words that the profiles must match, as other commands take them
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        query: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print shell code exporting a profile's credentials (pick one when omitted)
    Env {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = Shell::detect())]
        shell: Shell,
        /// Print code that removes the variables of the active profile instead
        #[arg(long, conflicts_with = "profile")]
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
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
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
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Open the provider's web console as a profile
    Console {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
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
        #[arg(required = true, add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = CredsFormat::Json)]
        format: CredsFormat,
        /// The EKS cluster's name, for `--format k8s-exec` with an AWS profile
        #[arg(long)]
        cluster: Option<String>,
        /// The Region of the EKS cluster's STS endpoint, for `--format
        /// k8s-exec` (default: the profile's, else us-east-1)
        #[arg(long)]
        region: Option<String>,
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
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        /// Every profile: deletes every token omnifob minted and clears every
        /// cached credential
        #[arg(long, conflicts_with = "profile")]
        all: bool,
    },
    /// Switch the current shell to a profile (needs the shell integration from `fob activate`)
    Use {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
    },
    /// Remove the active profile's variables from the current shell (needs `fob activate`)
    Unuse,
    /// Print shell integration: adds `fob use <profile>` and `fob unuse`
    Activate { shell: Shell },
    /// Create integrations from other tools' configuration
    #[command(subcommand)]
    Import(ImportCommand),
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
        #[arg(required = true, add = ArgValueCandidates::new(profile_candidates))]
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
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: String,
        /// Only show permissions whose name contains this
        filter: Option<String>,
    },
    /// List templates and their permissions
    Templates {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: String,
    },
    /// Create a template: pick services and their access level from the
    /// account's permissions, or name the permissions with --permission
    AddTemplate {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
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
    let Ok(cache) = profiles_file().and_then(|file| ProfileCache::load(&file)) else {
        return Vec::new();
    };
    let mut profiles: Vec<_> = cache.all().collect();
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
    let Ok(config) = paths::config_file().and_then(|file| Config::load_allowing_any_names(&file))
    else {
        return Vec::new();
    };
    config
        .integrations
        .iter()
        .map(|(name, i)| CompletionCandidate::new(name).help(Some(i.kind().into())))
        .collect()
}
