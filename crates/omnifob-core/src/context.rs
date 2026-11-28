//! The context omnifob-core works in: where its files are, which keychain
//! holds its secrets, the HTTP client, who answers an MFA prompt, and where
//! provider calls go.
//!
//! [`Context::from_env`] reads all of it from the standard locations and
//! variables, as the command line does. [`Context::builder`] reads nothing
//! from the environment, for a program that embeds the library, or a test
//! that points it at a mock server and a scratch directory.
//!
//! Functions find their context the way `tracing` finds its span: the one
//! entered on this thread ([`Context::enter`], or [`Context::scope`] for a
//! future, which enters it each time the future is polled, on whichever
//! thread), else the one [`Context::install`]ed for the process, else one
//! built by [`Context::from_env`] when first needed. So signatures do not
//! change, and two tests, or two embedders' tasks, can each work in their
//! own context at the same time.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::anyhow;

use crate::store::{self, Keychain};

/// Asks for a code from the MFA device whose ARN it is given.
pub type MfaPrompt = dyn Fn(&str) -> anyhow::Result<String> + Send + Sync;

/// Asks for the passphrase of the encrypted file vault
/// (`OMNIFOB_KEYRING=encrypted-file`); see [`PassphraseRequest`].
pub type PassphrasePrompt = dyn Fn(&PassphraseRequest) -> anyhow::Result<String> + Send + Sync;

/// The variable [`Context::builder_from_env`] reads the vault's
/// passphrase from. Programs omnifob runs (`fob exec` commands, `command`
/// integrations) never get it.
pub const VAULT_PASSPHRASE_VAR: &str = "OMNIFOB_VAULT_PASSPHRASE";

/// What a [`PassphrasePrompt`] is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseRequest {
    /// The vault's directory.
    pub vault: PathBuf,
    /// Whether the vault is being created, so the passphrase is new: a
    /// prompt should ask for it twice.
    pub new: bool,
}

/// See the [module](self) documentation. Cloning is cheap: clones share
/// the keychain, the HTTP client and its connections.
#[derive(Clone)]
pub struct Context(Arc<Inner>);

struct Inner {
    config_file: Result<PathBuf, String>,
    state_dir: Result<PathBuf, String>,
    keychain: Keychain,
    /// The keychain once chosen: choosing one may probe D-Bus, so it waits
    /// until a secret is needed.
    /// Chosen on first use; a failure is not kept, so a keychain that was
    /// unreachable (a D-Bus session not up yet) is tried again.
    store: OnceLock<store::Selected>,
    wsl_dpapi: bool,
    /// One client for every request, so they share TLS setup and pooled
    /// connections. `None` builds one per request: the fallback context
    /// may serve several runtimes, and a pooled connection belongs to the
    /// runtime that opened it. Built on first use, since loading the
    /// system's root certificates is wasted on commands that make no
    /// request (`fob activate` at every shell start, `fob list`, cached
    /// credentials).
    http: Option<OnceLock<reqwest::Client>>,
    mfa: Option<Box<MfaPrompt>>,
    vault: VaultUnlock,
    endpoints: Endpoints,
    agent: Option<Agent>,
}

/// How the encrypted file vault gets its key: a passphrase given up front
/// (`OMNIFOB_VAULT_PASSPHRASE`), else the prompt, and whether the derived
/// key is kept in the kernel keyring until reboot.
#[derive(Clone)]
pub(crate) struct VaultUnlock {
    pub(crate) passphrase: Option<String>,
    pub(crate) prompt: Option<Arc<PassphrasePrompt>>,
    pub(crate) cache_key: bool,
}

impl Default for VaultUnlock {
    fn default() -> Self {
        Self {
            passphrase: None,
            prompt: None,
            cache_key: true,
        }
    }
}

/// The coding agent whose command uses the library, which marks what it
/// gets on the provider's side: AWS sessions named `omnifob-agent` where
/// the config names none, Cloudflare tokens named `omnifob-agent
/// <template>`, and Entra ID tokens tagged with the agent's session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Agent {
    /// The agent's session, which Entra ID records in its tokens'
    /// `xms_cli_sid` claim as the Azure CLI asks it to:
    /// `COPILOT_AGENT_SESSION_ID`.
    pub session_id: Option<String>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("config_file", &self.0.config_file)
            .field("state_dir", &self.0.state_dir)
            .field("keychain", &self.0.keychain)
            .field("mfa_prompt", &self.0.mfa.is_some())
            .field("vault_passphrase", &self.0.vault.passphrase.is_some())
            .field("vault_prompt", &self.0.vault.prompt.is_some())
            .field("vault_key_cache", &self.0.vault.cache_key)
            .field("endpoints", &self.0.endpoints)
            .field("agent", &self.0.agent)
            .finish_non_exhaustive()
    }
}

/// Where provider calls go instead of the providers' own hosts: mock
/// servers in tests, a VPC endpoint for an AWS API. Each is a base URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Every AWS call, the console's `getSigninToken` included (at
    /// `<url>/federation`). `OMNIFOB_AWS_ENDPOINT`.
    pub aws: Option<String>,
    /// One AWS API each, keyed by the variable the AWS CLI and SDKs read for
    /// it: `AWS_ENDPOINT_URL_SSO_OIDC`, `AWS_ENDPOINT_URL_SSO`,
    /// `AWS_ENDPOINT_URL_STS`, `AWS_ENDPOINT_URL_SIGNIN`, `AWS_ENDPOINT_URL_IAM`.
    /// `aws` wins.
    pub aws_services: BTreeMap<String, String>,
    /// Microsoft Entra ID and Azure Resource Manager. `OMNIFOB_AZURE_ENDPOINT`.
    pub azure: Option<String>,
    /// Google's OAuth and Cloud APIs. `OMNIFOB_GOOGLE_ENDPOINT`.
    pub google: Option<String>,
    /// The Cloudflare v4 API. `OMNIFOB_CLOUDFLARE_API`.
    pub cloudflare_api: Option<String>,
    /// The Cloudflare dashboard's OAuth endpoints. `OMNIFOB_CLOUDFLARE_DASH`.
    pub cloudflare_dash: Option<String>,
    /// AWS calls go to dual-stack (IPv6) endpoints, where no URL above
    /// replaces them. `AWS_USE_DUALSTACK_ENDPOINT=true`, as the SDKs read it.
    pub aws_dual_stack: bool,
    /// AWS calls go to FIPS endpoints, where no URL above replaces them.
    /// `AWS_USE_FIPS_ENDPOINT=true`.
    pub aws_fips: bool,
}

/// The AWS APIs whose endpoint variable is read.
const AWS_SERVICE_VARIABLES: [&str; 5] = [
    "AWS_ENDPOINT_URL_SSO_OIDC",
    "AWS_ENDPOINT_URL_SSO",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_SIGNIN",
    "AWS_ENDPOINT_URL_IAM",
];

impl Endpoints {
    /// The overrides the environment sets.
    pub fn from_env() -> Self {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// The overrides `var` gives, read like [`Endpoints::from_env`] reads
    /// the environment. An empty value counts as unset. The AWS service
    /// variables are skipped when `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` is
    /// `true`, as in the AWS CLI. The global `AWS_ENDPOINT_URL` is not read:
    /// it usually points the command `fob exec` runs at a local emulator,
    /// which cannot sign anyone in.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Self {
        let get = |name: &str| var(name).filter(|v| !v.is_empty());
        let ignore_aws = get("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let aws_services = if ignore_aws {
            BTreeMap::new()
        } else {
            AWS_SERVICE_VARIABLES
                .iter()
                .filter_map(|name| Some((name.to_string(), get(name)?)))
                .collect()
        };
        Self {
            aws: get("OMNIFOB_AWS_ENDPOINT"),
            aws_services,
            azure: get("OMNIFOB_AZURE_ENDPOINT"),
            google: get("OMNIFOB_GOOGLE_ENDPOINT"),
            cloudflare_api: get("OMNIFOB_CLOUDFLARE_API"),
            cloudflare_dash: get("OMNIFOB_CLOUDFLARE_DASH"),
            aws_dual_stack: get("AWS_USE_DUALSTACK_ENDPOINT")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            aws_fips: get("AWS_USE_FIPS_ENDPOINT").is_some_and(|v| v.eq_ignore_ascii_case("true")),
        }
    }

    /// Where the AWS API whose endpoint variable is `variable` is called.
    pub(crate) fn aws_service(&self, variable: &str) -> Option<&str> {
        self.aws
            .as_deref()
            .or_else(|| self.aws_services.get(variable).map(String::as_str))
    }
}

/// Builds a [`Context`]; see [`Context::builder`].
pub struct ContextBuilder {
    config_file: Result<PathBuf, String>,
    state_dir: Result<PathBuf, String>,
    keychain: Keychain,
    wsl_dpapi: bool,
    shared_http: bool,
    mfa: Option<Box<MfaPrompt>>,
    vault: VaultUnlock,
    endpoints: Endpoints,
    agent: Option<Agent>,
}

impl ContextBuilder {
    /// The config file, `config.toml`.
    pub fn config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_file = Ok(path.into());
        self
    }

    /// The directory for discovered profiles, locks, caches and other
    /// non-secret state.
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Ok(dir.into());
        self
    }

    /// Where secrets are kept; the platform's keychain unless set.
    pub fn keychain(mut self, keychain: Keychain) -> Self {
        self.keychain = keychain;
        self
    }

    /// Whether, on WSL with the kernel keyring, long-lived secrets are also
    /// sealed with Windows DPAPI into the state directory so they survive a
    /// reboot. On unless set; `OMNIFOB_WSL_DPAPI=0` turns it off.
    pub fn wsl_dpapi(mut self, on: bool) -> Self {
        self.wsl_dpapi = on;
        self
    }

    /// Who answers when an AWS role asks for an MFA code. Without one, an
    /// operation that needs a code fails, saying how to get past it.
    pub fn mfa_prompt(
        mut self,
        prompt: impl Fn(&str) -> anyhow::Result<String> + Send + Sync + 'static,
    ) -> Self {
        self.mfa = Some(Box::new(prompt));
        self
    }

    /// Who answers when the encrypted file vault needs its passphrase. The
    /// library never reads a terminal itself; without a prompt or
    /// [`vault_passphrase`](Self::vault_passphrase), a locked vault fails,
    /// saying how to unlock it.
    pub fn passphrase_prompt(
        mut self,
        prompt: impl Fn(&PassphraseRequest) -> anyhow::Result<String> + Send + Sync + 'static,
    ) -> Self {
        self.vault.prompt = Some(Arc::new(prompt));
        self
    }

    /// The encrypted file vault's passphrase, for automation; it is used
    /// before any prompt. `OMNIFOB_VAULT_PASSPHRASE`.
    pub fn vault_passphrase(mut self, passphrase: Option<String>) -> Self {
        self.vault.passphrase = passphrase.filter(|p| !p.is_empty());
        self
    }

    /// Whether the key derived from the vault's passphrase is kept in the
    /// kernel keyring (Linux keyutils) until reboot, so the passphrase is
    /// asked once per boot rather than once per command. On unless set;
    /// `OMNIFOB_VAULT_KEY_CACHE=0` turns it off.
    pub fn vault_key_cache(mut self, on: bool) -> Self {
        self.vault.cache_key = on;
        self
    }

    /// Where provider calls go instead of the providers' own hosts.
    pub fn endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// The coding agent the library works for, if any; see [`Agent`].
    pub fn agent(mut self, agent: Option<Agent>) -> Self {
        self.agent = agent;
        self
    }

    pub fn build(self) -> Context {
        let http = self.shared_http.then(OnceLock::new);
        Context(Arc::new(Inner {
            config_file: self.config_file,
            state_dir: self.state_dir,
            keychain: self.keychain,
            store: OnceLock::new(),
            wsl_dpapi: self.wsl_dpapi,
            http,
            mfa: self.mfa,
            vault: self.vault,
            endpoints: self.endpoints,
            agent: self.agent,
        }))
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

static INSTALLED: OnceLock<Context> = OnceLock::new();

/// Leaves the context [`Context::enter`] entered when dropped, going back
/// to the one before.
#[must_use = "the context is left when this is dropped"]
pub struct Entered {
    previous: Option<Context>,
    /// Entered on one thread, left on the same one.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for Entered {
    fn drop(&mut self) {
        let previous = self.previous.take();
        // During the thread's teardown the slot is gone, and so is the need.
        let _ = CURRENT.try_with(|current| *current.borrow_mut() = previous);
    }
}

impl Context {
    /// Nothing from the environment: no config file or state directory
    /// until given, the platform's keychain, no MFA prompt, the providers'
    /// own hosts, and one HTTP client shared by every request.
    pub fn builder() -> ContextBuilder {
        ContextBuilder {
            config_file: Err("no config file was given".to_string()),
            state_dir: Err("no state directory was given".to_string()),
            keychain: Keychain::Native,
            wsl_dpapi: true,
            shared_http: true,
            mfa: None,
            vault: VaultUnlock::default(),
            endpoints: Endpoints::default(),
            agent: None,
        }
    }

    /// A builder with what the environment sets, as the command line reads
    /// it: the files from `OMNIFOB_CONFIG` and the XDG variables
    /// ([`crate::paths`]), the keychain from `OMNIFOB_KEYRING`,
    /// `OMNIFOB_WSL_DPAPI`, the vault's `OMNIFOB_VAULT_PASSPHRASE` and
    /// `OMNIFOB_VAULT_KEY_CACHE`, and [`Endpoints::from_env`].
    pub fn builder_from_env() -> ContextBuilder {
        let mut builder = Self::builder();
        builder.config_file = crate::paths::standard_config_file().map_err(|e| format!("{e:#}"));
        builder.state_dir = crate::paths::standard_state_dir().map_err(|e| format!("{e:#}"));
        builder.keychain = Keychain::from_env();
        builder.wsl_dpapi = std::env::var("OMNIFOB_WSL_DPAPI").map_or(true, |v| v != "0");
        builder = builder
            .vault_passphrase(std::env::var(VAULT_PASSPHRASE_VAR).ok())
            .vault_key_cache(std::env::var("OMNIFOB_VAULT_KEY_CACHE").map_or(true, |v| v != "0"));
        builder.endpoints = Endpoints::from_env();
        builder
    }

    /// [`Context::builder_from_env`], built.
    pub fn from_env() -> Self {
        Self::builder_from_env().build()
    }

    /// The context functions of this library work in: the one entered on
    /// this thread, else the installed one, else one from the environment.
    pub fn current() -> Self {
        CURRENT
            .try_with(|current| current.borrow().clone())
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                INSTALLED
                    .get_or_init(|| {
                        let mut builder = Self::builder_from_env();
                        builder.shared_http = false;
                        builder.build()
                    })
                    .clone()
            })
    }

    /// Makes this the context of the whole process, wherever no other is
    /// entered. Only the first call counts, and only before anything used
    /// the fallback; otherwise this context is handed back.
    pub fn install(self) -> Result<(), Self> {
        let mut this = Some(self);
        INSTALLED.get_or_init(|| this.take().expect("taken once"));
        match this {
            None => Ok(()),
            Some(this) => Err(this),
        }
    }

    /// Makes this the current context on this thread until the guard is
    /// dropped. For synchronous code, and for a test on a single-threaded
    /// runtime; a future that may move between threads uses
    /// [`Context::scope`].
    pub fn enter(&self) -> Entered {
        let previous = CURRENT.with(|current| current.borrow_mut().replace(self.clone()));
        Entered {
            previous,
            _not_send: std::marker::PhantomData,
        }
    }

    /// Runs `future` in this context: it is entered whenever the future is
    /// polled.
    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        let context = self.clone();
        let mut future = Box::pin(future);
        std::future::poll_fn(move |cx| {
            let _entered = context.enter();
            future.as_mut().poll(cx)
        })
    }

    pub fn config_file(&self) -> anyhow::Result<&Path> {
        self.0.config_file.as_deref().map_err(|e| anyhow!("{e}"))
    }

    pub fn state_dir(&self) -> anyhow::Result<&Path> {
        self.0.state_dir.as_deref().map_err(|e| anyhow!("{e}"))
    }

    /// The HTTP client, with omnifob's user agent and timeouts.
    pub fn http(&self) -> reqwest::Client {
        let build = || crate::http::builder().build().expect("HTTP client");
        match &self.0.http {
            Some(client) => client.get_or_init(build).clone(),
            None => build(),
        }
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.0.endpoints
    }

    /// The coding agent the library works for, if any.
    pub fn agent(&self) -> Option<&Agent> {
        self.0.agent.as_ref()
    }

    /// The keychain this context chose, for another context to share: the
    /// same secrets with other endpoints, for example.
    pub fn shared_keychain(&self) -> anyhow::Result<Keychain> {
        let store = self.store()?;
        Ok(Keychain::Custom {
            name: store.name().to_string(),
            store: store.inner().clone(),
        })
    }

    /// Whether secrets live in this process's memory only, so no other
    /// process shares them, nor needs a lock file to guard them.
    pub(crate) fn in_memory(&self) -> bool {
        matches!(self.0.keychain, Keychain::Memory)
    }

    pub(crate) fn mfa_prompt(&self) -> Option<&MfaPrompt> {
        self.0.mfa.as_deref()
    }

    pub(crate) fn wsl_dpapi(&self) -> bool {
        self.0.wsl_dpapi
    }

    pub(crate) fn vault_unlock(&self) -> &VaultUnlock {
        &self.0.vault
    }

    /// The keychain, chosen on first use.
    pub(crate) fn store(&self) -> anyhow::Result<&store::Selected> {
        if let Some(selected) = self.0.store.get() {
            return Ok(selected);
        }
        let selected = store::select(self, &self.0.keychain)
            .map_err(|e| anyhow!("no usable keychain: {e:#}"))?;
        // Another thread may have chosen meanwhile; the first choice stays.
        Ok(self.0.store.get_or_init(|| selected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_variables_are_read_as_the_aws_cli_reads_them() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        let e = Endpoints::from_vars(vars(&[
            ("AWS_ENDPOINT_URL_STS", "https://sts.vpce"),
            ("AWS_ENDPOINT_URL", "http://localstack"),
            ("OMNIFOB_AZURE_ENDPOINT", ""),
        ]));
        assert_eq!(
            e.aws_service("AWS_ENDPOINT_URL_STS"),
            Some("https://sts.vpce")
        );
        assert_eq!(e.aws_service("AWS_ENDPOINT_URL_SSO"), None);
        assert_eq!(e.azure, None);
        let ignored = Endpoints::from_vars(vars(&[
            ("AWS_ENDPOINT_URL_STS", "https://sts.vpce"),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "TRUE"),
        ]));
        assert_eq!(ignored.aws_service("AWS_ENDPOINT_URL_STS"), None);
        let all = Endpoints::from_vars(vars(&[
            ("AWS_ENDPOINT_URL_STS", "https://sts.vpce"),
            ("OMNIFOB_AWS_ENDPOINT", "http://mock"),
        ]));
        assert_eq!(all.aws_service("AWS_ENDPOINT_URL_STS"), Some("http://mock"));
        assert!(!all.aws_dual_stack && !all.aws_fips);
        let ipv6 = Endpoints::from_vars(vars(&[
            ("AWS_USE_DUALSTACK_ENDPOINT", "True"),
            ("AWS_USE_FIPS_ENDPOINT", "false"),
        ]));
        assert!(ipv6.aws_dual_stack && !ipv6.aws_fips);
    }

    #[test]
    fn the_entered_context_is_current_until_left() {
        let a = Context::builder().state_dir("/a").build();
        let b = Context::builder().state_dir("/b").build();
        let outer = a.enter();
        assert_eq!(Context::current().state_dir().unwrap(), Path::new("/a"));
        {
            let _inner = b.enter();
            assert_eq!(Context::current().state_dir().unwrap(), Path::new("/b"));
        }
        assert_eq!(Context::current().state_dir().unwrap(), Path::new("/a"));
        drop(outer);
        assert!(Context::builder().build().state_dir().is_err());
    }

    #[test]
    fn contexts_keep_their_secrets_apart_unless_they_share_a_keychain() {
        let memory = || Context::builder().keychain(Keychain::Memory).build();
        let (a, b) = (memory(), memory());
        {
            let _a = a.enter();
            store::set("k", &"in a").unwrap();
        }
        {
            let _b = b.enter();
            assert_eq!(store::get::<String>("k").unwrap(), None);
        }
        let shared = Context::builder()
            .keychain(a.shared_keychain().unwrap())
            .build();
        let _shared = shared.enter();
        assert_eq!(store::get::<String>("k").unwrap().as_deref(), Some("in a"));
        assert!(
            Context::builder()
                .keychain(Keychain::Named("nope".into()))
                .build()
                .store()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scoped_future_keeps_its_context_across_threads() {
        let a = Context::builder().state_dir("/a").build();
        let b = Context::builder().state_dir("/b").build();
        let task = |cx: Context, dir: &'static str| {
            tokio::spawn(cx.scope(async move {
                for _ in 0..20 {
                    assert_eq!(Context::current().state_dir().unwrap(), Path::new(dir));
                    tokio::task::yield_now().await;
                }
            }))
        };
        let (x, y) = tokio::join!(task(a, "/a"), task(b, "/b"));
        x.unwrap();
        y.unwrap();
    }
}
