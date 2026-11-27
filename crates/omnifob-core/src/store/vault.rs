//! An encrypted file vault, for machines without a keychain that keeps
//! secrets across reboots (headless Linux, containers):
//! `OMNIFOB_KEYRING=encrypted-file`, or `encrypted-file:<absolute dir>`.
//!
//! Each secret is one file, named like the keychain key it holds
//! ([`crate::files::encode_key_filename`]) with `.sealed` added, and
//! encrypted with AES-256-GCM under a key derived from a passphrase with
//! PBKDF2-HMAC-SHA256 ([`ITERATIONS`] iterations, a random 16 byte salt).
//! The key name is the associated data, so a file moved to another name
//! does not open. `vault.json` holds the salt, the iteration count and a
//! known value sealed with the key, which tells a wrong passphrase from a
//! damaged file.
//!
//! The passphrase comes from the context: `OMNIFOB_VAULT_PASSPHRASE`, else
//! its passphrase prompt (the command line asks in the terminal). The
//! library never reads a terminal. On Linux the derived key is then kept in
//! the kernel keyring until reboot, so the passphrase is asked once per
//! boot; `OMNIFOB_VAULT_KEY_CACHE=0` turns that off. The vault is unlocked
//! only when a secret is read or written: looking up a key that has no file
//! needs no passphrase.

use std::any::Any;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, bail};
use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{Credential, Entry, Error, Result};
use serde::{Deserialize, Serialize};

use crate::context::{PassphraseRequest, VaultUnlock};

/// What `OMNIFOB_KEYRING` starts with to choose this store.
pub const NAME: &str = "encrypted-file";

/// PBKDF2-HMAC-SHA256 iterations for a new vault: OWASP's recommendation
/// for that function (2023). `aws-lc-rs`, omnifob's cryptography, offers
/// no memory-hard function (scrypt, Argon2). The count is stored with the
/// vault, so a later release can raise it for new vaults.
pub const ITERATIONS: u32 = 600_000;

/// The shortest passphrase a new vault takes.
pub const MIN_PASSPHRASE: usize = 12;

const HEADER: &str = "vault.json";
const SUFFIX: &str = ".sealed";
const FORMAT: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Sealed with the key into `vault.json`, to check a passphrase.
const CHECK: &[u8] = b"omnifob encrypted-file vault";
const CHECK_AAD: &str = "omnifob-vault-check";
/// The kernel keyring service the derived key is kept under.
#[cfg(target_os = "linux")]
const KEY_CACHE_SERVICE: &str = "omnifob-vault-key";

/// The vault's directory from what follows [`NAME`] in `OMNIFOB_KEYRING`:
/// nothing (the `encrypted` directory in `state_dir`) or `:<absolute dir>`.
/// `state_dir` is needed only for the default directory, so an explicit
/// absolute one works without a state directory.
pub fn dir(rest: &str, state_dir: anyhow::Result<&Path>) -> anyhow::Result<PathBuf> {
    if rest.is_empty() {
        return Ok(state_dir?.join("encrypted"));
    }
    let Some(dir) = rest.strip_prefix(':').filter(|d| !d.is_empty()) else {
        bail!("OMNIFOB_KEYRING={NAME}{rest} is not a store: use {NAME}, or {NAME}:<absolute dir>");
    };
    let dir = PathBuf::from(dir);
    if !dir.is_absolute() {
        bail!(
            "OMNIFOB_KEYRING={NAME}:{} needs an absolute directory",
            dir.display()
        );
    }
    Ok(dir)
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: u8,
    kdf: String,
    iterations: u32,
    salt: String,
    check: String,
}

const KDF: &str = "pbkdf2-hmac-sha256";

/// The store: its entries share one `Vault`, so the vault is unlocked
/// once per process.
#[derive(Debug)]
pub struct Store(Arc<Vault>);

struct Vault {
    dir: PathBuf,
    unlock: VaultUnlock,
    key: Mutex<Option<Arc<RandomizedNonceKey>>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl Store {
    pub(crate) fn new(dir: &Path, unlock: VaultUnlock) -> anyhow::Result<Arc<Self>> {
        crate::files::create_private_dir(dir)?;
        Ok(Arc::new(Self(Arc::new(Vault {
            dir: dir.to_path_buf(),
            unlock,
            key: Mutex::new(None),
        }))))
    }
}

impl Vault {
    fn header_path(&self) -> PathBuf {
        self.dir.join(HEADER)
    }

    fn file(&self, key: &str) -> PathBuf {
        self.dir.join(format!(
            "{}{SUFFIX}",
            crate::files::encode_key_filename(key)
        ))
    }

    /// The key, unlocking the vault (or creating it) on first use.
    fn key(&self) -> anyhow::Result<Arc<RandomizedNonceKey>> {
        let mut held = self.key.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = &*held {
            return Ok(key.clone());
        }
        let key = Arc::new(self.unlock_or_create()?);
        *held = Some(key.clone());
        Ok(key)
    }

    fn read_header(&self) -> anyhow::Result<Option<Header>> {
        let text = match crate::files::retry_busy(|| std::fs::read_to_string(self.header_path())) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", self.header_path().display()));
            }
        };
        let header: Header = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a vault header", self.header_path().display()))?;
        if header.format != FORMAT || header.kdf != KDF {
            bail!(
                "{} is a vault of a format this omnifob does not know ({} {}); update omnifob",
                self.header_path().display(),
                header.format,
                header.kdf
            );
        }
        Ok(Some(header))
    }

    fn unlock_or_create(&self) -> anyhow::Result<RandomizedNonceKey> {
        match self.read_header()? {
            Some(header) => self.unlock_with(&header, None),
            None => self.create(),
        }
    }

    /// Opens an existing vault: with the key kept since boot, else with the
    /// passphrase (`passphrase`, when the caller already has it).
    fn unlock_with(
        &self,
        header: &Header,
        passphrase: Option<String>,
    ) -> anyhow::Result<RandomizedNonceKey> {
        let salt = BASE64
            .decode(&header.salt)
            .context("the vault's salt is not base64")?;
        // A tampered header must neither make every unlock take hours nor
        // weaken the key with a short salt or few iterations.
        if salt.len() < SALT_LEN {
            anyhow::bail!("the vault's salt is shorter than {SALT_LEN} bytes");
        }
        if !(ITERATIONS / 2..=ITERATIONS * 10).contains(&header.iterations) {
            anyhow::bail!(
                "the vault's iteration count {} is outside {}..={}",
                header.iterations,
                ITERATIONS / 2,
                ITERATIONS * 10
            );
        }
        let iterations =
            NonZeroU32::new(header.iterations).context("the vault has 0 iterations")?;
        let cache_id = BASE64.encode(&salt);
        if passphrase.is_none()
            && self.unlock.cache_key
            && let Some(bytes) = key_cache::get(&cache_id)
            && let Ok(key) = check(header, &bytes)
        {
            return Ok(key);
        }
        let passphrase = match passphrase {
            Some(p) => p,
            None => self.passphrase(false)?,
        };
        let bytes = derive(&passphrase, &salt, iterations);
        let key = check(header, &bytes).map_err(|_| {
            anyhow::anyhow!(
                "wrong passphrase for the encrypted vault in {}",
                self.dir.display()
            )
        })?;
        if self.unlock.cache_key {
            key_cache::set(&cache_id, &bytes);
        }
        Ok(key)
    }

    /// Creates the vault: a new passphrase, a random salt and the header.
    /// Another process creating it at the same time wins; this one then
    /// opens that vault with the same passphrase. Refused when sealed files
    /// are there without the header: a new salt would make them never open
    /// again, even with the same passphrase.
    fn create(&self) -> anyhow::Result<RandomizedNonceKey> {
        if self.has_sealed_files()? {
            bail!(
                "{} holds sealed secrets but no {HEADER}, whose salt they were sealed with; restore {HEADER} from a backup, or move the {SUFFIX} files away to start a new vault",
                self.dir.display()
            );
        }
        let passphrase = self.passphrase(true)?;
        if passphrase.chars().count() < MIN_PASSPHRASE {
            bail!("the encrypted vault's passphrase needs at least {MIN_PASSPHRASE} characters");
        }
        let mut salt = [0u8; SALT_LEN];
        aws_lc_rs::rand::fill(&mut salt).map_err(|_| anyhow::anyhow!("no system randomness"))?;
        let iterations = NonZeroU32::new(ITERATIONS).expect("not zero");
        let bytes = derive(&passphrase, &salt, iterations);
        let key = aead_key(&bytes)?;
        let header = Header {
            format: FORMAT,
            kdf: KDF.to_string(),
            iterations: ITERATIONS,
            salt: BASE64.encode(salt),
            check: BASE64.encode(seal(&key, CHECK_AAD, CHECK)?),
        };
        // Written aside and linked into place, which fails if the header
        // appeared meanwhile, so two processes never both create a vault.
        let staged = self
            .dir
            .join(format!("{HEADER}.{}.new", std::process::id()));
        crate::files::write_private(&staged, serde_json::to_vec_pretty(&header)?)?;
        let linked = std::fs::hard_link(&staged, self.header_path());
        let _ = std::fs::remove_file(&staged);
        match linked {
            Ok(()) => {
                if self.unlock.cache_key {
                    key_cache::set(&BASE64.encode(salt), &bytes);
                }
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let header = self.read_header()?.context("the vault header vanished")?;
                self.unlock_with(&header, Some(passphrase))
            }
            Err(e) => Err(e).with_context(|| format!("creating {}", self.header_path().display())),
        }
    }

    /// Whether the directory holds any sealed secret.
    fn has_sealed_files(&self) -> anyhow::Result<bool> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        Ok(entries
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(SUFFIX)))
    }

    fn passphrase(&self, new: bool) -> anyhow::Result<String> {
        if let Some(passphrase) = &self.unlock.passphrase {
            return Ok(passphrase.clone());
        }
        // While a command runs (the endpoints `fob exec` serves), a prompt
        // would fight the command for the terminal.
        let prompt = self
            .unlock
            .prompt
            .as_ref()
            .filter(|_| !crate::prompt::is_unattended());
        let Some(prompt) = prompt else {
            // An agent is not pointed at the variable: the passphrase is the
            // person's, entered in their terminal.
            let variable = if crate::Context::current().agent().is_some() {
                ""
            } else {
                ", or set OMNIFOB_VAULT_PASSPHRASE"
            };
            let message = if new {
                format!(
                    "creating the encrypted vault in {} needs a passphrase: run fob in a terminal{variable}",
                    self.dir.display()
                )
            } else {
                format!(
                    "the encrypted vault in {} is locked: run any fob command in a terminal to enter its passphrase (once per boot){variable}",
                    self.dir.display()
                )
            };
            return Err(crate::Coded::new(crate::Code::VaultLocked, message)
                .with("vault", self.dir.display().to_string())
                .into());
        };
        let passphrase = prompt(&PassphraseRequest {
            vault: self.dir.clone(),
            new,
        })?;
        if passphrase.is_empty() {
            bail!("no passphrase given");
        }
        Ok(passphrase)
    }

    fn open_file(&self, user: &str, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        let sealed = match std::fs::read(path) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let key = self.key()?;
        Ok(Some(open(&key, user, &sealed).with_context(|| {
            format!(
                "{} does not open with the vault's key: it was changed, or belongs to another key",
                path.display()
            )
        })?))
    }
}

fn derive(passphrase: &str, salt: &[u8], iterations: NonZeroU32) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase.as_bytes(),
        &mut out,
    );
    out
}

fn aead_key(bytes: &[u8]) -> anyhow::Result<RandomizedNonceKey> {
    RandomizedNonceKey::new(&AES_256_GCM, bytes).map_err(|_| anyhow::anyhow!("not an AES-256 key"))
}

/// The key `bytes` make if they open the header's check value.
fn check(header: &Header, bytes: &[u8]) -> anyhow::Result<RandomizedNonceKey> {
    let key = aead_key(bytes)?;
    let sealed = BASE64
        .decode(&header.check)
        .context("the vault's check value is not base64")?;
    match open(&key, CHECK_AAD, &sealed) {
        Ok(plain) if plain == CHECK => Ok(key),
        _ => bail!("the key does not open the vault"),
    }
}

/// `[format][nonce][ciphertext and tag]`, with `aad` bound to it.
fn seal(key: &RandomizedNonceKey, aad: &str, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut in_out = plain.to_vec();
    let nonce = key
        .seal_in_place_append_tag(Aad::from(aad.as_bytes()), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encrypting failed"))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + in_out.len());
    out.push(FORMAT);
    out.extend_from_slice(nonce.as_ref());
    out.extend_from_slice(&in_out);
    Ok(out)
}

fn open(key: &RandomizedNonceKey, aad: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
    let Some((&FORMAT, rest)) = sealed.split_first() else {
        bail!("not a sealed value of format {FORMAT}");
    };
    if rest.len() < NONCE_LEN {
        bail!("too short");
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let nonce =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow::anyhow!("bad nonce"))?;
    let mut in_out = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut in_out)
        .map_err(|_| anyhow::anyhow!("decrypting failed"))?;
    Ok(plain.to_vec())
}

/// The derived key kept in the kernel keyring (keyutils), which forgets it
/// on reboot. Failures only cost a passphrase prompt, so they are logged.
#[cfg(target_os = "linux")]
mod key_cache {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use keyring_core::CredentialStore;

    fn entry(id: &str) -> Option<keyring_core::Entry> {
        let store = linux_keyutils_keyring_store::Store::new()
            .map_err(|e| tracing::debug!("no kernel keyring for the vault key: {e}"))
            .ok()?;
        let store: std::sync::Arc<CredentialStore> = store;
        store.build(super::KEY_CACHE_SERVICE, id, None).ok()
    }

    pub(super) fn get(id: &str) -> Option<Vec<u8>> {
        BASE64.decode(entry(id)?.get_password().ok()?).ok()
    }

    pub(super) fn set(id: &str, key: &[u8]) {
        if let Some(entry) = entry(id)
            && let Err(e) = entry.set_password(&BASE64.encode(key))
        {
            tracing::debug!("could not keep the vault key in the kernel keyring: {e}");
        }
    }
}

/// No kernel keyring: the passphrase is needed by every command.
#[cfg(not(target_os = "linux"))]
mod key_cache {
    pub(super) fn get(_id: &str) -> Option<Vec<u8>> {
        None
    }

    pub(super) fn set(_id: &str, _key: &[u8]) {}
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "omnifob encrypted-file".to_string()
    }

    fn id(&self) -> String {
        self.0.dir.display().to_string()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        Ok(Entry::new_with_credential(Arc::new(Sealed {
            vault: self.0.clone(),
            service: service.to_string(),
            user: user.to_string(),
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct Sealed {
    vault: Arc<Vault>,
    service: String,
    user: String,
}

fn platform(e: anyhow::Error) -> Error {
    // A coded failure (the vault is locked) goes in as itself, so callers
    // still find its code through the keyring's error.
    match e.downcast::<crate::Coded>() {
        Ok(coded) => Error::PlatformFailure(Box::new(coded)),
        Err(e) => Error::PlatformFailure(e.into()),
    }
}

impl CredentialApi for Sealed {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let key = self.vault.key().map_err(platform)?;
        let sealed = seal(&key, &self.user, secret).map_err(platform)?;
        crate::files::write_private(&self.vault.file(&self.user), sealed).map_err(platform)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        match self
            .vault
            .open_file(&self.user, &self.vault.file(&self.user))
        {
            Ok(Some(secret)) => Ok(secret),
            Ok(None) => Err(Error::NoEntry),
            Err(e) => Err(platform(e)),
        }
    }

    fn delete_credential(&self) -> Result<()> {
        match std::fs::remove_file(self.vault.file(&self.user)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NoEntry),
            Err(e) => Err(Error::PlatformFailure(Box::new(e))),
        }
    }

    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        self.get_secret().map(|_| None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("omnifob-vault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Scratch(dir)
    }

    fn unlock(passphrase: Option<&str>) -> VaultUnlock {
        VaultUnlock {
            passphrase: passphrase.map(str::to_string),
            prompt: None,
            // Tests leave the real kernel keyring alone.
            cache_key: false,
        }
    }

    fn entry(dir: &Path, passphrase: Option<&str>, key: &str) -> Entry {
        let store: Arc<keyring_core::CredentialStore> =
            Store::new(dir, unlock(passphrase)).unwrap();
        store.build("omnifob", key, None).unwrap()
    }

    #[test]
    fn the_directory_is_the_state_dirs_or_an_absolute_one() {
        let state = std::env::temp_dir().join("state");
        assert_eq!(dir("", Ok(&state)).unwrap(), state.join("encrypted"));
        let absolute = std::env::temp_dir().join("vault");
        let named = format!(":{}", absolute.display());
        assert_eq!(dir(&named, Ok(&state)).unwrap(), absolute);
        // An absolute directory needs no state directory.
        assert_eq!(
            dir(&named, Err(anyhow::anyhow!("no state directory"))).unwrap(),
            absolute
        );
        assert!(dir("", Err(anyhow::anyhow!("no state directory"))).is_err());
        for rest in [":", "x", ":relative"] {
            assert!(dir(rest, Ok(&state)).is_err(), "{rest:?}");
        }
    }

    #[test]
    fn secrets_are_sealed_and_open_only_with_the_passphrase() {
        let scratch = scratch("roundtrip");
        let dir = scratch.0.join("vault");
        let pass = "correct horse battery";
        // Nothing stored needs no passphrase.
        let locked = entry(&dir, None, "aws-sso/acme/token");
        assert!(matches!(locked.get_password(), Err(Error::NoEntry)));
        let message = locked.set_password("x").unwrap_err().to_string();
        assert!(message.contains("needs a passphrase"), "{message}");
        let short = entry(&dir, Some("short"), "k")
            .set_password("x")
            .unwrap_err();
        assert!(
            short.to_string().contains("at least 12 characters"),
            "{short}"
        );

        let token = entry(&dir, Some(pass), "aws-sso/acme/token");
        token.set_password("{\"secret\":\"s3cr3t\"}").unwrap();
        let file = dir.join("aws-sso%2Facme%2Ftoken.sealed");
        let sealed = std::fs::read(&file).unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("s3cr3t"));
        let header = std::fs::read_to_string(dir.join(HEADER)).unwrap();
        assert!(header.contains("\"iterations\": 600000"), "{header}");
        assert!(header.contains("pbkdf2-hmac-sha256"), "{header}");

        // Another process: the same passphrase opens it, another does not,
        // and without one the vault is locked.
        assert_eq!(
            entry(&dir, Some(pass), "aws-sso/acme/token")
                .get_password()
                .unwrap(),
            "{\"secret\":\"s3cr3t\"}"
        );
        let wrong = entry(&dir, Some("not the passphrase"), "aws-sso/acme/token")
            .get_password()
            .unwrap_err()
            .to_string();
        assert!(wrong.contains("wrong passphrase"), "{wrong}");
        let locked = entry(&dir, None, "aws-sso/acme/token")
            .get_password()
            .unwrap_err();
        assert!(locked.to_string().contains("is locked"), "{locked}");
        assert_eq!(
            crate::classify(&anyhow::Error::from(locked)).0,
            crate::Code::VaultLocked
        );

        // A file moved to another key's name, or changed, does not open.
        std::fs::copy(&file, dir.join("aws-sso%2Fother%2Ftoken.sealed")).unwrap();
        let moved = entry(&dir, Some(pass), "aws-sso/other/token")
            .get_password()
            .unwrap_err();
        assert!(moved.to_string().contains("does not open"), "{moved}");
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&file, changed).unwrap();
        assert!(
            entry(&dir, Some(pass), "aws-sso/acme/token")
                .get_password()
                .is_err()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join(HEADER)), 0o600);
        }
        let token = entry(&dir, None, "aws-sso/acme/token");
        token.delete_credential().unwrap();
        assert!(matches!(token.delete_credential(), Err(Error::NoEntry)));
    }

    #[test]
    fn a_missing_header_never_starts_a_new_vault_over_sealed_secrets() {
        let scratch = scratch("no-header");
        let dir = scratch.0.join("vault");
        let pass = "correct horse battery";
        entry(&dir, Some(pass), "a").set_password("kept").unwrap();
        std::fs::remove_file(dir.join(HEADER)).unwrap();
        let refused = entry(&dir, Some(pass), "b")
            .set_password("new")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("no vault.json"), "{refused}");
        assert!(!dir.join(HEADER).exists());
        // Reading a missing key still needs nothing.
        assert!(matches!(
            entry(&dir, Some(pass), "c").get_password(),
            Err(Error::NoEntry)
        ));
    }

    #[test]
    fn an_agent_is_not_pointed_at_the_passphrase_variable() {
        let scratch = scratch("agent-hint");
        let dir = scratch.0.join("vault");
        entry(&dir, Some("correct horse battery"), "a")
            .set_password("x")
            .unwrap();
        let locked = || {
            entry(&dir, None, "a")
                .get_password()
                .unwrap_err()
                .to_string()
        };
        let person = crate::Context::builder().build();
        let message = {
            let _entered = person.enter();
            locked()
        };
        assert!(message.contains("OMNIFOB_VAULT_PASSPHRASE"), "{message}");
        let agent = crate::Context::builder()
            .agent(Some(crate::context::Agent::default()))
            .build();
        let _entered = agent.enter();
        let message = locked();
        assert!(message.contains("is locked"), "{message}");
        assert!(!message.contains("OMNIFOB_VAULT_PASSPHRASE"), "{message}");
    }

    #[test]
    fn the_prompt_is_asked_once_per_process_and_told_when_the_vault_is_new() {
        let scratch = scratch("prompt");
        let dir = scratch.0.join("vault");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        let unlock = VaultUnlock {
            passphrase: None,
            prompt: Some(Arc::new(move |request: &PassphraseRequest| {
                log.lock().unwrap().push(request.new);
                Ok("a long enough passphrase".to_string())
            })),
            cache_key: false,
        };
        let store: Arc<keyring_core::CredentialStore> = Store::new(&dir, unlock.clone()).unwrap();
        for key in ["a", "b", "c"] {
            store
                .build("omnifob", key, None)
                .unwrap()
                .set_password(key)
                .unwrap();
        }
        assert_eq!(*asked.lock().unwrap(), [true]);
        let again: Arc<keyring_core::CredentialStore> = Store::new(&dir, unlock).unwrap();
        assert_eq!(
            again
                .build("omnifob", "b", None)
                .unwrap()
                .get_password()
                .unwrap(),
            "b"
        );
        assert_eq!(*asked.lock().unwrap(), [true, false]);
    }
}
