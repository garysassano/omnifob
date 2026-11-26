//! Secret storage in the OS keychain, through `keyring-core`.
//!
//! Every secret (SSO tokens, bootstrap tokens, cached credentials) is one
//! JSON value under the service name `omnifob`.
//!
//! On Linux the Secret Service (GNOME Keyring, KWallet) is preferred. Where it
//! is unavailable, as on WSL or headless machines, the kernel keyutils store
//! is used instead; it keeps secrets until reboot. On WSL, sessions and
//! bootstrap tokens are also written to files encrypted with Windows DPAPI
//! (see [`wsl`]), so they survive reboots; keyutils stays the fast cache.
//! `OMNIFOB_KEYRING` forces a store: `keychain`, `windows`, `secret-service`
//! or `keyutils`, or `encrypted-file` for files encrypted with a passphrase
//! (see [`vault`]), which survive reboots where no keychain does. For tests
//! of the command line only,
//! `test-plaintext-files:<absolute dir>` keeps secrets unencrypted in files
//! (see [`test_files`]).

use std::sync::{Arc, OnceLock};

use anyhow::{Context as _, bail};
use keyring_core::{CredentialStore, Entry, Error as KeyringError};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Context;

pub mod vault;

const SERVICE: &str = "omnifob";

/// Where a [`Context`] keeps secrets.
#[derive(Debug, Clone)]
pub enum Keychain {
    /// The platform's: the macOS keychain, the Windows Credential Manager,
    /// else the Secret Service, falling back to keyutils on Linux.
    Native,
    /// A store by the name `OMNIFOB_KEYRING` gives it: `keychain`,
    /// `windows`, `secret-service`, `keyutils`, `encrypted-file` (see
    /// [`vault`]), or, for tests of the command
    /// line only, `test-plaintext-files:<absolute dir>` ([`test_files`]).
    Named(String),
    /// In memory, for tests: never touches the real keychain, and forgets
    /// everything with the context.
    Memory,
    /// Any `keyring-core` store; `name` describes it in `fob status`.
    Custom {
        name: String,
        store: Arc<CredentialStore>,
    },
}

impl Keychain {
    /// The store `OMNIFOB_KEYRING` names, else the platform's.
    pub fn from_env() -> Self {
        match std::env::var("OMNIFOB_KEYRING") {
            Ok(name) if !name.is_empty() => Self::Named(name),
            _ => Self::Native,
        }
    }
}

/// The store a context chose.
pub(crate) struct Selected {
    name: String,
    store: Arc<CredentialStore>,
    /// Whether long-lived values are also sealed with Windows DPAPI.
    wsl: OnceLock<bool>,
}

impl Selected {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn inner(&self) -> &Arc<CredentialStore> {
        &self.store
    }
}

pub(crate) fn select(cx: &Context, keychain: &Keychain) -> anyhow::Result<Selected> {
    let (name, store) = match keychain {
        Keychain::Native => use_native()?,
        Keychain::Named(name) => (name.clone(), use_named_store(cx, name)?),
        Keychain::Memory => (
            "memory".to_string(),
            keyring_core::mock::Store::new()? as Arc<CredentialStore>,
        ),
        Keychain::Custom { name, store } => (name.clone(), store.clone()),
    };
    Ok(Selected {
        name,
        store,
        wsl: OnceLock::new(),
    })
}

#[cfg(target_os = "macos")]
fn use_native() -> anyhow::Result<(String, Arc<CredentialStore>)> {
    Ok(("keychain".to_string(), use_store("keychain")?))
}

#[cfg(target_os = "windows")]
fn use_native() -> anyhow::Result<(String, Arc<CredentialStore>)> {
    Ok(("windows".to_string(), use_store("windows")?))
}

#[cfg(target_os = "linux")]
fn use_native() -> anyhow::Result<(String, Arc<CredentialStore>)> {
    let keyutils = || Ok(("keyutils".to_string(), use_store("keyutils")?));
    if !session_bus_may_exist(
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
    ) {
        tracing::debug!("no D-Bus session bus, so no Secret Service; using keyutils");
        return keyutils();
    }
    match use_store("secret-service") {
        Ok(store) => Ok(("secret-service".to_string(), store)),
        Err(e) => {
            tracing::debug!("Secret Service unavailable ({e:#}), using keyutils");
            keyutils()
        }
    }
}

/// Whether a D-Bus session bus, and so a Secret Service, may be reachable,
/// judged as zbus finds the bus: `DBUS_SESSION_BUS_ADDRESS` when set, else
/// the socket `$XDG_RUNTIME_DIR/bus`. Only a missing socket rules it out, so
/// a machine without a desktop session (WSL, a server) skips connecting to
/// a bus and probing the service. Without `XDG_RUNTIME_DIR` zbus guesses a
/// directory, so the Secret Service is still tried.
#[cfg(target_os = "linux")]
fn session_bus_may_exist(
    address: Option<&std::ffi::OsStr>,
    runtime_dir: Option<&std::ffi::OsStr>,
) -> bool {
    match (address, runtime_dir) {
        (Some(_), _) | (None, None) => true,
        (None, Some(dir)) => std::path::Path::new(dir).join("bus").exists(),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn use_native() -> anyhow::Result<(String, Arc<CredentialStore>)> {
    Ok(("secret-service".to_string(), use_store("secret-service")?))
}

/// A store `OMNIFOB_KEYRING` names, including the ones that need the
/// context: the encrypted vault (its directory and passphrase).
fn use_named_store(cx: &Context, name: &str) -> anyhow::Result<Arc<CredentialStore>> {
    if let Some(rest) = name.strip_prefix(vault::NAME) {
        let dir = vault::dir(rest, cx.state_dir()?)?;
        return Ok(vault::Store::new(&dir, cx.vault_unlock().clone())? as Arc<CredentialStore>);
    }
    use_store(name)
}

fn use_store(name: &str) -> anyhow::Result<Arc<CredentialStore>> {
    if let Some(rest) = name.strip_prefix(test_files::NAME) {
        let dir = test_files::dir(rest)?;
        let store = test_files::Store::new(&dir)?;
        tracing::warn!(
            "OMNIFOB_KEYRING keeps secrets UNENCRYPTED in {}; it is for tests only",
            dir.display()
        );
        return Ok(store as Arc<CredentialStore>);
    }
    Ok(match name {
        #[cfg(target_os = "macos")]
        "keychain" => apple_native_keyring_store::keychain::Store::new()? as Arc<CredentialStore>,
        #[cfg(target_os = "windows")]
        "windows" => windows_native_keyring_store::Store::new()? as Arc<CredentialStore>,
        #[cfg(all(unix, not(target_os = "macos")))]
        "secret-service" => {
            let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new()?;
            // Creating the store succeeds without a running service, so probe it.
            match store.build(SERVICE, "probe", None)?.get_password() {
                Ok(_) | Err(KeyringError::NoEntry) => {}
                Err(e) => return Err(e.into()),
            }
            store
        }
        #[cfg(target_os = "linux")]
        "keyutils" => linux_keyutils_keyring_store::Store::new()? as Arc<CredentialStore>,
        other => bail!("keychain store '{other}' is not available on this platform"),
    })
}

fn entry(store: &Selected, key: &str) -> anyhow::Result<Entry> {
    store
        .store
        .build(SERVICE, key, None)
        .with_context(|| format!("opening keychain entry '{key}'"))
}

/// Reads a value; `None` when nothing is stored under `key`.
pub fn get<T: DeserializeOwned>(key: &str) -> anyhow::Result<Option<T>> {
    let cx = Context::current();
    let store = cx.store()?;
    let json = match entry(store, key)?.get_password() {
        Ok(json) => {
            // Values stored before persistence existed get persisted once.
            if let Err(e) = wsl::write_if_missing(&cx, key, &json) {
                tracing::warn!("could not persist '{key}' with Windows DPAPI: {e:#}");
            }
            json
        }
        Err(KeyringError::NoEntry) => match wsl::read(&cx, key)? {
            // Restore what survived a reboot into the fast store.
            Some(json) => {
                entry(store, key)?.set_password(&json)?;
                json
            }
            None => return Ok(None),
        },
        Err(e) => return Err(e).with_context(|| format!("reading keychain entry '{key}'")),
    };
    serde_json::from_str(&json)
        .map(Some)
        .with_context(|| format!("keychain entry '{key}' is not valid"))
}

pub fn set<T: Serialize>(key: &str, value: &T) -> anyhow::Result<()> {
    let cx = Context::current();
    let json = serde_json::to_string(value)?;
    entry(cx.store()?, key)?
        .set_password(&json)
        .with_context(|| format!("writing keychain entry '{key}'"))?;
    wsl::write(&cx, key, &json)
}

/// Deletes a value; returns whether anything was stored.
pub fn delete(key: &str) -> anyhow::Result<bool> {
    let cx = Context::current();
    let in_keychain = match entry(cx.store()?, key)?.delete_credential() {
        Ok(()) => true,
        Err(KeyringError::NoEntry) => false,
        Err(e) => return Err(e).with_context(|| format!("deleting keychain entry '{key}'")),
    };
    Ok(wsl::delete(&cx, key)? || in_keychain)
}

/// Moves a value to another key; returns whether there was one.
pub fn rename(old: &str, new: &str) -> anyhow::Result<bool> {
    let Some(value) = get::<serde_json::Value>(old)? else {
        return Ok(false);
    };
    set(new, &value)?;
    delete(old)?;
    Ok(true)
}

/// Describes where secrets are kept, for `fob status`.
pub fn description() -> anyhow::Result<String> {
    let cx = Context::current();
    let store = &cx.store()?.name;
    if let Some(rest) = store.strip_prefix(test_files::NAME) {
        return Ok(format!(
            "unencrypted files in {} (tests only)",
            test_files::dir(rest)?.display()
        ));
    }
    if let Some(rest) = store.strip_prefix(vault::NAME) {
        return Ok(format!(
            "files encrypted with a passphrase in {}",
            vault::dir(rest, cx.state_dir()?)?.display()
        ));
    }
    Ok(if wsl::enabled(&cx) {
        format!(
            "{store}, persisted with Windows DPAPI in {}",
            wsl::dir(&cx)?.display()
        )
    } else if store == "keyutils" {
        "keyutils (lost on reboot)".to_string()
    } else {
        store.to_string()
    })
}

/// Persistence for WSL, where the kernel keyring forgets everything on
/// reboot. Values are encrypted with Windows DPAPI for the current Windows
/// user, through `powershell.exe`, and written to files. Only long-lived
/// values are persisted; cached credentials are cheap to recreate. Set
/// `OMNIFOB_WSL_DPAPI=0` to turn this off.
mod wsl {
    use anyhow::{Context as _, bail};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use crate::Context;

    const PROTECT: &str = "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))";
    const UNPROTECT: &str = "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))";

    pub fn enabled(cx: &Context) -> bool {
        let Ok(store) = cx.store() else {
            return false;
        };
        *store.wsl.get_or_init(|| {
            cfg!(target_os = "linux")
                && store.name == "keyutils"
                && cx.wsl_dpapi()
                && crate::platform::is_wsl()
                && crate::platform::wsl_interop()
                && crate::platform::on_path("powershell.exe")
        })
    }

    pub fn dir(cx: &Context) -> anyhow::Result<PathBuf> {
        Ok(cx.state_dir()?.join("vault"))
    }

    fn persisted(key: &str) -> bool {
        !key.starts_with("credentials/")
    }

    fn file(cx: &Context, key: &str) -> anyhow::Result<PathBuf> {
        Ok(dir(cx)?.join(format!("{}.dpapi", crate::files::encode_key_filename(key))))
    }

    /// Runs a DPAPI script with base64 on stdin; returns base64 from stdout.
    fn dpapi(script: &str, input_b64: &str) -> anyhow::Result<String> {
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting powershell.exe for Windows DPAPI")?;
        child
            .stdin
            .take()
            .context("no stdin")?
            .write_all(input_b64.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "Windows DPAPI failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    }

    // Each function checks `persisted` (and, below, the file) before
    // `enabled`, so a cached credential lookup never needs to learn whether
    // Windows is reachable.

    pub fn write(cx: &Context, key: &str, json: &str) -> anyhow::Result<()> {
        if !persisted(key) || !enabled(cx) {
            return Ok(());
        }
        let sealed = dpapi(PROTECT, &BASE64.encode(json.as_bytes()))?;
        // The directory and file are the user's only: even sealed, the file
        // names give away integrations and profiles.
        crate::files::create_private_dir(cx.state_dir()?)?;
        crate::files::write_private(&file(cx, key)?, sealed)
    }

    pub fn write_if_missing(cx: &Context, key: &str, json: &str) -> anyhow::Result<()> {
        if persisted(key) && !file(cx, key)?.exists() && enabled(cx) {
            write(cx, key, json)?;
        }
        Ok(())
    }

    pub fn read(cx: &Context, key: &str) -> anyhow::Result<Option<String>> {
        if !persisted(key) || !enabled(cx) {
            return Ok(None);
        }
        let sealed = match std::fs::read_to_string(file(cx, key)?) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let plain = BASE64
            .decode(dpapi(UNPROTECT, sealed.trim())?)
            .context("decoding the output of Windows DPAPI")?;
        Ok(Some(String::from_utf8(plain)?))
    }

    pub fn delete(cx: &Context, key: &str) -> anyhow::Result<bool> {
        if !persisted(key) || !enabled(cx) {
            return Ok(false);
        }
        match std::fs::remove_file(file(cx, key)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use base64::Engine;

        // Encoded by the hand-rolled base64 this replaced, and by
        // PowerShell's [Convert]::ToBase64String, which writes the sealed
        // files: standard alphabet, padded.
        const KNOWN: [(&str, &str); 8] = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("{\"k\":\"v\u{e9}?>~\"}", "eyJrIjoidsOpPz5+In0="),
        ];

        #[test]
        fn base64_matches_what_was_stored() {
            for (plain, encoded) in KNOWN {
                assert_eq!(super::BASE64.encode(plain.as_bytes()), encoded);
                assert_eq!(super::BASE64.decode(encoded).unwrap(), plain.as_bytes());
            }
        }
    }
}

/// A store of plaintext files, for end-to-end tests of the command line
/// only: `OMNIFOB_KEYRING=test-plaintext-files:<absolute dir>`.
///
/// Tests run the `fob` binary, so each command is a new process and the
/// in-memory store ([`Keychain::Memory`]) would forget everything between
/// commands; this store keeps secrets where the next command finds them,
/// without touching the real keychain. It does not protect them at all:
/// every secret is written unencrypted, one file per key, named by
/// [`crate::files::encode_key_filename`] (so `aws-sso/acme/token` is
/// `aws-sso%2Facme%2Ftoken`). To keep it from being
/// chosen by accident, it needs an absolute directory, says so on stderr
/// whenever it is used, and on Unix creates the directory `0700` and the
/// files `0600`. Never use it for real credentials.
pub mod test_files {
    use std::any::Any;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use anyhow::bail;
    use keyring_core::api::{CredentialApi, CredentialStoreApi};
    use keyring_core::{Credential, Entry, Error, Result};

    /// What `OMNIFOB_KEYRING` starts with to choose this store.
    pub const NAME: &str = "test-plaintext-files";

    /// The directory from what follows [`NAME`] in `OMNIFOB_KEYRING`, which
    /// must be `:<absolute dir>`.
    pub fn dir(rest: &str) -> anyhow::Result<PathBuf> {
        let Some(dir) = rest.strip_prefix(':').filter(|d| !d.is_empty()) else {
            bail!(
                "OMNIFOB_KEYRING={NAME}{rest} needs a directory: {NAME}:<absolute dir> (for tests only; it stores secrets unencrypted)"
            );
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

    #[derive(Debug)]
    pub struct Store {
        dir: PathBuf,
    }

    impl Store {
        pub fn new(dir: &Path) -> anyhow::Result<Arc<Self>> {
            crate::files::create_private_dir(dir)?;
            Ok(Arc::new(Self {
                dir: dir.to_path_buf(),
            }))
        }
    }

    impl CredentialStoreApi for Store {
        fn vendor(&self) -> String {
            "omnifob test-plaintext-files".to_string()
        }

        fn id(&self) -> String {
            self.dir.display().to_string()
        }

        fn build(
            &self,
            service: &str,
            user: &str,
            _modifiers: Option<&HashMap<&str, &str>>,
        ) -> Result<Entry> {
            Ok(Entry::new_with_credential(Arc::new(File {
                service: service.to_string(),
                user: user.to_string(),
                path: self.dir.join(crate::files::encode_key_filename(user)),
            })))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Debug)]
    struct File {
        service: String,
        user: String,
        path: PathBuf,
    }

    fn platform(e: std::io::Error) -> Error {
        Error::PlatformFailure(Box::new(e))
    }

    impl CredentialApi for File {
        /// Writes a temporary file and renames it over the old one, so a
        /// command reading at the same time never sees half a secret.
        fn set_secret(&self, secret: &[u8]) -> Result<()> {
            crate::files::write_private(&self.path, secret)
                .map_err(|e| Error::PlatformFailure(e.into()))
        }

        fn get_secret(&self) -> Result<Vec<u8>> {
            match std::fs::read(&self.path) {
                Ok(secret) => Ok(secret),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NoEntry),
                Err(e) => Err(platform(e)),
            }
        }

        fn delete_credential(&self) -> Result<()> {
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NoEntry),
                Err(e) => Err(platform(e)),
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

        #[test]
        fn the_directory_must_be_given_and_absolute() {
            for rest in ["", ":", "x", ":relative/dir"] {
                assert!(dir(rest).is_err(), "{rest:?}");
            }
            let absolute = std::env::temp_dir().join("omnifob-test-files");
            let rest = format!(":{}", absolute.display());
            assert_eq!(dir(&rest).unwrap(), absolute);
        }

        #[test]
        fn secrets_are_kept_in_private_files() {
            let root =
                std::env::temp_dir().join(format!("omnifob-test-files-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let dir = root.join("keyring");
            let store = Store::new(&dir).unwrap();
            let entry = store.build("omnifob", "aws-sso/acme/token", None).unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
            entry.set_password("{\"a\":1}").unwrap();
            entry.set_password("{\"a\":2}").unwrap();
            assert_eq!(entry.get_password().unwrap(), "{\"a\":2}");
            let path = dir.join("aws-sso%2Facme%2Ftoken");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":2}");
            let names: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names, ["aws-sso%2Facme%2Ftoken"], "no temporary files");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode(&dir), 0o700);
                assert_eq!(mode(&path), 0o600);
            }
            entry.delete_credential().unwrap();
            assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
            assert!(!path.exists());
            std::fs::remove_dir_all(&root).unwrap();
        }
    }
}

/// An exclusive lock shared by every omnifob process on this machine,
/// released when dropped. It guards read-modify-write of a stored value, such
/// as renewing a session with a refresh token that only works once.
pub struct Lock(#[allow(dead_code)] std::fs::File);

/// Takes the lock called `name`, waiting up to `timeout`. Returns `None` when
/// another process holds it that long, so the caller can go ahead unguarded
/// rather than hang.
pub async fn lock(name: &str, timeout: std::time::Duration) -> anyhow::Result<Option<Lock>> {
    let (file, path) = open_lock(name)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(taken) = try_lock(&file, &path, deadline)? {
            return Ok(taken.then_some(Lock(file)));
        }
        tokio::time::sleep(LOCK_POLL).await;
    }
}

/// [`lock`] for synchronous callers, which waits on this thread. Meant for
/// locks held only as long as a file is read and written back.
pub fn lock_blocking(name: &str, timeout: std::time::Duration) -> anyhow::Result<Option<Lock>> {
    let (file, path) = open_lock(name)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(taken) = try_lock(&file, &path, deadline)? {
            return Ok(taken.then_some(Lock(file)));
        }
        std::thread::sleep(LOCK_POLL);
    }
}

const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(50);

fn open_lock(name: &str) -> anyhow::Result<(std::fs::File, std::path::PathBuf)> {
    let path = lock_dir()?.join(lock_file_name(name));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok((file, path))
}

/// One attempt: `Some(true)` when taken, `Some(false)` when the deadline
/// passed, `None` to try again.
fn try_lock(
    file: &std::fs::File,
    path: &std::path::Path,
    deadline: std::time::Instant,
) -> anyhow::Result<Option<bool>> {
    match file.try_lock() {
        Ok(()) => Ok(Some(true)),
        Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => Ok(None),
        Err(std::fs::TryLockError::WouldBlock) => {
            tracing::debug!("{} is still locked; going ahead", path.display());
            Ok(Some(false))
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

/// The directory of lock files, `locks` in the state directory, created
/// private if missing.
pub fn lock_dir() -> anyhow::Result<std::path::PathBuf> {
    let state = crate::paths::state_dir()?;
    crate::files::create_private_dir(&state)?;
    let dir = state.join("locks");
    crate::files::create_private_dir(&dir)?;
    Ok(dir)
}

/// The file name of the lock called `name`: `<name>.lock`, with `name`
/// encoded by [`crate::files::encode_key_filename`] so distinct names never
/// share a lock.
pub fn lock_file_name(name: &str) -> String {
    format!("{}.lock", crate::files::encode_key_filename(name))
}

/// Key for the cached credentials of a profile.
pub fn credentials_key(profile_id: &str) -> String {
    format!("credentials/{profile_id}")
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    fn the_secret_service_is_skipped_only_without_a_bus_socket() {
        use std::ffi::OsStr;
        let dir = std::env::temp_dir().join(format!("omnifob-bus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runtime = Some(dir.as_os_str());
        assert!(!super::session_bus_may_exist(None, runtime));
        let address = Some(OsStr::new("unix:path=/elsewhere"));
        assert!(super::session_bus_may_exist(address, runtime));
        assert!(super::session_bus_may_exist(None, None));
        std::fs::write(dir.join("bus"), "").unwrap();
        assert!(super::session_bus_may_exist(None, runtime));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn distinct_lock_names_never_share_a_file() {
        assert_eq!(super::lock_file_name("aws-sso-acme"), "aws-sso-acme.lock");
        assert_eq!(
            super::lock_file_name("credentials-acme/111111111111/Admin"),
            "credentials-acme%2F111111111111%2FAdmin.lock"
        );
        // With `_` for every other character these were one lock.
        assert_ne!(
            super::lock_file_name("credentials-a/b_c/d"),
            super::lock_file_name("credentials-a/b/c_d")
        );
    }
}
