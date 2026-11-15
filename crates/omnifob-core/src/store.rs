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
//! or `keyutils`. For tests of the command line only,
//! `test-plaintext-files:<absolute dir>` keeps secrets unencrypted in files
//! (see [`test_files`]).

use std::sync::OnceLock;

use anyhow::{Context, anyhow, bail};
use keyring_core::{Entry, Error as KeyringError};
use serde::Serialize;
use serde::de::DeserializeOwned;

const SERVICE: &str = "omnifob";

static BACKEND: OnceLock<Result<&'static str, String>> = OnceLock::new();

/// Selects the platform store once; returns the name of the store in use.
pub fn init() -> anyhow::Result<&'static str> {
    BACKEND
        .get_or_init(|| select().map_err(|e| format!("{e:#}")))
        .clone()
        .map_err(|e| anyhow!("no usable keychain: {e}"))
}

fn select() -> anyhow::Result<&'static str> {
    let forced = std::env::var("OMNIFOB_KEYRING")
        .ok()
        .filter(|v| !v.is_empty());
    match forced.as_deref() {
        Some(name) => use_store(name).map(|_| leak(name)),
        None => use_native(),
    }
}

fn leak(name: &str) -> &'static str {
    Box::leak(name.to_string().into_boxed_str())
}

#[cfg(target_os = "macos")]
fn use_native() -> anyhow::Result<&'static str> {
    use_store("keychain").map(|_| "keychain")
}

#[cfg(target_os = "windows")]
fn use_native() -> anyhow::Result<&'static str> {
    use_store("windows").map(|_| "windows")
}

#[cfg(target_os = "linux")]
fn use_native() -> anyhow::Result<&'static str> {
    match use_store("secret-service") {
        Ok(()) => Ok("secret-service"),
        Err(e) => {
            tracing::debug!("Secret Service unavailable ({e:#}), using keyutils");
            use_store("keyutils").map(|_| "keyutils")
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn use_native() -> anyhow::Result<&'static str> {
    use_store("secret-service").map(|_| "secret-service")
}

fn use_store(name: &str) -> anyhow::Result<()> {
    use keyring_core::set_default_store;
    if let Some(rest) = name.strip_prefix(test_files::NAME) {
        let dir = test_files::dir(rest)?;
        set_default_store(test_files::Store::new(&dir)?);
        eprintln!(
            "fob: warning: OMNIFOB_KEYRING keeps secrets UNENCRYPTED in {}; it is for tests only",
            dir.display()
        );
        return Ok(());
    }
    match name {
        #[cfg(target_os = "macos")]
        "keychain" => set_default_store(apple_native_keyring_store::keychain::Store::new()?),
        #[cfg(target_os = "windows")]
        "windows" => set_default_store(windows_native_keyring_store::Store::new()?),
        #[cfg(all(unix, not(target_os = "macos")))]
        "secret-service" => {
            let store = zbus_secret_service_keyring_store::Store::new()?;
            set_default_store(store);
            // Creating the store succeeds without a running service, so probe it.
            match Entry::new(SERVICE, "probe")?.get_password() {
                Ok(_) | Err(KeyringError::NoEntry) => {}
                Err(e) => {
                    keyring_core::unset_default_store();
                    return Err(e.into());
                }
            }
        }
        #[cfg(target_os = "linux")]
        "keyutils" => set_default_store(linux_keyutils_keyring_store::Store::new()?),
        other => bail!("keychain store '{other}' is not available on this platform"),
    }
    Ok(())
}

fn entry(key: &str) -> anyhow::Result<Entry> {
    init()?;
    Entry::new(SERVICE, key).with_context(|| format!("opening keychain entry '{key}'"))
}

/// Reads a value; `None` when nothing is stored under `key`.
pub fn get<T: DeserializeOwned>(key: &str) -> anyhow::Result<Option<T>> {
    let json = match entry(key)?.get_password() {
        Ok(json) => {
            // Values stored before persistence existed get persisted once.
            if let Err(e) = wsl::write_if_missing(key, &json) {
                tracing::warn!("could not persist '{key}' with Windows DPAPI: {e:#}");
            }
            json
        }
        Err(KeyringError::NoEntry) => match wsl::read(key)? {
            // Restore what survived a reboot into the fast store.
            Some(json) => {
                entry(key)?.set_password(&json)?;
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
    let json = serde_json::to_string(value)?;
    entry(key)?
        .set_password(&json)
        .with_context(|| format!("writing keychain entry '{key}'"))?;
    wsl::write(key, &json)
}

/// Deletes a value; returns whether anything was stored.
pub fn delete(key: &str) -> anyhow::Result<bool> {
    let in_keychain = match entry(key)?.delete_credential() {
        Ok(()) => true,
        Err(KeyringError::NoEntry) => false,
        Err(e) => return Err(e).with_context(|| format!("deleting keychain entry '{key}'")),
    };
    Ok(wsl::delete(key)? || in_keychain)
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
    let store = init()?;
    if let Some(rest) = store.strip_prefix(test_files::NAME) {
        return Ok(format!(
            "unencrypted files in {} (tests only)",
            test_files::dir(rest)?.display()
        ));
    }
    Ok(if wsl::enabled() {
        format!(
            "{store}, persisted with Windows DPAPI in {}",
            wsl::dir().display()
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
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;

    use anyhow::{Context, bail};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    const PROTECT: &str = "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))";
    const UNPROTECT: &str = "$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))";

    pub fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| {
            cfg!(target_os = "linux")
                && super::init().is_ok_and(|s| s == "keyutils")
                && std::env::var("OMNIFOB_WSL_DPAPI").map_or(true, |v| v != "0")
                && std::fs::read_to_string("/proc/version")
                    .is_ok_and(|v| v.to_lowercase().contains("microsoft"))
                && Command::new("powershell.exe")
                    .arg("-?")
                    // WSL drains an inherited stdin into the Windows process,
                    // even unread, so input piped to `fob exec` would be lost.
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok()
        })
    }

    pub fn dir() -> PathBuf {
        crate::paths::state_dir().join("vault")
    }

    fn persisted(key: &str) -> bool {
        !key.starts_with("credentials/")
    }

    fn file(key: &str) -> PathBuf {
        let mut name = String::new();
        for b in key.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                name.push(b as char);
            } else {
                name.push_str(&format!("%{b:02X}"));
            }
        }
        dir().join(format!("{name}.dpapi"))
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

    pub fn write(key: &str, json: &str) -> anyhow::Result<()> {
        if !enabled() || !persisted(key) {
            return Ok(());
        }
        let sealed = dpapi(PROTECT, &BASE64.encode(json.as_bytes()))?;
        let path = file(key);
        std::fs::create_dir_all(dir())?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))
    }

    pub fn write_if_missing(key: &str, json: &str) -> anyhow::Result<()> {
        if enabled() && persisted(key) && !file(key).exists() {
            write(key, json)?;
        }
        Ok(())
    }

    pub fn read(key: &str) -> anyhow::Result<Option<String>> {
        if !enabled() || !persisted(key) {
            return Ok(None);
        }
        let sealed = match std::fs::read_to_string(file(key)) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let plain = BASE64
            .decode(dpapi(UNPROTECT, sealed.trim())?)
            .context("decoding the output of Windows DPAPI")?;
        Ok(Some(String::from_utf8(plain)?))
    }

    pub fn delete(key: &str) -> anyhow::Result<bool> {
        if !enabled() {
            return Ok(false);
        }
        match std::fs::remove_file(file(key)) {
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
/// in-memory store of [`use_memory_store`] would forget everything between
/// commands; this store keeps secrets where the next command finds them,
/// without touching the real keychain. It does not protect them at all:
/// every secret is written unencrypted, one file per key, named after the
/// key with every byte outside `[A-Za-z0-9._-]` written as `%XX` (so
/// `aws-sso/acme/token` is `aws-sso%2Facme%2Ftoken`). To keep it from being
/// chosen by accident, it needs an absolute directory, says so on stderr
/// whenever it is used, and on Unix creates the directory `0700` and the
/// files `0600`. Never use it for real credentials.
pub mod test_files {
    use std::any::Any;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use anyhow::{Context, bail};
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

    /// A file name for `key`.
    pub fn file_name(key: &str) -> String {
        let mut name = String::new();
        for b in key.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                name.push(b as char);
            } else {
                name.push_str(&format!("%{b:02X}"));
            }
        }
        name
    }

    #[derive(Debug)]
    pub struct Store {
        dir: PathBuf,
    }

    impl Store {
        pub fn new(dir: &Path) -> anyhow::Result<Arc<Self>> {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
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
                path: self.dir.join(file_name(user)),
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
            let dir = self.path.parent().unwrap_or(Path::new("."));
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let tmp = dir.join(format!(".{}-{nonce}.tmp", std::process::id()));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let written = options.open(&tmp).and_then(|mut file| {
                file.write_all(secret)?;
                drop(file);
                std::fs::rename(&tmp, &self.path)
            });
            if written.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            written.map_err(platform)
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

/// Puts this process on an in-memory store, so tests never touch the real
/// keychain. Must run before anything else uses the store.
#[doc(hidden)]
pub fn use_memory_store() -> anyhow::Result<()> {
    let chosen = BACKEND.get_or_init(|| {
        keyring_core::mock::Store::new()
            .map(|store| keyring_core::set_default_store(store))
            .map(|()| "memory")
            .map_err(|e| e.to_string())
    });
    match chosen {
        Ok("memory") => Ok(()),
        Ok(other) => bail!("the {other} store was already chosen"),
        Err(e) => bail!("{e}"),
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
    let dir = crate::paths::state_dir().join("locks");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.lock", lock_file_name(name)));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(Lock(file))),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                tracing::debug!("{} is still locked; going ahead", path.display());
                return Ok(None);
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).with_context(|| format!("locking {}", path.display()));
            }
        }
    }
}

/// A file name for a lock: letters, digits, `-`, `_` and `.` kept, the rest `_`.
fn lock_file_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Key for the cached credentials of a profile.
pub fn credentials_key(profile_id: &str) -> String {
    format!("credentials/{profile_id}")
}
