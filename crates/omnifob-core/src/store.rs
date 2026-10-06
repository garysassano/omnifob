//! Secret storage in the OS keychain, through `keyring-core`.
//!
//! Every secret (SSO tokens, bootstrap tokens, cached credentials) is one
//! JSON value under the service name `omnifob`.
//!
//! On Linux the Secret Service (GNOME Keyring, KWallet) is preferred. Where it
//! is unavailable, as on WSL or headless machines, the kernel keyutils store
//! is used instead; it keeps secrets until reboot, so a reboot means signing
//! in again. `OMNIFOB_KEYRING` forces a store: `keychain`, `windows`,
//! `secret-service` or `keyutils`.

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
    match entry(key)?.get_password() {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .with_context(|| format!("keychain entry '{key}' is not valid")),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading keychain entry '{key}'")),
    }
}

pub fn set<T: Serialize>(key: &str, value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string(value)?;
    entry(key)?
        .set_password(&json)
        .with_context(|| format!("writing keychain entry '{key}'"))
}

/// Deletes a value; returns whether anything was stored.
pub fn delete(key: &str) -> anyhow::Result<bool> {
    match entry(key)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(KeyringError::NoEntry) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("deleting keychain entry '{key}'")),
    }
}

/// Key for the cached credentials of a profile.
pub fn credentials_key(profile_id: &str) -> String {
    format!("credentials/{profile_id}")
}
