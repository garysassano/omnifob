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
//! or `keyutils`.

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
        let sealed = dpapi(PROTECT, &b64::encode(json.as_bytes()))?;
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
        let plain = b64::decode(&dpapi(UNPROTECT, sealed.trim())?)?;
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

    /// Minimal standard base64, to avoid a dependency for two calls.
    mod b64 {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        pub fn encode(data: &[u8]) -> String {
            let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
            for chunk in data.chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
                for i in 0..4 {
                    if i <= chunk.len() {
                        out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
                    } else {
                        out.push('=');
                    }
                }
            }
            out
        }

        pub fn decode(text: &str) -> anyhow::Result<Vec<u8>> {
            let mut out = Vec::with_capacity(text.len() / 4 * 3);
            let (mut n, mut bits) = (0u32, 0);
            for c in text
                .bytes()
                .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
            {
                let v = ALPHABET
                    .iter()
                    .position(|a| *a == c)
                    .ok_or_else(|| anyhow::anyhow!("invalid base64"))?
                    as u32;
                n = n << 6 | v;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((n >> bits & 0xff) as u8);
                }
            }
            Ok(out)
        }

        #[cfg(test)]
        mod tests {
            #[test]
            fn round_trips() {
                for s in [
                    "",
                    "f",
                    "fo",
                    "foo",
                    "foob",
                    "fooba",
                    "foobar",
                    "{\"k\":\"v\u{e9}\"}",
                ] {
                    assert_eq!(
                        super::decode(&super::encode(s.as_bytes())).unwrap(),
                        s.as_bytes()
                    );
                }
                assert_eq!(super::encode(b"foobar"), "Zm9vYmFy");
                assert_eq!(super::encode(b"fo"), "Zm8=");
            }
        }
    }
}

/// Key for the cached credentials of a profile.
pub fn credentials_key(profile_id: &str) -> String {
    format!("credentials/{profile_id}")
}
