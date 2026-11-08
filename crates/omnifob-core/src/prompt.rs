//! Questions the library may need to ask mid-operation. Whoever embeds it
//! answers them: the command line registers a terminal prompt when it runs in
//! one. Without a registered prompt, an operation that needs an answer fails
//! with an error that says how to get past it.

use std::sync::OnceLock;

use anyhow::bail;

type MfaPrompt = Box<dyn Fn(&str) -> anyhow::Result<String> + Send + Sync>;

static MFA: OnceLock<MfaPrompt> = OnceLock::new();

/// Registers the function that asks for a code from the MFA device whose ARN
/// it is given. Only the first registration counts.
pub fn set_mfa_prompt(prompt: impl Fn(&str) -> anyhow::Result<String> + Send + Sync + 'static) {
    let _ = MFA.set(Box::new(prompt));
}

/// A six-digit code from the MFA device `serial`, for `what` (a profile id).
pub fn mfa_code(serial: &str, what: &str) -> anyhow::Result<String> {
    let Some(prompt) = MFA.get() else {
        bail!(
            "{what} needs a code from the MFA device {serial}; run `fob creds {what}` in a terminal first"
        );
    };
    let code = prompt(serial)?.trim().to_string();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        bail!("an MFA code is six digits");
    }
    Ok(code)
}
