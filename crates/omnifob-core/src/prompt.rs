//! Questions the library may need to ask mid-operation. Whoever embeds it
//! answers them through its [`Context`](crate::Context): the command line
//! sets a terminal prompt when it runs in one. Without one, an operation
//! that needs an answer fails with an error that says how to get past it.

use anyhow::bail;

/// A six-digit code from the MFA device `serial`, for `what` (a profile id).
pub fn mfa_code(serial: &str, what: &str) -> anyhow::Result<String> {
    let cx = crate::Context::current();
    let Some(prompt) = cx.mfa_prompt() else {
        bail!(
            "{what} needs a code from the MFA device {serial}; run `fob exec {what} -- true` in a terminal first, which asks for it"
        );
    };
    let code = prompt(serial)?.trim().to_string();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        bail!("an MFA code is six digits");
    }
    Ok(code)
}
