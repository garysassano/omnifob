//! Questions the library may need to ask mid-operation. Whoever embeds it
//! answers them through its [`Context`](crate::Context): the command line
//! sets a terminal prompt when it runs in one. Without one, an operation
//! that needs an answer fails with an error that says how to get past it.

use std::cell::Cell;
use std::future::Future;

use anyhow::bail;

thread_local! {
    /// Set while an [`unattended`] future is polled.
    static UNATTENDED: Cell<bool> = const { Cell::new(false) };
}

/// Runs `future` where nobody answers prompts, whatever the context
/// offers: for the endpoints `fob exec` serves while its command runs,
/// where a prompt would share the terminal with the command. An operation
/// that needs an MFA code fails there instead, saying so.
pub fn unattended<F: Future>(future: F) -> impl Future<Output = F::Output> + use<F> {
    let mut future = Box::pin(future);
    std::future::poll_fn(move |cx| {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                // Not during the thread's teardown, when it is gone.
                let _ = UNATTENDED.try_with(|u| u.set(self.0));
            }
        }
        let _restore = Restore(UNATTENDED.try_with(|u| u.replace(true)).unwrap_or(true));
        future.as_mut().poll(cx)
    })
}

/// Whether prompts are off here, inside an [`unattended`] future.
pub(crate) fn is_unattended() -> bool {
    // A thread being torn down asks nobody.
    UNATTENDED.try_with(|u| u.get()).unwrap_or(true)
}

/// A six-digit code from the MFA device `serial`, for `what` (a profile id).
pub fn mfa_code(serial: &str, what: &str) -> anyhow::Result<String> {
    if is_unattended() {
        return Err(mfa_needed(
            what,
            format!(
                "{what} needs a code from the MFA device {serial}, which cannot be asked for while a command runs; run `fob exec {what} -- true` in a terminal first, which asks for it"
            ),
        ));
    }
    let cx = crate::Context::current();
    let Some(prompt) = cx.mfa_prompt() else {
        return Err(mfa_needed(
            what,
            format!(
                "{what} needs a code from the MFA device {serial}; run `fob exec {what} -- true` in a terminal first, which asks for it"
            ),
        ));
    };
    let code = prompt(serial)?.trim().to_string();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        bail!("an MFA code is six digits");
    }
    Ok(code)
}

/// The failure for a code no one can enter now.
fn mfa_needed(profile: &str, message: String) -> anyhow::Error {
    crate::Coded::new(crate::Code::MfaRequired, message)
        .with("profile", profile)
        .with("run", format!("fob exec {profile} -- true"))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_futures_never_prompt() {
        let cx = crate::Context::builder()
            .mfa_prompt(|_| Ok("123456".into()))
            .build();
        let _entered = cx.enter();
        assert_eq!(mfa_code("arn:mfa", "p").unwrap(), "123456");
        let asked = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(unattended(async { mfa_code("arn:mfa", "p") }));
        let err = asked.unwrap_err();
        assert_eq!(crate::classify(&err).0, crate::Code::MfaRequired);
        let err = err.to_string();
        assert!(err.contains("while a command runs"), "{err}");
        // Only while it is polled.
        assert_eq!(mfa_code("arn:mfa", "p").unwrap(), "123456");
    }
}
