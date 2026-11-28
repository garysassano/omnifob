//! Reading the system clipboard through the platform's own tools, so a token
//! copied in the browser reaches omnifob without being pasted on screen, and
//! writing to it, over SSH through the local terminal.

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

/// Commands that print the clipboard, in order of preference for this
/// platform.
fn readers() -> Vec<(&'static str, Vec<&'static str>)> {
    let powershell = (
        "powershell.exe",
        vec!["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"],
    );
    if cfg!(target_os = "macos") {
        vec![("pbpaste", vec![])]
    } else if cfg!(windows) {
        vec![powershell]
    } else {
        let mut readers = Vec::new();
        if omnifob_core::platform::is_wsl() {
            readers.push(powershell);
        }
        readers.push(("wl-paste", vec!["--no-newline"]));
        readers.push(("xclip", vec!["-selection", "clipboard", "-o"]));
        readers.push(("xsel", vec!["--clipboard", "--output"]));
        readers
    }
}

/// Returns the clipboard's text, trimmed.
pub fn read() -> anyhow::Result<String> {
    let mut tried = Vec::new();
    for (program, args) in readers() {
        let output = match Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => {
                tried.push(program);
                continue;
            }
        };
        let text = String::from_utf8(output.stdout).context("the clipboard does not hold text")?;
        return Ok(text.trim().to_string());
    }
    bail!("could not read the clipboard (tried {})", tried.join(", "))
}

/// Commands that set the clipboard from their stdin, in order of preference
/// for this platform.
fn writers() -> Vec<(&'static str, Vec<&'static str>)> {
    if cfg!(target_os = "macos") {
        vec![("pbcopy", vec![])]
    } else if cfg!(windows) {
        vec![("clip.exe", vec![])]
    } else {
        let mut writers = Vec::new();
        if omnifob_core::platform::is_wsl() {
            writers.push(("clip.exe", vec![]));
        }
        writers.push(("wl-copy", vec![]));
        writers.push(("xclip", vec!["-selection", "clipboard"]));
        writers.push(("xsel", vec!["--clipboard", "--input"]));
        writers
    }
}

/// Whether this runs over SSH, where the clipboard that matters is the
/// local terminal's, not this machine's.
pub fn over_ssh() -> bool {
    ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|v| !v.is_empty()))
}

/// Puts `text` on the clipboard; returns where it went, for a message. Over
/// SSH it asks the local terminal to set its clipboard (OSC 52, as tmux,
/// Neovim and aws-sso-cli do); otherwise it runs the platform's tool.
pub fn write(text: &str) -> anyhow::Result<&'static str> {
    if over_ssh() {
        let mut terminal = std::io::stderr();
        if !terminal.is_terminal() {
            bail!("no terminal to copy through over SSH; use --print");
        }
        let set = |name| std::env::var_os(name).is_some_and(|v| !v.is_empty());
        let multiplexer = if set("TMUX") {
            Some(Multiplexer::Tmux)
        } else if set("STY") {
            Some(Multiplexer::Screen)
        } else {
            None
        };
        terminal.write_all(osc52(text, multiplexer).as_bytes())?;
        terminal.flush()?;
        return Ok("to your terminal's clipboard (OSC 52)");
    }
    let mut tried = Vec::new();
    for (program, args) in writers() {
        let child = Command::new(program)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            tried.push(program);
            continue;
        };
        // A helper that exits without reading (no display for it) must not
        // end fob through SIGPIPE, which `main` restores for stdout's sake,
        // before the next helper is tried.
        let written = child
            .stdin
            .take()
            .map(|mut stdin| write_to_helper(&mut stdin, text.as_bytes()))
            .transpose();
        if written.is_ok() && child.wait().is_ok_and(|s| s.success()) {
            return Ok("to the clipboard");
        }
        tried.push(program);
    }
    bail!(
        "could not write to the clipboard (tried {}); use --print",
        tried.join(", ")
    )
}

/// The OSC 52 sequence that sets the terminal's clipboard to `text`, wrapped
/// for tmux to pass on when `tmux` is set.
/// A terminal multiplexer that passes OSC 52 on only inside its own
/// escape (DCS passthrough).
#[derive(Clone, Copy)]
enum Multiplexer {
    Tmux,
    Screen,
}

fn osc52(text: &str, multiplexer: Option<Multiplexer>) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let sequence = format!("\x1b]52;c;{encoded}\x07");
    match multiplexer {
        Some(Multiplexer::Tmux) => {
            format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
        }
        // screen passes a DCS string on as it is.
        Some(Multiplexer::Screen) => format!("\x1bP{sequence}\x1b\\"),
        None => sequence,
    }
}

/// Reads a token from the clipboard, refusing anything that does not look
/// like one, such as a URL or a sentence copied earlier.
pub fn read_token() -> anyhow::Result<String> {
    let text = read()?;
    if text.is_empty() {
        bail!("the clipboard is empty; copy the token first");
    }
    if text.len() < 20 || text.chars().any(|c| c.is_whitespace() || c == '/') {
        bail!("the clipboard does not look like a token; copy the token first");
    }
    Ok(text)
}

/// Reads a stored token integration's secret from the clipboard. Secrets
/// take many shapes (base64 with `/`, short API keys), so only what is
/// clearly not one is refused: nothing, text with whitespace, or a URL.
pub fn read_secret() -> anyhow::Result<String> {
    check_secret(read()?)
}

fn check_secret(text: String) -> anyhow::Result<String> {
    if text.is_empty() {
        bail!("the clipboard is empty; copy the secret first");
    }
    let lower = text.to_ascii_lowercase();
    if text.chars().any(char::is_whitespace)
        || lower.starts_with("http://")
        || lower.starts_with("https://")
    {
        bail!("the clipboard does not look like a secret; copy the secret first");
    }
    Ok(text)
}

/// Writes `bytes` to a helper's stdin so that a helper that exits without
/// reading (no display for it) fails the write with `BrokenPipe` instead of
/// ending fob through SIGPIPE, which `main` restores for stdout's sake; the
/// next helper is then tried.
fn write_to_helper(stdin: &mut std::process::ChildStdin, bytes: &[u8]) -> std::io::Result<()> {
    // macOS sends a pipe's SIGPIPE to the process, where any thread may take
    // it, so the descriptor itself is told not to raise it.
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `fcntl` on a descriptor this function borrows.
        if unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        stdin.write_all(bytes)
    }
    // Linux and the BSDs send it to the thread that wrote, so blocking it
    // there for the write, and discarding what the write left pending, is
    // enough.
    #[cfg(all(unix, not(target_os = "macos")))]
    // SAFETY: plain signal-mask calls on zero-initialised `sigset_t`s this
    // function owns; the mask is restored before it returns.
    unsafe {
        let mut pipe: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut pipe);
        libc::sigaddset(&mut pipe, libc::SIGPIPE);
        let pending = || {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigpending(&mut set) == 0 && libc::sigismember(&set, libc::SIGPIPE) == 1
        };
        let already = pending();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &pipe, &mut old);
        let result = stdin.write_all(bytes);
        if !already && pending() {
            let mut signal = 0;
            libc::sigwait(&pipe, &mut signal);
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        result
    }
    #[cfg(not(unix))]
    stdin.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_carries_the_text_in_base64() {
        assert_eq!(osc52("hi", None), "\x1b]52;c;aGk=\x07");
        assert_eq!(
            osc52("hi", Some(Multiplexer::Tmux)),
            "\x1bPtmux;\x1b\x1b]52;c;aGk=\x07\x1b\\"
        );
        assert_eq!(
            osc52("hi", Some(Multiplexer::Screen)),
            "\x1bP\x1b]52;c;aGk=\x07\x1b\\"
        );
    }

    #[test]
    fn secrets_may_have_any_shape_but_a_url_or_a_sentence() {
        for ok in ["abc", "a/b+c==", "ukc_0123/xyz"] {
            assert_eq!(check_secret(ok.into()).unwrap(), ok);
        }
        for bad in ["", "two words", "https://example.com/token", "HTTP://x"] {
            assert!(check_secret(bad.into()).is_err(), "{bad}");
        }
    }

    /// With SIGPIPE's default action, as `main` sets it, a helper that
    /// exits without reading fails the write instead of ending fob.
    #[cfg(unix)]
    #[test]
    fn a_helper_that_reads_nothing_does_not_end_fob() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("true").stdin(Stdio::piped()).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        child.wait().unwrap();
        // SAFETY: the test harness's own disposition is restored below.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        let written = write_to_helper(&mut stdin, &[0; 1 << 20]);
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        assert_eq!(written.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }
}
