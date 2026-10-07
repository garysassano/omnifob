//! Reading the system clipboard through the platform's own tools, so a token
//! copied in the browser reaches omnifob without being pasted on screen.

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
        let wsl = std::fs::read_to_string("/proc/version")
            .is_ok_and(|v| v.to_lowercase().contains("microsoft"));
        let mut readers = Vec::new();
        if wsl {
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
