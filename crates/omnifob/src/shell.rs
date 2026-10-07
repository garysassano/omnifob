//! Shell code generation: exporting credentials and the `fob use` wrapper.

use clap::ValueEnum;
use omnifob_core::Credentials;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// bash, zsh and other POSIX shells
    #[value(alias = "bash", alias = "zsh", alias = "sh")]
    Posix,
    Fish,
    #[value(alias = "pwsh")]
    Powershell,
}

impl Shell {
    /// Guesses the shell from `$SHELL`; POSIX unless it is clearly fish or PowerShell.
    pub fn detect() -> Self {
        let shell = std::env::var("SHELL").unwrap_or_default();
        let name = shell.rsplit(['/', '\\']).next().unwrap_or_default();
        match name {
            "fish" => Shell::Fish,
            "pwsh" | "pwsh.exe" | "powershell.exe" => Shell::Powershell,
            _ if cfg!(windows) && shell.is_empty() => Shell::Powershell,
            _ => Shell::Posix,
        }
    }
}

fn quote(shell: Shell, value: &str) -> String {
    match shell {
        Shell::Posix => format!("'{}'", value.replace('\'', r"'\''")),
        Shell::Fish => format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'")),
        Shell::Powershell => format!("'{}'", value.replace('\'', "''")),
    }
}

fn set(shell: Shell, name: &str, value: &str) -> String {
    let value = quote(shell, value);
    match shell {
        Shell::Posix => format!("export {name}={value}\n"),
        Shell::Fish => format!("set -gx {name} {value}\n"),
        Shell::Powershell => format!("$Env:{name} = {value}\n"),
    }
}

fn remove(shell: Shell, name: &str) -> String {
    match shell {
        Shell::Posix => format!("unset {name}\n"),
        Shell::Fish => format!("set -e {name}\n"),
        Shell::Powershell => format!("Remove-Item Env:{name} -ErrorAction SilentlyContinue\n"),
    }
}

/// Removes the variables a previous `fob use` set, plus omnifob's own markers.
pub fn unset(shell: Shell, previous: &[&str]) -> String {
    previous
        .iter()
        .copied()
        .chain(["OMNIFOB_PROFILE", "OMNIFOB_VARS"])
        .map(|name| remove(shell, name))
        .collect()
}

/// Exports `creds`, first removing variables of the previous profile that
/// this one does not set, so nothing stale (like `AWS_REGION`) lingers.
pub fn export(shell: Shell, profile_id: &str, creds: &Credentials, previous: &[&str]) -> String {
    let mut out: String = previous
        .iter()
        .filter(|name| !creds.env.contains_key(**name))
        .map(|name| remove(shell, name))
        .collect();
    for (name, value) in &creds.env {
        out.push_str(&set(shell, name, value));
    }
    let names: Vec<&str> = creds.env.keys().map(String::as_str).collect();
    out.push_str(&set(shell, "OMNIFOB_PROFILE", profile_id));
    out.push_str(&set(shell, "OMNIFOB_VARS", &names.join(",")));
    out
}

/// The line to add to a shell's startup file.
pub fn activation_line(shell: Shell) -> &'static str {
    match shell {
        Shell::Posix => r#"eval "$(fob activate bash)"    # or zsh"#,
        Shell::Fish => "fob activate fish | source",
        Shell::Powershell => "fob activate powershell | Out-String | Invoke-Expression",
    }
}

/// A `fob` wrapper function: `fob use [profile]` and `fob unuse` change the
/// current shell; everything else runs the binary. Also registers completions,
/// which ask the binary for profile ids as you type.
pub fn activate(shell: Shell) -> &'static str {
    match shell {
        Shell::Posix => {
            r#"fob() {
  case "$1" in
    use)
      shift
      local __fob_env
      __fob_env="$(command fob env --shell posix "$@")" && eval "$__fob_env"
      ;;
    unuse)
      eval "$(command fob env --shell posix --unset)"
      ;;
    *)
      command fob "$@"
      ;;
  esac
}
if [ -n "${ZSH_VERSION:-}" ]; then
  source <(COMPLETE=zsh command fob)
elif [ -n "${BASH_VERSION:-}" ]; then
  source <(COMPLETE=bash command fob)
fi
"#
        }
        Shell::Fish => {
            r#"function fob
  switch "$argv[1]"
    case use
      set -l __fob_env (command fob env --shell fish $argv[2..-1]); or return
      printf '%s\n' $__fob_env | source
    case unuse
      command fob env --shell fish --unset | source
    case '*'
      command fob $argv
  end
end
COMPLETE=fish command fob | source
"#
        }
        Shell::Powershell => {
            r#"function fob {
  if ($args.Count -gt 0 -and $args[0] -eq 'use') {
    $rest = @($args | Select-Object -Skip 1)
    $code = (& fob.exe env --shell powershell @rest) -join "`n"
    if ($LASTEXITCODE -eq 0) { Invoke-Expression $code }
  } elseif ($args.Count -gt 0 -and $args[0] -eq 'unuse') {
    Invoke-Expression ((& fob.exe env --shell powershell --unset) -join "`n")
  } else {
    & fob.exe @args
  }
}
$env:COMPLETE = "powershell"
fob.exe | Out-String | Invoke-Expression
Remove-Item Env:\COMPLETE
"#
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn creds(pairs: &[(&str, &str)]) -> Credentials {
        Credentials {
            env: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            expires_at: None,
            issued_at: None,
            token_id: None,
        }
    }

    #[test]
    fn quotes_awkward_values() {
        assert_eq!(quote(Shell::Posix, "it's"), r"'it'\''s'");
        assert_eq!(quote(Shell::Fish, r"a\b'c"), r"'a\\b\'c'");
        assert_eq!(quote(Shell::Powershell, "it's"), "'it''s'");
    }

    #[test]
    fn export_removes_stale_variables_only() {
        let out = export(
            Shell::Posix,
            "cf/acct/workers",
            &creds(&[("CLOUDFLARE_API_TOKEN", "t")]),
            &["AWS_REGION", "CLOUDFLARE_API_TOKEN"],
        );
        assert_eq!(
            out,
            "unset AWS_REGION\n\
             export CLOUDFLARE_API_TOKEN='t'\n\
             export OMNIFOB_PROFILE='cf/acct/workers'\n\
             export OMNIFOB_VARS='CLOUDFLARE_API_TOKEN'\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn posix_export_round_trips_through_sh() {
        let value = "a'b\"c $HOME `x` \\n";
        let code = export(Shell::Posix, "p", &creds(&[("FOB_TEST", value)]), &[]);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{code}printf %s \"$FOB_TEST\""))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), value);
    }
}
