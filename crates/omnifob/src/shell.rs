//! Shell code generation: exporting credentials and the `fob use` wrapper.

use anyhow::bail;
use clap::ValueEnum;
use omnifob_core::Credentials;
use omnifob_core::credentials::is_var_name;

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
    /// Guesses the shell from `$SHELL`; POSIX unless it is clearly fish or
    /// PowerShell. PowerShell on Unix leaves `$SHELL` as the login shell's,
    /// but sets `$PSModulePath`, which no Unix shell does.
    pub fn detect() -> Self {
        let shell = std::env::var("SHELL").unwrap_or_default();
        let name = shell.rsplit(['/', '\\']).next().unwrap_or_default();
        let ps_module_path = std::env::var_os("PSModulePath").is_some_and(|p| !p.is_empty());
        match name {
            "fish" => Shell::Fish,
            "pwsh" | "pwsh.exe" | "powershell.exe" => Shell::Powershell,
            _ if cfg!(windows) && shell.is_empty() => Shell::Powershell,
            _ if cfg!(unix) && ps_module_path => Shell::Powershell,
            _ => Shell::Posix,
        }
    }
}

fn quote(shell: Shell, value: &str) -> String {
    match shell {
        Shell::Posix => format!("'{}'", value.replace('\'', r"'\''")),
        Shell::Fish => format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'")),
        Shell::Powershell => {
            // PowerShell also ends a single-quoted string at the typographic
            // single quotes U+2018 to U+201B; doubling each keeps it literal.
            let mut quoted = String::with_capacity(value.len() + 2);
            quoted.push('\'');
            for c in value.chars() {
                if matches!(c, '\'' | '\u{2018}'..='\u{201B}') {
                    quoted.push(c);
                }
                quoted.push(c);
            }
            quoted.push('\'');
            quoted
        }
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

/// The variable names in `OMNIFOB_VARS` (a previous `fob use`'s list) that
/// are safe to put into shell code. The value comes from the environment, so
/// anything that is not a plain variable name is skipped: written into
/// `unset {name}` and passed to `eval`, it would run as a command.
fn previous_names<'a>(previous: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    previous.iter().copied().filter(|name| is_var_name(name))
}

/// Removes the variables a previous `fob use` set, plus omnifob's own markers.
pub fn unset(shell: Shell, previous: &[&str]) -> String {
    previous_names(previous)
        .chain(["OMNIFOB_PROFILE", "OMNIFOB_VARS", "OMNIFOB_EXPIRES_AT"])
        .map(|name| remove(shell, name))
        .collect()
}

/// Exports `creds`, first removing variables of the previous profile that
/// this one does not set, so nothing stale (like `AWS_REGION`) lingers, and
/// sets `OMNIFOB_PROFILE`, `OMNIFOB_VARS` and, when the credentials expire,
/// `OMNIFOB_EXPIRES_AT` (RFC 3339).
/// Refuses credentials with a variable name that is not
/// `[A-Za-z_][A-Za-z0-9_]*`, which the shell would read as code.
pub fn export(
    shell: Shell,
    profile_id: &str,
    creds: &Credentials,
    previous: &[&str],
) -> anyhow::Result<String> {
    if let Some(bad) = creds.env.keys().find(|name| !is_var_name(name)) {
        bail!("`{bad}` is not a valid environment variable name ([A-Za-z_][A-Za-z0-9_]*)");
    }
    let mut stale: Vec<String> = previous_names(previous)
        .filter(|name| !creds.env.contains_key(*name))
        .map(str::to_string)
        .collect();
    // As `fob exec` does: another source of AWS credentials in the shell
    // (`AWS_PROFILE`, a session token) would mix with these.
    stale.extend(crate::exec::stale_vars(creds));
    stale.sort();
    stale.dedup();
    let mut out: String = stale.iter().map(|name| remove(shell, name)).collect();
    for (name, value) in &creds.env {
        out.push_str(&set(shell, name, value));
    }
    let names: Vec<&str> = creds.env.keys().map(String::as_str).collect();
    out.push_str(&set(shell, "OMNIFOB_PROFILE", profile_id));
    out.push_str(&set(shell, "OMNIFOB_VARS", &names.join(",")));
    // For prompts (Starship and the like) to count down to, whatever the
    // provider.
    match creds.expires_at {
        Some(at) => out.push_str(&set(shell, "OMNIFOB_EXPIRES_AT", &at.to_string())),
        None => out.push_str(&remove(shell, "OMNIFOB_EXPIRES_AT")),
    }
    Ok(out)
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
/// current shell; everything else runs the binary. Global options before the
/// command (`fob --config x use p`) are passed on. `--help` and `--version`
/// go to the binary as they are, since their output is not shell code, and
/// the shell evaluates nothing when fob fails. Also registers completions,
/// which ask the binary for profile ids as you type. `bin` names the
/// function and the program, `fob` or `omnifob`.
pub fn activate(shell: Shell, bin: &str) -> String {
    let script = script(shell);
    if bin == "fob" {
        return script.to_string();
    }
    script
        .replace("fob() {", &format!("{bin}() {{"))
        .replace("function fob", &format!("function {bin}"))
        .replace("command fob", &format!("command {bin}"))
        .replace("Get-Command fob ", &format!("Get-Command {bin} "))
}

fn script(shell: Shell) -> &'static str {
    match shell {
        Shell::Posix => {
            r#"fob() {
  local __fob_config=
  while :; do
    case "${1:-}" in
      --config) [ $# -ge 2 ] || break; __fob_config="--config=$2"; shift 2 ;;
      --config=*) __fob_config="$1"; shift ;;
      *) break ;;
    esac
  done
  case "${1:-}" in
    use|unuse)
      local __fob_arg
      for __fob_arg in "$@"; do
        case "$__fob_arg" in
          -h|--help|-V|--version)
            command fob ${__fob_config:+"$__fob_config"} "$@"
            return
            ;;
        esac
      done
      ;;
  esac
  case "${1:-}" in
    use)
      shift
      local __fob_env
      __fob_env="$(command fob ${__fob_config:+"$__fob_config"} env --shell posix "$@")" && eval "$__fob_env"
      ;;
    unuse)
      shift
      local __fob_env
      __fob_env="$(command fob ${__fob_config:+"$__fob_config"} env --shell posix --unset "$@")" && eval "$__fob_env"
      ;;
    *)
      command fob ${__fob_config:+"$__fob_config"} "$@"
      ;;
  esac
}
if [ -n "${ZSH_VERSION:-}" ]; then
  eval "$(COMPLETE=zsh command fob)"
elif [ -n "${BASH_VERSION:-}" ]; then
  eval "$(COMPLETE=bash command fob)"
fi
"#
        }
        Shell::Fish => {
            r#"function fob
  set -l __fob_global
  while test (count $argv) -gt 0
    switch $argv[1]
      case --config
        test (count $argv) -ge 2; or break
        set -a __fob_global --config=$argv[2]
        set -e argv[1..2]
      case '--config=*'
        set -a __fob_global $argv[1]
        set -e argv[1]
      case '*'
        break
    end
  end
  if contains -- "$argv[1]" use unuse
    for __fob_arg in $argv[2..-1]
      if contains -- $__fob_arg -h --help -V --version
        command fob $__fob_global $argv
        return
      end
    end
  end
  switch "$argv[1]"
    case use
      set -l __fob_env (command fob $__fob_global env --shell fish $argv[2..-1]); or return
      printf '%s\n' $__fob_env | source
    case unuse
      set -l __fob_env (command fob $__fob_global env --shell fish --unset $argv[2..-1]); or return
      printf '%s\n' $__fob_env | source
    case '*'
      command fob $__fob_global $argv
  end
end
COMPLETE=fish command fob | source
"#
        }
        Shell::Powershell => {
            r#"$global:__fob_bin = (Get-Command fob -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
function fob {
  $fobGlobal = @()
  $fobArgs = @($args)
  while ($fobArgs.Count -gt 0) {
    if ($fobArgs[0] -eq '--config' -and $fobArgs.Count -ge 2) {
      $fobGlobal += "--config=$($fobArgs[1])"
      $fobArgs = @($fobArgs | Select-Object -Skip 2)
    } elseif ("$($fobArgs[0])" -like '--config=*') {
      $fobGlobal += $fobArgs[0]
      $fobArgs = @($fobArgs | Select-Object -Skip 1)
    } else {
      break
    }
  }
  $rest = @($fobArgs | Select-Object -Skip 1)
  $plain = @($rest | Where-Object { "$_" -cin @('-h', '--help', '-V', '--version') }).Count -gt 0
  if ($fobArgs.Count -gt 0 -and $fobArgs[0] -in @('use', 'unuse') -and $plain) {
    & $global:__fob_bin @args
  } elseif ($fobArgs.Count -gt 0 -and $fobArgs[0] -eq 'use') {
    $code = (& $global:__fob_bin @fobGlobal env --shell powershell @rest) -join "`n"
    if ($LASTEXITCODE -eq 0 -and $code) { Invoke-Expression $code }
  } elseif ($fobArgs.Count -gt 0 -and $fobArgs[0] -eq 'unuse') {
    $code = (& $global:__fob_bin @fobGlobal env --shell powershell --unset @rest) -join "`n"
    if ($LASTEXITCODE -eq 0 -and $code) { Invoke-Expression $code }
  } else {
    & $global:__fob_bin @args
  }
}
$env:COMPLETE = "powershell"
& $global:__fob_bin | Out-String | Invoke-Expression
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
        assert_eq!(
            quote(
                Shell::Powershell,
                "a\u{2018}b\u{2019}c\u{201A}d\u{201B}e\u{201C}"
            ),
            "'a\u{2018}\u{2018}b\u{2019}\u{2019}c\u{201A}\u{201A}d\u{201B}\u{201B}e\u{201C}'"
        );
    }

    #[test]
    fn export_removes_stale_variables_only() {
        let out = export(
            Shell::Posix,
            "cf/acct/workers",
            &creds(&[("CLOUDFLARE_API_TOKEN", "t")]),
            &["AWS_REGION", "CLOUDFLARE_API_TOKEN"],
        )
        .unwrap();
        assert_eq!(
            out,
            "unset AWS_REGION\n\
             export CLOUDFLARE_API_TOKEN='t'\n\
             export OMNIFOB_PROFILE='cf/acct/workers'\n\
             export OMNIFOB_VARS='CLOUDFLARE_API_TOKEN'\n\
             unset OMNIFOB_EXPIRES_AT\n"
        );
        let mut expiring = creds(&[("CLOUDFLARE_API_TOKEN", "t")]);
        expiring.expires_at = Some("2100-01-01T00:00:00Z".parse().unwrap());
        let out = export(Shell::Fish, "p", &expiring, &[]).unwrap();
        assert!(
            out.ends_with("set -gx OMNIFOB_EXPIRES_AT '2100-01-01T00:00:00Z'\n"),
            "{out}"
        );
        // AWS credentials clear another source in the shell, as `fob exec`
        // does, but keep the Region unless they set one.
        let aws = creds(&[("AWS_ACCESS_KEY_ID", "A"), ("AWS_SECRET_ACCESS_KEY", "s")]);
        let out = export(Shell::Posix, "p", &aws, &[]).unwrap();
        for stale in ["AWS_PROFILE", "AWS_SESSION_TOKEN"] {
            assert!(out.contains(&format!("unset {stale}\n")), "{out}");
        }
        assert!(!out.contains("unset AWS_REGION"), "{out}");
    }

    #[test]
    fn powershell_finds_fob_on_any_platform() {
        let script = activate(Shell::Powershell, "fob");
        assert!(!script.contains("fob.exe"), "{script}");
        assert!(script.contains("-and $code"), "{script}");
    }

    #[test]
    fn the_wrapper_is_named_as_fob_was_run() {
        for shell in [Shell::Posix, Shell::Fish, Shell::Powershell] {
            let script = activate(shell, "omnifob");
            assert!(
                !script.contains("command fob")
                    && !script.contains("function fob")
                    && !script.contains("\nfob() {")
                    && !script.contains("Get-Command fob "),
                "{script}"
            );
            assert!(script.contains("omnifob"), "{script}");
            // Its variables keep their names.
            assert!(script.contains("__fob_"), "{script}");
        }
        assert!(activate(Shell::Posix, "omnifob").starts_with("omnifob() {"));
    }

    #[test]
    #[cfg(unix)]
    fn the_posix_wrapper_works_under_set_u() {
        // Bare `fob` under `set -u` must reach the binary, not fail on "$1".
        // The function only: completion needs bash or zsh.
        let script = activate(Shell::Posix, "fob")
            .split("if [ -n")
            .next()
            .unwrap()
            .replace("command fob", "echo ran");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("set -u\n{script}fob\n"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "ran\n");
    }

    #[test]
    fn crafted_names_never_reach_shell_code() {
        let crafted = ["AWS_REGION", "X;touch /tmp/pwned", "$(id)", "A B", ""];
        for shell in [Shell::Posix, Shell::Fish, Shell::Powershell] {
            let out = unset(shell, &crafted);
            assert!(out.contains("AWS_REGION"), "{out}");
            assert!(out.contains("OMNIFOB_VARS"), "{out}");
            for bad in ["touch", "$(id)", "A B"] {
                assert!(!out.contains(bad), "{bad} in {out}");
            }
            assert_eq!(out.lines().count(), 4, "{out}");

            let out = export(shell, "p", &creds(&[("OK", "v")]), &crafted).unwrap();
            for bad in ["touch", "$(id)", "A B"] {
                assert!(!out.contains(bad), "{bad} in {out}");
            }

            let err = export(shell, "p", &creds(&[("X;id", "v")]), &[])
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("not a valid environment variable name"),
                "{err}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn posix_export_round_trips_through_sh() {
        let value = "a'b\"c $HOME `x` \\n";
        let code = export(Shell::Posix, "p", &creds(&[("FOB_TEST", value)]), &[]).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{code}printf %s \"$FOB_TEST\""))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), value);
    }
}
