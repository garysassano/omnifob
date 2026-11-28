# Using fob

- [Commands](#commands)
- [Picking a profile](#picking-a-profile)
- [Listing profiles](#listing-profiles)
- [Running a command](#running-a-command)
- [In the current shell](#in-the-current-shell)
- [The AWS console](#the-aws-console)

## Commands

```sh
fob login acme            # browser sign-in (kept while it still works), then discovers profiles
fob login                 # pick the integration from a fuzzy list (fob logout too)
fob login acme --force    # sign in again even though the stored sign-in works
fob login acme --device-code   # approve with a code on another device (automatic over SSH and without a display)
fob login acme --start    # print the device code and return (Identity Center, Azure) ...
fob login acme --wait     # ... then finish once it is approved, in another process
fob list                  # acme/prod/AdministratorAccess  prod?  admin?, cf/personal/workers  write, ...
fob list prod admin       # only the profiles those words match
fob list --account acme/prod/ReadOnly   # every role in that account, least access first
fob exec prod admin -- aws s3 ls
fob exec cf workers -- wrangler deploy   # like granted's `assume -x`, for Cloudflare
fob exec cf workers --ttl 4h -- wrangler dev   # longer-lived token for a long session
fob exec cf workers --revoke -- wrangler deploy   # token for this command only, deleted when it ends
fob cf add-template cf pages             # pick services and access levels, save a template
fob cf add-template cf r2 -p "Workers R2 Storage Bucket Item Write" --r2-bucket assets --s3
fob cf add-template cf dns -p "DNS Edit" --zone example.com   # only that zone
fob console prod admin    # opens the AWS console as that role
fob console prod admin --service ec2 --region eu-west-1 --duration 8h
fob console prod admin --copy   # copy the sign-in URL instead (over SSH, to your terminal's clipboard)
fob status                # sign-ins, profile counts, when each was synced, and the active profile
fob status --json         # the same for scripts and status bars
fob status --check        # also ask each provider whether the sign-in still works
fob check                 # do the sign-ins work? (exit status 1 if not; -q for scripts, --json)
fob check --integration acme   # only this sign-in
fob check prod admin      # do this profile's credentials work, and what do they act as?
fob rename acme work      # rename an integration; keeps its sign-in, profiles and the config entries naming them
fob revoke --all          # delete every minted token and clear every cached credential
fob logout --all          # sign out of every integration
```

Sign-ins and consoles open in the system's default browser; on WSL without a Linux opener (`wslview`, `xdg-open`) that is Windows' default browser, through `explorer.exe`. [Browsers](browsers.md) gives each integration a browser, or a browser profile, of its own.

## Picking a profile

Profiles are `<integration>/<account>/<role or template>`, but you rarely type the full id.

- Any words that together match one profile select it (`prod admin`, or just `dns-read`); a word equal to a whole segment wins, so `read` picks `cf/personal/read` over `cf/personal/dns-read`.
- An account ID works too (`fob exec 123456789012 admin -- ...`).
- `--account-id` with `--role` picks a profile without naming it at all, so a command written in a runbook works for colleagues whose integrations and accounts are named differently: `fob exec --account-id 123456789012 --role AdministratorAccess -- aws sts get-caller-identity` (also on `fob env`, `fob creds` and `fob console`). The account is the provider's (an AWS account, an Azure subscription, a Google Cloud project, a Cloudflare account) and the role is the last part of the id, ignoring case.
- With no match or several, `fob` shows a fuzzy picker that lists recently used profiles first; without a terminal it lists the matches instead.
- With no words at all, the [directory's default profile](configuration.md#default-profiles-per-directory) is used, when one is configured.

Under a coding agent, fob never guesses and takes only full ids; see [Coding agents](agents.md).

## Listing profiles

`fob list` shows each profile with its environment and access level ([how they are worked out](configuration.md#environments-and-access-levels)). Piped into another program, plain `fob list` prints only the ids.

`fob list --json` gives `env`, `access`, where each came from (`env_source` and `access_source`: `config`, `permissions` or `name`) and the integration's `sign_in` (`signed_in`, `needs_check`, `signed_out` or `unknown`); a chained or cross-partition profile also has `via`, the Identity Center profile it is assumed from, which the table shows as a note.

`fob list --account <account ID or profile>` lists the profiles of one account, from least to most access and those without an access label last, with the roles chained from them: where to look when a role is denied.

## Running a command

`fob exec <profile> -- <command>` runs the command with the profile's credentials in its environment. The command gets the profile's variables, `OMNIFOB_PROFILE` and, when the credentials expire, `OMNIFOB_EXPIRES_AT`.

It hands the command no stale variables:

- What a `fob use` in the same shell exported and this profile does not set is removed, and so is `OMNIFOB_VARS`.
- When the profile hands out an AWS access key, the AWS credential variables it does not set (`AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, `AWS_ACCOUNT_ID`), the other sources of AWS credentials (`AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_*`) and `AWS_ENDPOINT_URL_S3` are removed too, so a session token, profile or R2 endpoint left in the shell is not mixed with the new key.
- A Region you set yourself stays for a profile without one, but is replaced when the profile sets one (R2 sets `AWS_REGION=auto` and removes `AWS_DEFAULT_REGION`).

`fob use` clears the same variables from the shell.

`fob exec` exits with the command's status, or with 125 when fob itself fails (a config that does not load included), 127 when the command is not found and 126 when it cannot run, as `env` does. A Windows exit code too large for the 0 to 255 range is reported as 1 when its low byte would read as success in the runs fob waits for: `--revoke`, `--server`, `--token-file`, and Azure and Google profiles unless `--no-server`. Other `fob exec` runs pass it on whole.

For SDKs that read no token from the environment (Azure's `DefaultAzureCredential`, Google's Application Default Credentials, long-running AWS processes), `fob exec` also serves credentials from a local endpoint; see [Other tools](other-tools.md#sdks-that-read-no-token-from-the-environment).

## In the current shell

Add the wrapper to your shell's startup file:

```sh
eval "$(fob activate bash)"     # or zsh
fob activate fish | source      # fish
fob activate powershell | Out-String | Invoke-Expression   # PowerShell
```

Then `fob use prod admin` exports the credentials into the current shell, and `fob unuse` removes them. Switching profiles removes variables the previous one set and the new one does not. `OMNIFOB_PROFILE` names the active profile and `OMNIFOB_EXPIRES_AT` (RFC 3339) says when its credentials expire, for a shell prompt; `fob status` shows both.

`fob activate` and `fob unuse` work even when the config or `profiles.json` is broken, so a typo does not break every new shell. The wrapper also recognises `use` and `unuse` after `--config <path>`. In PowerShell the wrapper finds the `fob` binary on `PATH`, so it works with `pwsh` on Linux and macOS too.

The same line enables tab completion of commands, integration names and profile ids (`fob exec cf<TAB>`), read live from your discovered profiles. Only completion, without the `fob use` wrapper: `eval "$(COMPLETE=bash fob)"`, `eval "$(COMPLETE=zsh fob)"` or `COMPLETE=fish fob | source`. Candidates follow the command: `fob discover aws` offers AWS integrations, `fob cf` Cloudflare ones, `fob export gcp-adc` Google profiles and `fob list --account` account IDs, and `fob --config other.toml exec <TAB>` completes from `other.toml`.

## The AWS console

`fob console` signs in with new credentials each time, never cached ones, so the console session gets their whole lifetime: without a session length, the console signs you out when the credentials it was opened with expire.

`--duration` (or `console_duration` on an `aws-sso` integration or an `aws-iam` role) makes the console session last that long, 15 minutes to 12 hours, independently of the credentials.

- It has no default: it must be shorter than the role's maximum session duration (for an Identity Center role, the permission set's session duration, one hour unless your administrator raised it), which omnifob cannot see, and AWS refuses the sign-in otherwise.
- Chained roles and an IAM user's own session cannot take one: AWS refuses a session length for credentials from role chaining (at most an hour) and from `GetFederationToken` (which lasts the integration's `session_duration`).
- For an IAM user's roles, AWS accepts a length although STS counts these roles as chained; whether the console session lasts past the end of the user's `GetSessionToken` session has not been watched.
- Cross-partition roles cannot take one yet, until it has been tried whether AWS accepts it for them; their console session lasts as long as their `duration`, up to 12 hours.

`--service` opens a console page, given as the path after the console host (`ec2`, `s3`, `lambda`, `cloudformation`, `route53/v2`), and `--region` the Region it opens in, which must be in the profile's partition; without it the profile's exported Region is used, if any.

The AWS console signs out one identity when another signs in; [Browsers](browsers.md) explains how fob opens each profile's console apart from the others.
