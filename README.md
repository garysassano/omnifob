# omnifob

One sign-in for every cloud. `fob` signs you in once per identity source, discovers every account and role you can use, and hands out short-lived credentials as environment variables, to a command, to the web console, or to other tools.

## Status

Early. What changed in each version is in the [release notes](https://github.com/garysassano/omnifob/releases). Working today:

| Integration                     | Sign-in                                                 | Discovery                                                                 | Credentials                                                                                                                                                                       | Console               |
| ------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `aws-sso` (IAM Identity Center) | Browser (PKCE) or device flow, silent refresh           | Every account and role, plus configured chained and cross-partition roles | Role credentials; chained roles through STS AssumeRole; roles in other partitions through STS GetWebIdentityToken and AssumeRoleWithWebIdentity (the exchange not yet tried live) | Federated sign-in URL |
| `aws-iam` (IAM user)            | Access key, stored once; MFA per session                | The user's session, plus configured roles                                 | Session from STS GetSessionToken; roles assumed with it (up to 12 hours)                                                                                                          | Federated sign-in URL |
| `gcp` (Google account)          | Browser (PKCE) or pasted code, as `gcloud auth login`   | Every active project, plus configured service accounts                    | Your access token per project; service account tokens by impersonation                                                                                                            | Cloud console         |
| `azure` (Entra ID)              | Browser (PKCE) or device flow, as `az login`            | Every subscription in every tenant                                        | A Resource Manager token, with the subscription and tenant IDs (not yet tried on a live tenant)                                                                                   | Azure portal          |
| `cloudflare-oauth`              | Browser sign-in (OAuth with PKCE), silent refresh       | Approved accounts × templates                                             | Minted tokens, scoped by permission name, expiring                                                                                                                                | Dashboard             |
| `cloudflare-token`              | Bootstrap token, stored once                            | Accounts × templates                                                      | Minted tokens, scoped by permission name, expiring                                                                                                                                | Dashboard             |
| `token`                         | Paste once, checked against the provider where possible | One profile per integration                                               | The stored token under every variable the provider's tools read                                                                                                                   | Known console URL     |

Token presets: `hetzner`, `digitalocean`, `vultr`, `linode` (Akamai Cloud), `upstash`, `akamai-edgegrid`, `scaleway`, `modal`, `unikraft`, `vercel`, `netlify`, `fly`, `neon`, `supabase`, `github`. These providers' own CLIs keep tokens in plain-text files; omnifob keeps them in the keychain. [docs/providers](docs/providers/README.md) lists every provider and how omnifob handles it.

## Install

From source:

```sh
cargo install --locked --git https://github.com/garysassano/omnifob omnifob
```

Every [release](https://github.com/garysassano/omnifob/releases) has prebuilt binaries, with build provenance and the SHA-256 digest GitHub shows for each file, for Linux (x86_64 and ARM64, static musl binaries that run on any distribution), macOS (Apple Silicon and Intel) and Windows (x86_64 and ARM64). Up to 0.6.1 the Linux builds were linked against glibc, and there were no Intel macOS or Windows ARM64 builds. With mise:

```sh
mise use -g github:garysassano/omnifob
```

Or with [cargo binstall](https://github.com/cargo-bins/cargo-binstall), which downloads the same release archive for your platform:

```sh
cargo binstall --git https://github.com/garysassano/omnifob omnifob
```

This installs two names for the same binary: `fob` for daily use and `omnifob` for scripts.

## Configure

Coming from granted, aws-vault or the AWS CLI? `fob import aws` finds every IAM Identity Center portal your `~/.aws/config` profiles use (standard `sso_*` keys, `sso-session` sections with their `sso_registration_scopes`, granted's keys) and the roles chained from them (`role_arn` + `source_profile`, with session name, external ID, region, `mfa_serial` and `duration_seconds`), and prints matching integrations; `--write` appends them to the config. Roles assumed from a profile with an IAM user's access key become an `aws-iam` integration with those roles; the key itself is never read, so run `fob login <name>` afterwards to store it. Profiles it cannot import (a role assumed from another assumed role, a `credential_process` source, a `duration_seconds` AWS would refuse) are listed with the reason.

Integration names may contain only letters, digits, `.`, `_` and `-`, and may not start with `-`. A config with another name is refused with a pointer to `fob rename "<old name>" <new-name>`, which still works on it.

`~/.config/omnifob/config.toml` (or `$OMNIFOB_CONFIG`):

```toml
[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"          # where IAM Identity Center runs
default_region = "eu-central-1"  # exported as AWS_REGION (optional)
# console_duration = "4h"        # optional: `fob console` session length, 15m to 12h; must fit the
                                 # permission set's session duration, 1h unless an administrator raised it

# Roles assumed from an Identity Center role (role_arn + source_profile in ~/.aws/config).
# Profile id: acme/prod-deploy/Deploy. AWS limits these sessions to one hour.
[integrations.acme.chained.prod-deploy]
via_account_id = "111111111111"
via_role = "AdministratorAccess"
role_arn = "arn:aws:iam::222222222222:role/Deploy"
session_name = "me"          # optional, like role_session_name
external_id = "..."          # optional
region = "us-east-1"         # optional, defaults to the integration's
mfa_serial = "arn:aws:iam::111111111111:mfa/me"  # optional: asks for a code per session
duration = "30m"             # optional, 15m to 1h

# A role in another AWS partition (GovCloud, China, European Sovereign Cloud),
# reached from an Identity Center role with a web identity token.
# Profile id: acme/gov-audit/Audit. Setup in both accounts: docs/guides/aws-cross-partition.md.
# The token request is tried live; the exchange in the other partition is not yet.
[integrations.acme.cross_partition.gov-audit]
via_account_id = "111111111111"      # the Identity Center role that requests the token
via_role = "AdministratorAccess"
role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
audience = "omnifob"                 # a client ID of the destination's OIDC provider
region = "us-gov-west-1"             # destination STS Region, exported as AWS_REGION
source_region = "us-east-1"          # optional: defaults to default_region, then the portal's region
signing_algorithm = "ES384"          # optional: ES384 (default) or RS256
session_name = "me"                  # optional, defaults to "omnifob"
duration = "1h"                      # optional, 15m to the role's maximum (at most 12h)

# An additional Region of a multi-Region Identity Center instance: a second
# integration with that Region's portal URL (no /start), signed in on its own,
# since CLI sign-ins are not replicated across Regions.
[integrations.acme-eu]
type = "aws-sso"
start_url = "https://ssoins-1111111111111111.eu-west-1.portal.amazonaws.com"
region = "eu-west-1"

# An IAM user's access key, kept in the keychain like aws-vault keeps it. The key
# is never handed out: profiles get a session from STS GetSessionToken (one MFA
# code per session), and roles assumed with that session.
[integrations.legacy]
type = "aws-iam"
region = "eu-central-1"        # optional: STS region and AWS_REGION
mfa_serial = "arn:aws:iam::111111111111:mfa/me"  # optional
session_duration = "8h"        # optional, 15m to 36h (default 8h)

[integrations.legacy.roles.prod]   # profile id: legacy/prod/Admin
role_arn = "arn:aws:iam::222222222222:role/Admin"
duration = "4h"                # optional, 15m to 12h (default 1h)
console_duration = "8h"        # optional: `fob console` session length, 15m to 12h

# A Google account, signed in like `gcloud auth login` (with gcloud's OAuth client).
# Profile ids: google/<project>/user, and google/<label>/<name> per service account.
[integrations.google]
type = "gcp"
projects = ["my-proj"]         # optional: skip listing every project

[integrations.google.service_accounts.deploy]   # profile id: google/deploy/deploy
email = "deploy@my-proj.iam.gserviceaccount.com" # needs Service Account Token Creator for you
lifetime = "1h"                # optional, 15m to 12h (over 1h needs an org policy)

# An Entra ID account, signed in like `az login`. Profile ids: work/<subscription>/user.
[integrations.work]
type = "azure"
tenant = "contoso.onmicrosoft.com"   # optional: by default every tenant you belong to

[integrations.cf]
type = "cloudflare-oauth"       # browser sign-in, like `wrangler login`
client_id = "..."               # your OAuth client; see the Cloudflare guide
session = "12h"                 # optional: sign in again after this long
ttl = "1h"                      # lifetime of minted tokens

[integrations.cf-token]
type = "cloudflare-token"       # a bootstrap token instead of the browser
account_id = "0123456789abcdef0123456789abcdef"  # required for token_type = "account"
account_name = "personal"
token_type = "account"   # bootstrap owned by the account; "user" (default) for a user-owned one
ttl = "1h"               # lifetime of minted tokens
ips = ["current"]        # optional: tokens only work from this machine's public addresses

# Templates name permissions as the dashboard does; never IDs.
# `fob cf add-template` writes them for you.
[integrations.cf-token.templates.pages]
permissions = ["Pages Write", "Account Settings Read"]
ttl = "30m"
```

If you know IAM Identity Center through granted, the Cloudflare integrations work the same way: the browser sign-in or bootstrap token plays the part of the sign-in, templates the part of permission sets, and each `account × template` profile the part of an `account × role`; `fob exec` mints a short-lived token the way granted fetches role credentials. Unlike permission sets, templates live in your config, not in Cloudflare. A browser sign-in can only mint the permissions you approved on the consent page; a bootstrap token can mint any permission, so treat it like an administrator credential.

Registering the OAuth client, and creating a bootstrap token instead, account-owned or user-owned, are explained in [docs/guides/cloudflare.md](docs/guides/cloudflare.md).

Providers that only have long-lived tokens use `type = "token"`, usually with a preset:

```toml
[integrations.hetzner-prod]
type = "token"
preset = "hetzner"          # HCLOUD_TOKEN, checked against the Hetzner API at login
account = "prod"            # profile id: hetzner-prod/prod/hetzner

[integrations.upstash]
type = "token"
preset = "upstash"
vars = { UPSTASH_EMAIL = "me@example.com" }   # non-secret variables

[integrations.unikraft]
type = "token"
preset = "unikraft"         # UKC_TOKEN for `unikraft` and `kraft cloud`
vars = { UKC_METRO = "fra" }

[integrations.internal]
type = "token"
secrets = { token = ["INTERNAL_TOKEN"] }      # any provider: secret name → variables
verify_url = "https://api.example.com/me"     # optional: must answer 2xx for the token
console = "https://console.example.com"
```

### Browsers

Sign-ins and consoles open in the system's default browser. To keep each identity's sessions in a browser, or a browser profile, of its own, define the browsers once and name one in each integration with `browser`; it applies to `fob login` and `fob console` alike, and integrations without it keep the default.

```toml
[browsers.personal]
command = ["firefox", "-P", "personal", "{url}"]

[browsers.work]   # Windows Chrome from WSL; the profile is its folder, shown in chrome://version
command = ["/mnt/c/Program Files/Google/Chrome/Application/chrome.exe", "--profile-directory=Profile 1", "{url}"]

[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"
browser = "work"
```

The command runs without a shell, with `{url}` in any argument replaced by the URL. Chromium-based browsers (Chrome, Edge, Brave) pick a profile with `--profile-directory=<folder>`, Firefox with `-P <name>`. A sign-in must still open on this machine, since the browser returns to a listener on `127.0.0.1`.

## Use

```sh
fob login acme            # browser sign-in (kept while it still works), then discovers profiles
fob login acme --force    # sign in again even though the stored sign-in works
fob login acme --device-code   # approve with a code on another device (automatic over SSH)
fob list                  # acme/prod/AdministratorAccess, cf/personal/workers, ...
fob exec prod admin -- aws s3 ls
fob exec cf workers -- wrangler deploy   # like granted's `assume -x`, for Cloudflare
fob exec cf workers --ttl 4h -- wrangler dev   # longer-lived token for a long session
fob exec cf workers --revoke -- wrangler deploy   # token for this command only, deleted when it ends
fob cf add-template cf pages             # pick services and access levels, save a template
fob console prod admin    # opens the AWS console as that role
fob console prod admin --service ec2 --region eu-west-1 --duration 8h
fob status
fob check                 # do the sign-ins work? (exit status 1 if not; -q for scripts)
fob check prod admin      # do this profile's credentials work, and what do they act as?
fob rename acme work      # rename an integration; keeps its sign-in and profiles
```

### The AWS console

`fob console` signs in with new credentials each time, never cached ones, so the console session gets their whole lifetime: without a session length, the console signs you out when the credentials it was opened with expire. For an IAM user's roles that is also never past the end of the user's session.

`--duration` (or `console_duration` on an `aws-sso` integration or an `aws-iam` role) makes the console session last that long, 15 minutes to 12 hours, independently of the credentials. For an IAM user's roles, AWS does not state whether the console session can outlast the user's `GetSessionToken` session, and that has not been tried live. It has no default: it must be shorter than the role's maximum session duration (for an Identity Center role, the permission set's session duration, one hour unless your administrator raised it), which omnifob cannot see, and AWS refuses the sign-in otherwise. Chained roles and an IAM user's own session cannot take one: AWS refuses a session length for credentials from role chaining (at most an hour) and from `GetFederationToken` (which lasts the integration's `session_duration`). Cross-partition roles cannot take one yet, until it has been tried whether AWS accepts it for them; their console session lasts as long as their `duration`, up to 12 hours.

`--service` opens a console page, given as the path after the console host (`ec2`, `s3`, `lambda`, `cloudformation`, `route53/v2`), and `--region` the Region it opens in, which must be in the profile's partition; without it the profile's exported Region is used, if any.

Profiles are `<integration>/<account>/<role or template>`, but you rarely type the full id. Any words that together match one profile select it (`prod admin`, or just `dns-read`); a word equal to a whole segment wins, so `read` picks `cf/personal/read` over `cf/personal/dns-read`. An account ID works too (`fob exec 123456789012 admin -- ...`). With no match or several, `fob` shows a fuzzy picker that lists recently used profiles first; without a terminal it lists the matches instead.

`fob exec` exits with the command's status, or with 125 when fob itself fails, 127 when the command is not found and 126 when it cannot run, as `env` does.

### In the current shell

Add the wrapper to your shell's startup file:

```sh
eval "$(fob activate bash)"     # or zsh
fob activate fish | source      # fish
fob activate powershell | Out-String | Invoke-Expression   # PowerShell
```

Then `fob use prod admin` exports the credentials into the current shell, and `fob unuse` removes them. Switching profiles removes variables the previous one set and the new one does not.

The same line enables tab completion of commands, integration names and profile ids (`fob exec cf<TAB>`), read live from your discovered profiles. Only completion, without the `fob use` wrapper: `source <(COMPLETE=bash fob)`, `source <(COMPLETE=zsh fob)` or `COMPLETE=fish fob | source`.

### With other tools

```sh
fob creds acme/prod/ReadOnly                              # JSON: profile, env, expires_at
fob creds acme/prod/ReadOnly --format credential-process  # for ~/.aws/config
fob creds cf/personal/workers --format fnox               # for a fnox command lease
```

AWS profiles export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION` and `AWS_ACCOUNT_ID`, which the AWS SDKs use for account-based endpoints, plus `AWS_REGION` and `AWS_DEFAULT_REGION` when a Region is configured. The `credential-process` format carries the account as `AccountId`. These replace any you set yourself: an `AWS_ACCOUNT_ID` in your shell is overwritten by `fob exec` and `fob use`. With the account known, the SDKs send requests to account-based endpoints (DynamoDB, S3) on other hosts than the regional ones, which matters for firewall and VPC endpoint allowlists; `AWS_ACCOUNT_ID_ENDPOINT_MODE=disabled` turns that off.

AWS profiles for tools that want `--profile` or `AWS_PROFILE`: `fob export aws-config` prints one `[profile fob-<integration>-<account>-<role>]` per discovered role, each using `credential_process = fob creds ... --format credential-process`. `--write` keeps them in a marked block of `~/.aws/config` (backing up the previous file) and never touches anything outside it; the file is replaced in one step, keeping its permissions, and a symbolic link to it stays a link. Editors and GUI tools often run without your shell's `PATH`: `--absolute` writes the full path of the `fob` binary you ran instead, with symbolic links resolved, so run the export again after upgrading fob. On Linux and macOS a path with a space is written in double quotes; on Windows a path that needs quotes is refused, so put `fob` on `PATH` there instead.

```sh
fob export aws-config --write
aws s3 ls --profile fob-acme-prod-ReadOnly
```

fnox:

```toml
[leases.cloudflare]
type = "command"
create_command = "fob creds cf/personal/workers --format fnox"
```

### With coding agents

Coding agents run each command in a new shell with no one at the terminal, and whatever a command prints lands in the agent's context and its saved transcripts. fob recognises them by the variables they set (`CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`, `CURSOR_AGENT`, `COPILOT_AGENT_SESSION_ID`; set `OMNIFOB_AGENT=1` for another agent, or `OMNIFOB_AGENT=0` to turn this off) and then:

- Does not print credentials: `fob creds` (JSON), `fob env` and `fob console --print` refuse and point to `fob exec`. `--format credential-process` and `--format fnox` still work, because the AWS SDKs and fnox run them inside the agent's commands and read the output themselves.
- Never prompts, and takes a profile only by its full id (`fob list` shows them), so a command does what it says and permission rules can match it.
- Hands out only the profiles `[agent] profiles` allows, when it is set:

  ```toml
  [agent]
  profiles = ["acme/dev/*", "*/*/ReadOnly"]   # `*` matches within one segment
  ```

An agent gets credentials with `fob exec acme/dev/ReadOnly -- aws s3 ls`, or through AWS profiles from `fob export aws-config`, which work without fob in the command. When a sign-in lapses, the agent can ask you to run `fob login <integration>`, or run it itself: the browser opens on your screen for you to approve. Let the agent run `fob exec` per command rather than starting the agent itself inside `fob exec`, which would put the credentials in the environment of every command it runs.

This guards against accidents, not against the agent, which runs as you; the harness's sandbox and permission rules are the boundary. [`skills/omnifob`](skills/omnifob/SKILL.md) is a skill that teaches agents the above; install it with your agent's skill tooling, for example `npx skills add garysassano/omnifob`.

## Where secrets live

SSO sessions, the Cloudflare bootstrap token, stored tokens and cached credentials are kept in the OS keychain under the service `omnifob`: Keychain on macOS, Credential Manager on Windows, the Secret Service on Linux. Where no Secret Service runs (WSL, servers), the kernel keyring is used; it forgets everything on reboot. On WSL, long-lived secrets are therefore also written to `~/.local/state/omnifob/vault`, encrypted with Windows DPAPI for your Windows user, and restored after a reboot (`OMNIFOB_WSL_DPAPI=0` turns this off). `OMNIFOB_KEYRING` forces a store; `fob status` shows which one is in use.

Discovered profiles, which contain no secrets, are kept in `~/.local/state/omnifob/profiles.json`.

Credentials are cached until five minutes before they expire, and renewed in the background when a quarter of their lifetime is left, so commands rarely wait for new ones. Credentials asked for with `--ttl` are not cached, so the next command gets the configured lifetime again. `fob sync` deletes the cached credentials of profiles that went away. `fob revoke <profile>` deletes the Cloudflare tokens minted for a profile and clears its cache. Cloudflare tokens omnifob mints are named `omnifob <template>` (for example `omnifob workers`); omnifob remembers their IDs, deletes expired ones after each mint and on `fob sync`, and deletes all of them on `fob logout`. Tokens it did not mint are never touched.

## Documentation

[docs/](docs/README.md) has the guides, the design notes and the research behind omnifob, including the other tools in its space.
