# omnifob

One sign-in for every cloud. `fob` signs you in once per identity source, discovers every account and role you can use, and hands out short-lived credentials as environment variables, to a command, to the web console, or to other tools.

## Status

Early. What changed in each version is in the [release notes](https://github.com/garysassano/omnifob/releases). Working today:

| Integration                     | Sign-in                                                 | Discovery                                                                 | Credentials                                                                                                                                                                                                             | Console                                                |
| ------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `aws-sso` (IAM Identity Center) | Browser (PKCE) or device flow, silent refresh           | Every account and role, plus configured chained and cross-partition roles | Role credentials; chained roles through STS AssumeRole; roles in other partitions through STS GetWebIdentityToken and AssumeRoleWithWebIdentity (the exchange not yet tried live)                                       | Federated sign-in URL                                  |
| `aws-iam` (IAM user)            | Access key, stored once; MFA per session                | The user's session, plus configured roles                                 | Session from STS GetSessionToken; roles assumed with it (up to 1 hour), or with the key for `no_session` roles (up to 12 hours)                                                                                         | Federated sign-in URL                                  |
| `aws-login` (console sign-in)   | Browser or pasted code, as `aws login`; silent refresh  | The signed-in console identity, plus configured roles                     | 15 minute credentials from AWS Sign-In, renewed with a DPoP-bound refresh token until the sign-in ends (12 hours by default, up to 90 days); roles through STS AssumeRole with them (up to 1 hour) (not yet tried live) | Federated sign-in URL                                  |
| `gcp` (Google account)          | Browser (PKCE) or pasted code, as `gcloud auth login`   | Every active project, plus configured service accounts                    | Your access token per project; service account tokens by impersonation                                                                                                                                                  | Cloud console                                          |
| `azure` (Entra ID)              | Browser (PKCE) or device flow, as `az login`            | Every subscription in every tenant                                        | A Resource Manager token, with the subscription and tenant IDs (not yet tried on a live tenant)                                                                                                                         | Azure portal                                           |
| `cloudflare-oauth`              | Browser sign-in (OAuth with PKCE), silent refresh       | Approved accounts × templates                                             | Minted tokens, scoped by permission name, expiring                                                                                                                                                                      | Dashboard                                              |
| `cloudflare-token`              | Bootstrap token, stored once                            | Accounts × templates                                                      | Minted tokens, scoped by permission name, expiring                                                                                                                                                                      | Dashboard                                              |
| `token`                         | Paste once, checked against the provider where possible | One profile per integration                                               | The stored token under every variable the provider's tools read                                                                                                                                                         | Known console URL                                      |
| `command` (any program)         | Nothing stored: the program signs in however it does    | One profile per integration                                               | What the program prints, omnifob's JSON or the AWS `credential_process` format, cached until the expiry it states                                                                                                       | `console`, else a federated sign-in URL for AWS output |

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

Coming from granted, aws-vault or the AWS CLI? `fob import aws` finds every IAM Identity Center portal your `~/.aws/config` profiles use (standard `sso_*` keys, `sso-session` sections with their `sso_registration_scopes`, granted's keys) and the roles chained from them (`role_arn` + `source_profile`, with session name, external ID, region, `mfa_serial` and `duration_seconds`), and prints matching integrations; `--write` appends them to the config. Roles assumed from a profile with an IAM user's access key become an `aws-iam` integration with those roles; the key itself is never read, so run `fob login <name>` afterwards to store it. A profile `aws login` signed in (`login_session`) becomes an `aws-login` integration, which `fob login <name>` signs in again, since the AWS CLI's cached tokens are not read. Profiles it cannot import (a role assumed from another assumed role, a `credential_process` source, a `duration_seconds` AWS would refuse, a role ARN or Region the config would refuse) are listed with the reason.

Integration names may contain only letters, digits, `.`, `_` and `-`, and may not start with `-`. A config with another name is refused with a pointer to `fob rename "<old name>" <new-name>`, which still works on it.

Every key is checked when the config loads, and an error names the key: Regions, account IDs, role ARNs and their partitions, session names and lengths, `https://` start URLs, service account emails, Cloudflare template names, IP ranges and lifetimes (more than five minutes, when omnifob would mint the token again), token presets and variable names, and configured roles whose labels would give two profiles one id.

The config has a JSON Schema, [schema/config.schema.json](schema/config.schema.json), for completion and checks in editors and [taplo](https://taplo.tamasfe.dev). Name it on the first line of the config:

```toml
#:schema https://raw.githubusercontent.com/garysassano/omnifob/main/schema/config.schema.json
```

Then `taplo check ~/.config/omnifob/config.toml` checks the file, and editors with the Even Better TOML extension (which uses taplo) complete keys and show their descriptions. The schema knows the keys and their types; the checks above that need more than that (partitions, clashing ids) still run when omnifob loads the config.

`~/.config/omnifob/config.toml` (or `$OMNIFOB_CONFIG`, or `--config <path>` on any command, which has to name an existing file except for `fob import aws --write`):

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
duration = "45m"               # optional, 15m to 1h (default 1h)
console_duration = "8h"        # optional: `fob console` session length, 15m to 12h

[integrations.legacy.roles.batch]  # profile id: legacy/batch/Batch
role_arn = "arn:aws:iam::222222222222:role/Batch"
no_session = true              # assumed with the key itself, as aws-vault --no-session:
duration = "12h"               # up to 12h, with an MFA code for each new session

# Console credentials, as `aws login` gets them: the browser picks a console
# session (an IAM user, root or a federated role), and no access key is stored.
# Profile id: console/<account ID>/<user, root or role name>.
[integrations.console]
type = "aws-login"
region = "eu-central-1"        # the Region signed in through; also AWS_REGION
default_region = "eu-west-1"   # optional: AWS_REGION instead of region

[integrations.console.roles.audit]  # profile id: console/audit/Audit, assumed with the
role_arn = "arn:aws:iam::333333333333:role/Audit"   # console credentials: role chaining,
duration = "1h"                # so 15m to 1h (default 1h)

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

A `secrets` table replaces the preset's secrets and the fixed variables that come with them (`UNIKRAFT_PROFILE_ENV` for unikraft), so set those under `vars` if you still want them.

`fob login` and `fob check` check the token with the provider where it has a call for that: a bearer token for most presets, Scaleway's secret key in `X-Auth-Token` (looking up its own access key, as `scw init` does), and Upstash's API key with `UPSTASH_EMAIL` as HTTP Basic credentials. A token the provider refuses (401 or 403) is reported as rejected; a provider that cannot be reached or answers 5xx is reported as not checked, so try again later. Fly.io tokens are not checked, since Fly.io has no call that every token, app-scoped deploy tokens included, may make.

`fob login <name>` asks for each secret. An integration with a single secret also takes it from the clipboard (`--from-clipboard`, which refuses an empty clipboard, text with whitespace and URLs) or from stdin (`--token-stdin`).

Any program that prints credentials becomes a profile with `type = "command"`: saml2aws, gimme-aws-creds, okta-aws-cli, IAM Roles Anywhere's `credential_process` helper or an in-house script.

```toml
[integrations.okta]
type = "command"
command = ["okta-aws-cli", "web", "--format", "process-credentials", "--session-duration", "{ttl_seconds}"]
format = "credential-process"   # the AWS credential_process JSON; default "omnifob"
ttl = "1h"                      # optional: what {ttl_seconds} and OMNIFOB_TTL_SECONDS ask for
region = "eu-west-1"            # optional, with credential-process: AWS_REGION
timeout = "5m"                  # optional, 1s to 10m (default 2m)
account = "prod"                # optional: profile id okta/prod/okta-aws-cli
```

The program runs without a shell, so arguments need no quoting and nothing in them is expanded; it is a name on `PATH`, an absolute path or one under `~/`. It keeps the terminal's stdin and stderr, so it can prompt and report, gets `OMNIFOB_PROFILE` (but not `OMNIFOB_VAULT_PASSPHRASE`), and is stopped after `timeout`, or as soon as it prints more than 1 MiB. Its stdout is read as omnifob's JSON (`{"env": {"NAME": "value"}, "expires_at": "<RFC 3339>"}`, as `fob creds` prints it; `expires_at` is optional) or, with `format = "credential-process"`, the AWS format, which makes an AWS profile. Credentials with an expiry are cached until five minutes before it; credentials without one are fetched for every use. omnifob never prints the program's output, not even when it cannot read it. Without `ttl`, the program chooses the lifetime and `--ttl` is refused; with it, `--ttl` and `[agent] max_ttl` change what is asked for. `fob login` has nothing to do for these integrations, and `fob check` runs the program once.

### Browsers

Sign-ins and consoles open in the system's default browser. To keep each identity's sessions in a browser, or a browser profile, of its own, define the browsers once and name one in each integration with `browser`; it applies to `fob login` and `fob console` alike, and integrations without it keep the default.

```toml
[browsers.work]
type = "chrome"            # fob finds it, also Windows Chrome from WSL
profile = "Profile 1"      # optional: the Chrome profile folder sign-ins use, as chrome://version shows it

[browsers.personal]
type = "zen"
profile = "personal"       # optional: the Firefox profile name

[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"
browser = "work"
```

`type` names the browser. fob looks for it where its installers put it: Program Files and `%LOCALAPPDATA%` on Windows (from WSL too, before any Linux browser, since the Windows browser is the desktop's), `/Applications` and `~/Applications` on macOS, and the program names below on `PATH` on Linux, Flatpak app ids included. Set `path` when it is elsewhere: an absolute path (a macOS `.app` bundle or the program in it), one under `~/`, or a name on `PATH`. A sign-in must still open on this machine, since the browser returns to a listener on `127.0.0.1`.

The AWS console signs out one identity when another signs in, so a second profile's console would log out the first. fob opens each AWS profile's console apart from the others, in the way the browser supports:

| `type`      | Browser        | Engine   | Linux programs                                       | Consoles kept apart |
| ----------- | -------------- | -------- | ---------------------------------------------------- | ------------------- |
| `chrome`    | Google Chrome  | Chromium | `google-chrome-stable`, `google-chrome`              | `profile`           |
| `edge`      | Microsoft Edge | Chromium | `microsoft-edge-stable`, `microsoft-edge`            | `profile`           |
| `brave`     | Brave          | Chromium | `brave-browser`, `brave`                             | `profile`           |
| `vivaldi`   | Vivaldi        | Chromium | `vivaldi-stable`, `vivaldi`                          | `profile`           |
| `chromium`  | Chromium       | Chromium | `chromium`, `chromium-browser`, `ungoogled-chromium` | `profile`           |
| `helium`    | Helium         | Chromium | `helium`, `helium-browser`                           | `profile`           |
| `thorium`   | Thorium        | Chromium | `thorium-browser`, `thorium`                         | `profile`           |
| `opera`     | Opera          | Chromium | `opera`                                              | no                  |
| `arc`       | Arc            | Chromium | (macOS only)                                         | no                  |
| `firefox`   | Firefox        | Gecko    | `firefox`, `firefox-esr`, Developer Edition, Nightly | `container`         |
| `zen`       | Zen            | Gecko    | `zen-browser`, `zen`                                 | `container`         |
| `librewolf` | LibreWolf      | Gecko    | `librewolf`                                          | `container`         |
| `waterfox`  | Waterfox       | Gecko    | `waterfox`                                           | `container`         |
| `floorp`    | Floorp         | Gecko    | `floorp`                                             | `container`         |
| `safari`    | Safari         | WebKit   | (macOS only)                                         | no                  |
| `orion`     | Orion          | WebKit   | (macOS only)                                         | no                  |

- `profile`: a browser profile per fob profile, `--profile-directory=fob <integration> <account> <role>`, which the browser creates on first use and reuses after; delete one in the browser's profile manager.
- `container`: a container (Firefox's Container Tabs) per fob profile, opened as `ext+granted-containers:name=<profile id>&url=<console URL>`. It needs the [Granted Containers](https://addons.mozilla.org/en-US/firefox/addon/granted/) add-on in that browser, which creates the container, named after the profile, the first time.

`isolate = "none"` opens every console in the browser profile sign-ins use instead. Asking a browser for a kind of isolation it does not have (`isolate = "container"` on Chrome) fails when the config loads. fob knows no reliable command-line switch for Opera's and Arc's profiles, and Safari and Orion take none, so their consoles are not kept apart. Sign-ins and other providers' consoles open in the browser profile `profile` names, since they rely on the session already there.

Any other browser, a Flatpak or Snap wrapper or a script, is `type = "command"`: the program and its arguments, run without a shell, with `{url}` in any argument replaced by the URL. `engine` says what the browser is built on, which gives its consoles that engine's isolation (`chromium`: `profile`, replacing any `--profile-directory` in the command; `gecko`: `container`; `webkit`: none); without it they are not kept apart.

```toml
[browsers.flatpak-firefox]
type = "command"
command = ["flatpak", "run", "org.mozilla.firefox", "-P", "work", "{url}"]
engine = "gecko"
```

Containers can be told apart at a glance by colour and icon, set per profile pattern (`*` matches within one part of the id, as in `[agent] profiles`); the first entry that matches wins, and unmatched containers get the add-on's own colour:

```toml
[[browsers.personal.containers]]
profiles = ["*/prod/*", "*/prod-*/*"]
color = "red"         # blue, turquoise, green, yellow, orange, red, pink or purple
icon = "fingerprint"  # fingerprint, briefcase, dollar, cart, circle, gift, vacation, food, fruit, pet, tree or chill

[[browsers.personal.containers]]
profiles = ["*/dev/*"]
color = "green"
```

fob adds them to the URL as `color` and `icon`, which Granted Containers applies when it creates the container.

### Default profiles per directory

`[directories]` maps a directory to the profile `fob exec` and `fob use` pick in it, and below it, when you name none. The longest matching directory wins, and a named profile always beats it. The mapping lives in your own config, so repositories carry no integration names:

```toml
[directories]
"~/git/acme" = "acme/dev/ReadOnly"
"~/git/acme/billing" = "acme/prod-billing/ReadOnly"
"/srv/deploy" = "acme/prod/Deploy"
```

`fob exec -- terraform plan` in `~/git/acme/billing/infra` then runs with `acme/prod-billing/ReadOnly`. Commands run by a coding agent still name the profile in full (the error says which one the directory would pick), so what they use stays in the command.

## Use

```sh
fob login acme            # browser sign-in (kept while it still works), then discovers profiles
fob login                 # pick the integration from a fuzzy list (fob logout too)
fob login acme --force    # sign in again even though the stored sign-in works
fob login acme --device-code   # approve with a code on another device (automatic over SSH and without a display)
fob list                  # acme/prod/AdministratorAccess, cf/personal/workers, ...
fob list prod admin       # only the profiles those words match
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
fob rename acme work      # rename an integration; keeps its sign-in and profiles
fob revoke --all          # delete every minted token and clear every cached credential
fob logout --all          # sign out of every integration
```

Without `browser`, URLs open in the system's default browser; on WSL without a Linux opener (`wslview`, `xdg-open`) that is Windows' default browser, through `explorer.exe`.

### The AWS console

`fob console` signs in with new credentials each time, never cached ones, so the console session gets their whole lifetime: without a session length, the console signs you out when the credentials it was opened with expire.

`--duration` (or `console_duration` on an `aws-sso` integration or an `aws-iam` role) makes the console session last that long, 15 minutes to 12 hours, independently of the credentials. For an IAM user's roles, AWS accepts a length although STS counts these roles as chained; whether the console session lasts past the end of the user's `GetSessionToken` session has not been watched. It has no default: it must be shorter than the role's maximum session duration (for an Identity Center role, the permission set's session duration, one hour unless your administrator raised it), which omnifob cannot see, and AWS refuses the sign-in otherwise. Chained roles and an IAM user's own session cannot take one: AWS refuses a session length for credentials from role chaining (at most an hour) and from `GetFederationToken` (which lasts the integration's `session_duration`). Cross-partition roles cannot take one yet, until it has been tried whether AWS accepts it for them; their console session lasts as long as their `duration`, up to 12 hours.

`--service` opens a console page, given as the path after the console host (`ec2`, `s3`, `lambda`, `cloudformation`, `route53/v2`), and `--region` the Region it opens in, which must be in the profile's partition; without it the profile's exported Region is used, if any.

Profiles are `<integration>/<account>/<role or template>`, but you rarely type the full id. Any words that together match one profile select it (`prod admin`, or just `dns-read`); a word equal to a whole segment wins, so `read` picks `cf/personal/read` over `cf/personal/dns-read`. An account ID works too (`fob exec 123456789012 admin -- ...`), and `--account-id` with `--role` picks a profile without naming it at all, so a command written in a runbook works for colleagues whose integrations and accounts are named differently: `fob exec --account-id 123456789012 --role AdministratorAccess -- aws sts get-caller-identity` (also on `fob env`, `fob creds` and `fob console`). The account is the provider's (an AWS account, an Azure subscription, a Google Cloud project, a Cloudflare account) and the role is the last part of the id, ignoring case. With no match or several, `fob` shows a fuzzy picker that lists recently used profiles first; without a terminal it lists the matches instead.

`fob exec` exits with the command's status, or with 125 when fob itself fails (a config that does not load included), 127 when the command is not found and 126 when it cannot run, as `env` does. A Windows exit code too large for the 0 to 255 range is reported as 1 when its low byte would read as success in the runs fob waits for: `--revoke`, `--server`, `--token-file`, and Azure and Google profiles unless `--no-server`. Other `fob exec` runs pass it on whole.

The command gets the profile's variables, `OMNIFOB_PROFILE` and, when the credentials expire, `OMNIFOB_EXPIRES_AT`. What a `fob use` in the same shell exported and this profile does not set is removed, and so is `OMNIFOB_VARS`. When the profile hands out an AWS access key, the AWS credential variables it does not set (`AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, `AWS_ACCOUNT_ID`), the other sources of AWS credentials (`AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_*`) and `AWS_ENDPOINT_URL_S3` are removed too, so a session token, profile or R2 endpoint left in the shell is not mixed with the new key. A Region you set yourself stays for a profile without one, but is replaced when the profile sets one (R2 sets `AWS_REGION=auto` and removes `AWS_DEFAULT_REGION`).

### In the current shell

Add the wrapper to your shell's startup file:

```sh
eval "$(fob activate bash)"     # or zsh
fob activate fish | source      # fish
fob activate powershell | Out-String | Invoke-Expression   # PowerShell
```

Then `fob use prod admin` exports the credentials into the current shell, and `fob unuse` removes them. Switching profiles removes variables the previous one set and the new one does not. `OMNIFOB_PROFILE` names the active profile and `OMNIFOB_EXPIRES_AT` (RFC 3339) says when its credentials expire, for a shell prompt; `fob status` shows both. `fob activate` and `fob unuse` work even when the config or `profiles.json` is broken, so a typo does not break every new shell. The wrapper also recognises `use` and `unuse` after `--config <path>`. In PowerShell the wrapper finds the `fob` binary on `PATH`, so it works with `pwsh` on Linux and macOS too.

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

#### SDKs that read no token from the environment

`fob exec` also serves the credentials the way each cloud's SDKs look for them when no variable will do, from an endpoint on `127.0.0.1` that lives as long as the command and answers only requests carrying its random secret:

- **Azure**: an Azure profile's command gets a managed identity endpoint, as App Service runs one (`IDENTITY_ENDPOINT` and `IDENTITY_HEADER`). The Azure Identity libraries' `DefaultAzureCredential` and `ManagedIdentityCredential` then get tokens for any resource (Resource Manager, Key Vault, Storage, Graph) from your sign-in, without `~/.azure`. Variables that would make them pick another credential (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `MSI_ENDPOINT`, ...) are removed. The `az` CLI uses it only after `az login --identity`, which writes `~/.azure`, so it keeps its own sign-in.
- **Google Cloud**: a Google profile's command gets Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, a private file deleted afterwards) whose token URL is the endpoint, so the client libraries get the profile's token and come back for a new one when it nears its end. The file holds the endpoint's secret, not a Google token. `--token-file` gives gcloud its token in a private file (`CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`) that fob rewrites before the token expires, so a long-running script's gcloud calls keep working.
- **AWS**: with `--server`, the command gets a container credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI` and `AWS_CONTAINER_AUTHORIZATION_TOKEN`) instead of the key variables, and the SDKs and the AWS CLI fetch renewed credentials from it, so a dev server or an IDE started with `fob exec --server` outlives a one-hour session. A `[default]` profile in `~/.aws/config` or `~/.aws/credentials` wins over the endpoint, since every SDK reads the shared files before the container provider; the endpoint's credentials apply when the default profile has none.

`--no-server` turns the Azure and Google endpoints off. The endpoints never prompt: a request that would need an MFA code, because a role's session ended during the run, is answered with an error that says to run `fob exec <profile> -- true` in a terminal.

```sh
fob exec work/prod/user -- python deploy.py              # DefaultAzureCredential works
fob exec google/proj-a/user -- go run ./cmd/importer     # ADC works
fob exec acme/dev/Admin --server -- code .               # renewed for the IDE's lifetime
```

#### Kubernetes

`fob creds --format k8s-exec` writes the `ExecCredential` a kubectl exec plugin returns: for an AWS profile an EKS token (`--cluster <name>`, made as `aws eks get-token` makes it, in the profile's Region or `--region`), for a Google profile its access token (GKE), and for an Azure profile an Entra ID token for AKS's server application, as `kubelogin` asks for it. It answers in the `apiVersion` kubectl asks for.

```yaml
users:
  - name: eks-dev
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: fob
        args: [creds, acme/dev/Admin, --format, k8s-exec, --cluster, dev]
        interactiveMode: Never
```

#### Google executable-sourced credentials

Google's executable-sourced credentials take a third-party token and exchange it at Google's STS through a workload identity pool; they cannot take an access token. `fob creds <google profile> --format gcp-executable` prints the executable response with your account's Google ID token, and `fob export gcp-adc <profile> --audience <provider>` writes an ADC file that runs it, for a workload identity pool provider that trusts `https://accounts.google.com` (with the OAuth client's ID as an allowed audience); a service account profile adds impersonation of that account. The file holds no token, and the libraries run fob only with `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. Without such a pool, `fob exec` above is the way to give the libraries your token.

### With coding agents

Coding agents run each command in a new shell with no one at the terminal, and whatever a command prints lands in the agent's context and its saved transcripts. fob recognises them by the variables they set (`AI_AGENT`, which several agents set, and `CLAUDECODE`, `CODEX_SANDBOX`, `CODEX_THREAD_ID`, `GEMINI_CLI`, `CURSOR_AGENT`, `COPILOT_AGENT_SESSION_ID`, `COPILOT_CLI`, `OPENCODE`, `CRUSH`, `QWEN_CODE`, `CLINE_ACTIVE`, `GOOSE_TERMINAL`, `PI_CODING_AGENT`, `ANTIGRAVITY_AGENT`; set `OMNIFOB_AGENT=1` for another agent, such as Aider or Windsurf, which set none, or `OMNIFOB_AGENT=0` to turn this off) and then:

- Does not print credentials: `fob creds` (JSON), `fob env` and `fob console --print` refuse and point to `fob exec`. `--format credential-process`, `fnox`, `k8s-exec` and `gcp-executable` still work, because the AWS SDKs, fnox, kubectl and Google's libraries run them inside the agent's commands and read the output themselves.
- Never prompts, and takes a profile only by its full id (`fob list` shows them, marking those `[agent] profiles` keeps from agents with `(not open to agents)`, or `"open_to_agents": false` with `--json`), so a command does what it says and permission rules can match it.
- Hands out only the profiles `[agent] profiles` allows, when it is set:

  ```toml
  [agent]
  profiles = ["acme/dev/*", "*/*/ReadOnly"]   # `*` matches within one segment
  ```

- Marks what agents get on the provider's side: AWS roles whose config names no `session_name` get the session name `omnifob-agent` (instead of `omnifob`), so CloudTrail tells them apart; minted Cloudflare tokens are named `omnifob-agent <template>`; and under GitHub Copilot's agent, Entra ID tokens carry its session (`COPILOT_AGENT_SESSION_ID`) as the Azure CLI sends it, which Entra ID records in the token. Credentials cached before the agent asked keep their original marks.
- Optionally shortens and revokes what agents get:

  ```toml
  [agent]
  max_ttl = "15m"      # at most this long, where omnifob picks the lifetime (not cached)
  auto_revoke = true   # `fob exec` on a Cloudflare profile acts as `--revoke`
  ```

  `max_ttl` applies to Cloudflare tokens, chained, cross-partition, IAM users' and console sign-ins' roles, IAM user sessions and Google service accounts, except where each new session asks for an MFA code (IAM user sessions with `mfa_serial`, `no_session` roles of such a user, and chained and console sign-ins' roles with `mfa_serial`), whose cached credentials agents get as they are. It also caps what `fob exec`'s endpoints and `--token-file` serve. The provider sets the lifetime of Identity Center roles, Google accounts' and Azure tokens, and console sign-in credentials.

An agent gets credentials with `fob exec acme/dev/ReadOnly -- aws s3 ls`, or through AWS profiles from `fob export aws-config`, which work without fob in the command. When a sign-in lapses, the agent can ask you to run `fob login <integration>`, or run it itself: the browser opens on your screen for you to approve. Let the agent run `fob exec` per command rather than starting the agent itself inside `fob exec`, which would put the credentials in the environment of every command it runs.

This guards against accidents, not against the agent, which runs as you; the harness's sandbox and permission rules are the boundary. [`skills/omnifob`](skills/omnifob/SKILL.md) is a skill that teaches agents the above; install it with your agent's skill tooling, for example `npx skills add garysassano/omnifob`. The skill names the fob release it describes (`metadata.fob-version`); `fob status`, and `fob list` under an agent, point out a copy in `~/.agents/skills`, Claude Code's, Codex's or OpenCode's skill folder that describes another release, which `npx skills update` refreshes.

### Audit log

```toml
[audit]
enabled = true
```

appends one JSON line to `~/.local/state/omnifob/audit.jsonl` for every credential fob hands out: the time, command, profile, integration, the agent's marker variable when an agent ran it, how it was handed over (`env`, `credential-process`, `aws-container`, `azure-identity`, `gcp-adc`, `k8s-exec`, `console`, ...), when it expires and a minted Cloudflare token's ID. Never a secret. The file is private and only grows; rotate or delete it as you like.

## Where secrets live

SSO sessions, the Cloudflare bootstrap token, stored tokens and cached credentials are kept in the OS keychain under the service `omnifob`: Keychain on macOS, Credential Manager on Windows, the Secret Service on Linux. Where no Secret Service runs (WSL, servers), the kernel keyring is used, straight away when there is no D-Bus session bus; it forgets everything on reboot. On WSL, long-lived secrets are therefore also written to `~/.local/state/omnifob/vault`, encrypted with Windows DPAPI for your Windows user, and restored after a reboot (`OMNIFOB_WSL_DPAPI=0` turns this off). `OMNIFOB_KEYRING` forces a store; `fob status` shows which one is in use.

On a machine without a keychain that survives reboots (a headless Linux server, a container with a mounted state directory), `OMNIFOB_KEYRING=encrypted-file` keeps the secrets in files encrypted with a passphrase instead, in `~/.local/state/omnifob/encrypted` (or `encrypted-file:<absolute dir>`). The first command that stores a secret asks for a new passphrase (at least 12 characters), and the passphrase is asked again only after a reboot: the key derived from it is kept in the kernel keyring until then (`OMNIFOB_VAULT_KEY_CACHE=0` asks every time). Scripts and services pass it in `OMNIFOB_VAULT_PASSPHRASE`, which fob removes from the environment of the commands and credential helpers it runs. If `vault.json` goes missing while sealed files remain, fob refuses to start a new vault over them, since a new salt would make them never open again; restore the file, or move the sealed files away. Each secret is encrypted with AES-256-GCM under a key derived with PBKDF2-HMAC-SHA256 (600,000 iterations); the passphrase cannot be recovered, and forgetting it means signing in to every integration again after deleting the directory. What this protects against, and what not, is in [docs/decisions.md](docs/decisions.md).

Discovered profiles, which contain no secrets, are kept in `~/.local/state/omnifob/profiles.json` (`$XDG_STATE_HOME/omnifob`). Without a home directory, set `XDG_STATE_HOME` and `OMNIFOB_CONFIG` (or `XDG_CONFIG_HOME`): omnifob then refuses to start rather than keep its files in the current directory. If it cannot be read, `fob sync` and `fob login` start over from no profiles and rewrite it, and `fob status` and `fob logout` carry on with a warning. On Linux and macOS the state directory and the vault are readable by you only (`0700`, files `0600`), and every file in them is replaced atomically, so a concurrent `fob` never reads half of one.

Credentials are cached until five minutes before they expire, and renewed in the background when a quarter of their lifetime is left, so commands rarely wait for new ones. Credentials asked for with `--ttl` are not cached, so the next command gets the configured lifetime again. `fob sync` deletes the cached credentials of profiles that went away. `fob revoke <profile>` deletes the Cloudflare tokens minted for a profile and clears its cache; `fob revoke --all` does it for every profile, leaving the sign-ins. A renewal in the background is skipped for roles that need a code each session (chained and console sign-ins' roles with `mfa_serial`, and an IAM user's `no_session` roles when the user has `mfa_serial`); the next command that needs one asks for it. Cloudflare tokens omnifob mints are named `omnifob <template>` (for example `omnifob workers`); omnifob remembers their IDs, deletes expired ones after each mint and on `fob sync`, and deletes all of them on `fob logout`. Tokens it did not mint are never touched.

## Documentation

[docs/](docs/README.md) has the guides, the design notes and the research behind omnifob, including the other tools in its space.
