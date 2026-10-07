# omnifob

One sign-in for every cloud. `fob` signs you in once per identity source, discovers every account and role you can use, and hands out short-lived credentials as environment variables, to a command, to the web console, or to other tools.

It takes its ideas from tools that each solved part of the problem:

- [granted](https://github.com/fwdcloudsec/granted) (AWS): `assume`-style switching in the current shell and opening the console.
- [aws-vault](https://github.com/ByteNess/aws-vault) (AWS): SSO tokens in the OS keychain, renewed silently with refresh tokens.
- [Leapp](https://github.com/Noovolari/leapp) (AWS, Azure) and [aws-sso-cli](https://github.com/synfinatic/aws-sso-cli) (AWS): sign in once, then discover every account and role.
- [wrangler](https://github.com/cloudflare/workers-sdk) and [cf](https://github.com/cloudflare/cf) (Cloudflare): Cloudflare sign-in and the variables Cloudflare tools read.
- [fnox](https://github.com/jdx/fnox) (many providers): short-lived credential leases for project secrets; `fob creds --format fnox` plugs into it.

## Status

Early. What changed in each version is in the [release notes](https://github.com/garysassano/omnifob/releases). Working today:

| Integration | Sign-in | Discovery | Credentials | Console |
| --- | --- | --- | --- | --- |
| `aws-sso` (IAM Identity Center) | Device flow, silent refresh | Every account and role, plus configured chained roles | Role credentials; chained roles through STS AssumeRole | Federated sign-in URL |
| `cloudflare` | Bootstrap token, stored once | Accounts × templates | Minted tokens, scoped by permission name, expiring | Dashboard |
| `token` | Paste once, checked against the provider where possible | One profile per integration | The stored token under every variable the provider's tools read | Known console URL |

Token presets: `hetzner`, `digitalocean`, `vultr`, `linode` (Akamai Cloud), `upstash`, `akamai-edgegrid`, `scaleway`, `vercel`, `netlify`, `fly`, `neon`, `supabase`, `github`. These providers' own CLIs keep tokens in plain-text files; omnifob keeps them in the keychain.

Planned: Cloudflare browser sign-in (OAuth with PKCE), Google Cloud (modelled on `gcloud` impersonation), Azure (modelled on `az`), per-directory profiles through mise.

## Install

From source:

```sh
cargo install --locked --git https://github.com/garysassano/omnifob omnifob
```

Once releases are published (built for Linux x86_64 and ARM, macOS Apple Silicon and Windows, with checksums and build provenance), with mise:

```sh
mise use -g github:garysassano/omnifob
```

This installs two names for the same binary: `fob` for daily use and `omnifob` for scripts.

## Configure

Coming from granted, aws-vault or the AWS CLI? `fob import aws` finds every IAM Identity Center portal your `~/.aws/config` profiles use (standard `sso_*` keys, `sso-session` sections, granted's keys) and the roles chained from them (`role_arn` + `source_profile`, with session name, external ID and region), and prints matching integrations; `--write` appends them to the config. Profiles that need MFA are reported and skipped for now.

`~/.config/omnifob/config.toml` (or `$OMNIFOB_CONFIG`):

```toml
[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"          # where IAM Identity Center runs
default_region = "eu-central-1"  # exported as AWS_REGION (optional)

# Roles assumed from an Identity Center role (role_arn + source_profile in ~/.aws/config).
# Profile id: acme/prod-deploy/Deploy. AWS limits these sessions to one hour.
[integrations.acme.chained.prod-deploy]
via_account_id = "111111111111"
via_role = "AdministratorAccess"
role_arn = "arn:aws:iam::222222222222:role/Deploy"
session_name = "me"          # optional, like role_session_name
external_id = "..."          # optional
region = "us-east-1"         # optional, defaults to the integration's

[integrations.cf]
type = "cloudflare"
account_id = "0123456789abcdef0123456789abcdef"  # optional: discovered when omitted
account_name = "personal"
ttl = "1h"                                       # lifetime of minted tokens

# Templates name permissions as the dashboard does; never IDs.
[integrations.cf.templates.pages]
permissions = ["Pages Write", "Account Settings Read"]
ttl = "30m"
```

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

[integrations.internal]
type = "token"
secrets = { token = ["INTERNAL_TOKEN"] }      # any provider: secret name → variables
verify_url = "https://api.example.com/me"     # optional: must answer 2xx for the token
console = "https://console.example.com"
```

Cloudflare comes with built-in templates; `fob cf templates <integration>` lists them and `fob cf permissions <integration> [filter]` lists every permission name your account offers. Names can be written as the API does ("Workers Scripts Write") or as the dashboard does ("Workers Scripts Edit").

- `workers`: everything a Worker and its usual bindings need. The dashboard's "Edit Cloudflare Workers" template plus what it never caught up with: D1, Queues, Workers AI, Vectorize, Hyperdrive, Containers, Pipelines, and when your account offers them Browser Run, AI Gateway, Observability, Builds, Agents, Secrets Store and more.
- `dns-read`, `dns-edit`, `read`.

A template lists `permissions` (required) and `optional` ones, which are added when the account offers them and skipped otherwise.

## Use

```sh
fob login acme            # browser sign-in, then discovers profiles
fob list                  # acme/prod/AdministratorAccess, cf/personal/workers, ...
fob exec prod admin -- aws s3 ls
fob exec cf workers -- wrangler deploy   # like granted's `assume -x`, for Cloudflare
fob exec cf workers -- claude            # give an agent a token without pasting it anywhere
fob exec cf workers --ttl 4h -- claude   # longer-lived token for a long session
fob console prod admin    # opens the AWS console as that role
fob status
fob rename acme work      # rename an integration; keeps its sign-in and profiles
```

Profiles are `<integration>/<account>/<role or template>`. Any words that together match one profile select it (`prod admin`); with no match or several, `fob` shows a fuzzy picker.

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

AWS profiles for tools that want `--profile` or `AWS_PROFILE`: `fob export aws-config` prints one `[profile fob-<integration>-<account>-<role>]` per discovered role, each using `credential_process = fob creds ... --format credential-process`. `--write` keeps them in a marked block of `~/.aws/config` (backing up the previous file) and never touches anything outside it.

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

## Where secrets live

SSO sessions, the Cloudflare bootstrap token, stored tokens and cached credentials are kept in the OS keychain under the service `omnifob`: Keychain on macOS, Credential Manager on Windows, the Secret Service on Linux. Where no Secret Service runs (WSL, servers), the kernel keyring is used; it forgets everything on reboot. On WSL, long-lived secrets are therefore also written to `~/.local/state/omnifob/vault`, encrypted with Windows DPAPI for your Windows user, and restored after a reboot (`OMNIFOB_WSL_DPAPI=0` turns this off). `OMNIFOB_KEYRING` forces a store; `fob status` shows which one is in use.

Discovered profiles, which contain no secrets, are kept in `~/.local/state/omnifob/profiles.json`.

Credentials are cached until five minutes before they expire, and renewed in the background when a quarter of their lifetime is left, so commands rarely wait for new ones. `fob revoke <profile>` deletes the Cloudflare tokens minted for a profile and clears its cache. Cloudflare tokens omnifob mints are named `omnifob:<profile>@<time>`, and expired ones are deleted on the next mint so they do not pile up in the dashboard.

## Credits

omnifob borrows ideas, not code, from these projects. Thank you to their authors.

- Credential tools: [granted](https://github.com/fwdcloudsec/granted), [aws-vault](https://github.com/ByteNess/aws-vault), [Leapp](https://github.com/Noovolari/leapp), [aws-sso-cli](https://github.com/synfinatic/aws-sso-cli), [fnox](https://github.com/jdx/fnox), [1Password shell plugins](https://github.com/1Password/shell-plugins).
- Provider CLIs whose sign-in flows were studied: [AWS CLI](https://github.com/aws/aws-cli), [gcloud](https://cloud.google.com/sdk), [Azure CLI](https://github.com/Azure/azure-cli), [OCI CLI](https://github.com/oracle/oci-cli), [wrangler](https://github.com/cloudflare/workers-sdk), [cf](https://github.com/cloudflare/cf), [doctl](https://github.com/digitalocean/doctl), [hcloud](https://github.com/hetznercloud/cli), [ovhcloud-cli](https://github.com/ovh/ovhcloud-cli), [linode-cli](https://github.com/linode/linode-cli), [scaleway-cli](https://github.com/scaleway/scaleway-cli), [vercel](https://github.com/vercel/vercel), [flyctl](https://github.com/superfly/flyctl), [neonctl](https://github.com/neondatabase/neonctl), [supabase](https://github.com/supabase/cli), [upstash](https://github.com/upstash/cli).

Notes on what each contributed are in [plan/research.md](plan/research.md) and [plan/landscape.md](plan/landscape.md).

## License

MIT
