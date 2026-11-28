# omnifob

One sign-in for every cloud, for you and your coding agents.

`fob` signs you in once per identity source, discovers every account and role you can use, and hands out short-lived credentials: to a command, to your shell, to the web console, or to other tools. Think of it as mise for cloud sign-ins: one tool and one set of commands instead of granted, aws-vault, `gcloud auth`, `wrangler login` and a folder of plain-text tokens, which also gives the Azure SDKs your `az login`-style sign-in.

```sh
fob login acme                          # sign in once; every account and role is discovered
fob exec prod admin -- terraform plan   # run a command as a profile
fob use dev read                        # or switch the current shell
fob console prod admin                  # open the AWS console as that role
```

- **Short-lived by default.** AWS role sessions, Google and Azure tokens, and Cloudflare tokens minted per permission template, all expiring. Long-lived tokens that a provider can't avoid live in the OS keychain, never in plain-text files.
- **Discovers, doesn't ask.** No profile per account to write: one sign-in finds every AWS account and role, Google Cloud project, Azure subscription and Cloudflare account.
- **Built for agents too.** Under Claude Code, Codex, Cursor, Gemini CLI and other coding agents, fob hands credentials to the command without printing them, never prompts or guesses, keeps agents to the profiles you allow, and fails with machine-readable error codes. [More below](#coding-agents).

## What it covers

| Provider                                                                                                                  | `type`                                 | You get                                                                     |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| AWS IAM Identity Center                                                                                                   | `aws-sso`                              | Every account and role, plus chained and cross-partition roles              |
| AWS IAM user                                                                                                              | `aws-iam`                              | MFA sessions and assumed roles; the access key is never handed out          |
| AWS console sign-in (`aws login`)                                                                                         | `aws-login`                            | The console identity's credentials, plus assumed roles                      |
| Google Cloud                                                                                                              | `gcp`                                  | Your token per project, plus service account impersonation                  |
| Azure                                                                                                                     | `azure`                                | A token per subscription, in every tenant                                   |
| Cloudflare                                                                                                                | `cloudflare-token`, `cloudflare-oauth` | Tokens minted per account and template, scoped by permission name, expiring |
| Hetzner, DigitalOcean, Vultr, Akamai, Scaleway, Upstash, Modal, Unikraft, Vercel, Netlify, Fly.io, Neon, Supabase, GitHub | `token` with a `preset`                | The stored token under every variable the provider's tools read             |
| Anything else                                                                                                             | `token` or `command`                   | Your own variables, or whatever a program such as saml2aws prints           |

omnifob is young: Azure has not yet been tried on a live tenant, and a few AWS paths (console sign-in roles, the cross-partition exchange) not yet live. [docs/providers](docs/providers/README.md) has the details for each provider, and the [release notes](https://github.com/garysassano/omnifob/releases) what changed in each version.

## Install

```sh
mise use -g github:garysassano/omnifob   # prebuilt binary
cargo binstall omnifob                   # prebuilt binary
cargo install --locked omnifob           # from source
```

[Releases](https://github.com/garysassano/omnifob/releases) have binaries for Linux (x86_64 and ARM64, static), macOS (Apple Silicon and Intel) and Windows (x86_64 and ARM64), with build provenance. Each installs two names for the same binary: `fob` for daily use and `omnifob` for scripts.

## Quick start

### 1. Add your sign-ins

**Coming from granted, aws-vault or the AWS CLI?** Skip writing anything: `fob import aws --write` turns your `~/.aws/config` into integrations. Coming from another tool, see [Migrating](#migrating).

Otherwise, create `~/.config/omnifob/config.toml` with one entry per sign-in you use. The name after `integrations.` is yours to choose:

```toml
[integrations.acme]                 # AWS IAM Identity Center
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"             # the Region Identity Center runs in

[integrations.google]               # Google Cloud
type = "gcp"

[integrations.work]                 # Azure
type = "azure"

[integrations.cf]                   # Cloudflare, with a bootstrap token
type = "cloudflare-token"

[integrations.hetzner]              # any token preset
type = "token"
preset = "hetzner"
```

That is all most setups need. Every other key is optional: [Configuration](docs/guides/configuration.md) is the full reference, from chained roles to per-directory default profiles.

### 2. Sign in

```sh
fob login acme      # opens the browser, then discovers every account and role
fob login           # or pick from a list
fob list            # acme/prod/AdministratorAccess  prod?  admin?, google/my-proj/user, ...
```

Profile ids are `<integration>/<account>/<role>`. A few words that match one profile are enough (`prod admin`), and with none fob shows a fuzzy picker.

### 3. Use it

```sh
fob exec prod admin -- aws s3 ls        # one command with that profile's credentials
fob exec cf workers -- wrangler deploy  # a fresh Cloudflare token, scoped to Workers
fob console prod admin                  # the provider's web console, as that profile
fob status                              # what you are signed in to
```

To switch the shell itself, add the wrapper to your shell's startup file, which also enables tab completion of profile ids:

```sh
eval "$(fob activate bash)"   # or zsh; `fob activate fish | source` for fish
```

```sh
fob use prod admin    # export the credentials into this shell
fob unuse             # and remove them
```

[Using fob](docs/guides/usage.md) covers every command, how profiles are matched, and the AWS console.

## Migrating

| Coming from                              | Do this                                                                                            |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| granted, aws-vault, AWS CLI SSO profiles | `fob import aws --write`, then `fob login <name>`                                                  |
| `aws login`                              | `fob import aws --write` (it becomes an `aws-login` integration)                                   |
| Leapp, aws-sso-cli                       | An `aws-sso` entry with the portal's start URL and Region                                          |
| saml2aws, gimme-aws-creds, okta-aws-cli  | A `command` integration that runs the tool                                                         |
| `gcloud auth login`                      | `type = "gcp"`; gcloud and the client libraries pick up the token under `fob exec`                 |
| `az login`                               | `type = "azure"`; `DefaultAzureCredential` works under `fob exec`                                  |
| `wrangler login`                         | `type = "cloudflare-token"`, then `fob exec cf workers -- wrangler ...`                            |
| hcloud, doctl, vercel, fly, ...          | `type = "token"` with the preset; the token moves from the CLI's plain-text file into the keychain |

[Migrating from other tools](docs/guides/migrating.md) walks through each, with the matching commands (`assume` → `fob use`, `aws-vault exec` → `fob exec`, `assume -c` → `fob console`, ...).

## Coding agents

Agents run each command in a fresh shell with no one at the terminal, and everything a command prints ends up in their context and transcripts. fob recognises them (Claude Code, Codex, Cursor, Gemini CLI, Copilot, OpenCode and others) and then:

- hands credentials to the command but never prints them: `fob exec acme/dev/ReadOnly -- aws s3 ls`;
- never prompts and takes only full profile ids, so a command does exactly what it says and permission rules can match it;
- gives agents only the profiles you allow, optionally with shorter lifetimes and Cloudflare tokens revoked when the command ends;
- marks their sessions at the provider (`omnifob-agent` in CloudTrail and in Cloudflare token names);
- ends every failure with a `fob-error:` JSON line carrying a stable code (`login_required`, `mfa_required`, ...) and the command to run.

```toml
[agent]
profiles = ["acme/dev/*", "*/*/ReadOnly"]   # what agents may use
max_ttl = "15m"                             # and for how long
```

Install the skill that teaches agents all this with `npx skills add garysassano/omnifob`. [Coding agents](docs/guides/agents.md) has the details, the error codes and the audit log.

## Documentation

- Guides: [configuration](docs/guides/configuration.md), [using fob](docs/guides/usage.md), [migrating](docs/guides/migrating.md), [coding agents](docs/guides/agents.md), [other tools](docs/guides/other-tools.md) (`~/.aws/config` profiles, fnox, SDKs, Kubernetes), [browsers](docs/guides/browsers.md), [where secrets live](docs/guides/secrets.md), [Cloudflare](docs/guides/cloudflare.md), [AWS roles in another partition](docs/guides/aws-cross-partition.md).
- [docs/](docs/README.md) also has the design notes and the research behind omnifob, including the other tools in its space.
