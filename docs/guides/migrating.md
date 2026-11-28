# Migrating from other tools

fob replaces the sign-in part of other tools, not the tools themselves: you keep using `aws`, `gcloud`, `wrangler`, Terraform and the rest, and fob hands them credentials. Every CLI lets an environment variable win over its own sign-in (`AWS_ACCESS_KEY_ID`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `HCLOUD_TOKEN`), so `fob exec` and `fob use` work without changing any tool's configuration.

- [granted, aws-vault and the AWS CLI](#granted-aws-vault-and-the-aws-cli)
- [Leapp and aws-sso-cli](#leapp-and-aws-sso-cli)
- [saml2aws, gimme-aws-creds, okta-aws-cli](#saml2aws-gimme-aws-creds-okta-aws-cli)
- [gcloud](#gcloud)
- [az](#az)
- [wrangler](#wrangler)
- [Token-only CLIs: hcloud, doctl, vercel, fly and the rest](#token-only-clis-hcloud-doctl-vercel-fly-and-the-rest)
- [direnv and per-project `AWS_PROFILE`](#direnv-and-per-project-aws_profile)

## granted, aws-vault and the AWS CLI

One command reads your `~/.aws/config` and writes the matching integrations:

```sh
fob import aws            # print what it would add
fob import aws --write    # append it to ~/.config/omnifob/config.toml (created if missing)
fob login acme            # sign in once per portal; every account and role is discovered
fob list                  # acme/prod/AdministratorAccess, acme/dev/ReadOnly, ...
```

What it reads:

- **IAM Identity Center portals**: standard `sso_*` keys, `sso-session` sections with their `sso_registration_scopes`, and granted's `granted_sso_*` keys. One integration per portal, however many profiles used it, since fob discovers every account and role itself.
- **Chained roles** (`role_arn` + `source_profile`), with session name, external ID, region, `mfa_serial` and `duration_seconds`. A role that several accounts assume from their own permission set becomes one `chained_rules` rule.
- **IAM user access keys** (aws-vault, or `~/.aws/credentials`): roles assumed from such a profile become an `aws-iam` integration with those roles. The key itself is never read, so run `fob login <name>` to store it in fob's keychain; afterwards `aws-vault remove <profile>` or deleting it from `~/.aws/credentials` leaves one copy.
- **`aws login` profiles** (`login_session`) become an `aws-login` integration; `fob login <name>` signs in again, since the AWS CLI's cached tokens are not read.

Profiles it cannot import (a role assumed from another assumed role, a `credential_process` source, a `duration_seconds` AWS would refuse, a role ARN or Region the config would refuse) are listed with the reason. Roles your permission sets may assume that no file names can be found with [`fob discover aws`](configuration.md#finding-roles-to-chain).

### Commands

| Before                                                         | With fob                               |
| -------------------------------------------------------------- | -------------------------------------- |
| `aws sso login`, `granted sso login`                           | `fob login acme`                       |
| `assume prod-admin`, `export AWS_PROFILE=prod-admin`           | `fob use prod admin`                   |
| `assume prod-admin --exec "cmd"`, `aws-vault exec prod -- cmd` | `fob exec prod admin -- cmd`           |
| `assume -c prod-admin`, `aws-vault login prod`                 | `fob console prod admin`               |
| `assume -c prod-admin -s ec2`                                  | `fob console prod admin --service ec2` |
| `assume --unset`                                               | `fob unuse`                            |
| `aws-vault exec --ecs-server prod -- cmd`                      | `fob exec prod admin --server -- cmd`  |
| `aws sts get-caller-identity --profile prod`                   | `fob check prod admin`                 |

`fob use` needs the shell wrapper (`eval "$(fob activate bash)"`, see [Using fob](usage.md#in-the-current-shell)), as granted's `assume` needs its alias.

### Keeping `--profile`

Tools that insist on a named profile (IDEs, GUI clients, scripts with `--profile`) keep working through `credential_process`:

```sh
fob export aws-config --write          # a marked block of [profile fob-acme-prod-ReadOnly] entries
aws s3 ls --profile fob-acme-prod-ReadOnly
```

Once those work, the old `sso_*` profiles can go; [Other tools](other-tools.md#aws-profiles-in-awsconfig) has the details.

### Firefox containers

granted's container add-on works as before: give the integration a Firefox (or Zen, LibreWolf, Waterfox, Floorp) browser, and each profile's console opens in its own container. See [Browsers](browsers.md).

```toml
[browsers.firefox]
type = "firefox"

[integrations.acme]
# ...
browser = "firefox"
```

## Leapp and aws-sso-cli

Their configs are not imported. Copy each portal's start URL and Region into an `aws-sso` integration, then `fob login`; every account and role is discovered, so nothing per account needs copying:

```toml
[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"
```

IAM user keys from Leapp go into an [`aws-iam`](configuration.md#aws-iam-user-aws-iam) integration.

## saml2aws, gimme-aws-creds, okta-aws-cli

Keep the tool and let fob run it: a [`command`](configuration.md#any-program-command) integration runs any program that prints AWS `credential_process` JSON (or fob's own JSON), caches the result until it expires, and makes it a profile like any other, with `fob exec`, `fob use` and `fob console`.

```toml
[integrations.okta]
type = "command"
command = ["okta-aws-cli", "web", "--format", "process-credentials"]
format = "credential-process"
```

## gcloud

```toml
[integrations.google]
type = "gcp"
```

`fob login google` signs in as `gcloud auth login` does, with gcloud's own OAuth client, and finds every active project. Then:

| Before                                     | With fob                                                                            |
| ------------------------------------------ | ----------------------------------------------------------------------------------- |
| `gcloud auth login`                        | `fob login google`                                                                  |
| `gcloud config set project my-proj`        | `fob use google/my-proj/user`                                                       |
| `gcloud auth application-default login`    | `fob exec google/my-proj/user -- <program>`                                         |
| `--impersonate-service-account deploy@...` | a [`service_accounts`](configuration.md#google-cloud-gcp) entry                     |
| `gcloud auth print-access-token`           | `fob exec google/my-proj/user -- <program>` gets it as `CLOUDSDK_AUTH_ACCESS_TOKEN` |

gcloud reads `CLOUDSDK_AUTH_ACCESS_TOKEN` and `CLOUDSDK_CORE_PROJECT` from the environment, and under `fob exec` the client libraries find Application Default Credentials that fob serves and renews. Nothing is written to `~/.config/gcloud`.

## az

```toml
[integrations.work]
type = "azure"
```

`fob login work` signs in as `az login` does, with az's own client, and finds every subscription in every tenant. A profile per subscription (`work/<subscription>/user`) exports `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `ARM_SUBSCRIPTION_ID`, `ARM_TENANT_ID` and a Resource Manager token, and under `fob exec` the Azure Identity libraries' `DefaultAzureCredential` gets tokens for any resource from a local managed identity endpoint. The `az` CLI itself keeps its own sign-in: it has no variable for a token. Azure support has not yet been tried on a live tenant.

## wrangler

`wrangler login` keeps one OAuth token with every permission wrangler asks for. fob mints a short-lived token per command instead, with only the permissions a template names; the built-in `workers` template covers what wrangler needs for Workers and their bindings.

The quickest start is a bootstrap token, created once in the dashboard (`fob login` opens the page):

```toml
[integrations.cf]
type = "cloudflare-token"
```

```sh
fob login cf                              # opens the dashboard; paste the bootstrap token
fob exec cf workers -- wrangler deploy    # CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID for this command
fob exec cf workers --revoke -- wrangler deploy   # a token deleted as soon as the command ends
wrangler logout                           # once fob works, drop wrangler's own long-lived sign-in
```

A browser sign-in like `wrangler login` (`type = "cloudflare-oauth"`) needs an OAuth client registered in your account once. The [Cloudflare guide](cloudflare.md) covers both, account-owned bootstrap tokens, sessions and your own templates (`fob cf add-template`).

Long-lived API tokens kept in `.env` files or CI-like shell profiles can go the same way: a template with the same permissions, and `fob exec` in front of the command.

## Token-only CLIs: hcloud, doctl, vercel, fly and the rest

These CLIs keep their tokens in plain-text files. fob keeps them in the OS keychain and hands them out under the variables the CLI reads, which win over its own config:

```toml
[integrations.hetzner]
type = "token"
preset = "hetzner"
```

```sh
fob login hetzner                 # paste the token (or --from-clipboard); checked with the provider
fob exec hetzner -- hcloud server list
```

Then remove the token from the CLI's own file (`hcloud context delete`, `doctl auth remove`, `vercel logout`, `fly auth logout`, ...). Presets exist for Hetzner, DigitalOcean, Vultr, Akamai, Upstash, Scaleway, Modal, Unikraft, Vercel, Netlify, Fly.io, Neon, Supabase and GitHub; [providers](../providers/README.md) lists the variables each sets, and [`token`](configuration.md#token-only-providers-token) covers any other provider.

## direnv and per-project `AWS_PROFILE`

An `.envrc` exporting `AWS_PROFILE` per project becomes a `[directories]` entry in your own config, so repositories carry no profile names:

```toml
[directories]
"~/git/acme" = "acme/dev/ReadOnly"
```

`fob exec -- terraform plan` anywhere under `~/git/acme` then uses that profile. See [Default profiles per directory](configuration.md#default-profiles-per-directory).
