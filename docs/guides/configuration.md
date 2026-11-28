# Configuration

Everything fob needs is in one TOML file: `~/.config/omnifob/config.toml`, or `$OMNIFOB_CONFIG`, or `--config <path>` on any command (which has to name an existing file, except for `fob import aws --write`).

Most setups need only a few lines per sign-in: the [quick start](../../README.md#quick-start) shows the smallest working entry for each provider. This page is the full reference; every key beyond the first lines of each example is optional.

- [The file](#the-file): names, checks and the JSON Schema
- Integrations: [AWS IAM Identity Center](#aws-iam-identity-center-aws-sso), [IAM user](#aws-iam-user-aws-iam), [console sign-in](#aws-console-sign-in-aws-login), [Google Cloud](#google-cloud-gcp), [Azure](#azure-azure), [Cloudflare](#cloudflare), [token-only providers](#token-only-providers-token), [any program](#any-program-command)
- [Default profiles per directory](#default-profiles-per-directory)
- [Environments and access levels](#environments-and-access-levels)
- Elsewhere: [`[browsers]`](browsers.md), [`[agent]` and `[audit]`](agents.md)

## The file

The config is a set of _integrations_, one per sign-in, each with a `type`:

```toml
[integrations.acme]   # the integration's name, the first part of its profile ids
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"
```

Integration names may contain only letters, digits, `.`, `_` and `-`, and may not start with `-`. A config with another name is refused with a pointer to `fob rename "<old name>" <new-name>`, which still works on it.

Every key is checked when the config loads, and an error names the key: Regions, account IDs, role ARNs and their partitions, session names and lengths, `https://` start URLs, service account emails, Cloudflare template names, IP ranges and lifetimes (more than five minutes, when omnifob would mint the token again), token presets and variable names, and configured roles whose labels would give two profiles one id.

The config has a JSON Schema, [schema/config.schema.json](../../schema/config.schema.json), for completion and checks in editors and [taplo](https://taplo.tamasfe.dev). Name it on the first line of the config:

```toml
#:schema https://raw.githubusercontent.com/garysassano/omnifob/main/schema/config.schema.json
```

Then `taplo check ~/.config/omnifob/config.toml` checks the file, and editors with the Even Better TOML extension (which uses taplo) complete keys and show their descriptions. The schema knows the keys and their types; the checks above that need more than that (partitions, clashing ids) still run when omnifob loads the config.

Two commands write integrations for you: `fob import aws --write` (see [Migrating](migrating.md#granted-aws-vault-and-the-aws-cli)) and `fob discover aws --write` (below). `fob cf add-template` writes Cloudflare templates.

## AWS IAM Identity Center (`aws-sso`)

```toml
[integrations.acme]
type = "aws-sso"
start_url = "https://acme.awsapps.com/start"
region = "eu-central-1"          # where IAM Identity Center runs
default_region = "eu-central-1"  # optional: exported as AWS_REGION
console_duration = "4h"          # optional: `fob console` session length, 15m to 12h; must fit the
                                 # permission set's session duration, 1h unless an administrator raised it
```

`fob login acme` discovers every account and role the portal gives you. Profile ids are `acme/<account>/<permission set>`.

### Chained roles

Roles assumed from an Identity Center role, as `role_arn` + `source_profile` do in `~/.aws/config`. AWS limits these sessions to one hour.

```toml
# Profile id: acme/prod-deploy/Deploy.
[integrations.acme.chained.prod-deploy]
via_account_id = "111111111111"
via_role = "AdministratorAccess"
role_arn = "arn:aws:iam::222222222222:role/Deploy"
session_name = "me"          # optional, like role_session_name
external_id = "..."          # optional
region = "us-east-1"         # optional, defaults to the integration's
mfa_serial = "arn:aws:iam::111111111111:mfa/me"  # optional: asks for a code per session
duration = "30m"             # optional, 15m to 1h
```

When the same role name is chained from one permission set in every account that has it, write one rule instead of a `chained` table per account; accounts added later are covered too:

```toml
# Profile id: acme/<account>/admin-root, next to that account's Identity Center roles.
[integrations.acme.chained_rules.root]
via_role = "PowerUserAccess"     # the permission set to start from
role_name = "admin-root"         # assumed as arn:aws:iam::<account>:role/admin-root
path = "/ops/"                   # optional IAM path, "/" by default
accounts = ["111111111111"]      # optional: only these accounts
exclude_accounts = []            # optional: leave these out
# session_name, external_id, region, mfa_serial and duration as for chained roles
```

### Finding roles to chain

Roles that no file names and Identity Center does not list, such as an administrator role each account's power-user role may assume, can be found: `fob discover aws <integration> [--via <permission set>]`.

- It lists each account's IAM roles with that permission set's credentials, keeps those, in its account or another account of the integration, whose trust policy lets the account or the permission set's role assume them, and asks the IAM policy simulator whether the permission set may.
- It prints what is not configured yet, a role found in several accounts as one `chained_rules` rule, and `--write` appends it; `--json` prints what was found, skipped and left out instead.
- CDK bootstrap roles, which the CDK CLI assumes for itself, are left out unless `--all` is given.
- It also searches an `aws-iam` integration's IAM user and an `aws-login` integration's console identity, in their own account, and writes what it finds as `roles` tables.
- It needs `iam:ListRoles` and `iam:SimulatePrincipalPolicy`. When the simulator is refused, as it is for `ReadOnlyAccess` and `SecurityAudit`, it reads the source's own policies instead and marks the result as an estimate; when those cannot be read either, `--trust-only` lists the roles whose trust policy lets the source in, unchecked and never written.

It assumes nothing (so no `AssumeRole` reaches CloudTrail), and is a guess: resource control policies, and trust-policy conditions other than those on the permission set's own ARN, account and type, are not checked, and it says which conditions a role needs (an external ID, MFA, a tag).

### Roles in another partition

A role in GovCloud, China or the European Sovereign Cloud, reached from an Identity Center role with a web identity token. The setup in both accounts is in [AWS roles in another partition](aws-cross-partition.md). The token request is tried live; the exchange in the other partition is not yet.

```toml
# Profile id: acme/gov-audit/Audit.
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
```

### More Regions of one instance

An additional Region of a multi-Region Identity Center instance is a second integration with that Region's portal URL (no `/start`), signed in on its own, since CLI sign-ins are not replicated across Regions:

```toml
[integrations.acme-eu]
type = "aws-sso"
start_url = "https://ssoins-1111111111111111.eu-west-1.portal.amazonaws.com"
region = "eu-west-1"
```

## AWS IAM user (`aws-iam`)

An IAM user's access key, kept in the keychain like aws-vault keeps it; `fob login legacy` asks for it. The key is never handed out: profiles get a session from STS GetSessionToken (one MFA code per session), and roles assumed with that session.

```toml
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
```

## AWS console sign-in (`aws-login`)

Console credentials, as `aws login` gets them: the browser picks a console session (an IAM user, root or a federated role), and no access key is stored. Profile id: `console/<account ID>/<user, root or role name>`.

```toml
[integrations.console]
type = "aws-login"
region = "eu-central-1"        # the Region signed in through; also AWS_REGION
default_region = "eu-west-1"   # optional: AWS_REGION instead of region

[integrations.console.roles.audit]  # profile id: console/audit/Audit, assumed with the
role_arn = "arn:aws:iam::333333333333:role/Audit"   # console credentials: role chaining,
duration = "1h"                # so 15m to 1h (default 1h)
```

## Google Cloud (`gcp`)

A Google account, signed in like `gcloud auth login` (with gcloud's OAuth client). Profile ids: `google/<project>/user`, and `google/<label>/<name>` per service account.

```toml
[integrations.google]
type = "gcp"
projects = ["my-proj"]         # optional: skip listing every project

[integrations.google.service_accounts.deploy]   # profile id: google/deploy/deploy
email = "deploy@my-proj.iam.gserviceaccount.com" # needs Service Account Token Creator for you
lifetime = "1h"                # optional, 15m to 12h (over 1h needs an org policy)
```

`client_id` and `client_secret` (both or neither) use an OAuth client of your own, a Desktop app client, instead of gcloud's.

## Azure (`azure`)

An Entra ID account, signed in like `az login`. Profile ids: `work/<subscription>/user`.

```toml
[integrations.work]
type = "azure"
tenant = "contoso.onmicrosoft.com"   # optional: by default every tenant you belong to
subscriptions = ["..."]              # optional: by default every subscription you can see
```

## Cloudflare

Two types sign in differently and work the same afterwards: `cloudflare-oauth` signs in in the browser like `wrangler login`, and `cloudflare-token` uses a bootstrap token you create once. Registering the OAuth client, and creating a bootstrap token instead, account-owned or user-owned, are explained in the [Cloudflare guide](cloudflare.md).

```toml
[integrations.cf]
type = "cloudflare-oauth"       # browser sign-in, like `wrangler login`
client_id = "..."               # your OAuth client; see the Cloudflare guide
session = "12h"                 # optional: sign in again after this long
ttl = "1h"                      # optional: lifetime of minted tokens (default 1h)

[integrations.cf-token]
type = "cloudflare-token"       # a bootstrap token instead of the browser
token_type = "account"          # optional: bootstrap owned by the account; "user" (default) for a user-owned one
account_id = "0123456789abcdef0123456789abcdef"  # required for token_type = "account"
account_name = "personal"       # optional: the account's segment of profile ids
ips = ["current"]               # optional: tokens only work from this machine's public addresses

# Templates name permissions as the dashboard does; never IDs.
# `fob cf add-template` writes them for you.
[integrations.cf-token.templates.pages]
permissions = ["Pages Write", "Account Settings Read"]
ttl = "30m"
```

If you know IAM Identity Center through granted, the Cloudflare integrations work the same way: the browser sign-in or bootstrap token plays the part of the sign-in, templates the part of permission sets, and each `account × template` profile the part of an `account × role`; `fob exec` mints a short-lived token the way granted fetches role credentials. Unlike permission sets, templates live in your config, not in Cloudflare; built-in ones (`workers`, `dns-read`, `dns-edit`, `read`) are there from the start. A browser sign-in can only mint the permissions you approved on the consent page; a bootstrap token can mint any permission, so treat it like an administrator credential.

## Token-only providers (`token`)

Providers that only have long-lived tokens use `type = "token"`, usually with a preset. Presets: `hetzner`, `digitalocean`, `vultr`, `linode` (Akamai Cloud), `upstash`, `akamai-edgegrid`, `scaleway`, `modal`, `unikraft`, `vercel`, `netlify`, `fly`, `neon`, `supabase`, `github`; [docs/providers](../providers/README.md) lists the variables each sets.

```toml
[integrations.hetzner-prod]
type = "token"
preset = "hetzner"          # HCLOUD_TOKEN, checked against the Hetzner API at login
account = "prod"            # optional: profile id hetzner-prod/prod/hetzner

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

`fob login <name>` asks for each secret. An integration with a single secret also takes it from the clipboard (`--from-clipboard`, which refuses an empty clipboard, text with whitespace and URLs) or from stdin (`--token-stdin`).

`fob login` and `fob check` check the token with the provider where it has a call for that: a bearer token for most presets, Scaleway's secret key in `X-Auth-Token` (looking up its own access key, as `scw init` does), and Upstash's API key with `UPSTASH_EMAIL` as HTTP Basic credentials.

- A token the provider refuses (401, or 403 where any valid token may make the call) is reported as rejected.
- For Scaleway, GitHub, Neon and DigitalOcean a 403 still proves the token, since their narrowly scoped tokens (a GitHub Actions or app token, a Neon organization key, a DigitalOcean token without `account:read`) may not read the URL checked.
- A provider that cannot be reached or answers 5xx is reported as not checked, so try again later.
- Fly.io tokens are not checked, since Fly.io has no call that every token, app-scoped deploy tokens included, may make.

## Any program (`command`)

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

- The program runs without a shell, so arguments need no quoting and nothing in them is expanded; it is a name on `PATH`, an absolute path or one under `~/`.
- It keeps the terminal's stdin and stderr, so it can prompt and report, gets `OMNIFOB_PROFILE` (but not `OMNIFOB_VAULT_PASSPHRASE`), and is stopped after `timeout`, or as soon as it prints more than 1 MiB.
- Its stdout is read as omnifob's JSON (`{"env": {"NAME": "value"}, "expires_at": "<RFC 3339>"}`, as `fob creds` prints it; `expires_at` is optional) or, with `format = "credential-process"`, the AWS format, which makes an AWS profile.
- Credentials with an expiry are cached until five minutes before it; credentials without one are fetched for every use. omnifob never prints the program's output, not even when it cannot read it.
- Without `ttl`, the program chooses the lifetime and `--ttl` is refused; with it, `--ttl` and `[agent] max_ttl` change what is asked for.
- `fob login` has nothing to do for these integrations, and `fob check` runs the program once.

## Default profiles per directory

`[directories]` maps a directory to the profile `fob exec` and `fob use` pick in it, and below it, when you name none. The longest matching directory wins, and a named profile always beats it. The mapping lives in your own config, so repositories carry no integration names:

```toml
[directories]
"~/git/acme" = "acme/dev/ReadOnly"
"~/git/acme/billing" = "acme/prod-billing/ReadOnly"
"/srv/deploy" = "acme/prod/Deploy"
```

`fob exec -- terraform plan` in `~/git/acme/billing/infra` then runs with `acme/prod-billing/ReadOnly`. Commands run by a coding agent still name the profile in full (the error says which one the directory would pick), so what they use stays in the command.

## Environments and access levels

`fob list` shows each profile's environment and access level, in red for production, so you and your agents can tell a production admin role from a development read-only one. fob guesses them from the words of the id (`prd`, `staging`, `uat`, `dev`; `AdministratorAccess`, `PowerUserAccess`, `ReadOnly`, `Contributor`, `Reader`, and `root` when no other word says otherwise) and reads a Cloudflare template's permissions; a `?` marks a guess. `[[labels]]` states them, the first entry that matches and sets a label winning (`*` matches within one segment of the id):

```toml
[[labels]]
profiles = ["acme/*-prd/*", "acme/prod/*"]
env = "prod"

[[labels]]
profiles = ["acme/*/acme-pe"]
access = "write"
```

`fob list --json` gives `env`, `access` and where each came from (`env_source` and `access_source`: `config`, `permissions` or `name`); [Using fob](usage.md#listing-profiles) has the rest of its fields.
