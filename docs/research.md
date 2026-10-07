# Research

Tools studied on 2026-10-06, with what omnifob takes from each.
Each was read from a shallow clone of its repository.

## AWS

### granted (fwdcloudsec/granted, Go)

- Still maintained after Common Fate: five maintainers in `MAINTAINERS.md`, about 16 PRs merged after v0.39.0, but no release since March 2026 and no darwin binaries because the Apple signing certificate left with Common Fate (issue #936).
- Design: an `Assumer` interface per profile type (SSO, IAM, credential process, SAML helpers) with `AssumeTerminal` and `AssumeConsole`. Profiles come from `~/.aws/config`.
- SSO tokens are stored per start URL in the keychain (`99designs/keyring`). Device code flow by default, PKCE opt-in, device flow forced on headless machines.
- A shell wrapper (`assume`) exports into the current shell; `credential_process` mode for SDKs.
- **Taken:** terminal and console as the two outputs of every profile; the shell wrapper; device flow by default.

### aws-vault (ByteNess/aws-vault fork, Go)

- `SSORoleCredentialsProvider`: OIDC token cache keyed by start URL; with `sso:account:access` scope Identity Center returns a refresh token.
- Refreshes 15 minutes before expiry (matching the AWS CLI). A refresh token is single use, so on a failed refresh it re-reads the cache before deleting anything, in case another process refreshed first.
- A 401 from GetRoleCredentials drops the cached token and retries once.
- `exec`, `export`, `login` (console) and a local ECS/EC2 metadata server.
- **Taken:** the refresh window, the default scope, 401 handling.

### Leapp (Noovolari/leapp, TypeScript)

- _Integrations_ (an AWS SSO portal, Azure) produce _sessions_; `syncSessions` lists accounts and roles and creates a session for each.
- Session types cover AWS IAM user, chained role, federated, SSO role, Azure, with Google and Alibaba enum values that never matured.
- Throttles `ListAccountRoles` because Identity Center rate-limits it.
- **Taken:** the integration → discovered profiles model, the vocabulary, throttled discovery.

### aws-sso-cli (synfinatic/aws-sso-cli, Go, active)

- The most complete Identity Center experience: auto-discovery, tags, fuzzy selection, multiple console sessions, generates `~/.aws/config`, ECS server.
- **To take later:** tags and fuzzy selection on account metadata, generating `~/.aws/config` profiles that call `fob creds`.

### Others

- saml2aws (Versent), gimme-aws-creds (Nike): SAML and Okta into AWS. Relevant if omnifob ever supports SAML identity providers.
- awsume: Python, plugin-based role assumption.

## Multi-provider

### fnox (jdx/fnox, Rust, very active)

- Secrets from many providers plus _leases_: `aws-sts`, `gcp-iam`, `azure-token`, `cloudflare`, `github-app`, `vault`, `command`.
- The Cloudflare lease already mints child tokens (user or account owned, policies, expiry, revocation), but needs permission group IDs in config, and by default inherits the parent token's policies.
- AWS needs an existing sign-in (`aws sso login`); no discovery, switching or console.
- Lease ledger caches credentials until five minutes before expiry.
- `command` lease contract: stdout JSON `{"credentials": {...}, "expires_at": "...", "lease_id": "..."}`.
- **Taken:** the five-minute margin; the integration point (`fob creds --format fnox`).

### 1Password shell-plugins (Go)

- 86 plugins, each describing a CLI's credential schema and how to provision it (env vars, files). Includes aws, digitalocean, flyctl, vercel; no Cloudflare.
- **To take later:** the idea of per-tool provisioners for long-lived tokens (a generic `token` integration).

### teller, envchain

- Static secrets into the environment. teller (Rust) is quiet since early 2026; envchain since 2024.

## Cloudflare

See [providers/cloudflare.md](providers/cloudflare.md).

## Google Cloud, Azure and other providers

Studied on 2026-10-06 with about twenty other provider CLIs; see [landscape.md](landscape.md).

## Second round (2026-10-07)

The 15 tools marked "to study" in [tools/](tools/README.md), read for the specific points listed there, plus a second look at aws-sso-cli.

### AWS Identity Center tools

- **aws-sso-util** (`61418/aws-sso-util`): `run-as --account-id ... --role-name ...` runs a command without knowing any profile name; account IDs are stable and can be shared with colleagues, account names cannot. `check` diagnoses the Identity Center configuration and whether you can reach an account and role, with a quiet mode for scripts. Generated profile names are built from configurable components; whitespace in account names becomes `-` because SDKs parse such names inconsistently (omnifob's slugs already avoid that).
- **aws-sso-cli** (second look): a _History_ of recently used roles (`HistoryLimit`, `HistoryMinutes`) shown first in the picker; per-account and per-role tags; console URLs can be opened, printed, copied, sent with OSC 52 (copies to the local clipboard over SSH), or opened in a **Firefox container** per role (granted's extension or "Open URL in Container"), so several accounts' consoles stay signed in side by side, colour-coded.
- **aws-cli-auth**: deliberately does not store the Identity Center refresh token and is meant for `credential_process`; less risk if the machine is compromised, at the cost of more sign-ins.
- **aws-sso-creds**: a terminal UI that generates profiles into `~/.aws/config` and browses them with a fuzzy finder; nothing omnifob lacks.
- **yawsso**: copies an Identity Center session into `~/.aws/credentials` for tools that predate SSO and `credential_process`.
- **aws-mfa**: the reference for MFA sessions from long-term IAM keys (GetSessionToken with a TOTP code); relevant to chained roles with `mfa_serial`, which `fob import aws` skips today.

### Federation through an identity provider

- **saml2aws**: about 20 identity providers (Okta, Entra ID, ADFS, Keycloak, Ping, Shibboleth...), including a generic _browser_ provider that captures the SAML response from a real browser. Many organisations sign in to AWS through SAML without Identity Center; omnifob cannot serve them yet.
- **okta-aws-cli**: Okta's own tool pairs an Okta OIDC native app with the AWS federation app, signs in with the **device flow** (it can also print a **QR code** to finish on a phone), then calls `AssumeRoleWithSAML`; with the `okta.users.read.self` grant it discovers which AWS environments the user is assigned. A native Okta integration is feasible, but needs an Okta admin to set up the apps.
- **gimme-aws-creds**: also recommends Okta's device flow, and reuses the same SAML sign-in for **Alibaba Cloud** RAM credentials: one sign-in, two clouds.
- **aws-azure-login**: drives a hidden Chrome (Puppeteer) through Entra ID's login. Brittle and heavy; a pattern to avoid.
- **clisso**: providers for Okta and OneLogin behind one CLI, with YubiKey support; a small version of the same idea.

### Extensibility and multi-tool patterns

- **awsume**: a plugin system (pluggy hooks) for collecting profiles and fetching credentials. A lighter equivalent for omnifob: a `command` integration, where any program that prints credentials as JSON becomes a profile, covering saml2aws, gimme-aws-creds and in-house scripts without in-process plugins.
- **secretenv**: a "three-file model": the repository commits only alias names, and each machine maps aliases to real backends. For omnifob this solves naming a profile from a project, since profile ids contain each person's own integration names.
- **gh**: several accounts per host with `gh auth switch`; `gh auth token` for other tools; acts as git's credential helper.
- **Azure Developer CLI**: can hand sign-in to `az` (`auth.useAzCliAuth`) instead of duplicating it; supports letting official CLIs own sign-in for Azure and Google.
- **kubelogin (int128)**: a kubectl exec plugin with a choice of token cache (disk, keyring or none); the model for an omnifob kubectl plugin.
