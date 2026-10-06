# Research

Tools studied on 2026-10-06, with what omnifob takes from each.
Shallow clones were read in the session scratchpad; re-clone to look again.

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

- *Integrations* (an AWS SSO portal, Azure) produce *sessions*; `syncSessions` lists accounts and roles and creates a session for each.
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

- Secrets from many providers plus *leases*: `aws-sts`, `gcp-iam`, `azure-token`, `cloudflare`, `github-app`, `vault`, `command`.
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

## Google Cloud, Azure

Not studied yet. Plan: read the `gcloud` SDK source (installed by mise) for `auth login`, application default credentials and `--impersonate-service-account`; read azure-cli and MSAL for `az login` and subscriptions.
