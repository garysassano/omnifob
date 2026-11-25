# Research

Tools studied on 2026-10-06, with what omnifob takes from each.
Each was read from a shallow clone of its repository.

## AWS

### granted (fwdcloudsec/granted, Go)

- Still maintained after Common Fate: five maintainers in `MAINTAINERS.md`. v0.39.0 (March 2026) shipped no darwin binaries because the Apple signing certificate left with Common Fate (issue #936); v0.40.0 (2026-10-20) ships them again.
- Second look at v0.40.0 (2026-11-08): PKCE is opt-in (device flow by default, forced on SSH, containers and CI). The SSO token is refreshed only after it has expired, a failed refresh falls back to a full browser sign-in, and a refresh response without a refresh token stores none, ending silent renewal. Tokens are stored under start URL plus `sso_session` name but cleared on a 401 under the start URL alone, so the clear misses with `sso-session` profiles. Tokens from `~/.aws/sso/cache` overwrite the keychain token, refresh token included. `GetRoleCredentials` is retried on 403 for fresh assignments (opt-in). Console sign-in handles the GovCloud, China and European Sovereign Cloud partitions through regional sign-in hosts.
- Design: an `Assumer` interface per profile type (SSO, IAM, credential process, SAML helpers) with `AssumeTerminal` and `AssumeConsole`. Profiles come from `~/.aws/config`.
- SSO tokens are stored per start URL in the keychain (`99designs/keyring`). Device code flow by default, PKCE opt-in, device flow forced on headless machines.
- A shell wrapper (`assume`) exports into the current shell; `credential_process` mode for SDKs.
- Browsers (read 2026-11-16): one console browser and optionally a separate SSO sign-in browser, both global (`DefaultBrowser`, `CustomBrowserPath`, `CustomSSOBrowserPath`), or Go-template launch commands (`AWSConsoleBrowserLaunchTemplate`, `SSOBrowserLaunchTemplate`, with `{{.URL}}` and `{{.Profile}}`) split on whitespace and quotes. Chromium-based browsers get a profile per AWS profile, found by name in the browser's `Local State` file, which granted also rewrites to rename the profile; Firefox opens a container per profile through granted's extension. Nothing ties a browser to a start URL.
- **Taken:** terminal and console as the two outputs of every profile; the shell wrapper; the device flow on its own over SSH and in containers; launch commands with a URL placeholder, as a list of arguments and per integration rather than global; a Chromium profile or Granted Containers Firefox container per AWS profile's console (`isolate`, 2026-11-21). Its device flow by default was taken at first and reversed on 2026-11-08: omnifob signs in with PKCE by default, as the AWS CLI does (see [decisions](decisions.md)).

### AWS CLI v2 (aws/aws-cli, Python; read 2026-11-08)

- `aws sso login` uses the authorization code flow with PKCE by default since 2.22.0; `--use-device-code` falls back to the device flow. There is no automatic headless detection.
- Registration: `clientName` `botocore-client-<session>`, type `public`, grant types `authorization_code` and `refresh_token`, redirect `http://127.0.0.1/oauth/callback` without a port, `issuerUrl` the start URL, scopes default `sso:account:access`. The callback listens on a free port on `127.0.0.1`.
- The consent URL is the OIDC endpoint the SDK resolves for the region plus `/authorize`, with `response_type`, `client_id`, `redirect_uri`, `state`, `code_challenge_method=S256`, `scopes` (space-separated, `%20`) and `code_challenge`.
- Registrations are cached apart from tokens, keyed by start URL, session name and scopes, and reused until they expire (90 days); `aws sso logout` removes tokens and calls the portal's `Logout`.
- Tokens are refreshed 15 minutes before expiry.
- The consent URL's base is the endpoint the OIDC client resolves (`_get_base_authorization_uri` in `awscli/botocore/utils.py`, read 2026-11-18), so a configured endpoint such as `AWS_ENDPOINT_URL_SSO_OIDC` moves the consent page too; `RegisterClient`'s `authorizationEndpoint` is not used.
- **Taken:** PKCE by default with the device flow as fallback, the portless registration, `scopes`, the separate registration cache, `Logout` on sign-out.

### AWS CLI v2 `aws login` (aws/aws-cli, Python; read 2026-11-18)

- `awscli/customizations/login/`: OAuth authorization code with PKCE against AWS Sign-In, with the public clients `arn:aws:signin:::devtools/same-device` (loopback redirect `http://127.0.0.1:<port>/oauth/callback`) and `arn:aws:signin:::devtools/cross-device` (`--remote`: redirect `<endpoint>/v1/sessions/confirmation`, and the user pastes base64 of `state=…&code=…`).
- Consent page `<endpoint>/v1/authorize` with `response_type=code`, `client_id`, `state`, `code_challenge_method=SHA-256`, `scope=openid`, `redirect_uri`, `code_challenge`; the endpoint is the one the `signin` client resolves.
- `CreateOAuth2Token` (unsigned, `tokenInput`) with a DPoP header: an ES256 JWT, `typ` `dpop+jwt`, the P-256 public key as `jwk`, claims `htm` `POST`, `htu` the request URL, `iat`, `jti`. A new key per sign-in, stored in the cache as SEC1 PEM.
- The cache, `~/.aws/login/cache/<sha256 of the session ARN>.json`, holds the credentials, refresh token, client ID, ID token, DPoP key and the sign-in Region (`signInRegion`), which renewal uses. The profile gets `login_session = <ARN>`, the ID token's `sub`.
- Renewal five minutes before expiry with the `refresh_token` grant; `TOKEN_EXPIRED`, `USER_CREDENTIALS_CHANGED` and `INSUFFICIENT_PERMISSIONS` are named, `AUTHCODE_EXPIRED` at sign-in. `aws logout` only deletes the cache.
- **Taken:** the clients, parameters, DPoP proof, renewal window and error handling. **Not taken:** the file cache (the keychain instead).

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

- **aws-sso-util** (`61418/aws-sso-util`): `run-as --account-id ... --role-name ...` runs a command without knowing any profile name; account IDs are stable and can be shared with colleagues, account names cannot. `check` diagnoses the Identity Center configuration and whether you can reach an account and role, with a quiet mode for scripts. Generated profile names are built from configurable components; whitespace in account names becomes `-` because SDKs parse such names inconsistently (omnifob's slugs already avoid that). **Taken:** `--account-id` and `--role` on `fob exec`, `env`, `creds` and `console`.
- **aws-sso-cli** (second look): a _History_ of recently used roles (`HistoryLimit`, `HistoryMinutes`) shown first in the picker; per-account and per-role tags; console URLs can be opened, printed, copied, sent with OSC 52 (copies to the local clipboard over SSH), or opened in a **Firefox container** per role (granted's extension or "Open URL in Container"), so several accounts' consoles stay signed in side by side, colour-coded. **Taken:** colour and icon per profile pattern for granted's extension (`[[browsers.<name>.containers]]`); its parser (`src/opener/parser.ts`, read 2026-11-25) reads `name`, `url`, `color` and `icon` and silently drops a colour or icon outside Firefox's lists, so omnifob checks them when the config loads.
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

## Cloudflare token tools (2026-10-07)

- **create-cf-token**: an interactive picker over the permission catalogue, grouped by service (the name without Read, Write or Edit), with Read or Write per service and live fuzzy filtering; write also adds read. When Cloudflare rejects a permission it parses the name from the error, leaves it out and retries, and it always leaves out token-management permissions, which child tokens cannot carry. It can revoke the token it just made before exiting. **Taken:** the service-grouped picker (`fob cf add-template`) and revoking a token as soon as it is no longer needed (`fob exec --revoke`).
- **cftoken**: scoped tokens per zone, with requester IP ranges (`allow-cidrs`, required unless the config sets defaults), TTL and per-zone permission templates in one JSON config. **Taken:** IP restrictions (`ips`, with `"current"`), and zone-limited templates (`zones`, by name or ID).
- **terraform-cloudflare-r2-api-token**: tokens limited to named R2 buckets, read or write. **Taken:** bucket-limited templates (`r2_buckets`), and the S3 credentials R2 derives from a token (the token ID as access key, the SHA-256 of the token as secret).

## Provisioners and agent markers (2026-11-25)

Contracts read before `fob exec` started serving credentials and `fob creds` learned the Kubernetes and Google formats; the provider notes have the details.

- **AWS container credentials** (SDKs and Tools Reference Guide): `AWS_CONTAINER_CREDENTIALS_FULL_URI` plus `AWS_CONTAINER_AUTHORIZATION_TOKEN` (or `_FILE`, which wins), loopback only over HTTP, supported by every SDK and the CLI. aws-vault's `exec --server` (ECS-style, with a token) and `--ec2-server` (metadata emulation on `169.254.169.254`, needing root and sending no secret) and aws-sso-cli's ECS server use it. **Taken:** the ECS-style endpoint on `127.0.0.1` with a random token, per command. **Not taken:** the EC2 emulation, and a standalone `fob server`: a container on another network cannot reach the host's loopback, and the SDKs refuse a non-loopback HTTP endpoint, so `fob exec --server -- <command>` covers what the server would.
- **Azure managed identity** (App Service's endpoint; MSAL and Azure Identity choose it from `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`): `GET ?resource&api-version=2019-08-01` with `X-IDENTITY-HEADER`. The Azure CLI's refresh token is valid for any resource its client is pre-authorized for, as `az account get-access-token --resource` shows. **Taken:** the endpoint during `fob exec`, minting per resource. Terraform's `azurerm` (`use_msi`) and `az` (`az login --identity`) were not checked to use it.
- **Azure agent sessions**: the Azure CLI forwards `COPILOT_AGENT_SESSION_ID` as `client_session` (and with the broker as an `xms_cli_sid` claims challenge). **Taken**, as the non-broker path sends it.
- **Google**: gcloud reads `CLOUDSDK_AUTH_ACCESS_TOKEN` first and `auth/access_token_file` on every run. Executable-sourced credentials federate an OIDC or SAML token through STS and cannot carry an access token; `external_account_authorized_user` refreshes at any `token_url`. **Taken:** an `external_account_authorized_user` ADC file pointing at a loopback endpoint during `fob exec`, the account's ID token for executable-sourced credentials, and a kept-fresh token file for gcloud.
- **Kubernetes** (`client.authentication.k8s.io/v1` and `v1beta1` `ExecCredential`, kubectl passing `KUBERNETES_EXEC_INFO`): kubelogin (int128 and Azure) and aws-iam-authenticator. aws-iam-authenticator presigns `GetCallerIdentity` for 60 seconds with `x-k8s-aws-id` signed and reports 14 minutes; Azure's kubelogin asks for the AKS server application `6dae42f8-4368-4678-94ff-3960e28e3630`; `gke-gcloud-auth-plugin` returns the account's access token. **Taken:** all three, answering in the version kubectl asks for, without a token cache of fob's own (kubectl keeps the credential until its expiry).
- **Agent markers**, from each agent's source or documentation: Claude Code (`CLAUDECODE`, `AI_AGENT`, seen in its commands), Codex (`CODEX_SANDBOX`, `CODEX_THREAD_ID` in `codex-rs/protocol/src/shell_environment.rs`), Gemini CLI (`GEMINI_CLI=1`), Qwen Code (`QWEN_CODE=1`), Crush (`CRUSH=1`, `AI_AGENT=crush`), Cline (`CLINE_ACTIVE=true` in the terminals it opens), GitHub Copilot CLI (`COPILOT_CLI=1`, changelog), OpenCode (`OPENCODE=1`, `AI_AGENT=opencode`, merged in anomalyco/opencode#51975), Goose (`GOOSE_TERMINAL=1`, restored in aaif-goose/goose#13598), Pi (`PI_CODING_AGENT=true`, `AI_AGENT=pi`, its `docs/environment-variables.md`) and Antigravity (`ANTIGRAVITY_AGENT=1`, in its `agy` binary). `AI_AGENT` is the cross-agent marker proposed in agentsmd/agents.md#136. Aider has none yet (Aider-AI/aider#5521 is open), and no documented marker was found for Windsurf, Amp or Kiro, so they need `OMNIFOB_AGENT=1`. `CLAUDECODE` is also set in Claude Code's IDE terminals, a known false positive.
- **AWS session tags** for agents (`omnifob:agent=true`) were not taken: `AssumeRole` with tags needs `sts:TagSession` in the role's trust policy, and a trust policy without it would refuse every agent's session. The session name needs nothing.
