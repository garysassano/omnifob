# Roadmap

## v0.1: AWS and Cloudflare, end to end

- [x] Workspace: `omnifob-core` + `omnifob` (binaries `fob` and `omnifob`).
- [x] Config file, XDG paths, profile cache.
- [x] Keychain storage with Linux fallback.
- [x] AWS Identity Center: device sign-in, refresh, discovery, role credentials, console URL.
- [x] Cloudflare: bootstrap token, templates by permission name, minting, cleanup, dashboard link.
- [x] Commands: login, logout, status, sync, list, env, exec, console, creds, activate, cf permissions, cf templates.
- [x] Fuzzy profile picker; automatic sign-in when a session is missing.
- [x] Live test AWS against a personal test Identity Center: login, sync, exec, env, use/unuse (bash, fish), creds (json, fnox, credential-process), console URL, silent refresh. See [log.md](log.md).
- [x] Test the 401 path (revoked token → sign in again) on a copied session.
- [ ] Open the console in a browser from WSL for real (configuration inspected only).
- [x] Cloudflare against mocks: library (wiremock) and full CLI (Python mock).
- [x] Live test Cloudflare with a real bootstrap token: names confirmed and corrected, wrangler accepts minted tokens, D1 propagation handled.
- [ ] Deploy a real Worker with D1 and other bindings using `fob exec cf workers -- wrangler deploy`.
- [x] Commit, create the GitHub repository with the baseline settings (github-repo-setup skill), first push.

## v0.2: Daily-driver quality

- [x] Keep secrets across reboots on WSL (Windows DPAPI files behind keyutils).
- [x] Background renewal of credentials before they expire.

- [ ] `fob exec --revoke`: delete a minted Cloudflare token as soon as the command exits (needs spawn instead of exec, and Ctrl-C handling).
- [x] `--ttl 4h` to override a template's lifetime for long agent sessions.
- [ ] `fob cf templates --check`: show which template permissions the account offers.
- [x] `fob revoke <profile>` (Cloudflare tokens deleted, cache cleared).

- [ ] Cloudflare browser sign-in (OAuth + PKCE) with an omnifob OAuth client.
- [ ] Per-directory profiles via mise (`[env]` hook or a mise plugin calling `fob env`), like wrangler's directory bindings.
- [x] `fob import aws`: create integrations from `~/.aws/config` `sso-session` sections and granted profiles.
- [x] Generate `~/.aws/config` profiles that call `fob creds --format credential-process` (`fob export aws-config`).
- [x] Shell completions, including profile ids (bash, zsh, fish, PowerShell; zsh untested).
- [x] CI on Linux, macOS and Windows.
- [x] Release workflow: binaries for Linux, macOS, Windows with checksums and provenance; installable with `mise use github:garysassano/omnifob`.
- [x] Publish the first release (v0.1.0, 2026-10-07).
- [ ] macOS code signing and notarisation (needed for Keychain prompts to remember the app; not needed to run it).

## Next: from the second study round

Ordered by value for daily use against effort; reasons in [research.md](research.md#second-round-2026-10-07).

- [x] Find profiles by AWS account ID too (`fob exec 123456789012 admin -- ...`), after aws-sso-util's `run-as`. Small.
- [x] Order the picker by recent use, after aws-sso-cli's History; matters with hundreds of profiles. Small.
- [ ] `fob console`: `--copy`, OSC 52 for SSH sessions, and Firefox containers so several accounts' consoles stay open side by side, after aws-sso-cli. Medium.
- [x] `fob check [profile]`: diagnose sign-in and access, with a quiet mode for scripts, after aws-sso-util. Small.
- [ ] A `command` integration: any program that prints credentials as JSON becomes a profile; covers saml2aws, gimme-aws-creds and scripts, instead of awsume-style plugins. Medium.
- [ ] Per-directory profiles through aliases: the repository names an alias, each machine maps it to a profile (secretenv's model; wrangler's directory bindings). Medium.
- [ ] MFA for chained roles: TOTP prompt, or an `mfa_command` (ykman, 1Password), after aws-mfa; unblocks profiles `fob import aws` skips. Medium.
- [ ] QR code for the AWS device sign-in, for SSH and headless machines, after okta-aws-cli. Small.
- [ ] Okta integration: device flow, then `AssumeRoleWithSAML` for AWS and Alibaba Cloud, after okta-aws-cli and gimme-aws-creds; needs an Okta admin to set up the apps. Large.
- [ ] Opt-in `store_refresh_token = false`, after aws-cli-auth. Small, niche.
- [ ] Export to `~/.aws/credentials` for tools that predate SSO, after yawsso. Small, niche.
- Not planned: headless-browser sign-in scraping (aws-azure-login), in-process plugins (awsume), tags (aws-sso-cli).

## v0.3: More clouds

See [landscape.md](landscape.md) for how each provider's CLI signs in.

- [ ] Name the provider shapes in the core: session exchange, mint, static.
- [x] Generic `token` integration in the keychain with presets: Hetzner, DigitalOcean, Vultr, Akamai Cloud, Upstash, Akamai EdgeGrid, Scaleway, Vercel, Netlify, Fly.io, Neon, Supabase, GitHub.
- [ ] Browser sign-in then mint, shared by Cloudflare, Akamai Cloud (Linode) and Scaleway; OVHcloud consumer keys.
- [ ] `aws-signin` integration for `aws login` (IAM users, root, console federation), DPoP key in the keychain.
- [ ] Provisioners beyond env vars: files with cleanup, Google executable-sourced credentials, kubectl exec plugin.
- [ ] `--agent` mode: shorter lifetimes, marked credentials (AWS session tags or source identity, token names), a record of what went to which agent. After the Azure CLI's agentic sessions.
- [ ] Fly.io with offline macaroon attenuation.

- [ ] Google Cloud: study `gcloud auth login`, ADC and `--impersonate-service-account`; sign in as the user, discover projects and impersonable service accounts, mint access tokens.
- [ ] Azure: study `az login` and MSAL; Entra ID device flow, discover subscriptions, tokens for ARM.
- [ ] Generic long-lived token integration (Hetzner, DigitalOcean, Vercel...) with per-tool variable names, after 1Password shell-plugins.
- [ ] GitHub App installation tokens.

## Later

- Not planned: a mise registry entry (user decision, 2026-10-07); install with `github:garysassano/omnifob`.
- MFA for chained roles (`mfa_serial`), and chains more than one role deep.
- Google Cloud provider once there is a project to test against.

- [x] AWS role chaining from Identity Center roles (imported from `~/.aws/config`).
- AWS console destinations, multiple console sessions.
- Local credential server (ECS-style) for containers.
- Show jdx; discuss which parts belong in fnox.
