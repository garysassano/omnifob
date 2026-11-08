# Decisions

Newest last. Each entry says what was decided and why, so later changes can weigh the same reasons.

## 2026-10-06: Build a new tool rather than fork granted

granted is AWS-shaped throughout (`~/.aws/config` profiles, STS, console federation), and a fork would mean keeping up with upstream AWS fixes to keep unrelated features working. A new tool borrows the ideas without the coupling.

## 2026-10-06: Name omnifob, command `fob`

"omni" says every cloud; a fob is the small thing that opens your doors. Alternatives rejected: omnicloud (taken by a 656-star project and the GitHub user), omnikey (HID Global's card reader brand), omnipass (Softex's old fingerprint product), omnifox (reads as a fnox fork). Both binaries are installed; `fob` for daily use, `omnifob` for scripts.

## 2026-10-06: Rust

Same language as mise and fnox, which makes a later merge into fnox realistic. Official AWS SDK for Rust, `keyring-core` for every OS keychain, single static binary.

## 2026-10-06: Integrations produce profiles (Leapp's model)

An integration is something you sign in to once; sync discovers its profiles. Users configure a handful of integrations, never hundreds of profiles. Profiles are cached on disk without secrets and refreshed by `fob sync`.

## 2026-10-06: Two crates

`omnifob-core` holds config, storage and providers; `omnifob` holds the command line. Provider code can then move into another project (fnox) without the CLI.

## 2026-10-06: Secrets in the OS keychain through keyring-core

`keyring` v4 itself says applications should link `keyring-core` and pick stores. macOS Keychain, Windows Credential Manager, Secret Service on Linux, falling back to kernel keyutils when no Secret Service is running (WSL, servers). keyutils loses secrets on reboot; acceptable for now. Revisit an encrypted-file store (wrangler has one, `db-keystore` exists) if that annoys.

## 2026-10-06: AWS device flow first

Works on every machine including headless and WSL; PKCE needs a local callback server. aws-vault and granted both default to device flow. Superseded on 2026-11-08, below.

## 2026-10-06: Cloudflare bootstrap token first, OAuth second

Cloudflare's third-party OAuth only allows PKCE (no device flow) and it is unverified whether `account_api_tokens:create` is available to third-party clients. The bootstrap token works today and is a one-click, one-time setup. OAuth comes next, keeping the bootstrap token as fallback. Superseded on 2026-10-09, below.

## 2026-10-06: Permissions by name, not ID

Scoping tokens in the dashboard is the pain omnifob removes, and fnox needs IDs too. Names are resolved at mint time from the permission groups API, so they never go stale in config, and typos get suggestions.

## 2026-10-06: Clean up expired minted tokens

Cloudflare keeps expired tokens listed. Minted tokens carry the `omnifob:` prefix, and after each mint expired ones with that prefix are deleted. Tokens omnifob did not create are never touched.

## 2026-10-06: Shell switching through a wrapper function

A process cannot change its parent's environment, so `fob activate <shell>` prints a `fob` function where `use` and `unuse` eval `fob env`. `fob env` remembers the variables it set in `OMNIFOB_VARS` and removes stale ones when switching. The picker draws on stderr so it works inside `$(...)`.

## 2026-10-06: Credential output formats for other tools

`--format json` (generic), `fnox` (command lease contract), `credential-process` (AWS SDKs). This makes omnifob useful before every provider is native, and is the integration point with fnox.

## 2026-10-07: Release notes in releases only

There is no CHANGELOG.md alongside the release notes. Notes are written once, in the signed tag's message (`--cleanup=verbatim` keeps Markdown headings), and the release workflow copies them into the GitHub release. Generated notes are only a fallback: they list merged pull requests, and changes here have gone straight to main.

## 2026-10-07: Pull requests for changes

Changes go through a pull request, squash-merged after CI passes, matching the repository's merge settings (squash only, title and description from the PR). Small changes (a typo, a log line) may still go straight to `main`. Repository settings match `garysassano/shin-bucket-deployment`, except that Dependabot alerts stay enabled here: the baseline never turns a security feature off to match the reference.

## 2026-10-07: No profile aliases for now

Profile ids are long (`<integration>/<account>/<role or template>`), but they are rarely typed: any words that match one profile select it, a whole-segment match wins, and shell completion fills in the rest. Aliases would add a second naming scheme to learn and keep in sync for little gain. The repeated case, the same profile in the same project, is better served by a per-directory default profile, which is planned. Revisit if real collisions keep forcing long queries; an alias would then be an exact match checked before word matching, so it never changes what existing queries select.

## 2026-10-09: Cloudflare browser sign-in as its own type

Third-party OAuth clients can request "Account API Tokens Write" now (a sensitive scope the consent page leaves off by default), and an access token with it creates and deletes account-owned tokens in every account approved on the consent page. So a browser sign-in replaces the bootstrap token without losing what minting gives: narrow tokens per template, IP limits, R2 bucket limits and S3 credentials, and `--revoke`.

The sign-in method is the integration type, as with `aws-sso`: `cloudflare-oauth` and `cloudflare-token` (the bootstrap token, formerly `cloudflare`). Both share configuration, templates and minting, so a template gives the same token either way. A clean break from `cloudflare` while omnifob is 0.x, named in the release notes.

A sign-in can only mint permissions whose scope the consent granted; Cloudflare refuses the rest. omnifob therefore requests the scopes its templates need, from a table of permission name to scope ID, since the IDs do not follow the names (`page.write` for Pages, `query-cache.write` for Hyperdrive). The OAuth client must have those scopes registered. Until omnifob ships a public client, each user registers a private one; a public client needs a verified domain for its client URL, and making a client public cannot be undone.

## 2026-10-09: GitHub accounts stay with git and Git Credential Manager

omnifob briefly gained per-directory profiles, a git credential helper and a GitHub sign-in, meant to replace a hand-written gh wrapper that picks a GitHub account per directory. All three were reverted before any release.

git's `includeIf` already maps each directory to an account (`credential.https://github.com.username`, next to `user.name` and `user.email`), and Git Credential Manager already keeps one token per account and picks it by that username. omnifob's versions repeated the mapping in a second place, chose by directory while ignoring the username git sends, and needed an OAuth app registered and a sign-in per account. The wrapper could not go away either, since a shell function is invisible to non-interactive shells such as coding agents. The only gain was the `read:org` scope Git Credential Manager does not request, which a classic token stored in it also provides. omnifob keeps the `github` token preset for handing a token to a command; [providers/github.md](providers/github.md) has what was learned.

Per-directory profiles went too: nothing used them yet, and wrangler and `cf` bind accounts to directories themselves. Revisit them when a provider without that needs it, keeping the mapping in omnifob's config rather than in repositories.

## 2026-11-08: AWS browser sign-in by default, device flow as fallback

The AWS CLI has signed in with the authorization code flow and PKCE by default since 2.22.0; the device flow is behind `--use-device-code`. The device flow lets anyone who tricks a user into entering a code take over the session (device code phishing), while PKCE binds the sign-in to a listener on the machine that started it. The 2026-10-06 reason for the device flow no longer holds: omnifob has had a loopback callback since the Cloudflare browser sign-in, and on WSL the Windows browser reaches `127.0.0.1` in WSL (checked 2026-11-08). `fob login` uses the device flow with `--device-code`, and on its own over SSH and in containers, where a browser cannot reach the loopback listener (granted makes the same check).

Two details follow the AWS CLI rather than plain OAuth: the client is registered with the portless redirect `http://127.0.0.1/oauth/callback` and the sign-in uses any free port (RFC 8252, section 7.3), and the consent page takes the scopes as `scopes`, not `scope`.

## 2026-11-08: Renew AWS sessions under a lock shared by every process

Each refresh returns a new refresh token, and omnifob treats the old one as spent (as aws-vault does; whether Identity Center refuses a reused one is not verified), so two `fob` processes renewing the same session at once (parallel `credential_process` calls after a laptop wakes, or two background renewals) left the loser with a spent token and a false "session ended". Renewal now runs under a file lock per integration and reads the token again once it holds the lock. A 401 from the portal renews once and retries, and drops the session only if it still holds the refused token, so a session another process just renewed is never thrown away.

## 2026-11-08: IAM users through STS sessions, like aws-vault

granted and aws-vault both support IAM users, and some accounts still have them. omnifob stores the access key in the keychain and never exports it: profiles get a `GetSessionToken` session, and roles are assumed with that session rather than with the key. Roles then get sessions of up to 12 hours (role chaining would cap them at one), and one MFA code covers every role for the session's length. Long-lived keys stay discouraged; this keeps them off disk and out of environments where they exist anyway.

## 2026-11-08: MFA codes through a prompt the embedder registers

`omnifob-core` stays usable as a library, so it never reads the terminal. The command line registers a prompt when stdin and stderr are terminals; elsewhere (background renewal, `credential_process` without a terminal) a profile that needs a code fails with a message saying to run `fob creds` in a terminal first. Fetches are serialized per profile, so parallel `credential_process` calls ask once and share the result.
