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

Works on every machine including headless and WSL; PKCE needs a local callback server. aws-vault and granted both default to device flow.

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
