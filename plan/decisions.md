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

Cloudflare's third-party OAuth only allows PKCE (no device flow) and it is unverified whether `account_api_tokens:create` is available to third-party clients. The bootstrap token works today and is a one-click, one-time setup. OAuth comes next, keeping the bootstrap token as fallback.

## 2026-10-06: Permissions by name, not ID

The user's complaint was the dashboard; fnox needs IDs too. Names are resolved at mint time from the permission groups API, so they never go stale in config, and typos get suggestions.

## 2026-10-06: Clean up expired minted tokens

Cloudflare keeps expired tokens listed. Minted tokens carry the `omnifob:` prefix, and after each mint expired ones with that prefix are deleted. Tokens omnifob did not create are never touched.

## 2026-10-06: Shell switching through a wrapper function

A process cannot change its parent's environment, so `fob activate <shell>` prints a `fob` function where `use` and `unuse` eval `fob env`. `fob env` remembers the variables it set in `OMNIFOB_VARS` and removes stale ones when switching. The picker draws on stderr so it works inside `$(...)`.

## 2026-10-06: Credential output formats for other tools

`--format json` (generic), `fnox` (command lease contract), `credential-process` (AWS SDKs). This makes omnifob useful before every provider is native, and is the integration point with fnox.

## 2026-10-07: Release notes in releases only

The user does not want a CHANGELOG.md alongside release notes. Notes are written once, in the signed tag's message (`--cleanup=verbatim` keeps Markdown headings), and the release workflow copies them into the GitHub release. Generated notes are only a fallback: they list merged pull requests, and changes here have gone straight to main.

## 2026-10-07: Pull requests for changes

Changes go through a pull request, squash-merged after CI passes, matching the repository's merge settings (squash only, title and description from the PR). Small changes (a typo, a log line) may still go straight to `main`. Repository settings match `garysassano/shin-bucket-deployment`, except that Dependabot alerts stay enabled here: the baseline never turns a security feature off to match the reference.
