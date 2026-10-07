# Changelog

All notable changes to omnifob. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-07

### Added

- AWS roles chained from IAM Identity Center roles (`role_arn` with a `source_profile` that signs in through Identity Center). List them under `[integrations.<name>.chained.<label>]`; each becomes a profile whose credentials come from STS AssumeRole, with optional session name, external ID and region. They work with `exec`, `use`, `console`, the cache, background renewal and `export aws-config`.
- `fob import aws` imports chained roles too, adds missing ones to portals that are already configured, and reports profiles it cannot import (MFA, or a source profile without an account and role).

### Changed

- Sign-in errors say why a new sign-in is needed, for example that an Identity Center session ended after its 8-hour default.
- `fob status` no longer promises that a session renews beyond the portal session's lifetime.
- The minimum supported Rust version is 1.94.1, which the AWS SDK already required.

### Fixed

- `omnifob --version`, help and error messages said `fob`; the command is now named after the binary you run.
- Piping output into a command that closes early (`fob list | head`) no longer panics.

### Security

- Updated the AWS STS SDK so that `aws-smithy-json` is no longer affected by an uncontrolled-recursion denial-of-service advisory.

## [0.1.0] - 2026-10-07

First release.

### Added

- AWS IAM Identity Center: device sign-in with silent refresh, discovery of every account and role, role credentials, console sign-in links.
- Cloudflare: one bootstrap token, then short-lived tokens minted from templates that name permissions as the dashboard or the API does. The built-in `workers` template covers the developer platform (D1, Queues, Workers AI, Vectorize, Hyperdrive, Containers, Browser Run and more). Waits until D1 accepts a new token, and deletes expired tokens it created.
- `token` integrations for providers with long-lived tokens only, with presets for Hetzner, DigitalOcean, Vultr, Akamai Cloud (Linode), Upstash, Akamai EdgeGrid, Scaleway, Vercel, Netlify, Fly.io, Neon, Supabase and GitHub.
- Commands: `login`, `logout`, `status`, `sync`, `list`, `env`, `exec`, `use`, `unuse`, `console`, `creds` (JSON, fnox lease and AWS `credential_process` formats), `revoke`, `activate`, `import aws`, `export aws-config`, `cloudflare permissions`, `cloudflare templates`.
- Profile search by words with a fuzzy picker, and automatic sign-in when a session is missing.
- Credentials cached in the OS keychain and renewed in the background before they expire; `--ttl` for minted credentials.
- Shell integration for bash, zsh, fish and PowerShell, with tab completion of live profile ids.
- On WSL, secrets survive reboots: they are also stored encrypted with Windows DPAPI.
- Release builds for Linux (x86_64, aarch64), macOS (Apple Silicon) and Windows, with checksums and build provenance.

[0.2.0]: https://github.com/garysassano/omnifob/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/garysassano/omnifob/releases/tag/v0.1.0
