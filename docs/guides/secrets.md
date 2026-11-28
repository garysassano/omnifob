# Where secrets live

## The OS keychain

SSO sessions, the Cloudflare bootstrap token, stored tokens and cached credentials are kept in the OS keychain under the service `omnifob`. `OMNIFOB_KEYRING` forces a store; `fob status` shows which one is in use.

- **macOS**: Keychain.
- **Windows**: Credential Manager.
- **Linux**: the Secret Service. Where none runs (WSL, servers), the kernel keyring is used, straight away when there is no D-Bus session bus; it forgets everything on reboot.
- **WSL**: since the kernel keyring forgets on reboot, long-lived secrets are also written to `~/.local/state/omnifob/vault`, encrypted with Windows DPAPI for your Windows user, and restored after a reboot (`OMNIFOB_WSL_DPAPI=0` turns this off).

## The encrypted file vault

On a machine without a keychain that survives reboots (a headless Linux server, a container with a mounted state directory), `OMNIFOB_KEYRING=encrypted-file` keeps the secrets in files encrypted with a passphrase instead, in `~/.local/state/omnifob/encrypted` (or `encrypted-file:<absolute dir>`).

- The first command that stores a secret asks for a new passphrase (at least 12 characters).
- The passphrase is asked again only after a reboot: the key derived from it is kept in the kernel keyring until then (`OMNIFOB_VAULT_KEY_CACHE=0` asks every time).
- Scripts and services pass it in `OMNIFOB_VAULT_PASSPHRASE`, which fob removes from the environment of the commands and credential helpers it runs.
- Each secret is encrypted with AES-256-GCM under a key derived with PBKDF2-HMAC-SHA256 (600,000 iterations).
- The passphrase cannot be recovered: forgetting it means deleting the directory and signing in to every integration again.
- If `vault.json` goes missing while sealed files remain, fob refuses to start a new vault over them, since a new salt would make them never open again; restore the file, or move the sealed files away.

What this protects against, and what not, is in [docs/decisions.md](../decisions.md).

## State files

Discovered profiles, which contain no secrets, are kept in `~/.local/state/omnifob/profiles.json` (`$XDG_STATE_HOME/omnifob`).

- Without a home directory, set `XDG_STATE_HOME` and `OMNIFOB_CONFIG` (or `XDG_CONFIG_HOME`): omnifob then refuses to start rather than keep its files in the current directory.
- If `profiles.json` cannot be read, `fob sync` and `fob login` start over from no profiles and rewrite it, and `fob status` and `fob logout` carry on with a warning.
- On Linux and macOS the state directory and the vault are readable by you only (`0700`, files `0600`), and every file in them is replaced atomically, so a concurrent `fob` never reads half of one.

## Cached credentials

- Credentials are cached until five minutes before they expire, and renewed in the background when a quarter of their lifetime is left, so commands rarely wait for new ones.
- Credentials asked for with `--ttl` are not cached, so the next command gets the configured lifetime again.
- A renewal in the background is skipped for roles that need a code each session (chained and console sign-ins' roles with `mfa_serial`, an IAM user's `no_session` roles and session when the user has `mfa_serial`); the next command that needs one asks for it.
- `fob sync` deletes the cached credentials of profiles that went away.

## Revoking

- `fob revoke <profile>` deletes the Cloudflare tokens minted for a profile and clears its cache.
- `fob revoke --all` does it for every profile, leaving the sign-ins. When `profiles.json` is lost it still deletes user tokens and the configured account's, and refuses rather than forgetting account tokens it cannot list.
- Cloudflare tokens omnifob mints are named `omnifob <template>` (for example `omnifob workers`). omnifob remembers their IDs, deletes expired ones after each mint and on `fob sync`, and deletes all of them on `fob logout`. Tokens it did not mint are never touched.
