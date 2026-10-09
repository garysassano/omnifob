# GitHub

Studied on 2026-10-09, while trying to make omnifob choose a GitHub account per directory for gh and git. The conclusion is in [decisions.md](../decisions.md): git and Git Credential Manager already do this, so omnifob only offers the `github` token preset.

## How the official CLI signs in

`gh auth login` runs the OAuth device flow against gh's own OAuth app and asks for `repo`, `read:org` and `gist`, which gh treats as its minimum (`gh auth refresh --scopes` adds more). It stores tokens in the OS keyring and supports several accounts per host, one of them active (`gh auth switch`). `gh auth token --user <login>` prints any stored account's token. `GH_TOKEN` and `GITHUB_TOKEN` override the stored accounts.

gh can serve git as a credential helper (`gh auth git-credential`), but only with the active account: when git asks for a different username it answers nothing (`pkg/cmd/auth/gitcredential/helper.go`, gh 2.102.0). It ignores `store` and `erase`, so git cannot sign it out.

## Git Credential Manager

Git Credential Manager keeps one token per account and picks it by the username git sends, which `credential.<url>.username` sets, per directory through `includeIf`. With `user.name` and `user.email` in the same included file, one mapping sets both who commits and who pushes.

It signs in to GitHub with its own OAuth app and hardcoded scopes. Checked on 2026-10-09: its token carries `gist`, `repo` and `workflow`, without `read:org`, so gh commands that read organization data (team reviewers, some `gh pr` fields, organization projects) fail with it; the REST API still works. A setting that adds scopes is requested in [git-credential-manager#1882](https://github.com/git-ecosystem/git-credential-manager/issues/1882). Until then, `git-credential-manager github login --username <login>` and its Token option store a classic personal access token with `read:org` instead.

## Tokens

- Fine-grained personal access tokens cannot access several organizations at once, nor repositories where the user is an outside collaborator (GitHub docs, 2026-10-09). A token per account that spans organizations has to be classic or OAuth.
- OAuth app tokens do not expire. Revoking one through the API (`DELETE /applications/{client_id}/token`) needs the app's client secret.
- GitHub's only expiring user tokens are a GitHub App's user access tokens (8 hours, renewed with a refresh token). They act only within the app's installations, so the app has to be installed in every organization the user works in, often with an owner's approval. Installation tokens (1 hour) act as the app, not the user.

## Device flow

- `POST https://github.com/login/device/code` with `client_id` and `scope` returns `device_code`, `user_code`, `verification_uri`, `expires_in` and `interval`. An unknown `client_id` gets 404 (checked live).
- `POST https://github.com/login/oauth/access_token` with `client_id`, `device_code` and `grant_type=urn:ietf:params:oauth:grant-type:device_code` answers `authorization_pending`, `slow_down` (with a longer `interval`), `expired_token`, `access_denied` or `device_flow_disabled` until it returns `access_token` and the granted `scope`.
- Device flow must be enabled on the OAuth app; no client secret is needed.

## Git over HTTPS

GitHub ignores the username when the password is a token: `x-access-token`, the account's login and an empty URL username all authenticated a dry-run push with an OAuth token (checked live on 2026-10-09).
