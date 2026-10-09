# GitHub

## How the official CLI signs in

`gh auth login` runs the OAuth device flow against gh's own OAuth app and asks for `repo`, `read:org` and `gist`, which gh treats as its minimum (`gh auth refresh --scopes` adds more; `workflow` is commonly added). It stores the token in the OS keyring, supports several accounts per host with `gh auth switch`, prints the active token with `gh auth token`, and can serve git as a credential helper (`gh auth git-credential`). `GH_TOKEN` and `GITHUB_TOKEN` override the stored account.

## Git Credential Manager

Git Credential Manager signs in to GitHub with its own OAuth app and hardcoded scopes. Checked on 2026-10-09: its token carries `gist`, `repo` and `workflow`, without `read:org`, so gh commands that read organization data (team reviewers, some `gh pr` fields, organization projects) fail with it. The request for a setting that adds scopes is [git-credential-manager#1882](https://github.com/git-ecosystem/git-credential-manager/issues/1882). Its `github login --pat` (or the Token option of its dialog) stores a personal access token instead.

## Device flow

From the GitHub docs, checked on 2026-10-09:

- `POST https://github.com/login/device/code` with `client_id` and `scope` returns `device_code`, `user_code`, `verification_uri`, `expires_in` and `interval`.
- `POST https://github.com/login/oauth/access_token` with `client_id`, `device_code` and `grant_type=urn:ietf:params:oauth:grant-type:device_code` answers `authorization_pending`, `slow_down` (with a longer `interval`), `expired_token`, `access_denied` or `device_flow_disabled` until it returns `access_token` and the granted `scope`.
- Device flow must be enabled on the OAuth app; no client secret is needed. An unknown `client_id` gets 404 from the first endpoint (checked live).
- OAuth app tokens do not expire. Revoking one through the API (`DELETE /applications/{client_id}/token`) needs the client secret.

## Expiring credentials

GitHub's only expiring user tokens are a GitHub App's user access tokens (8 hours, renewed with a refresh token). They act only within the app's installations and the app's permissions, so the app has to be installed in every organization the user works in, often with an owner's approval. Installation tokens (1 hour) act as the app, not the user. omnifob therefore keeps a long-lived OAuth token, and its value for GitHub lies in choosing the account per directory and keeping the token out of the shell and plain-text files, not in shortening its life.

## Git over HTTPS

GitHub ignores the username when the password is a token: `x-access-token`, the account's login and an empty URL username all authenticated a dry-run push with an OAuth token (checked live on 2026-10-09).
