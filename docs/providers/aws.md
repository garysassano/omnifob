# AWS IAM Identity Center

## Flow

`fob login` signs in the way `aws sso login` does since AWS CLI 2.22.0.

1. `RegisterClient` (name `omnifob`, type `public`, scopes `sso:account:access`). For the browser flow also grant types `authorization_code` and `refresh_token`, the redirect `http://127.0.0.1/oauth/callback` without a port, and the start URL as `issuerUrl`. Registrations are kept per flow at `aws-sso/<integration>/client/<flow>`, apart from the session, and reused until a day before they expire; `fob logout` keeps them, as the AWS CLI does.
2. Browser flow (the default): listen on a free port on `127.0.0.1`, open the consent page (`RegisterClient`'s `authorizationEndpoint`, else the OIDC endpoint the SDK resolves for the region, plus `/authorize`) with `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge_method=S256`, `scopes` and `code_challenge`, wait up to ten minutes for `/oauth/callback`, check `state`, then `CreateToken` with the `authorization_code` grant, the code, the PKCE verifier and the same redirect URI.
3. Device flow (`--device-code`, and on its own when `SSH_CONNECTION`, `SSH_CLIENT`, `SSH_TTY` or `CODESPACES` is set or `/.dockerenv` or `/run/.containerenv` exists): `StartDeviceAuthorization`, show `verificationUriComplete` and the user code, poll `CreateToken`; `AuthorizationPending` keeps polling, `SlowDown` adds five seconds.
4. Store `{start_url, region, access_token, expires_at, refresh_token, client_id, client_secret, client_expires_at}` in the keychain at `aws-sso/<integration>/token`.
5. Before use: refresh with the refresh token when within 15 minutes of expiry, under a file lock per integration (`locks/aws-sso-<integration>.lock` in the state directory), reading the token again once the lock is held. On refresh failure the token is used while it is still valid.
6. Discovery: `ListAccounts` then `ListAccountRoles` per account, four at a time. Profile ids `<integration>/<slug(account name)>/<role>`; colliding slugs get `-<account id>`.
7. Credentials: `GetRoleCredentials` → `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, and `AWS_REGION`/`AWS_DEFAULT_REGION` when `default_region` is set.
8. Console: the federation endpoint of the region's partition (`signin.aws.amazon.com`, `signin.amazonaws-us-gov.com`, `signin.amazonaws.cn`, `signin.amazonaws-eusc.eu`), regional (`<region>.signin...`) when a region is set and is not the partition's first, `getSigninToken`, then a `login` URL to the regional console.
9. `fob logout`: the portal's `Logout` ends the session at Identity Center, then the token is deleted.

`GetRoleCredentials` answers 403 for a while after an account assignment is made; omnifob retries twice (after 1 and 2 seconds) before reporting no access, as granted can.

A 401 from a portal call renews the session once and retries. If the portal refuses the renewed token too, or the renewal fails, the session is deleted (only if it still holds the refused token) and a new sign-in is asked for.

The SDK clients are built without `aws-config` (the portal and OIDC calls are unsigned), which keeps dependencies down. `OMNIFOB_AWS_ENDPOINT` sends every AWS call to one URL; the tests in `crates/omnifob-core/tests/aws_sso.rs` point it at a mock.

## Chained roles

Roles reached from an Identity Center role (`role_arn` with `source_profile` in `~/.aws/config`) are configured under `chained`. omnifob gets the Identity Center role's credentials, then calls STS `AssumeRole` with the configured session name and external ID. AWS limits chained sessions to one hour. `AWS_REGION` is exported only when the role or the integration sets a region; STS is called in the portal's region otherwise. With `mfa_serial`, `AssumeRole` sends the device and a code the user types; the credentials are then cached for the session, and parallel requests for the profile wait for one prompt. `duration` sets the session length, 15 minutes to 1 hour, and `fob exec --ttl` overrides it.

## The AWS config file

`fob import aws` reads `sso-session` sections, legacy `sso_start_url` profiles and granted's keys from `~/.aws/config`, and writes integrations and chained roles. `fob export aws-config` writes a marked block of profiles that call `fob creds --format credential-process`, so tools that read the AWS config get omnifob's credentials.

## IAM users

`type = "aws-iam"` keeps an IAM user's access key in the keychain at `aws-iam/<integration>/key`, the way aws-vault does, and never hands it out.

- `fob login` asks for the access key ID and secret (or reads both from `--token-stdin`), refuses temporary `ASIA` keys, checks the key with `GetCallerIdentity` and stores it.
- Profiles: `<integration>/<account or account ID>/session` for the user's own session, and `<integration>/<label>/<role>` per entry under `roles`.
- The session comes from `GetSessionToken`, with `SerialNumber` and a typed code when `mfa_serial` is set, lasting `session_duration` (15 minutes to 36 hours, default 8 hours). It is kept at `aws-iam/<integration>/session` and reused until five minutes before it ends; a new one is started under a lock shared by every omnifob process, so parallel commands ask for one code.
- Roles are assumed with the session. That is not role chaining, so their sessions last up to 12 hours (`duration`, default 1 hour, never past the session's end), and the session's MFA satisfies trust policies that require it: one code covers every role.
- Console: session credentials cannot sign in, so the session profile gets a federated session from `GetFederationToken` with the access key, limited to the user's own permissions by an allow-all policy (as aws-vault does). Users whose policies require MFA should open the console through a role.
