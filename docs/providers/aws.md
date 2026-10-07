# AWS IAM Identity Center

## Flow

1. `RegisterClient` (name `omnifob`, type `public`, scopes `sso:account:access`). The registration is reused while valid and the start URL is unchanged.
2. `StartDeviceAuthorization` → show `verificationUriComplete` and the user code, open the browser.
3. Poll `CreateToken` with the device code grant; `AuthorizationPending` keeps polling, `SlowDown` adds five seconds.
4. Store `{start_url, region, access_token, expires_at, refresh_token, client_id, client_secret, client_expires_at}` in the keychain at `aws-sso/<integration>/token`.
5. Before use: refresh with the refresh token when within 15 minutes of expiry; on refresh failure use the token while it is still valid.
6. Discovery: `ListAccounts` then `ListAccountRoles` per account, four at a time. Profile ids `<integration>/<slug(account name)>/<role>`; colliding slugs get `-<account id>`.
7. Credentials: `GetRoleCredentials` → `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, and `AWS_REGION`/`AWS_DEFAULT_REGION` when `default_region` is set.
8. Console: `signin.aws.amazon.com/federation` `getSigninToken`, then a `login` URL to the regional console.

A 401 from any portal call deletes the stored token and asks for a new sign-in.

The SDK clients are built without `aws-config` (the portal and OIDC calls are unsigned), which keeps dependencies down.

## Chained roles

Roles reached from an Identity Center role (`role_arn` with `source_profile` in `~/.aws/config`) are configured under `chained`. omnifob gets the Identity Center role's credentials, then calls STS `AssumeRole` with the configured session name and external ID. AWS limits chained sessions to one hour. Roles that need MFA are not supported and are skipped by `fob import aws`.

## The AWS config file

`fob import aws` reads `sso-session` sections, legacy `sso_start_url` profiles and granted's keys from `~/.aws/config`, and writes integrations and chained roles. `fob export aws-config` writes a marked block of profiles that call `fob creds --format credential-process`, so tools that read the AWS config get omnifob's credentials.
