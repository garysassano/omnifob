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

## Not done yet

- PKCE authorization code flow (aws-vault and granted offer it; device flow is fine everywhere and is the default).
- Role chaining from an SSO role (`AssumeRole` into another account), as granted supports through `source_profile`.
- Writing `~/.aws/config` profiles that call `fob creds --format credential-process`, like aws-sso-cli's config generation.
- Reading existing `~/.aws/config` `sso-session` sections to create integrations automatically (`fob import aws`).
- Respecting `AWS_USE_FIPS_ENDPOINT` and dual-stack settings (granted fixed this in #965).
- Multiple console sessions (aws-sso-cli) and console destinations (`--service s3`).
