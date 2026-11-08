# Google Cloud

## Flow

`fob login` signs in the way `gcloud auth login` does, read from the Cloud SDK 585.0.0 (`googlecloudsdk/core/credentials/flow.py`, `api_lib/auth/util.py`, `surface/auth/login.py`) on 2026-11-08.

1. The OAuth client is gcloud's own (`CLOUDSDK_CLIENT_ID` in `core/config.py`), an installed-app client whose "secret" ships in gcloud. `client_id` and `client_secret` in the config name a Desktop client of your own instead.
2. The scopes are gcloud's `DEFAULT_SCOPES`: `openid`, `userinfo.email`, `cloud-platform` and `sqlservice.login`. A consent without `cloud-platform` is refused, as gcloud refuses it.
3. Browser flow (the default): listen on a free port on `127.0.0.1`, open `accounts.google.com/o/oauth2/auth` with `response_type=code`, `redirect_uri=http://localhost:<port>/`, `access_type=offline`, `state` and an S256 `code_challenge`, wait for the redirect to `/`, then exchange the code at `oauth2.googleapis.com/token` with the client secret and the PKCE verifier.
4. From another device (`--device-code`, and on its own over SSH and in containers): gcloud's `--no-launch-browser` flow. The URL opens anywhere; Google's page `sdk.cloud.google.com/authcode.html` shows a code to paste back. The request adds `prompt=consent` and `token_usage=remote`. Google serves that page only to its own clients, so this needs gcloud's client.
5. Store `{refresh_token, access_token, expires_at, email, client_id}` at `gcp/<integration>/oauth`. The email comes from the ID token's claims.
6. Renewal: the `refresh_token` grant. Google does not rotate refresh tokens. `invalid_grant` asks for a new sign-in; with `error_subtype=invalid_rapt` the message says Google Cloud session control wants one.
7. Discovery: `cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE`, every page, as `gcloud projects list` does; `projects` in the config skips it. One profile per project, `<integration>/<project id>/user`, plus one per configured service account, `<integration>/<label>/<account name>`.
8. Credentials for a project: a fresh access token from the refresh token. For a service account: `iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken` with the scopes `cloud-platform` and `userinfo.email`, the `lifetime` (one hour by default; up to 12 hours where the organization policy `iam.allowServiceAccountCredentialLifetimeExtension` lists the account) and any `delegates`, as `gcloud --impersonate-service-account` does. Impersonating needs the Service Account Token Creator role on the account.
9. Console: `console.cloud.google.com/home/dashboard?project=<id>&authuser=<email>`. Google has no way to open the console as a service account.
10. `fob logout`: `oauth2.googleapis.com/revoke` with the refresh token, as `gcloud auth revoke` does, then the token is deleted.

`OMNIFOB_GOOGLE_ENDPOINT` sends every Google call to one URL; the tests in `crates/omnifob-core/tests/gcp.rs` point it at a mock.

## Variables

| Variable                     | Read by                                       |
| ---------------------------- | --------------------------------------------- |
| `CLOUDSDK_AUTH_ACCESS_TOKEN` | gcloud (instead of its stored credentials)    |
| `GOOGLE_OAUTH_ACCESS_TOKEN`  | Terraform's and OpenTofu's `google` providers |
| `CLOUDSDK_CORE_PROJECT`      | gcloud                                        |
| `GOOGLE_CLOUD_PROJECT`       | Client libraries, Terraform                   |

The client libraries' Application Default Credentials do not read an access token from the environment; they need a credentials file. Programs built on them still use `gcloud auth application-default login`.
