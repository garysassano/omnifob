# Google Cloud

## Flow

`fob login` signs in the way `gcloud auth login` does, read from the Cloud SDK 585.0.0 (`googlecloudsdk/core/credentials/flow.py`, `api_lib/auth/util.py`, `surface/auth/login.py`) on 2026-11-08.

1. The OAuth client is gcloud's own (`CLOUDSDK_CLIENT_ID` in `core/config.py`), an installed-app client whose "secret" ships in gcloud. `client_id` and `client_secret` in the config name a Desktop client of your own instead.
2. The scopes are gcloud's `DEFAULT_SCOPES`: `openid`, `userinfo.email`, `cloud-platform` and `sqlservice.login`. A consent without `cloud-platform` is refused, as gcloud refuses it.
3. Browser flow (the default): listen on a free port on `127.0.0.1` for up to ten minutes, open `accounts.google.com/o/oauth2/auth` with `response_type=code`, `redirect_uri=http://localhost:<port>/`, `access_type=offline`, `state` and an S256 `code_challenge`, wait for the redirect to `/`, then exchange the code at `oauth2.googleapis.com/token` with the client secret and the PKCE verifier.
4. From another device (`--device-code`, and on its own over SSH, in containers and on Linux without a display): gcloud's `--no-launch-browser` flow. The URL opens anywhere; Google's page `sdk.cloud.google.com/authcode.html` shows a code to paste back. The request adds `prompt=consent` and `token_usage=remote`. Google serves that page only to its own clients, so this needs gcloud's client.
5. Store `{refresh_token, access_token, expires_at, email, client_id}` at `gcp/<integration>/oauth`. The email comes from the ID token's claims. `fob login` keeps a stored sign-in only for the configured client, since its refresh token renews only with that one, and a stored access or ID token is not used once `client_id` names another client.
6. Renewal: the `refresh_token` grant. Google does not rotate refresh tokens. Renewal writes the sign-in back, so it runs under a lock per integration (`gcp-<integration>`) that `fob login` takes to store a new sign-in, which a renewal can then not overwrite. A renewal that finds, once it holds the lock, that another process renewed the token meanwhile uses that one. `invalid_grant` forgets the sign-in, so `fob status` stops counting it, and asks for a new one; with `error_subtype=invalid_rapt` the message says Google Cloud session control wants one. A 401 from listing projects or from `generateAccessToken` (an access token revoked before its time) renews the token and tries once more.
7. Discovery: `cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE`, every page, as `gcloud projects list` does; `projects` in the config skips it. One profile per project, `<integration>/<project id>/user`, plus one per configured service account, `<integration>/<label>/<account name>`. A service account's `email` and `delegates` must be emails without `/`, `?`, `#`, `%` or whitespace, since they go into the IAM Credentials URL; two labels that slug alike are refused when the config loads, and a label named like a project, for an account named `user`, fails discovery.
8. Credentials for a project: a fresh access token from the refresh token. For a service account: `iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>:generateAccessToken` with the scopes `cloud-platform` and `userinfo.email`, the `lifetime` (one hour by default; up to 12 hours where the organization policy `iam.allowServiceAccountCredentialLifetimeExtension` lists the account) and any `delegates`, as `gcloud --impersonate-service-account` does. Impersonating needs the Service Account Token Creator role on the account.
9. Console: `console.cloud.google.com/home/dashboard?project=<id>&authuser=<email>`. Google has no way to open the console as a service account.
10. `fob logout`: `oauth2.googleapis.com/revoke` with the refresh token, as `gcloud auth revoke` does, then the token is deleted.

`OMNIFOB_GOOGLE_ENDPOINT` (in the library, a context's `Endpoints::google`) sends every Google call to one URL; the tests in `crates/omnifob-core/tests/mock/gcp.rs` point it at a mock.

## Variables

| Variable                     | Read by                                       |
| ---------------------------- | --------------------------------------------- |
| `CLOUDSDK_AUTH_ACCESS_TOKEN` | gcloud (instead of its stored credentials)    |
| `GOOGLE_OAUTH_ACCESS_TOKEN`  | Terraform's and OpenTofu's `google` providers |
| `CLOUDSDK_CORE_PROJECT`      | gcloud                                        |
| `GOOGLE_CLOUD_PROJECT`       | Client libraries, Terraform                   |

gcloud reads `CLOUDSDK_AUTH_ACCESS_TOKEN` before the `auth/access_token_file` property (`CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`) and any stored account (`_Load` in `googlecloudsdk/core/credentials/store.py`, Cloud SDK 585.0.0), and reads the file on every run, so `fob exec --token-file` replaces the variable with a private file that fob rewrites ten minutes before the token ends, and at least hourly while a longer token lasts, so the clean-up of files a killed `fob exec` left (two hours old) never takes it.

The client libraries' Application Default Credentials do not read an access token from the environment; they need a credentials file. `fob exec` gives them one for the command's lifetime (see below), so programs built on them no longer need `gcloud auth application-default login`.

## Application Default Credentials

Read from google-auth-library-python as gcloud 585.0.0 bundles it (`google/auth/pluggable.py`, `external_account.py`, `external_account_authorized_user.py`, `oauth2/sts.py`) on 2026-11-25.

- **Executable-sourced credentials** (`external_account` with `credential_source.executable`) run a command, split with `shlex`, only when `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. The command prints `{"version": 1, "success": true, "token_type", "id_token" or "saml_response", "expiration_time"}`, and `token_type` must be `urn:ietf:params:oauth:token-type:jwt`, `id_token` or `saml2`. That subject token is then exchanged at `token_url` (Google's STS) for the `audience`, a workload identity pool provider. So the contract cannot carry a Google access token: it federates an outside identity. `fob creds --format gcp-executable` answers with the account's Google ID token (issuer `https://accounts.google.com`, audience the OAuth client, kept from the last renewal and renewed when it has under ten minutes left), which a pool with an OIDC provider for that issuer accepts. `fob export gcp-adc` writes the file, with `service_account_impersonation_url` for a service account profile.
- **`external_account_authorized_user`**, the type gcloud writes for workforce identity federation, refreshes with a `refresh_token` grant at `token_url`, with `client_id` and `client_secret` as HTTP Basic, and checks neither the URL's host nor the token's form. `fob exec` writes one whose `token_url` is a loopback endpoint and whose `refresh_token` is that endpoint's random secret; the endpoint answers with the profile's access token and `expires_in`. It is the type `gcloud auth application-default login` writes for workforce identity federation, so the other client libraries read it too; only the Python library's code was read, and none was tried against the endpoint live. The file is private, in `~/.local/state/omnifob/run/`, and deleted when the command ends.
- Not taken: a fake metadata server (`GCE_METADATA_HOST`), since the libraries send it no secret and any local process could ask it for the token; `authorized_user` files, which hold the refresh token.
