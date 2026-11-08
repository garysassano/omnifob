# Azure

## Flow

`fob login` signs in the way `az login` does, read from azure-cli (`src/azure-cli-core/azure/cli/core/auth/identity.py`, `auth/constants.py`, `_profile.py`) on 2026-11-08.

1. The client is the Azure CLI's public client, `04b07795-8ddb-461a-bbee-02f9e1bf7b46`, which Microsoft's Azure Identity libraries also default to for interactive sign-in. Public clients send no secret.
2. The authority is `login.microsoftonline.com/organizations`, or the configured `tenant`. The scope is Resource Manager's, `https://management.core.windows.net//.default` (the resource ends in a slash), plus `offline_access`, `openid` and `profile`, which MSAL adds.
3. Browser flow (the default): listen on a free port on `127.0.0.1`, open `<authority>/oauth2/v2.0/authorize` with `redirect_uri=http://localhost:<port>`, `prompt=select_account`, `state` and an S256 `code_challenge`, then exchange the code at `<authority>/oauth2/v2.0/token` with the PKCE verifier.
4. Device flow (`--device-code`, and on its own over SSH and in containers): `<authority>/oauth2/v2.0/devicecode`, show the URL and code, poll the token endpoint; `authorization_pending` keeps polling, `slow_down` adds five seconds.
5. Store `{refresh_token, username, tenant_id}` at `azure/<integration>/oauth`; the user name and home tenant come from the ID token's `preferred_username` and `tid`.
6. A token for a tenant: the `refresh_token` grant at that tenant's authority. Entra ID rotates refresh tokens, and the new one is stored each time. `invalid_grant` from the home tenant asks for a new sign-in.
7. Discovery, as `az` does: `GET /tenants`, then for each tenant a token and `GET /subscriptions` (`api-version=2022-12-01`, following `nextLink`). A tenant that refuses a token (MFA or conditional access it wants satisfied) is skipped with a warning. A subscription reachable from two tenants is kept once, under the first. Disabled subscriptions are left out. With `tenant` set only that tenant is searched; `subscriptions` keeps only the listed IDs. Profile ids are `<integration>/<slug(subscription name)>/user`.
8. Credentials: a Resource Manager token for the subscription's tenant.
9. Console: `portal.azure.com/#@<tenant>/resource/subscriptions/<id>/overview`.
10. `fob logout` deletes the refresh token. Entra ID gives public clients no revocation endpoint; `az logout` does the same.

`OMNIFOB_AZURE_ENDPOINT` sends every Entra ID and Resource Manager call to one URL; the tests in `crates/omnifob-core/tests/azure.rs` point it at a mock. Not yet tried against a live tenant.

## Variables

Azure's tools take no access token from the environment: the CLI, the Azure Identity libraries and Terraform's `azurerm` provider (`use_cli`) sign in through `az`. Profiles therefore export what selects a subscription, and the raw token for scripts.

| Variable                                   | Read by                                                  |
| ------------------------------------------ | -------------------------------------------------------- |
| `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID` | Azure Developer CLI, many SDK samples and scripts        |
| `ARM_SUBSCRIPTION_ID`, `ARM_TENANT_ID`     | Terraform's and OpenTofu's `azurerm` providers           |
| `AZURE_ACCESS_TOKEN`                       | Nothing standard: `curl -H "Authorization: Bearer $..."` |

Feeding `az` and the SDKs a token would need a local endpoint that answers like a managed identity (`IDENTITY_ENDPOINT` and `IDENTITY_HEADER`), which omnifob does not run.
