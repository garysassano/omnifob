# Azure

## Flow

`fob login` signs in the way `az login` does, read from azure-cli (`src/azure-cli-core/azure/cli/core/auth/identity.py`, `auth/constants.py`, `_profile.py`) on 2026-11-08.

1. The client is the Azure CLI's public client, `04b07795-8ddb-461a-bbee-02f9e1bf7b46`, which Microsoft's Azure Identity libraries also default to for interactive sign-in. Public clients send no secret.
2. The authority is `login.microsoftonline.com/organizations`, or the configured `tenant`. The scope is Resource Manager's, `https://management.core.windows.net//.default` (the resource ends in a slash), plus `offline_access`, `openid` and `profile`, which MSAL adds.
3. Browser flow (the default): listen on a free port on `127.0.0.1` for up to ten minutes, open `<authority>/oauth2/v2.0/authorize` with `redirect_uri=http://localhost:<port>`, `prompt=select_account`, `state` and an S256 `code_challenge`, then exchange the code at `<authority>/oauth2/v2.0/token` with the PKCE verifier.
4. Device flow (`--device-code`, and on its own over SSH, in containers and on Linux without a display): `<authority>/oauth2/v2.0/devicecode`, show the URL and code, poll the token endpoint; `authorization_pending` keeps polling, `slow_down` adds five seconds. `fob login --start` keeps the device code, interval, expiry and tenant under `azure/<name>/pending` and returns; `fob login --wait` polls with them later. Entra ID keeps the authorization for the code's lifetime (fifteen minutes); `az login --use-device-code` has no split.
5. Store `{refresh_token, username, tenant_id, tenant}` at `azure/<integration>/oauth`; the user name and home tenant come from the ID token's `preferred_username` and `tid`, and `tenant` is the configured one (none for `organizations`). `fob login` keeps a stored sign-in only while `tenant` is unchanged, or names the tenant signed in to.
6. A token for a tenant: the `refresh_token` grant at that tenant's authority. Entra ID rotates refresh tokens, and the new one is stored each time, under a lock per integration (`azure-<integration>`) that `fob login` takes too, so a rotated token never overwrites a sign-in stored meanwhile. Entra ID keeps the previous refresh token valid, so parallel commands lose nothing. `invalid_grant` from the home tenant deletes the stored sign-in if it still holds the refused token, and asks for a new one.
7. Discovery, as `az` does: `GET /tenants`, then for each tenant a token and `GET /subscriptions` (`api-version=2022-12-01`, following `nextLink` only while it stays on Resource Manager's scheme, host and port, so the token goes nowhere else). Tokens are obtained one tenant at a time, in order, since each exchange rotates the refresh token; the subscription lists of the tenants that have one are fetched at the same time. A tenant other than the home tenant that refuses a token (MFA or conditional access it wants satisfied) or fails to list its subscriptions is skipped with a warning. A subscription reachable from two tenants is kept once, under the first. Disabled subscriptions are left out. With `tenant` set only that tenant is searched; `subscriptions` keeps only the listed IDs. Profile ids are `<integration>/<slug(subscription name)>/user`; when the names of two subscriptions slug alike (`Pay-As-You-Go` in two tenants), both get `-<subscription id>` on the segment.
8. Credentials: a Resource Manager token for the subscription's tenant.
9. Console: `portal.azure.com/#@<tenant>/resource/subscriptions/<id>/overview`.
10. `fob logout` deletes the refresh token. Entra ID gives public clients no revocation endpoint; `az logout` does the same.

`OMNIFOB_AZURE_ENDPOINT` (in the library, a context's `Endpoints::azure`) sends every Entra ID and Resource Manager call to one URL; the tests in `crates/omnifob-core/tests/azure.rs` point it at a mock. Not yet tried on a live tenant: none is available to test with.

## Variables

Azure's tools take no access token from the environment: the CLI, the Azure Identity libraries and Terraform's `azurerm` provider (`use_cli`) sign in through `az`. Profiles therefore export what selects a subscription, and the raw token for scripts.

| Variable                                   | Read by                                                  |
| ------------------------------------------ | -------------------------------------------------------- |
| `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID` | Azure Developer CLI, many SDK samples and scripts        |
| `ARM_SUBSCRIPTION_ID`, `ARM_TENANT_ID`     | Terraform's and OpenTofu's `azurerm` providers           |
| `AZURE_ACCESS_TOKEN`                       | Nothing standard: `curl -H "Authorization: Bearer $..."` |

## Managed identity endpoint

During `fob exec` for an Azure profile, fob answers like App Service's managed identity endpoint (Microsoft Learn, "Managed identities for App Service", read 2026-11-25): `IDENTITY_ENDPOINT` is `http://127.0.0.1:<port>/msi/token` and `IDENTITY_HEADER` a random secret that each request must send back as `X-IDENTITY-HEADER`, compared in constant time. `GET ?resource=<uri>&api-version=2019-08-01` answers `{access_token, expires_on (seconds, as a string), resource, token_type: Bearer, client_id}`. The token is minted from the stored sign-in for `<resource>/.default offline_access` in the subscription's tenant, the scope the Azure CLI's `resource_to_scopes` writes, and kept per resource while it has more than 15 minutes left. A request for a user-assigned identity (`client_id`, `principal_id`, `object_id`, `mi_res_id`) is refused. The Azure Identity libraries pick App Service when `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set without `IDENTITY_SERVER_THUMBPRINT` (Service Fabric) or `IMDS_ENDPOINT` (Arc), so those, the older `MSI_ENDPOINT` and `MSI_SECRET`, and the variables of the credentials `DefaultAzureCredential` tries first (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_FEDERATED_TOKEN_FILE`, ...) are removed from the command. `az` uses a managed identity only after `az login --identity`, which writes `~/.azure`, so fob does not change what `az` does. `--no-server` turns it off.

AKS: `fob creds --format k8s-exec` asks for the AKS server application `6dae42f8-4368-4678-94ff-3960e28e3630`, as `kubelogin` does.

## Agent sessions

The Azure CLI (`azure/cli/core/auth/agentic_session.py` and `msal_credentials.py`, read 2026-11-25) reads `COPILOT_AGENT_SESSION_ID` and, outside the broker, sends it as `client_session` in the token request's body and query; with the broker it also sends the claims challenge `{"access_token": {"xms_cli_sid": {"values": [<id>]}}}`. Entra ID then marks the tokens as an agent's, for Conditional Access, Defender and Purview. omnifob makes the same refresh-token requests as the non-broker path, so under an agent with that variable it sends `client_session` the same way, for every token (Resource Manager, the managed identity endpoint, AKS).
