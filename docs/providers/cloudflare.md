# Cloudflare

## How the official CLIs sign in

Studied in `cloudflare/workers-sdk` (wrangler) and `cloudflare/cf` on 2026-10-06.

- The auth layer moved out of wrangler into `@cloudflare/workers-auth` (internal package, v0.13.0) shared by wrangler and the new `cf` CLI (`npm i -g cf`, 1.0.0-beta.12, "the agentic CLI for the entire Cloudflare API").
- OAuth endpoints: `https://dash.cloudflare.com/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`, plus `/oauth2/device/auth` for device flow.
- wrangler client ID `54d11594-84e4-41aa-b438-e81b8fa78ee7`, callback `http://localhost:8976/oauth/callback`. `cf` client ID `cbca97e7-c331-4cdd-8fd8-e25a451b98bf`, callback port 8877.
- Both now have **auth profiles** (`wrangler auth create <name>`, `cf auth create <name>`) and **directory bindings** (`auth activate` binds a profile to a directory), stored in the OS keyring under service `cloudflare` (cf) or wrangler's own.
- The `cf` OAuth app registers the scope `account_api_tokens:create`, so a browser sign-in can mint account-owned API tokens.
- Variables read by the tools: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` (also `CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL` for the legacy global key).

## Third-party OAuth

From developers.cloudflare.com/fundamentals/oauth:

- Any account can register OAuth clients (dashboard: Manage Account > OAuth clients, or `POST /accounts/{id}/oauth_clients` with "OAuth Clients Write").
- CLI apps must use Authorization Code with PKCE (S256), `token_endpoint_auth_method = none`. **Device flow is not available to third-party clients.**
- Scope names correspond to API token permission names; `GET /oauth/scopes` lists them.
- Unverified: whether `account_api_tokens:create` is requestable by a third-party client.

## Token API

- User-owned tokens: `POST /user/tokens`, permission groups from `GET /user/tokens/permission_groups`. The bootstrap token comes from the "Create additional tokens" template (User > API Tokens > Edit, only available in that template).
- Account-owned tokens: `POST /accounts/{id}/tokens`, groups from `GET /accounts/{id}/tokens/permission_groups`; bootstrap needs Account > Account API Tokens > Edit.
- Policies: resources `com.cloudflare.api.account.<id>: "*"`, zones of an account as `com.cloudflare.api.account.<id>: {"com.cloudflare.api.account.zone.*": "*"}`, the user as `com.cloudflare.api.user.<tag>: "*"`. Permission groups carry their scope.
- `expires_on` and `not_before` as `YYYY-MM-DDTHH:MM:SSZ`; optional `condition.request.ip` CIDR lists.
- Expired tokens stay listed until deleted.

## How omnifob does it

- Integration `type = "cloudflare"` with a stored bootstrap token (`fob login <name>` prompts for it with instructions).
- Templates list permission _names_; names resolve to IDs at mint time, case-insensitive, with suggestions for typos.
- One policy per resource scope, limited to the profile's account; user-level permissions get the user tag from the bootstrap token's own policy (no extra permission needed).
- Built-in templates: `workers` (the full developer platform: the dashboard's "Edit Cloudflare Workers" set plus D1, Queues, Workers AI, Vectorize, Hyperdrive, Containers, Pipelines, and optional Browser Run, AI Gateway, Observability, Builds, Agents, Secrets Store, CI, Cloudchamber, Images, AI Search, Email Sending), `dns-read`, `dns-edit`, `read`. Required names verified against the docs; optional names are guesses where the docs lag the dashboard, which is why they are optional.
- Dashboard "Edit" and API "Write" names are interchangeable in templates. An Edit permission includes read: a token with only "Workers Scripts Write" lists scripts (checked 2026-10-07).
- `fob cf add-template` groups the permission catalogue by service (the name without Read, Write or Edit) and asks for a level per service, after create-cf-token's service-grouped picker; user-level services are hidden for account-owned bootstraps.
- `ips` becomes the token's `condition.request_ip.in`. `"current"` asks `/cdn-cgi/trace` on the API host twice, bound once to IPv4 and once to IPv6, so whichever version a tool later uses is allowed. Checked live 2026-10-07: from another address the API answers "Cannot use the access token from location: <ip>".
- Bucket-level R2 permissions have the scope `com.cloudflare.edge.r2.bucket`; their resources are `com.cloudflare.edge.r2.bucket.<account>_<jurisdiction>_<bucket>`, with jurisdiction `default` or `eu`. R2's S3 access key is the token ID and the secret the SHA-256 of the token value. Checked live 2026-10-07 with two temporary buckets: `aws s3 cp` worked in the listed bucket and got AccessDenied in the other.
- `fob exec --revoke` mints outside the cache, runs the command as a child instead of replacing omnifob with it, and deletes the token by ID when the child ends. omnifob ignores Ctrl-C and hangups while it waits (the child receives them from the terminal) and forwards SIGTERM.
- The dashboard's own "Edit Cloudflare Workers" template (seen 2026-10-06): Workers Scripts, Workers Routes, Account Settings Read, User Details Read, Workers Tail Read, Workers R2 Storage, Cloudflare Pages, Workers Builds Configuration, Workers Agents Configuration, Memberships Read, Workers Observability, Containers. No D1, Queues, Workers AI, Vectorize, Hyperdrive or Browser Run.
- Tokens named `omnifob <template>` (until 0.2: `omnifob:<profile>@<time>`, still recognised). Their IDs are tracked per profile in the catalog state file; expired ones are deleted after each mint and on `sync`, all of them on `logout`, and those of one profile on `revoke`. The API can report an expired token as `active`, so expiry is judged by `expires_on`.
- Console: `https://dash.cloudflare.com/<account_id>`.

## Behaviour learned live

- New tokens reach D1 about 3 s after creation and flap before settling; omnifob waits for three consecutive acceptances when the token includes a D1 permission. Workers, KV, Queues, R2, Vectorize, Hyperdrive and Workers AI accept new tokens immediately.
- The `/user/tokens/verify` endpoint says "active" before D1 accepts the token, so it cannot be used to detect readiness.
- A "Create Additional Tokens" bootstrap token can list permission groups (413 on 2026-10-06) and create, list and delete user tokens.

## Bootstrap kinds (2026-10-07)

- User-owned and account-owned bootstraps both stay first-class. As in AWS, it is one identity for many accounts (user-owned) versus a role in one account (account-owned). No prompt to choose; the README documents both.
- Account-owned: template URL pre-fills name, `account_api_tokens` edit and the account; tested in the browser on 2026-10-07 (the dashboard's buttons are "Review token" then "Create token"; the docs still say "Continue to summary"). Tokens are `cfat_`-prefixed. Product support: everything omnifob's `workers` template needs; not Turnstile, Registrar, Page Rules, Super Bot Fight Mode, Intel Data Platform, Zero Trust Client Platform.
- The account token list has a "Created via" column ("Direct" for dashboard-made tokens); what it shows for API-minted tokens is still to be seen.
- No OAuth route for third parties: none of the 392 OAuth scopes creates API tokens.
- Tokens created through the API cannot manage tokens: asking the bootstrap to mint a child with "Account API Tokens Write" fails with code 1001, "sub-token is not allowed to have permissions to manage other tokens" (2026-10-07). Only dashboard-made tokens can create, roll or delete tokens, so nothing omnifob mints can, and the bootstrap can only be retired in the dashboard or by rolling. Whether a dashboard-made token may delete itself is untested.

## Sessions (2026-10-07)

- A dashboard-made token with "Account API Tokens Edit" can edit itself: setting and removing its own `expires_on` worked live, and the token stayed active. `session` uses this right after login, keeping the token's name, policies and IP condition.
- The same holds for anyone holding the token, so a session limits a stolen copy's lifetime but cannot stop an intruder during the session from removing the expiry or minting long-lived tokens.
- Template URLs cannot pre-fill an expiry or IP filter (only `permissionGroupKeys`, `name`, and for user tokens `accountId` and `zoneId`), which is why fob sets the expiry itself.
- Cloudflare has no second factor for API token creation and no OAuth scope that creates tokens for third-party clients; the dashboard sign-in is the only Cloudflare-enforced second factor, hence a new bootstrap per session.
