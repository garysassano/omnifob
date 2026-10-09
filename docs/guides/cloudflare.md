# Cloudflare

omnifob mints short-lived Cloudflare API tokens, scoped by permission name, from one sign-in. There are two ways to sign in, each its own integration type; templates, profiles and minting are the same for both:

- `cloudflare-oauth`: in the browser, like `wrangler login`. You pick the accounts on Cloudflare's consent page, and fob renews the sign-in by itself.
- `cloudflare-token`: a bootstrap token you create once in the dashboard and paste. Works without a browser, and can be owned by an account rather than by you.

## Browser sign-in

```toml
[integrations.cf]
type = "cloudflare-oauth"
client_id = "..."
session = "12h"   # optional: sign in again after this long
```

`fob login cf` opens Cloudflare's consent page. Pick the accounts fob may use, turn on **Account API Tokens Write** under Sensitive scopes (minting needs it, and Cloudflare leaves it off by default), and authorize. fob receives the answer on `http://localhost:8977/callback`, keeps the refresh token in the keychain, and renews the sign-in in the background until `session` ends or you run `fob logout cf`, which also revokes it on Cloudflare. **My Profile > Access Management > Connected Applications** in the dashboard lists and revokes it too.

Every approved account gets a profile per template. A browser sign-in can only mint the permissions it was granted, so fob asks for the scopes your templates need; optional template permissions you decline on the consent page are left out of the tokens.

### The OAuth client

The consent page belongs to an OAuth client, which omnifob does not ship yet, so register one in your account once:

1. **Manage Account > OAuth clients > Create client**: name `omnifob`, response type Code, grant types Authorization Code and Refresh Token, token authentication method None, redirect URL `http://localhost:8977/callback`. Leave the optional fields empty.
2. Pick at least the Account API Tokens Edit scope and create the client. Copy its client ID into `client_id`.
3. Give the client every scope your templates need. The dashboard's picker does not offer every one (Workers Scripts Read and Write are missing), so set them through the API with a token that has **OAuth Client: Edit**: `PATCH /accounts/<account>/oauth_clients/<client_id>` with `scopes` (and `optional_scopes` for those that may be declined). The `scope` parameter of the sign-in URL `fob login` prints lists the scopes it requests.

The client is private: only members of the account that owns it can sign in with it, but they can approve any account they belong to.

## The bootstrap token

Without a browser sign-in, `fob login cf` needs one bootstrap token that can create others. You make it once in the dashboard; omnifob keeps it in the keychain and mints short-lived tokens from it. There are two kinds, set with `token_type`, and they map onto the AWS model:

|             | Account-owned (`token_type = "account"`)                                                                                                                                                                                    | User-owned (`token_type = "user"`, the default)                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Like in AWS | An IAM role scoped to one account                                                                                                                                                                                           | One Identity Center sign-in that reaches many accounts                                                                              |
| Reaches     | The configured `account_id` only                                                                                                                                                                                            | Every account you belong to; omnifob discovers them                                                                                 |
| Owned by    | The account, not a person; keeps working if you leave it                                                                                                                                                                    | You; acts as you                                                                                                                    |
| Creating it | `fob login` opens a pre-filled form (name "omnifob bootstrap", permission Account API Tokens: Edit): Review token, Create token, copy                                                                                       | `fob login` opens the API Tokens page: Create Token, "Create Additional Tokens" template, name it "omnifob bootstrap", create, copy |
| If it leaks | Limited to one account; the `cfat_` format is recognised by secret scanners                                                                                                                                                 | Can create tokens for all your accounts                                                                                             |
| Limits      | No user-level permissions (User Details, Memberships), so `wrangler whoami` shows less; not yet supported by Turnstile, Registrar, Page Rules, Super Bot Fight Mode, Intel Data Platform and the Zero Trust Client Platform | None                                                                                                                                |

Use account-owned when you work in one account (Cloudflare recommends account tokens for durable integrations), user-owned when one token should cover several accounts. You can configure both, as two integrations.

After creating the token, press Enter at the prompt and fob reads it from the clipboard, so it never appears on screen; `--from-clipboard` does the same without a prompt, and `--token-stdin` reads it from a pipe. Templates leave out user-level permissions for account-owned tokens.

## Sessions

A bootstrap token without an expiry works forever and needs no second factor, so anything that copies it from your machine keeps full access to the account. With `session`, the bootstrap works like an AWS IAM Identity Center sign-in instead:

```toml
[integrations.cf]
type = "cloudflare-token"
token_type = "account"
account_id = "..."
session = "12h"
```

- `fob login cf` opens the pre-filled form as usual. The dashboard asks for your password and second factor when its own session has lapsed. Create the token, copy it, and fob makes it expire after `session`.
- When the session ends, fob asks you to sign in again, as it does for AWS. Cloudflare enforces the expiry, so a stolen copy stops working too.
- Signing in again deletes the previous session's bootstrap, and `fob logout cf` deletes the current one, so they do not pile up.
- Tokens minted during the session keep their own lifetime.

Someone who controls your machine during a session can still create long-lived tokens with it, just as someone holding an AWS administrator session can create IAM users. A session limits how long a stolen bootstrap works; it does not replace keeping your machine clean.

## Templates

Cloudflare comes with built-in templates; `fob cf templates <integration>` lists them and `fob cf permissions <integration> [filter]` lists every permission name your account offers. Names can be written as the API does ("Workers Scripts Write") or as the dashboard does ("Workers Scripts Edit").

- `workers`: everything a Worker and its usual bindings need. The dashboard's "Edit Cloudflare Workers" template plus what it never caught up with: D1, Queues, Workers AI, Vectorize, Hyperdrive, Containers, Pipelines, and when your account offers them Browser Run, AI Gateway, Observability, Builds, Agents, Secrets Store and more.
- `dns-read`, `dns-edit`, `read`.

A template lists `permissions` (required) and `optional` ones, which are added when the account offers them and skipped otherwise.

### Making your own

`fob cf add-template <integration> <name>` lists the services your account offers, searchable, and asks for the access level of each one you pick: Read or Edit (which includes read), as in the dashboard's token form. Pick "Done" and the template is saved to the config, with permission names rather than IDs, and its profiles are ready to use. Without a terminal, name the permissions instead:

```sh
fob cf add-template cf pages -p "Pages Edit" -p "Account Settings Read" --ttl 30m
```

`--replace` overwrites a template of the same name. A template named like a built-in one replaces it for that integration.

## Narrower tokens

Three template settings narrow what a minted token can do beyond its permissions:

```toml
[integrations.cf]
type = "cloudflare-token"
ips = ["current"]                  # every template: usable only from here

[integrations.cf.templates.backups]
permissions = ["Workers R2 Storage Bucket Item Edit"]
r2_buckets = ["backups", "eu/archive"]   # only these buckets; "eu/" for a jurisdiction
s3 = true                                # also hand out R2's S3 credentials
ips = ["203.0.113.0/24"]                 # replaces the integration's ips
```

- `ips` limits where the token can be used from: IP addresses, CIDR ranges, or `"current"` for this machine's public IPv4 and IPv6 addresses when the token is minted. Cloudflare rejects the token anywhere else ("Cannot use the access token from location"). A cached token stops working if your address changes; `fob exec --no-cache` or `fob revoke` gets a new one.
- `r2_buckets` lists the buckets that bucket-level permissions ("Workers R2 Storage Bucket Item Read" or "Edit") apply to. Account-level R2 permissions ("Workers R2 Storage Write") still cover every bucket.
- `s3 = true` adds the S3-compatible credentials R2 derives from the token, so S3 tools work without creating R2 API keys in the dashboard: `AWS_ACCESS_KEY_ID` (the token ID), `AWS_SECRET_ACCESS_KEY` (the SHA-256 of the token), `AWS_ENDPOINT_URL_S3` and `AWS_REGION=auto`. For example `fob exec cf backups -- aws s3 ls s3://backups`. These variables replace AWS credentials in that shell, so prefer `fob exec` over `fob use` for such templates.

## Tokens for one command

`fob exec <profile> --revoke -- <command>` mints a token for that command alone, outside the cache, and deletes it as soon as the command ends, including after Ctrl-C or when the terminal closes. Use it to hand a token to an agent or a script without leaving it valid for the rest of its lifetime. Tokens that cannot be deleted then (the network is down, say) still expire, and `fob revoke <profile>` deletes them later.
