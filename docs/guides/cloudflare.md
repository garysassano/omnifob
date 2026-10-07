# Cloudflare

The `cloudflare` integration mints short-lived API tokens, scoped by permission name, from one bootstrap token.

## The bootstrap token

Cloudflare has no sign-in that lets another app create API tokens, so `fob login cf` needs one bootstrap token that can create others. You make it once in the dashboard; omnifob keeps it in the keychain and mints short-lived tokens from it. There are two kinds, set with `token_type`, and they map onto the AWS model:

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

## Templates

Cloudflare comes with built-in templates; `fob cf templates <integration>` lists them and `fob cf permissions <integration> [filter]` lists every permission name your account offers. Names can be written as the API does ("Workers Scripts Write") or as the dashboard does ("Workers Scripts Edit").

- `workers`: everything a Worker and its usual bindings need. The dashboard's "Edit Cloudflare Workers" template plus what it never caught up with: D1, Queues, Workers AI, Vectorize, Hyperdrive, Containers, Pipelines, and when your account offers them Browser Run, AI Gateway, Observability, Builds, Agents, Secrets Store and more.
- `dns-read`, `dns-edit`, `read`.

A template lists `permissions` (required) and `optional` ones, which are added when the account offers them and skipped otherwise.
