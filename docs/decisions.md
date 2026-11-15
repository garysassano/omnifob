# Decisions

Newest last. Each entry says what was decided and why, so later changes can weigh the same reasons.

## 2026-10-06: Build a new tool rather than fork granted

granted is AWS-shaped throughout (`~/.aws/config` profiles, STS, console federation), and a fork would mean keeping up with upstream AWS fixes to keep unrelated features working. A new tool borrows the ideas without the coupling.

## 2026-10-06: Name omnifob, command `fob`

"omni" says every cloud; a fob is the small thing that opens your doors. Alternatives rejected: omnicloud (taken by a 656-star project and the GitHub user), omnikey (HID Global's card reader brand), omnipass (Softex's old fingerprint product), omnifox (reads as a fnox fork). Both binaries are installed; `fob` for daily use, `omnifob` for scripts.

## 2026-10-06: Rust

Same language as mise and fnox, which makes a later merge into fnox realistic. Official AWS SDK for Rust, `keyring-core` for every OS keychain, single static binary.

## 2026-10-06: Integrations produce profiles (Leapp's model)

An integration is something you sign in to once; sync discovers its profiles. Users configure a handful of integrations, never hundreds of profiles. Profiles are cached on disk without secrets and refreshed by `fob sync`.

## 2026-10-06: Two crates

`omnifob-core` holds config, storage and providers; `omnifob` holds the command line. Provider code can then move into another project (fnox) without the CLI.

## 2026-10-06: Secrets in the OS keychain through keyring-core

`keyring` v4 itself says applications should link `keyring-core` and pick stores. macOS Keychain, Windows Credential Manager, Secret Service on Linux, falling back to kernel keyutils when no Secret Service is running (WSL, servers). keyutils loses secrets on reboot; acceptable for now. Revisit an encrypted-file store (wrangler has one, `db-keystore` exists) if that annoys.

## 2026-10-06: AWS device flow first

Works on every machine including headless and WSL; PKCE needs a local callback server. aws-vault and granted both default to device flow. Superseded on 2026-11-08, below.

## 2026-10-06: Cloudflare bootstrap token first, OAuth second

Cloudflare's third-party OAuth only allows PKCE (no device flow) and it is unverified whether `account_api_tokens:create` is available to third-party clients. The bootstrap token works today and is a one-click, one-time setup. OAuth comes next, keeping the bootstrap token as fallback. Superseded on 2026-10-09, below.

## 2026-10-06: Permissions by name, not ID

Scoping tokens in the dashboard is the pain omnifob removes, and fnox needs IDs too. Names are resolved at mint time from the permission groups API, so they never go stale in config, and typos get suggestions.

## 2026-10-06: Clean up expired minted tokens

Cloudflare keeps expired tokens listed. Minted tokens carry the `omnifob:` prefix, and after each mint expired ones with that prefix are deleted. Tokens omnifob did not create are never touched.

## 2026-10-06: Shell switching through a wrapper function

A process cannot change its parent's environment, so `fob activate <shell>` prints a `fob` function where `use` and `unuse` eval `fob env`. `fob env` remembers the variables it set in `OMNIFOB_VARS` and removes stale ones when switching. The picker draws on stderr so it works inside `$(...)`.

## 2026-10-06: Credential output formats for other tools

`--format json` (generic), `fnox` (command lease contract), `credential-process` (AWS SDKs). This makes omnifob useful before every provider is native, and is the integration point with fnox.

## 2026-10-07: Release notes in releases only

There is no CHANGELOG.md alongside the release notes. Notes are written once, in the signed tag's message (`--cleanup=verbatim` keeps Markdown headings), and the release workflow copies them into the GitHub release. Generated notes are only a fallback: they list merged pull requests, and changes here have gone straight to main.

## 2026-10-07: Pull requests for changes

Changes go through a pull request, squash-merged after CI passes, matching the repository's merge settings (squash only, title and description from the PR). Small changes (a typo, a log line) may still go straight to `main`. Repository settings match `garysassano/shin-bucket-deployment`, except that Dependabot alerts stay enabled here: the baseline never turns a security feature off to match the reference.

## 2026-10-07: No profile aliases for now

Profile ids are long (`<integration>/<account>/<role or template>`), but they are rarely typed: any words that match one profile select it, a whole-segment match wins, and shell completion fills in the rest. Aliases would add a second naming scheme to learn and keep in sync for little gain. The repeated case, the same profile in the same project, is better served by a per-directory default profile, which is planned. Revisit if real collisions keep forcing long queries; an alias would then be an exact match checked before word matching, so it never changes what existing queries select.

## 2026-10-09: Cloudflare browser sign-in as its own type

Third-party OAuth clients can request "Account API Tokens Write" now (a sensitive scope the consent page leaves off by default), and an access token with it creates and deletes account-owned tokens in every account approved on the consent page. So a browser sign-in replaces the bootstrap token without losing what minting gives: narrow tokens per template, IP limits, R2 bucket limits and S3 credentials, and `--revoke`.

The sign-in method is the integration type, as with `aws-sso`: `cloudflare-oauth` and `cloudflare-token` (the bootstrap token, formerly `cloudflare`). Both share configuration, templates and minting, so a template gives the same token either way. A clean break from `cloudflare` while omnifob is 0.x, named in the release notes.

A sign-in can only mint permissions whose scope the consent granted; Cloudflare refuses the rest. omnifob therefore requests the scopes its templates need, from a table of permission name to scope ID, since the IDs do not follow the names (`page.write` for Pages, `query-cache.write` for Hyperdrive). The OAuth client must have those scopes registered. Until omnifob ships a public client, each user registers a private one; a public client needs a verified domain for its client URL, and making a client public cannot be undone.

## 2026-10-09: GitHub accounts stay with git and Git Credential Manager

omnifob briefly gained per-directory profiles, a git credential helper and a GitHub sign-in, meant to replace a hand-written gh wrapper that picks a GitHub account per directory. All three were reverted before any release.

git's `includeIf` already maps each directory to an account (`credential.https://github.com.username`, next to `user.name` and `user.email`), and Git Credential Manager already keeps one token per account and picks it by that username. omnifob's versions repeated the mapping in a second place, chose by directory while ignoring the username git sends, and needed an OAuth app registered and a sign-in per account. The wrapper could not go away either, since a shell function is invisible to non-interactive shells such as coding agents. The only gain was the `read:org` scope Git Credential Manager does not request, which a classic token stored in it also provides. omnifob keeps the `github` token preset for handing a token to a command; [providers/github.md](providers/github.md) has what was learned.

Per-directory profiles went too: nothing used them yet, and wrangler and `cf` bind accounts to directories themselves. Revisit them when a provider without that needs it, keeping the mapping in omnifob's config rather than in repositories.

## 2026-11-08: AWS browser sign-in by default, device flow as fallback

The AWS CLI has signed in with the authorization code flow and PKCE by default since 2.22.0; the device flow is behind `--use-device-code`. The device flow lets anyone who tricks a user into entering a code take over the session (device code phishing), while PKCE binds the sign-in to a listener on the machine that started it. The 2026-10-06 reason for the device flow no longer holds: omnifob has had a loopback callback since the Cloudflare browser sign-in, and on WSL the Windows browser reaches `127.0.0.1` in WSL (checked 2026-11-08). `fob login` uses the device flow with `--device-code`, and on its own over SSH and in containers, where a browser cannot reach the loopback listener (granted makes the same check).

Two details follow the AWS CLI rather than plain OAuth: the client is registered with the portless redirect `http://127.0.0.1/oauth/callback` and the sign-in uses any free port (RFC 8252, section 7.3), and the consent page takes the scopes as `scopes`, not `scope`.

## 2026-11-08: Renew AWS sessions under a lock shared by every process

Each refresh returns a new refresh token, and omnifob treats the old one as spent (as aws-vault does; whether Identity Center refuses a reused one is not verified), so two `fob` processes renewing the same session at once (parallel `credential_process` calls after a laptop wakes, or two background renewals) left the loser with a spent token and a false "session ended". Renewal now runs under a file lock per integration and reads the token again once it holds the lock. A 401 from the portal renews once and retries, and drops the session only if it still holds the refused token, so a session another process just renewed is never thrown away.

## 2026-11-08: IAM users through STS sessions, like aws-vault

granted and aws-vault both support IAM users, and some accounts still have them. omnifob stores the access key in the keychain and never exports it: profiles get a `GetSessionToken` session, and roles are assumed with that session rather than with the key. Roles then get sessions of up to 12 hours (role chaining would cap them at one), and one MFA code covers every role for the session's length. Long-lived keys stay discouraged; this keeps them off disk and out of environments where they exist anyway.

## 2026-11-08: MFA codes through a prompt the embedder registers

`omnifob-core` stays usable as a library, so it never reads the terminal. The command line registers a prompt when stdin and stderr are terminals; elsewhere (background renewal, `credential_process` without a terminal) a profile that needs a code fails with a message saying to run `fob creds` in a terminal first. Fetches are serialized per profile, so parallel `credential_process` calls ask once and share the result.

## 2026-11-08: Google and Azure sign in with their CLIs' own clients

A sign-in needs an OAuth client. Google publishes none for third-party tools, and registering one means a Google Cloud project, a consent screen and, for the `cloud-platform` scope, either verification or a warning page. omnifob signs in with gcloud's installed-app client, as gcloud itself does, so it works wherever gcloud works and needs no setup; `client_id` and `client_secret` name a client of your own instead. Rolle reads the refresh token gcloud leaves in a plain file instead; omnifob keeps its own sign-in in the keychain and does not need gcloud installed. For Azure, the Azure CLI's public client is the default of Microsoft's own Azure Identity libraries for interactive sign-in, so using it follows Microsoft's practice.

Both follow their CLI's flows: PKCE with a `localhost` redirect by default; from another device, gcloud's pasted-code page and Entra ID's device flow.

## 2026-11-08: Modal as a stored token

The Modal CLI creates tokens through its gRPC API (`TokenFlowCreate` and `TokenFlowWait`), which can make them expire, and stores them in plain text in `~/.modal.toml`. Implementing that flow would mean hand-encoding protobuf for an internal API. The `modal` preset stores the token ID and secret in the keychain and hands them out as `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`, which the Modal client reads before its config file (checked with Modal 1.6.3).

## 2026-11-08: Presets carry fixed variables; Unikraft Cloud as a stored token

Unikraft Cloud has two CLIs. `kraft` (KraftKit) builds unikernels and has a `kraft cloud` subcommand, deprecated with support ending 2026-11-26; `unikraft` (`unikraft-cloud/cli`) replaces it. Both sign in to the same control plane, and the token they keep is a static robot-account credential (`base64(robot$<name>.users.kraftcloud:<secret>)`) with no expiry and no API to mint narrower ones, so the `unikraft` preset stores it. `kraft` reads `UKC_TOKEN` and `UKC_METRO` whenever they are set; `unikraft` reads them only with `UNIKRAFT_PROFILE_ENV=true`, so presets gained fixed variables (`vars`, overridden by the integration's own) and this one sets that flag. Checked live with `unikraft quotas` and `kraft cloud quota`, each given only what `fob exec` exports.

## 2026-11-15: CI runs the OS matrix on the top of a stack, checks the minimum Rust, and runs cargo deny

The Linux, macOS and Windows jobs (`check`, and `msrv` below) run on every push to `main` and on every pull request that is not part of a stack. In a stack of pull requests they run only on the top PR: its tree contains every layer below it, so a pass there covers the whole stack, and running the matrix on each layer would repeat the same builds once per layer on every rebase. The stack is merged once the top PR passes, and the push to `main` runs the matrix again on what was merged. A job-level `if` is enough because `main` has no required status checks, so a skipped job blocks nothing.

`rust-version` in the workspace `Cargo.toml` is a promise, so `msrv` installs exactly that toolchain, read from the manifest, and runs `cargo check --all-targets` on all three systems, since much of the code is behind platform `cfg`s. It runs no clippy or tests, because lints differ between compiler versions. The AWS SDK crates currently set the floor at 1.94.1.

`cargo deny` (`deny.toml`) checks every target and all features, and runs ungated because it takes seconds. Every RustSec advisory and every yanked version fails it. Licences are an allow-list of those in the tree that are compatible with shipping MIT binaries, so a new licence needs a review before it is added. Only crates.io is allowed as a source, and wildcard versions are refused. Duplicate versions only warn, since they come and go with the ecosystem. Three advisories are accepted by ID: RUSTSEC-2026-0370, -0371 and -0372 mark `zvariant`, `zbus_names` and `zvariant_derive` unmaintained because zbus 6 absorbed them, and they reach omnifob only through the Linux Secret Service keyring store (`zbus-secret-service-keyring-store` → `secret-service` → zbus 5). They are notices, not vulnerabilities, and no stable release of that chain uses zbus 6 yet (`secret-service` 6 was a release candidate on 2026-11-15). Drop the three entries once the keyring store moves to zbus 6.

Dependabot opens one grouped pull request a week for crates and one for GitHub Actions, so pins and dependencies stay current between manual update passes.

## 2026-11-15: AWS partitions in one type, read from role ARNs

The console sign-in guessed the partition from a Region prefix, treated every unknown prefix as commercial, and assumed each partition has an unprefixed sign-in host. The European Sovereign Cloud has none, so a portal there without `default_region` sent the sign-in to `signin.amazonaws-eusc.eu`, which does not resolve. `Partition` (`providers/aws_partition.rs`) now holds the partitions with a public console, their ARN names and hosts, and is parsed from the role ARN where a profile has one, since an ARN states its partition and a Region only implies it. The isolated partitions are recognised by their Region prefixes (`us-iso-`, `us-isob-`, `eu-isoe-`, `us-isof-`) and ARN names and refused by name. Without an exported Region the other partitions keep their unprefixed sign-in host, which matches the unprefixed console the sign-in lands on; only the European Sovereign Cloud falls back to the portal's Region. Cross-partition profiles use the same type to check that a source Region and a destination role are in different partitions.

## 2026-11-15: Only a final refresh error ends an AWS session

Every failed refresh used to count as the end of the session: after a 401 from the portal the session was deleted, and an expired token gave "run `fob login`", even when the refresh had only timed out or met a 500. A laptop waking offline, or a brief Identity Center outage, then sent the user through a browser sign-in although the session at Identity Center was intact. `CreateToken` documents which errors are final (`InvalidGrantException`, `ExpiredTokenException`, `InvalidClientException`, `UnauthorizedClientException`, `AccessDeniedException`); only those delete the session and ask for a sign-in. Any other failure keeps the session and reports the cause, with a hint to sign in again if it persists, as the AWS CLI keeps its token cache when a refresh fails. `InvalidClientException` and `UnauthorizedClientException` also delete the refused client's registration, since the next sign-in would otherwise reuse it.

## 2026-11-15: Only this sign-in's callback ends the wait on the loopback listener

The listener behind the four browser sign-ins (AWS, Google, Azure, Cloudflare) served one connection at a time and treated every failure as the end of the sign-in: a connection that sent nothing for ten seconds, as browsers open speculatively, aborted it, and held up the real callback meanwhile; and a callback with another `state`, which any local page or an old tab can send, cancelled it. The listener now serves connections side by side, closes one that has not sent its request within two seconds (and the oldest when more than 64 wait, or when file descriptors run out), answers other paths with 404 and a callback with another `state` with 400, and keeps waiting until the sign-in's deadline. Only a callback with this sign-in's `state` ends the wait, with its code or the provider's `error`; `state` is checked before `error`, since RFC 6749 returns it with errors too, so a refusal without it cannot cancel the sign-in either.

## 2026-11-15: One HTTP client with timeouts for calls outside the AWS SDK

The Cloudflare API client, the stored-token check and the AWS console sign-in built a bare `reqwest::Client`, which has no timeout, so a server that accepted the connection and never answered hung the command. The Google, Azure and Cloudflare OAuth clients each built their own with a user agent but no timeout either. They all now come from `http::client()` in `omnifob-core`: a 10 second connect timeout (the AWS SDK clients use 3.1 seconds), a 30 second limit on the whole request, long enough for the slowest call a provider makes (a token mint or an account listing page), and the `omnifob/<version>` user agent, which Cloudflare's bot protection requires. The Cloudflare trace lookup keeps its own 5 second limit on the same builder.

## 2026-11-15: `fob console` signs in with new credentials

Without `SessionDuration`, a console session lasts as long as the credentials given to the federation endpoint, and `fob console` passed cached ones, which are handed out until five minutes before they expire, so the console could sign the user out almost at once. It now gets new credentials for every console sign-in, for every AWS profile type: `GetRoleCredentials` for an Identity Center role, `AssumeRole` for a chained role and an IAM user's role, and (as before) a new `GetFederationToken` session for an IAM user's own console. The new credentials also replace the cached ones, so the next command reuses them.

The alternative was to keep cached credentials that still had at least half their lifetime left. That saves one call, but the console session would still end at an unpredictable time, as early as half an hour into a one-hour role, and the user cannot tell which they got. A new set costs one fast API call with no prompt for Identity Center roles and IAM users' roles (their user session, and its MFA, is reused). The cost lands on chained roles with `mfa_serial`, which ask for a code each time the console opens, the same as `--no-cache` does; an IAM user's role is also still capped by what is left of the user's session. Chained roles cannot take a console session length, since AWS refuses `SessionDuration` for role chaining. For an IAM user's role, `console_duration` (below) sends one, which AWS documents as independent of the credentials' duration; whether it holds past the end of the user's `GetSessionToken` session is not stated and has not been tried live.

## 2026-11-15: `console_duration` has no default

The federation endpoint's `SessionDuration` (15 minutes to 12 hours) lets a console session outlast its credentials, for credentials from `AssumeRole*` and Identity Center; it fails for role chaining and `GetFederationToken`. `fob console --duration` and a `console_duration` key on `aws-sso` integrations and `aws-iam` roles send it. It is opt-in with no default: `SessionDuration` must be shorter than the role's maximum session duration (for an Identity Center role, the permission set's session duration, one hour by default), omnifob cannot see that maximum, and a value at or above it makes the sign-in fail, so any built-in default would break `fob console` for roles with a short maximum. Left unset, the console lasts as long as the new credentials it is opened with. `--duration` is refused before any call for chained roles and an IAM user's own session, and the integration's `console_duration` is not sent for its chained roles.

The credentials now go to `getSigninToken` in a form POST, which the federation endpoint accepts, instead of the query string of a GET, so they stay out of proxy and access logs and out of error messages, which quote the request URL. `--service` and `--region` build the destination as granted does (`https://<console host>/<service>/home?region=<region>`); the service is the console path as given, without granted's shortcut table, which would need upkeep as consoles move, and the Region is checked against the profile's partition. `Partition` refuses any Region not shaped like one (lowercase words joined by hyphens, ending in a number), in `of_region` and wherever a Region becomes part of a host name: it treats unknown prefixes as commercial so new Regions keep working, and without the shape check a Region such as `attacker.example#` turned the sign-in host into another one, which would have received the credentials.

## 2026-11-15: The credential cache holds the configured lifetime only

A `--ttl` request used to replace a profile's cached credentials, so `fob exec --ttl 15m` once left every plain command after it with credentials of 15 minutes, renewed early and handed out until five minutes before they ended. Credentials asked for with `--ttl` are now not cached, and an IAM user's session started with `--ttl` is not kept as the session its roles are assumed with. The cache therefore holds only credentials of the configured lifetime: those a plain command gets, and the new ones `fob console` gets, which replace the cached ones. A `--ttl` command always asks the provider anyway, so not caching its credentials costs nothing.

`fob sync` replaced an integration's profiles without touching the credentials cached for the ones that went away (an assignment removed, a role taken out of the config, an integration deleted), so keychain entries accumulated. It now deletes `credentials/<profile id>` for every profile the sync dropped or whose target changed under the same id (a chained or IAM user's role whose `role_arn` moved to another account), after the new profile list is saved; such credentials belong to the old target and would otherwise be handed out with the new account's `AWS_ACCOUNT_ID`. A small leak remains: a background renewal, or a command started with the old profile list, can write `credentials/<id>` for a dropped profile after the sync has pruned it, and later syncs no longer know that profile, so the entry stays until it is deleted by hand or the keychain forgets it (the kernel keyring on reboot). Closing it would mean listing the keychain's `credentials/` entries, which not every store can do.

AWS credentials now carry `AWS_ACCOUNT_ID`, and the `credential-process` output `AccountId`, for the SDKs' account-based endpoints. It is added when credentials are handed out rather than by each provider, so credentials cached before the change carry it too. The account is the profile's for Identity Center roles and an IAM user's session (whose account now comes from `GetCallerIdentity`'s `Account` rather than the fourth field of the ARN), and the role ARN's for chained roles and an IAM user's roles, as the profile recorded it at discovery rather than as the config states it now: credentials cached before a `role_arn` edit belong to the old account until `fob sync` drops them, and are labelled with it meanwhile. Only a role profile synced before the account was recorded falls back to the config.

## 2026-11-15: Integration names are letters, digits, `.`, `_` and `-`

Integration names could contain anything but `/`, and a name with a space broke the `credential_process = fob creds <id> ...` line that `fob export aws-config` writes, since the AWS guide requires double quotes around a parameter with a space. `Config::parse` now accepts only `[A-Za-z0-9._-]`, not starting with `-` (the command line would read such a name as an option), rather than the export quoting the id: one rule then covers every place the name ends up, the AWS config line, keychain keys (`aws-sso/<integration>/token`), lock file names (where `a b` and `a_b` would share `aws-sso-a_b.lock`) and the WSL vault's file names, where quoting would have fixed only the first. Account and role labels already went through `slug`, and names `fob import aws` suggests always did. A config with another name fails with an error that names `fob rename "<old>" <new-name>`, which reads the config without the check so it can fix it, and refuses a new name that breaks the rule; `fob cf add-template` refuses such a template name, since template names become the last segment of profile ids. This breaks configs with other characters in a name, which 0.x allows; the release notes name it.

## 2026-11-15: `fob import aws` reads the AWS config as the SDKs do

The AWS CLI v2 keeps an inline comment in a value (`region = eu-west-1 # home` reads as `eu-west-1 # home`, which it then refuses as a Region), while the SDKs' profile parser drops a `#` or `;` comment that follows whitespace. The import follows the SDKs, since a line like that is meant as a comment and the SDKs are what most tools reading the file use. Static keys are not imported at all: profiles that roles are assumed from become `aws-iam` integrations, their key values are dropped while parsing, and the user stores the key with `fob login`, which checks it with STS before keeping it.

## 2026-11-15: Cross-partition roles get their own `cross_partition` table

Roles in another partition, reached with STS `GetWebIdentityToken` and `AssumeRoleWithWebIdentity`, are configured under `[integrations.<name>.cross_partition.<label>]` on `aws-sso` integrations, not as a flag on `chained`. The required keys differ (`audience` and the destination `region`, which a chained role does not need), the duration limits differ (up to 12 hours rather than the one hour of role chaining), and the errors point at different administrators (outbound identity federation in the source account, an OIDC provider and trust policy in the destination). The table is named `cross_partition` because that is AWS's own term for the feature, so it is what a user searches for; `federated` already means three other things in this codebase (console federation, `GetFederationToken`, SAML). The config is checked when it loads, so mistakes surface before any call: `role_arn` must be an IAM role ARN in a partition other than the source Region's, which must be the portal's partition, where the Identity Center role's credentials work; `region` must be in the partition of `role_arn`; `audience` is 1 to 255 characters, since it must equal a client ID of the destination's IAM OIDC provider and IAM takes client IDs up to 255 (`GetWebIdentityToken` alone would take 1000), and `duration` is 15 minutes to 12 hours. A label that would give a cross-partition role the same profile id as a chained role is refused, and one that collides with an Identity Center role at `fob sync` gets a `-cross-partition` suffix and a warning rather than failing the sync, so a renamed AWS account cannot stop `fob sync` from working. The suffix has a risk, which chained roles have shared all along with their `-chained` suffix: if an Identity Center account is later added or renamed so that its slug matches a label, the next sync gives the unsuffixed id to the Identity Center role, and an existing id (in `~/.aws/config`, scripts, shell history) then points at a different role in a different account, with only a warning to say so. Choosing labels that cannot match an account name (such as `gov-audit` rather than `audit`) avoids it. The other direction is checked too: a chained role's `role_arn` must be an IAM role ARN in the portal's partition, since `AssumeRole` cannot cross partitions, so one in another partition is refused at load with a pointer to `cross_partition` instead of failing at the first STS call, and `fob import aws` skips such a profile with that reason. A portal in an isolated partition, which `Partition` does not model, gets the ARN shape check only.

Every Region key on AWS integrations is now checked to be shaped like a Region when the config loads, so a malformed one fails with the key's name rather than at the first command that builds a host name from it. The check is the shape only, not `Partition::of_region`: that also refuses the isolated partitions' Regions by name, which would newly break `aws-sso` and `aws-iam` integrations that use them for credentials; the console still refuses them, and the cross-partition keys use the full partition check, since isolated partitions have no cross-partition access.

## 2026-11-15: Cross-partition tokens last a minute, are signed with ES384, and never leave memory

A cross-partition role's credentials come from a web identity token that the Identity Center role requests with `GetWebIdentityToken` and that `AssumeRoleWithWebIdentity` exchanges at once. The token asks for `DurationSeconds = 60`, the minimum STS allows: the exchange follows within the same call, so a minute is plenty; a short token fits any `sts:DurationSeconds` limit an administrator puts in the permission set; it can never outlive the source credentials (which `SessionDurationEscalation` would refuse), since those are new for each request and last the permission set's session duration; and a token that leaked would be useless sooner. The default of five minutes buys nothing here. `ES384` is the default signing algorithm because AWS recommends it ("optimal security and performance") and uses it in every cross-partition example, and STS in the destination partition accepts it; `RS256` stays available for an administrator who requires it with `sts:SigningAlgorithm`. The token is a bearer credential for its lifetime, so it is held in a type whose `Debug` output is redacted, sent once, and dropped; it is never cached, logged or written. Only `iss`, `sub` and `aud` are read from its payload, without a signature check, to show in errors and the debug log, because they are what the destination's administrator must match and `sub` (the reserved Identity Center role's ARN) is hard to guess. The AWS SDK logs whole requests and responses at trace level, so the CLI now drops the SDK orchestrator's trace events whatever `OMNIFOB_LOG` asks for, which keeps the token, role credentials and Identity Center tokens out of the log alike.

The exchange is sent from an STS client with no credentials provider, so it is unsigned, as AWS's examples do with `--no-sign-request`: no source credentials travel to the destination partition, where they mean nothing. A `SessionDurationEscalation` is retried once with new source credentials and an `ExpiredToken` once with a new token; `IDPCommunicationError` is left to the SDK, which already retries it as a server error with the same token. `fob console --duration` is refused for these profiles until it is tried live: the federation endpoint refuses `SessionDuration` for credentials from role chaining, and whether an exchange whose token role credentials requested counts as chaining is not documented. Refusing it costs little, since without `SessionDuration` the console session lasts as long as the credentials, and `duration` can make those last up to 12 hours; allowing it and being wrong would fail every console sign-in that sends it.

## 2026-11-15: Smaller release binaries, and only static musl builds for Linux

The release profile uses thin LTO, one codegen unit and stripped symbols. On x86_64 Linux this took `fob` from 34.5 MB (20.9 MB once stripped) to 17.2 MB (17.3 MB for the static musl build), and both release builds took about 2.5 minutes on two jobs. Fat LTO and `opt-level = "z"` were not tried: they trade a much longer build or a slower binary for a little more size. `panic` stays `unwind`, so a panic still prints its message and runs destructors.

Releases are built for x86_64 and ARM64 Linux, Apple Silicon and Intel macOS, and x86_64 and ARM64 Windows. Linux gets only static musl builds (`static-pie`), which start on any distribution, including Alpine; that is the single static binary the Rust entry promises. Up to 0.6.1 Linux had glibc builds from GitHub's Ubuntu runners, and a glibc build from Ubuntu 24.04 needs glibc 2.39, which leaves out Debian 12, Ubuntu 22.04 and RHEL 9. Publishing both would not help them: mise's `github:` backend scores an asset's C library against the host's, so on those glibc systems it would still pick the glibc build that cannot start. The musl build is the same size, and a CLI that spends its time waiting on HTTPS calls gains nothing from glibc's allocator. With one Linux asset per architecture, mise and `cargo binstall` (whose `overrides` in `crates/omnifob` send its gnu targets to the musl archive) need no configuration: mise moves to the musl asset on the next upgrade, and only a mise `asset_pattern` or `matching` that names `gnu` has to change.

The only C in the tree is AWS-LC, through `aws-lc-sys` (rustls' crypto provider, used by the AWS SDK and reqwest). Its sources include `<linux/random.h>`, and Ubuntu's `musl-gcc` wrapper searches only musl's own headers, which do not include the kernel's, so the musl builds use `cargo-zigbuild` with Zig, which ships musl and the Linux kernel headers for every architecture. Windows ARM64 is built natively on `windows-11-arm`, where AWS-LC finds `clang-cl`, and Intel macOS is cross-compiled on Apple Silicon. Asset names keep the Rust target triple, which mise and `cargo binstall` match on; `[package.metadata.binstall]` in `crates/omnifob` names the archive layout.

The build matrix lives in a reusable `build.yml`. `release.yml` calls it on a tag and then publishes; run by hand, it only builds. `ci.yml` calls it too, behind the stack gate, so a new target or a profile change fails on the pull request rather than at release time. The plain release build in the `check` job was dropped: the release build covers macOS and Windows with the real flags, and Linux through the musl targets, while `check` still runs the tests natively on Ubuntu.

## 2026-11-15: End-to-end tests keep secrets in a plaintext test store

The command line had no tests of its own beyond a few unit tests, because every command reads and writes the keychain, and the in-memory store the library tests use (`use_memory_store`) lives only as long as one process, while each `fob` command is a new one. `crates/omnifob/tests` now runs the built binary against a scratch `OMNIFOB_CONFIG` and `XDG_STATE_HOME`, with every provider call sent to a local mock through the existing endpoint variables, and `OMNIFOB_KEYRING=test-plaintext-files:<absolute dir>` puts the secrets in files there. Files rather than the real keychain, because a test must never read or overwrite the maintainer's sign-ins (the keychain is shared, whatever the config path), CI runners have no Secret Service, and parallel tests each need their own store; files rather than a long-lived helper process, because they need nothing running and a test can seed a sign-in or check that a cached credential was deleted by looking at one file.

The store writes secrets unencrypted, so it is built to be hard to choose by accident and obvious when chosen: the name says `test` and `plaintext`, there is no default directory (a bare `test-plaintext-files` or a relative path is refused, so it never lands in the working directory), every process that uses it prints a warning to stderr, `fob status` describes it as "unencrypted files in <dir> (tests only)", and on Unix the directory is created `0700` and each file `0600`, written through a temporary file and a rename so a concurrent command never reads half a value. It is not meant for anything but tests and is documented only here and in `store.rs`. With `OMNIFOB_KEYRING` unset, or set to one of the platform stores, nothing changes.
