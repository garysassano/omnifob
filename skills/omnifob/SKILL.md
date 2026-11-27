---
name: omnifob
description: Get cloud credentials through fob (omnifob) when the user has it set up — run AWS, Google Cloud, Azure, Cloudflare and token-based CLIs with `fob exec`, find profiles, and handle sign-in errors. Use whenever a command needs cloud credentials and `fob` is installed, and on errors such as no credentials, expired token, ExpiredToken, "not signed in" or "run `fob login`".
metadata:
  fob-version: "0.13.0"
---

# Cloud credentials with fob

fob keeps the user's sign-ins and hands out short-lived credentials per profile. Everything you print lands in your context and the session transcript, so credentials only ever go into the environment of the command that needs them.

## Running commands

1. Find the profile: `fob list` (optionally `fob list <words>`). Ids look like `<integration>/<account>/<role or template>`, e.g. `acme/prod/ReadOnly`. Profiles marked `(not open to agents)` are ones the user keeps from you; don't try them.
2. Run the command with it, naming the profile by its full id:

   ```sh
   fob exec acme/dev/ReadOnly -- aws s3 ls
   fob exec cf/personal/workers -- wrangler deploy
   fob exec cf/personal/workers --revoke -- wrangler deploy   # Cloudflare token for this command only
   ```

   Each of your commands starts in a new shell, so put `fob exec` on every command that needs credentials. When the user gives an account and a role instead of a profile (from a runbook, say), `fob exec --account-id 123456789012 --role ReadOnly -- <command>` picks the one profile they name.

   Azure and Google profiles also give the command a local endpoint their SDKs use (`DefaultAzureCredential`, Google's Application Default Credentials), so code that uses those SDKs works under `fob exec` without `az login` or `gcloud auth application-default login`. For a long-running AWS command (a dev server), `fob exec <profile> --server -- <command>` serves renewed credentials to the SDKs.

3. Pick the least-privileged profile that does the job (a read-only role to look, a deploy role to deploy). Ask before using an admin or production profile the user did not name. `fob list` shows each profile's environment and access level (`fob list --json`: `env`, `access`); a trailing `?` (`"env_source": "name"`) is fob's guess from the id, so treat an unlabelled or guessed profile with care rather than as safe. A profile noted `(signed out)` needs `fob login` first.

For AWS, profiles exported with `fob export aws-config` work without fob in the command: `aws s3 ls --profile fob-acme-dev-ReadOnly`, or `AWS_PROFILE` for tools and SDKs. Check `~/.aws/config` for `fob-` profiles before assuming they exist; do not run `fob export aws-config --write` unless asked.

`fob exec` exits with the command's own status; 125 means fob failed before running it, 127 that the command was not found.

## Never

- Print credentials: no `fob creds` (except `--format credential-process`, `fnox`, `k8s-exec` or `gcp-executable` inside the config of a tool that reads it), `fob env`, `fob use` or `fob console --print`, and no `env`, `printenv` or `echo $AWS_SECRET_ACCESS_KEY` inside `fob exec`. Under an agent, fob refuses the first ones; that refusal is not something to work around.
- Change the user's setup unprompted: `fob login --force`, `fob logout`, `fob revoke`, `fob rename`, `fob import ... --write`, `fob export ... --write`, `fob cf add-template`, or edits to `~/.config/omnifob/config.toml` (including its `[agent]` section).

## When fob says no

When fob fails, the last line of its stderr is `fob-error: ` followed by JSON: a `code`, the `message`, and the values that go with the code. Act on the code, not the wording:

- `login_required` (`integration`, `run`): the sign-in lapsed. Either ask the user to run `fob login <integration>`, or sign in yourself:
  - Identity Center (`aws-sso`) and Azure: run `fob login <integration> --start`. It opens the approval page on the user's screen, prints the URL and code, and returns at once. Tell the user both, then run `fob login <integration> --wait` with a 15-minute timeout; it returns once they approve.
  - Other integrations: run `fob login <integration>` with a 15-minute timeout and tell the user to approve the sign-in in the browser window that opens on their screen.

  Either returns at once, without opening anything, while the sign-in still works.
- `profile_ambiguous` (`candidates`, `matches`, `query`): name the profile by one of the full ids in `candidates`. With a single candidate from "this directory's default", the user mapped the working directory to that profile; name it in full.
- `profile_not_found` (`query`): no profile matches; look in `fob list`. When the query came from `[directories]`, the user's entry is stale; tell them.
- `not_open_to_agents` (`profile`): the user limited agents to some profiles. Use an allowed one, or ask the user to run the command.
- `mfa_required` (`profile`, `run`): ask the user to run the `run` command (`fob exec <profile> -- true`) in their terminal, then retry.
- `vault_locked`: the user keeps secrets in an encrypted vault that has not been unlocked since boot. Ask them to run any `fob` command (`fob status`) in their terminal to enter the passphrase, then retry; never ask for the passphrase or set `OMNIFOB_VAULT_PASSPHRASE` yourself.
- `use_exec` (`run`): the command would print credentials or change a shell you do not keep; run what you need as `fob exec <profile> -- <command>`.
- `config_invalid` (`path`): the message names the key and why (`chained.prod: duration must be...`). Tell the user; do not edit the config yourself.
- `integration_not_found` (`configured`): use one of the configured names.
- `other`: read the message. Some it may be:
  - "would both be the profile" or "two profiles of '...' would both be": two accounts or configured roles would share a profile id. Report it; the user renames one.
  - "could not check the token ... try again later" or "could not reach": the provider is down or unreachable, and the token may be fine; retry later. "the token was rejected" means the token itself is refused and the user must replace it.
- `fob login` printing a URL and a code instead of opening a browser: this session looks remote, in a container or (on Linux) without a display. Pass both to the user to approve on any device; with `--start`, then run `--wait`.
- AWS `AccessDenied` right after the user was given access: Identity Center takes a minute to propagate; retry once, then report.
- `fob check` (exit status 1 if a sign-in fails; `--integration <name>` for one, `--json` for structured output), `fob check <profile>` (what the credentials act as) and `fob status --check` diagnose without printing secrets. Plain `fob status` shows only what is stored: a sign-in whose token "renews on next use if the portal session is still open" (`"needs_check": true` in `--json`) may have ended, so check before telling the user it works.
- "the omnifob skill in ... describes fob ...": this skill is out of date or ahead of fob. Tell the user, who updates it (`npx skills update`) or fob; meanwhile prefer what `fob <command> --help` says over this file.
