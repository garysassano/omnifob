---
name: omnifob
description: Get cloud credentials through fob (omnifob) when the user has it set up — run AWS, Google Cloud, Azure, Cloudflare and token-based CLIs with `fob exec`, find profiles, and handle sign-in errors. Use whenever a command needs cloud credentials and `fob` is installed, and on errors such as no credentials, expired token, ExpiredToken, "not signed in" or "run `fob login`".
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

3. Pick the least-privileged profile that does the job (a read-only role to look, a deploy role to deploy). Ask before using an admin or production profile the user did not name.

For AWS, profiles exported with `fob export aws-config` work without fob in the command: `aws s3 ls --profile fob-acme-dev-ReadOnly`, or `AWS_PROFILE` for tools and SDKs. Check `~/.aws/config` for `fob-` profiles before assuming they exist; do not run `fob export aws-config --write` unless asked.

`fob exec` exits with the command's own status; 125 means fob failed before running it, 127 that the command was not found.

## Never

- Print credentials: no `fob creds` (except `--format credential-process`, `fnox`, `k8s-exec` or `gcp-executable` inside the config of a tool that reads it), `fob env`, `fob use` or `fob console --print`, and no `env`, `printenv` or `echo $AWS_SECRET_ACCESS_KEY` inside `fob exec`. Under an agent, fob refuses the first ones; that refusal is not something to work around.
- Change the user's setup unprompted: `fob login --force`, `fob logout`, `fob revoke`, `fob rename`, `fob import ... --write`, `fob export ... --write`, `fob cf add-template`, or edits to `~/.config/omnifob/config.toml` (including its `[agent]` section).

## When fob says no

- "run `fob login <integration>`": the sign-in lapsed. Either ask the user to run it, or run `fob login <integration>` yourself with a 15-minute timeout (a browser sign-in waits up to ten minutes, an Entra ID device code up to fifteen) and tell the user to approve the sign-in in the browser window that opens on their screen. If it is still valid, it returns at once without opening anything.
- "name the profile by its full id": use one of the ids it lists. "this directory's default (...) is <id>": the user mapped the working directory to that profile; name it in full.
- "the default profile of ... is not a profile": the user's `[directories]` entry is stale; tell them, and name a profile from `fob list`.
- "is not open to agents": the user limited agents to some profiles. Use an allowed one, or ask the user to run the command.
- "needs a code from the MFA device": ask the user to run the `fob exec ... -- true` command it names in their terminal, then retry.
- "the encrypted vault ... is locked": the user keeps secrets in an encrypted vault that has not been unlocked since boot. Ask them to run any `fob` command (`fob status`) in their terminal to enter the passphrase, then retry; never ask for the passphrase or set `OMNIFOB_VAULT_PASSPHRASE` yourself.
- `fob login` printing a URL and a code instead of opening a browser: this session looks remote, in a container or (on Linux) without a display. Pass both to the user to approve on any device, and keep the command running until it returns.
- "parsing .../config.toml" followed by a key (`chained.prod: duration must be...`): the config is invalid. Tell the user which key and why; do not edit the config yourself.
- "would both be the profile" or "two profiles of '...' would both be": two accounts or configured roles would share a profile id. Report it; the user renames one.
- "could not check the token ... try again later" or "could not reach": the provider is down or unreachable, and the token may be fine; retry later. "the token was rejected" means the token itself is refused and the user must replace it.
- AWS `AccessDenied` right after the user was given access: Identity Center takes a minute to propagate; retry once, then report.
- `fob check` (exit status 1 if a sign-in fails; `--integration <name>` for one, `--json` for structured output), `fob check <profile>` (what the credentials act as) and `fob status` diagnose without printing secrets.
