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

   Each of your commands starts in a new shell, so put `fob exec` on every command that needs credentials.

3. Pick the least-privileged profile that does the job (a read-only role to look, a deploy role to deploy). Ask before using an admin or production profile the user did not name.

For AWS, profiles exported with `fob export aws-config` work without fob in the command: `aws s3 ls --profile fob-acme-dev-ReadOnly`, or `AWS_PROFILE` for tools and SDKs. Check `~/.aws/config` for `fob-` profiles before assuming they exist; do not run `fob export aws-config --write` unless asked.

`fob exec` exits with the command's own status; 125 means fob failed before running it, 127 that the command was not found.

## Never

- Print credentials: no `fob creds` (except `--format credential-process` or `--format fnox` inside the config of a tool that reads it), `fob env`, `fob use` or `fob console --print`, and no `env`, `printenv` or `echo $AWS_SECRET_ACCESS_KEY` inside `fob exec`. Under an agent, fob refuses the first ones; that refusal is not something to work around.
- Change the user's setup unprompted: `fob login --force`, `fob logout`, `fob revoke`, `fob rename`, `fob import ... --write`, `fob export ... --write`, `fob cf add-template`, or edits to `~/.config/omnifob/config.toml` (including its `[agent]` section).

## When fob says no

- "run `fob login <integration>`": the sign-in lapsed. Either ask the user to run it, or run `fob login <integration>` yourself with a 10-minute timeout and tell the user to approve the sign-in in the browser window that opens on their screen. If it is still valid, it returns at once without opening anything.
- "name the profile by its full id": use one of the ids it lists.
- "is not open to agents": the user limited agents to some profiles. Use an allowed one, or ask the user to run the command.
- "needs a code from the MFA device": ask the user to run the `fob exec ... -- true` command it names in their terminal, then retry.
- AWS `AccessDenied` right after the user was given access: Identity Center takes a minute to propagate; retry once, then report.
- `fob check` (exit status 1 if a sign-in fails; `--integration <name>` for one, `--json` for structured output), `fob check <profile>` (what the credentials act as) and `fob status` diagnose without printing secrets.
