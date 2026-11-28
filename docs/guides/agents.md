# Coding agents

fob is built to be used by coding agents as much as by people. Agents run each command in a new shell with no one at the terminal, and whatever a command prints lands in the agent's context and its saved transcripts. fob notices when an agent runs it and changes what it does, so an agent can get the credentials it needs without ever seeing them.

## Setup

1. Install the [omnifob skill](../../skills/omnifob/SKILL.md), which teaches agents what follows: `npx skills add garysassano/omnifob`, or your agent's own skill tooling.
2. Optionally, limit what agents may use, shorten what they get, and log it:

   ```toml
   [agent]
   profiles = ["acme/dev/*", "*/*/ReadOnly"]   # only these; `*` matches within one segment
   max_ttl = "15m"                             # at most this long (not cached)
   auto_revoke = true                          # `fob exec` on a Cloudflare profile acts as `--revoke`

   [audit]
   enabled = true                              # one JSON line per credential handed out
   ```

3. Let the agent run `fob exec <profile id> -- <command>` per command, rather than starting the agent itself inside `fob exec`, which would put the credentials in the environment of every command it runs.

The skill names the fob release it describes (`metadata.fob-version`); `fob status`, and `fob list` under an agent, point out a copy in `~/.agents/skills`, Claude Code's, Codex's or OpenCode's skill folder that describes another release, which `npx skills update` refreshes.

## What changes under an agent

fob recognises agents by the variables they set: `AI_AGENT`, which several agents set, and `CLAUDECODE`, `CODEX_SANDBOX`, `CODEX_THREAD_ID`, `GEMINI_CLI`, `CURSOR_AGENT`, `COPILOT_AGENT_SESSION_ID`, `COPILOT_CLI`, `OPENCODE`, `CRUSH`, `QWEN_CODE`, `CLINE_ACTIVE`, `GOOSE_TERMINAL`, `PI_CODING_AGENT`, `ANTIGRAVITY_AGENT`. Set `OMNIFOB_AGENT=1` for another agent, such as Aider or Windsurf, which set none, or `OMNIFOB_AGENT=0` to turn this off. Under an agent, fob:

- **Does not print credentials**: `fob creds` (JSON), `fob env` and `fob console --print` refuse and point to `fob exec`. `--format credential-process`, `fnox`, `k8s-exec` and `gcp-executable` still work, because the AWS SDKs, fnox, kubectl and Google's libraries run them inside the agent's commands and read the output themselves.
- **Never prompts, and takes a profile only by its full id**, so a command does what it says and permission rules can match it. `fob list` shows the ids, marking those `[agent] profiles` keeps from agents with `(not open to agents)`, or `"open_to_agents": false` with `--json`.
- **Hands out only the profiles `[agent] profiles` allows**, when it is set.
- **Marks what agents get on the provider's side**: AWS roles whose config names no `session_name` get the session name `omnifob-agent` (instead of `omnifob`), so CloudTrail tells them apart; minted Cloudflare tokens are named `omnifob-agent <template>`; and under GitHub Copilot's agent, Entra ID tokens carry its session (`COPILOT_AGENT_SESSION_ID`) as the Azure CLI sends it, which Entra ID records in the token. Credentials cached before the agent asked keep their original marks.
- **Optionally shortens and revokes what agents get**, with `max_ttl` and `auto_revoke` (below).
- **Fails with a code** agents can act on (below).

This guards against accidents, not against the agent, which runs as you; the harness's sandbox and permission rules are the boundary.

## Getting credentials

An agent gets credentials with `fob exec acme/dev/ReadOnly -- aws s3 ls`, or through AWS profiles from [`fob export aws-config`](other-tools.md#aws-profiles-in-awsconfig), which work without fob in the command.

When a sign-in lapses, the agent can ask you to run `fob login <integration>`, or run it itself: the browser opens on your screen for you to approve. Agents see a command's output only when it ends, so for Identity Center and Azure they run `fob login <integration> --start`, which opens the approval page, prints the URL and code and returns, pass the code on to you, and then run `fob login <integration> --wait`.

## Shorter credentials

`max_ttl` applies to Cloudflare tokens, chained, cross-partition, IAM users' and console sign-ins' roles, IAM user sessions and Google service accounts, except where each new session asks for an MFA code (IAM user sessions with `mfa_serial`, `no_session` roles of such a user, and chained and console sign-ins' roles with `mfa_serial`), whose cached credentials agents get as they are. It also caps what `fob exec`'s endpoints and `--token-file` serve.

AWS sessions whose length the provider sets (Identity Center roles, console sign-ins) are shortened instead with STS `GetScopedCredentials`, a copy of the session that ends sooner and keeps its identity, logged in CloudTrail as `fob exec (agent)`; the role needs `sts:GetScopedCredentials`, and fob fails rather than hand out the full session when it is refused. Google accounts' and Azure tokens keep the provider's lifetime.

## Error codes

When fob fails under an agent, the last line of stderr is `fob-error: ` and JSON with a `code`, the `message` and the values the code needs, so the agent acts on the code rather than the wording; people see only the message, and `OMNIFOB_ERROR_FORMAT=json` adds the line for scripts:

```text
fob: getting credentials for acme/dev/ReadOnly: not signed in to 'acme'; run `fob login acme`
fob-error: {"code":"login_required","integration":"acme","message":"getting credentials for acme/dev/ReadOnly: not signed in to 'acme'; run `fob login acme`","run":"fob login acme"}
```

| Code                    | Values                           | Meaning                                                                                                                        |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `login_required`        | `integration`, `run`             | The integration needs `fob login`.                                                                                             |
| `profile_ambiguous`     | `candidates`, `matches`, `query` | Several profiles match, or under an agent the words were not a full id.                                                        |
| `profile_not_found`     | `query`                          | No profile matches.                                                                                                            |
| `not_open_to_agents`    | `profile`, `integration`         | `[agent] profiles` keeps the profile (or every role `fob discover aws` would search) from agents.                              |
| `mfa_required`          | `profile`, `run`                 | A code from the MFA device is needed; `run` in a terminal asks for it.                                                         |
| `vault_locked`          | `vault`                          | The encrypted vault has not been unlocked since boot.                                                                          |
| `use_exec`              | `run`, `profile`                 | The command would print credentials or change the shell; run what `run` says (`fob exec`, or `fob console` without `--print`). |
| `config_invalid`        | `path`                           | The config file does not load, cannot be read, or the file `--config` names does not exist.                                    |
| `integration_not_found` | `integration`, `configured`      | No integration of that name.                                                                                                   |
| `other`                 |                                  | Anything else; the message says what.                                                                                          |

`fob check --json` and `fob status --check --json` give a failed check's `code` too. Codes keep their meaning across releases; new ones may be added.

## Audit log

```toml
[audit]
enabled = true
```

appends one JSON line to `~/.local/state/omnifob/audit.jsonl` for every credential fob hands out, to people and agents alike: the time, command, profile, integration, the agent's marker variable when an agent ran it, how it was handed over (`env`, `credential-process`, `aws-container`, `azure-identity`, `gcp-adc`, `k8s-exec`, `console`, ...), when it expires and a minted Cloudflare token's ID. Never a secret. The file is private and only grows; rotate or delete it as you like.
