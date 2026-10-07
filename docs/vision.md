# Vision

## The problem

Every cloud has its own way to sign in and its own tool for short-lived credentials: granted, aws-vault, Leapp and aws-sso-cli for AWS, `gcloud` for Google, `az` for Azure, wrangler and `cf` for Cloudflare, and nothing at all for many smaller providers.
Each works differently, stores secrets differently and has different commands.
Cloudflare is the sharpest pain: API tokens never expire and scoping one in the dashboard takes minutes every time.

The AWS tools are also fragile as projects: granted slowed down after Common Fate wound down, aws-vault survives only as a fork, Leapp's company stopped.

## The idea

A mise for cloud credentials.
mise replaced nvm, pyenv and tfenv with one tool and one mental model; omnifob does the same for cloud sign-in.

1. Sign in once per identity source (an _integration_): an IAM Identity Center portal, a Cloudflare account, later a Google or Entra ID account.
2. omnifob discovers every identity that sign-in can reach (a _profile_): each AWS account and role, each Cloudflare account and permission template.
3. Any profile becomes short-lived credentials on demand: exported into the shell, injected into a command, opened in the web console, or handed to another tool.

The project is called omnifob; the command is `fob`, since it is typed many times a day.

## Who it is for

People who work across several clouds and many accounts, interactively, from a terminal.
CI is a secondary concern: CI usually has its own workload identity, and fnox already serves project secrets well.

## What it is not

- Not a secrets manager. Static secrets belong in fnox, 1Password or a cloud secret store.
- Not a replacement for each provider's CLI. omnifob gives those CLIs credentials; it does not wrap their commands.
- Not a fork of granted. It borrows ideas, not code, and is written in Rust.

## Relationship to fnox

fnox (by jdx, the author of mise) already does _leases_: short-lived credentials for AWS STS, GCP, Azure, Cloudflare and more, injected into project commands.
What fnox does not do is the human sign-in layer: native SSO flows, discovery of everything you can reach, interactive switching and consoles.
omnifob is that layer, and it plugs into fnox through fnox's `command` lease (`fob creds --format fnox`).
Parts of omnifob may fit into fnox directly one day, so provider code stays in `omnifob-core`, separate from the CLI.
