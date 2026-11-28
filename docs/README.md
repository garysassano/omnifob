# Documentation

## Guides

- [Configuration](guides/configuration.md): every integration type and key, default profiles per directory, and environment and access labels.
- [Using fob](guides/usage.md): the commands, how profiles are picked, `fob exec` and `fob use`, and the AWS console.
- [Migrating from other tools](guides/migrating.md): granted, aws-vault, the AWS CLI, Leapp, saml2aws, gcloud, az, wrangler and token-only CLIs.
- [Coding agents](guides/agents.md): what changes when an agent runs fob, `[agent]` settings, error codes and the audit log.
- [Other tools](guides/other-tools.md): `fob creds`, AWS profiles in `~/.aws/config`, fnox, SDK endpoints, Kubernetes and Google executable-sourced credentials.
- [Browsers](guides/browsers.md): a browser or browser profile per integration, and AWS consoles kept apart.
- [Where secrets live](guides/secrets.md): keychains, the encrypted file vault, state files and the credential cache.
- [Cloudflare](guides/cloudflare.md): the bootstrap token, account-owned or user-owned, and the built-in templates.
- [AWS roles in another partition](guides/aws-cross-partition.md): reaching a GovCloud, China or European Sovereign Cloud role from an IAM Identity Center role, and the setup in both accounts.

## Design

- [Vision](vision.md): what omnifob is, who it is for, and what it deliberately is not.
- [Decisions](decisions.md): design decisions with their reasons, newest last.
- [Providers](providers/README.md): every provider omnifob has worked on and how it gets credentials for each, with detailed notes for [AWS](providers/aws.md), [Google Cloud](providers/gcp.md), [Azure](providers/azure.md), [Cloudflare](providers/cloudflare.md) and [GitHub](providers/github.md).

## Research

- [Prior art](research.md): the credential tools studied and what omnifob takes from each.
- [Landscape](landscape.md): how about twenty cloud and platform CLIs sign in, store and mint credentials.
- [Tools](tools/README.md): the active tools in omnifob's space, by category, with what to study in each; `docs/tools/refresh.sh [status]` adds live GitHub data.
