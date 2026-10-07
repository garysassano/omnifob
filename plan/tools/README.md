# Tools in omnifob's space

Tools worth knowing when improving omnifob: what each one does that matters here, whether it has been studied, and what to look at. Only active projects are listed, each under its current repository; archived projects and look-alikes from other fields are left out.

Status: *studied* means it was read and its findings are in [research.md](../research.md) or [landscape.md](../landscape.md); **to study** means it is worth reading next; *reference* means it is known and no study is planned.

Live stars, last push and archived state: `plan/tools/refresh.sh` (optionally `plan/tools/refresh.sh to-study`). Remove a tool here once it is archived.

## Credential managers

Local sign-in, session and profile managers for people. The closest relatives of omnifob.

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [granted](https://github.com/fwdcloudsec/granted) | aws | Assume-style shell switching, console launching, browser profiles | studied |  |
| [aws-vault](https://github.com/ByteNess/aws-vault) | aws | OIDC token cache, refresh handling, exec and metadata-server modes | studied |  |
| [Leapp](https://github.com/Noovolari/leapp) | aws, azure | Integrations that sync sessions; desktop app plus CLI | studied |  |
| [aws-sso-cli](https://github.com/synfinatic/aws-sso-cli) | aws | The most complete Identity Center CLI: tags, fuzzy selection, profile generation, ECS server | studied | Tag-based selection, frecency, how it generates and updates ~/.aws/config, multiple console sessions |
| [aws-sso-creds](https://github.com/JorgeReus/aws-sso-creds) | aws | Small, opinionated Identity Center role browser that populates ~/.aws/config | studied | Its role browser UI and what it writes to the AWS config |
| [aws-sso-util](https://github.com/61418/aws-sso-util) | aws | Ben Kehoe's Identity Center helpers: config population, role listing, login | studied | How it names generated profiles for large organisations; its credential_process |
| [yawsso](https://github.com/victorskl/yawsso) | aws | Syncs an AWS CLI v2 SSO session into legacy credential files for older tools | studied | Which tools still need ~/.aws/credentials and how it keeps them fresh |
| [awsume](https://github.com/trek10inc/awsume) | aws | Role assumption into the shell with a plugin system (SAML, console, MFA) | studied | Its plugin interface, as a model for omnifob providers |
| [clisso](https://github.com/allcloud-io/clisso) | aws, okta, onelogin | Temporary credentials for several providers from one CLI | studied | How it abstracts providers |
| [aws-export-credentials](https://github.com/benkehoe/aws-export-credentials) | aws | Exports any profile's credentials to env vars, files or credential_process | reference |  |
| [aws-mfa](https://github.com/broamski/aws-mfa) | aws | MFA session tokens for IAM users; relevant to MFA on chained roles | studied | MFA prompt and caching, for chained roles with mfa_serial |
| [awsp](https://github.com/antonbabenko/awsp) | aws | Minimal shell profile switcher. Inactive since 2022 | reference |  |
| [aws-profile-manager](https://github.com/99stealth/aws-profile-manager) | aws | Interactive manager for ~/.aws/credentials profiles. Inactive since 2023 | reference |  |

## IdP federation

Sign in through an external identity provider (SAML or OIDC) to get cloud credentials.

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [saml2aws](https://github.com/Versent/saml2aws) | aws, adfs, okta, pingfederate, keycloak, google, azure-ad | The established SAML-to-AWS tool with many IdP providers | studied | Its IdP provider abstraction; how it stores IdP passwords; role selection |
| [gimme-aws-creds](https://github.com/Nike-Inc/gimme-aws-creds) | aws, alibaba, okta | Okta SAML into AWS and Alibaba Cloud | studied | Okta device and FastPass flows; the Alibaba Cloud support |
| [okta-aws-cli](https://github.com/okta/okta-aws-cli) | aws, okta | Okta's own CLI: web, device, direct and machine-to-machine modes | studied | The device authorization mode and how it maps Okta apps to AWS roles |
| [aws-azure-login](https://github.com/aws-azure-login/aws-azure-login) | aws, azure-ad | Entra ID SSO with MFA into AWS | studied | How it drives the Entra ID login (headless browser) and its pitfalls |
| [aws-google-auth](https://github.com/cevoaustralia/aws-google-auth) | aws, google | Google Workspace SAML into AWS | reference |  |
| [aws-cli-auth](https://github.com/DevLabFoundry/aws-cli-auth) | aws | SAML, portal, role chaining and web identity; deliberately does not persist the SSO refresh token | studied | The reasoning for not persisting refresh tokens, versus omnifob's silent refresh |
| [aws-saml-cli](https://github.com/asagage/aws-saml-cli) | aws, adfs | ADFS SAML role selection | reference |  |
| [awscli-saml-sso](https://github.com/octo-technology/awscli-saml-sso) | aws | Browser-based SAML login into AWS config files | reference |  |

## Provider CLIs

Official CLIs, studied for how they sign in and store credentials. Findings in [landscape.md](../landscape.md).

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [AWS CLI](https://github.com/aws/aws-cli) | aws | Aws sso login (PKCE), aws login (DPoP), refresh windows | studied |  |
| [Azure CLI](https://github.com/Azure/azure-cli) | azure | MSAL sign-in, brokers, agentic session claims | studied |  |
| [Azure Developer CLI](https://github.com/Azure/azure-dev) | azure | Azd's own login and environment model, alongside az | studied | How azd and az share or separate sign-ins |
| [OCI CLI](https://github.com/oracle/oci-cli) | oracle | Key-bound session tokens | studied |  |
| [wrangler](https://github.com/cloudflare/workers-sdk) | cloudflare | OAuth, auth profiles with directory bindings, keyring storage | studied |  |
| [cf](https://github.com/cloudflare/cf) | cloudflare | Cloudflare's new CLI; OAuth app with account_api_tokens:create | studied |  |
| [doctl](https://github.com/digitalocean/doctl) | digitalocean | Contexts with plain-text tokens | studied |  |
| [hcloud](https://github.com/hetznercloud/cli) | hetzner | Contexts, one token per project | studied |  |
| [ovhcloud-cli](https://github.com/ovh/ovhcloud-cli) | ovhcloud | Consumer keys with access rules, approved in the browser | studied |  |
| [linode-cli](https://github.com/linode/linode-cli) | akamai-cloud | Browser OAuth, then minting a token with scopes and expiry | studied |  |
| [scaleway-cli](https://github.com/scaleway/scaleway-cli) | scaleway | Browser login that creates an expiring IAM API key | studied |  |
| [vercel](https://github.com/vercel/vercel) | vercel | OAuth device flow with refresh tokens | studied |  |
| [flyctl](https://github.com/superfly/flyctl) | fly | Macaroon tokens attenuated offline | studied |  |
| [supabase](https://github.com/supabase/cli) | supabase | Browser login with an ECDH-encrypted handoff | studied |  |
| [upstash](https://github.com/upstash/cli) | upstash | Email plus management API key | studied |  |
| [gh](https://github.com/cli/cli) | github | Device flow, keyring storage, several accounts with gh auth switch | studied | Multi-account switching and how gh auth token is exposed to other tools |

## Secret managers and brokers

Secrets into processes, and services that issue dynamic credentials.

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [fnox](https://github.com/jdx/fnox) | aws, gcp, azure, cloudflare, github, vault | Leases for short-lived credentials; integration point through command leases | studied |  |
| [1Password shell plugins](https://github.com/1Password/shell-plugins) | many | Per-CLI credential provisioning | studied |  |
| [teller](https://github.com/tellerops/teller) | many | Secrets from many backends into the environment, in Rust | studied |  |
| [secretenv](https://github.com/TechAlchemistX/secretenv) | aws, 1password, vault | Runs a process with secrets from several backends, in Rust | studied | Backend abstraction and how it avoids writing secrets to disk |
| [envchain](https://github.com/sorah/envchain) | any | Environment variables from the OS keychain | studied |  |
| [HashiCorp Vault](https://github.com/hashicorp/vault) | aws, azure, gcp, kubernetes | Dynamic cloud credentials as a central service | reference |  |
| [OpenBao](https://github.com/openbao/openbao) | aws, azure, gcp, kubernetes | Open-source Vault fork with dynamic secrets | reference |  |
| [Infisical](https://github.com/Infisical/infisical) | aws, azure, gcp, kubernetes | Developer secrets platform with dynamic secrets and a CLI | reference |  |
| [Doppler CLI](https://github.com/DopplerHQ/cli) | any | Secrets injection into processes | reference |  |
| [Bitwarden Secrets Manager SDK](https://github.com/bitwarden/sdk-sm) | any | Machine secrets from Bitwarden | reference |  |
| [SOPS](https://github.com/getsops/sops) | any | Encrypted files in git with age, PGP or cloud KMS | reference |  |
| [chamber](https://github.com/segmentio/chamber) | aws | Application secrets in SSM Parameter Store | reference |  |

## Kubernetes

Cluster authentication helpers and operators.

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [kubelogin (int128)](https://github.com/int128/kubelogin) | oidc | Kubectl exec plugin for OIDC, with token cache | studied | The ExecCredential contract and cache, for an omnifob kubectl plugin |
| [kubelogin (Azure)](https://github.com/Azure/kubelogin) | azure | Entra ID exec plugin for AKS | reference |  |
| [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator) | aws | EKS authentication from AWS credentials | reference |  |
| [External Secrets Operator](https://github.com/external-secrets/external-secrets) | many | Syncs cloud secrets into Kubernetes; adjacent, not a local tool | reference |  |

## Access platforms

Server-side access tooling.

| Tool | Covers | Why it matters | Status | What to look at |
| --- | --- | --- | --- | --- |
| [Geodesic](https://github.com/cloudposse/geodesic) | aws | DevOps toolbox container with credential helpers | reference |  |
