# Other tools

`fob exec` covers most tools: they read credentials from the environment. This page covers the rest: tools that want a profile name, a credential helper, a file or a local endpoint.

- [Credentials as JSON or another tool's format](#credentials-for-other-tools)
- [AWS profiles in `~/.aws/config`](#aws-profiles-in-awsconfig)
- [fnox](#fnox)
- [SDKs that read no token from the environment](#sdks-that-read-no-token-from-the-environment)
- [Kubernetes](#kubernetes)
- [Google executable-sourced credentials](#google-executable-sourced-credentials)

## Credentials for other tools

```sh
fob creds acme/prod/ReadOnly                              # JSON: profile, env, expires_at
fob creds acme/prod/ReadOnly --format credential-process  # for ~/.aws/config
fob creds cf/personal/workers --format fnox               # for a fnox command lease
```

AWS profiles export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION` and `AWS_ACCOUNT_ID`, which the AWS SDKs use for account-based endpoints, plus `AWS_REGION` and `AWS_DEFAULT_REGION` when a Region is configured. The `credential-process` format carries the account as `AccountId`. These replace any you set yourself: an `AWS_ACCOUNT_ID` in your shell is overwritten by `fob exec` and `fob use`. With the account known, the SDKs send requests to account-based endpoints (DynamoDB, S3) on other hosts than the regional ones, which matters for firewall and VPC endpoint allowlists; `AWS_ACCOUNT_ID_ENDPOINT_MODE=disabled` turns that off.

## AWS profiles in `~/.aws/config`

For tools that want `--profile` or `AWS_PROFILE`, `fob export aws-config` prints one `[profile fob-<integration>-<account>-<role>]` per discovered role, each using `credential_process = fob creds ... --format credential-process`:

```sh
fob export aws-config --write
aws s3 ls --profile fob-acme-prod-ReadOnly
```

- `--write` keeps them in a marked block of `~/.aws/config` (backing up the previous file) and never touches anything outside it; the file is replaced in one step, keeping its permissions, and a symbolic link to it stays a link.
- Editors and GUI tools often run without your shell's `PATH`: `--absolute` writes the full path of the `fob` binary you ran instead, with symbolic links resolved, so run the export again after upgrading fob. On Linux and macOS a path with a space is written in double quotes; on Windows a path that needs quotes is refused, so put `fob` on `PATH` there instead.
- A config named with `--config` is written into each line too.
- With no AWS profiles, nothing is written and an old block is removed, and a block whose end marker is gone is refused rather than guessed at.

## fnox

```toml
[leases.cloudflare]
type = "command"
create_command = "fob creds cf/personal/workers --format fnox"
```

## SDKs that read no token from the environment

`fob exec` also serves the credentials the way each cloud's SDKs look for them when no variable will do, from an endpoint on `127.0.0.1` that lives as long as the command and answers only requests carrying its random secret:

- **Azure**: an Azure profile's command gets a managed identity endpoint, as App Service runs one (`IDENTITY_ENDPOINT` and `IDENTITY_HEADER`). The Azure Identity libraries' `DefaultAzureCredential` and `ManagedIdentityCredential` then get tokens for any resource (Resource Manager, Key Vault, Storage, Graph) from your sign-in, without `~/.azure`. Variables that would make them pick another credential (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `MSI_ENDPOINT`, ...) are removed. The `az` CLI uses it only after `az login --identity`, which writes `~/.azure`, so it keeps its own sign-in.
- **Google Cloud**: a Google profile's command gets Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, a private file deleted afterwards) whose token URL is the endpoint, so the client libraries get the profile's token and come back for a new one when it nears its end. The file holds the endpoint's secret, not a Google token. `--token-file` gives gcloud its token in a private file (`CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`) that fob rewrites before the token expires, so a long-running script's gcloud calls keep working.
- **AWS**: with `--server`, the command gets a container credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI` and `AWS_CONTAINER_AUTHORIZATION_TOKEN`) instead of the key variables, and the SDKs and the AWS CLI fetch renewed credentials from it, so a dev server or an IDE started with `fob exec --server` outlives a one-hour session. A `[default]` profile in `~/.aws/config` or `~/.aws/credentials` wins over the endpoint, since every SDK reads the shared files before the container provider; the endpoint's credentials apply when the default profile has none.

`--no-server` turns the Azure and Google endpoints off. The endpoints never prompt: a request that would need an MFA code, because a role's session ended during the run, is answered with an error that says to run `fob exec <profile> -- true` in a terminal.

```sh
fob exec work/prod/user -- python deploy.py              # DefaultAzureCredential works
fob exec google/proj-a/user -- go run ./cmd/importer     # ADC works
fob exec acme/dev/Admin --server -- code .               # renewed for the IDE's lifetime
```

## Kubernetes

`fob creds --format k8s-exec` writes the `ExecCredential` a kubectl exec plugin returns: for an AWS profile an EKS token (`--cluster <name>`, made as `aws eks get-token` makes it, in the profile's Region or `--region`), for a Google profile its access token (GKE), and for an Azure profile an Entra ID token for AKS's server application, as `kubelogin` asks for it. It answers in the `apiVersion` kubectl asks for.

```yaml
users:
  - name: eks-dev
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: fob
        args: [creds, acme/dev/Admin, --format, k8s-exec, --cluster, dev]
        interactiveMode: Never
```

## Google executable-sourced credentials

Google's executable-sourced credentials take a third-party token and exchange it at Google's STS through a workload identity pool; they cannot take an access token. `fob creds <google profile> --format gcp-executable` prints the executable response with your account's Google ID token, and `fob export gcp-adc <profile> --audience <provider>` writes an ADC file that runs it, for a workload identity pool provider that trusts `https://accounts.google.com` (with the OAuth client's ID as an allowed audience); a service account profile adds impersonation of that account. The file holds no token, and the libraries run fob only with `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. Without such a pool, `fob exec` is the way to give the libraries your token.
