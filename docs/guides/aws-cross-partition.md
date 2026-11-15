# AWS roles in another partition

AWS partitions (commercial `aws`, GovCloud `aws-us-gov`, China `aws-cn`, the European Sovereign Cloud `aws-eusc`) have separate IAM, so credentials from one do not work in another, and `AssumeRole` cannot cross the boundary. Since November 2026 STS can: a principal in one partition asks STS for a short-lived token (`GetWebIdentityToken`), and STS in the other partition exchanges that token for a role's credentials (`AssumeRoleWithWebIdentity`). AWS calls this [cross-partition identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_cross_partition.html).

omnifob uses it to reach a role in another partition from an IAM Identity Center role, so one `fob login` covers both partitions. Each such role is a `cross_partition` entry on an `aws-sso` integration and becomes its own profile:

```toml
# Profile id: acme/gov-audit/Audit
[integrations.acme.cross_partition.gov-audit]
via_account_id = "111111111111"      # the Identity Center role that requests the token
via_role = "AdministratorAccess"
role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
audience = "omnifob"                 # a client ID of the destination's OIDC provider
region = "us-gov-west-1"             # destination STS Region, exported as AWS_REGION
source_region = "us-east-1"          # optional: defaults to default_region, then the portal's region
signing_algorithm = "ES384"          # optional: ES384 (default) or RS256
session_name = "me"                  # optional, defaults to "omnifob"
duration = "1h"                      # optional, 15m to the role's maximum (at most 12h)
```

> **The exchange is not yet tried live.** It has been tested against a mock of STS only: no account in a second partition was available. The source half was tried on 2026-11-15 in one commercial account with an IAM Identity Center role session: enabling outbound federation, requesting a one-minute ES384 token from the Regional endpoint, and reading its claims. What that showed is marked "Tried live" below; what it could not show is marked "Not yet tried". If you use this across partitions, please report what worked and what did not.

## Before you start

AWS presents the feature for workloads. Nothing in its documentation rules out a person's role session, and the token carries the Identity Center user's ID, but AWS asks you to "consult your compliance team to make sure that your implementation aligns with your regulatory or compliance obligations". Partitions such as GovCloud and the China Regions exist for regulatory reasons; ask before connecting one to another.

Setting it up is an administrator's job in both accounts. The examples use a commercial source account `111111111111`, a GovCloud destination account `222222222222` and the audience `omnifob`; replace them with yours.

## 1. Enable outbound identity federation in the source account

This is an account-wide setting. It creates the account's issuer URL, which the destination will trust.

```sh
aws iam enable-outbound-web-identity-federation
aws iam get-outbound-web-identity-federation-info   # shows the issuer URL again later
```

Both commands return it as `IssuerIdentifier`. Until federation is enabled, `get-outbound-web-identity-federation-info` fails with `FeatureDisabled` and a token request with `OutboundWebIdentityFederationDisabledException`. Disabling it again (`aws iam disable-outbound-web-identity-federation`) took a moment to apply: a token request made right after it still succeeded, and the next one, a few minutes later, was refused.

The issuer URL looks like `https://<id>.tokens.sts.global.api.aws` for a commercial account (`tokens.sts.us-gov.api.aws` in GovCloud, `tokens.sts.global.api.amazonwebservices.com.cn` in China, `tokens.sts.global.api.amazonwebservices.eu` in the European Sovereign Cloud). The part after `https://` is the issuer host, used in the policies below.

## 2. Allow the Identity Center role to request tokens

Add an inline policy to the permission set that `via_role` names (IAM Identity Center > Permission sets > the set > Inline policy), so every account it is assigned in can request tokens, limited to what omnifob asks for: one audience, ES384 (or RS256 if you set `signing_algorithm`), and tokens that last one minute.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:GetWebIdentityToken",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringEquals": { "sts:IdentityTokenAudience": "omnifob" },
        "Null": { "sts:IdentityTokenAudience": "false" },
        "StringEquals": { "sts:SigningAlgorithm": "ES384" },
        "NumericLessThanEquals": { "sts:DurationSeconds": 60 }
      }
    }
  ]
}
```

> **Tried live:** an Identity Center role whose permission set already allowed all actions got a token from the Regional endpoint (`sts.us-east-1.amazonaws.com`) with one audience, ES384 and `DurationSeconds` 60, and the token's `exp` was 60 seconds after its `iat`. The global endpoint (`sts.amazonaws.com`) refused the same request with `InvalidAction` ("Operation not supported on STS global endpoint"). **Not yet tried:** the inline policy above with its conditions, and how a request outside them (such as 300 seconds) is refused.

## 3. Create an OIDC provider in the destination account

In the destination account (here in GovCloud), create an IAM OpenID Connect provider for the source account's issuer URL, with the audience as a client ID:

```sh
aws iam create-open-id-connect-provider \
  --url https://<issuer host> \
  --client-id-list omnifob
```

The audience in omnifob's config must equal one of the provider's client IDs.

## 4. Trust the provider in the destination role

The destination role's trust policy allows `sts:AssumeRoleWithWebIdentity` through that provider. Its condition keys are the issuer host, a colon and the claim name ([AWS's table](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif), AWS STS tab).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws-us-gov:iam::222222222222:oidc-provider/<issuer host>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "<issuer host>:aud": "omnifob",
          "<issuer host>:source_region": "us-east-1"
        },
        "StringLike": {
          "<issuer host>:sub": "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AdministratorAccess_*"
        }
      }
    }
  ]
}
```

### What `sub` is

The token's `sub` is the ARN of the IAM principal that requested it. For an assumed role that is the role, not the session, and an Identity Center role is the reserved role IAM Identity Center creates for the permission set in each account: `arn:aws:iam::<account>:role/aws-reserved/sso.amazonaws.com/<region>/AWSReservedSSO_<permission set>_<suffix>`, with a random suffix. The `StringLike` pattern above matches it without the suffix; once you know the exact value, `StringEquals` on it is tighter.

> **Tried live:** `sub` was the reserved role's full ARN, path included: `arn:aws:iam::<account>:role/aws-reserved/sso.amazonaws.com/<Identity Center Region>/AWSReservedSSO_<permission set>_<suffix>`, where the Region is the Identity Center instance's (not the Region the token was requested in). `iss` was `https://<id>.tokens.sts.global.api.aws`, the `IssuerIdentifier` from step 1. The namespaced claims also held `aws_account`, `source_region` (where the token was requested), `principal_id` (the same ARN as `sub`), `original_session_exp`, `org_id`, `ou_path` and `identity_store_user_id`; the header named `ES384` and a key ID. **Not yet tried:** an instance in `us-east-1`, whose path may differ.

To see the claims of your own token, run the profile with debug logging; omnifob shows `iss`, `sub` and `aud` and nothing else from the token, and never the token itself:

```sh
OMNIFOB_LOG=omnifob_core=debug fob creds acme/gov-audit/Audit > /dev/null
```

A refused exchange shows the same three values in the error.

### Pinning the role to one person

`sub` matches every session of the permission set's role, that is everyone assigned that permission set in the source account. To let only one person in, also match the Identity Center user, which a token from an Identity Center session carries as `identity_store_user_id`:

```json
"Condition": {
  "StringEquals": {
    "<issuer host>:aud": "omnifob",
    "<issuer host>:identity_store_user_id": "<user id>"
  },
  "StringLike": {
    "<issuer host>:sub": "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AdministratorAccess_*"
  }
}
```

The user ID is shown in IAM Identity Center > Users > the user (User ID). Keep the `sub` condition too, so the trust names the permission set as well as the person. These keys are checked when the role is assumed only; they are not kept in the role's session.

> **Tried live:** the token carried `identity_store_user_id`, a UUID-shaped user ID. It did **not** carry `identity_store_arn`, which AWS's table lists, so do not put `<issuer host>:identity_store_arn` in a trust policy: an absent key fails `ArnEquals` and the role refuses every token. It did not carry `mfa_present` either. AWS documents that claim as `"true"` when the principal authenticated with MFA and left out otherwise; whether an Identity Center sign-in with MFA sets it is **not yet tried**, so do not require `<issuer host>:mfa_present` until you have seen it in your own token.

## Using the profile

`fob sync` adds the profile; then use it like any other: `fob exec acme/gov-audit/Audit -- aws sts get-caller-identity`, `fob use`, `fob creds`, `fob status`, `fob console`.

- Each new set of credentials gets the Identity Center role's credentials, requests a token for the one audience that lasts one minute, and exchanges it at once; the token is never stored. The credentials are cached like any other profile's.
- `--ttl` asks for another session length, from 15 minutes to 12 hours, and at most the destination role's maximum session duration; such credentials are not cached.
- `fob console` signs in to the destination partition's console, in the destination Region unless `--region` names another Region of that partition. `--duration` is refused for now: whether the federation endpoint takes `SessionDuration` for these credentials has not been confirmed, so the console session lasts as long as the credentials, which `duration` sets (up to 12 hours).
- The credentials cannot call `GetSessionToken` or `GetFederationToken`, an AWS rule for every `AssumeRoleWithWebIdentity` session.

## When it fails

omnifob names who has to act:

| Error                                               | Meaning                                                                                                                                                           |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Outbound identity federation is not enabled         | Step 1 is missing in the source account.                                                                                                                          |
| `<role>` may not request a web identity token       | The permission set lacks `sts:GetWebIdentityToken`, or its conditions do not admit the audience, algorithm or 60 seconds (step 2).                                |
| The credentials expire sooner, even new ones        | STS refused a token that would outlive the source session (`SessionDurationEscalation`); omnifob already retried once with new credentials.                       |
| `<role ARN>` does not accept the web identity token | The destination's OIDC provider (issuer URL, client ID) or the role's trust policy does not match the token (steps 3 and 4). The error shows `iss`, `sub`, `aud`. |
| Could not reach the source account's issuer         | STS in the destination could not fetch the issuer's keys (`IDPCommunicationError`), even after the SDK retried; usually transient.                                |
| Does not allow sessions of N seconds                | `duration` or `--ttl` is longer than the destination role's maximum session duration.                                                                             |

Afterwards, to undo the setup: remove the destination role's trust statement and the OIDC provider, remove the inline policy from the permission set, and disable outbound federation in the source account (`aws iam disable-outbound-web-identity-federation`) unless something else uses it.
