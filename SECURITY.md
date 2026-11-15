# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's [Security tab](https://github.com/garysassano/omnifob/security) and choose **Report a vulnerability**. Please do not open a public issue or pull request for them.

Include what you can of:

- the omnifob version (`fob --version`), operating system and credential store (`fob status` shows it);
- the integration type involved (`aws-sso`, `cloudflare-oauth`, `token` and so on);
- what an attacker can do, and the steps or a proof of concept that shows it.

Leave out real secrets: tokens, keys and credentials in logs or screenshots should be redacted or revoked first.

## Supported versions

While omnifob is at `0.x`, only the latest release gets security fixes. Fixes ship in a new release; upgrade rather than expecting backports.
