# GitHub

omnifob keeps one GitHub token per account in the keychain and hands it to gh, git and other tools for the directory you work in. There are two ways to get the token, each its own integration type; profiles, directories and git credentials are the same for both:

- `github-oauth`: in the browser, like `gh auth login`, with the scopes gh needs.
- `token` with `preset = "github"`: a token you create and paste, such as a fine-grained or classic personal access token.

## Browser sign-in

```toml
[integrations.gh-me]
type = "github-oauth"
client_id = "Ov23li..."   # your OAuth app; see below
account = "me"            # profile id: gh-me/me/github
```

`fob login gh-me` prints a code and opens `https://github.com/login/device`; enter the code and authorize. omnifob asks for `repo`, `read:org`, `gist` and `workflow`: gh's minimum, plus what git needs to push changes to workflow files. `scopes` replaces that list. The token is checked against the API and kept in the keychain; `fob check gh-me` checks it again.

GitHub OAuth app tokens do not expire. `fob logout gh-me` forgets the token, but GitHub keeps the authorization until you revoke it under **Settings > Applications > Authorized OAuth Apps**; only an app's client secret can revoke a token through the API, and omnifob has none.

### The OAuth app

The sign-in page belongs to an OAuth app, which omnifob does not ship yet, so register one in your account once:

1. **Settings > Developer settings > OAuth Apps > New OAuth App**: name `omnifob`, any homepage URL, callback URL `http://localhost` (the device flow never uses it).
2. Tick **Enable Device Flow** and register the app. Copy its client ID into `client_id`. No client secret is needed.

Organizations that restrict OAuth app access hide their private repositories and data from the token until an owner approves the app. The authorization page offers to request that, and **Authorized OAuth Apps > omnifob** shows each organization's status.

For GitHub Enterprise Server, set `git_host` to its host name and `verify_url` to `https://<host>/api/v3/user`, and register the app there.

## Per directory, for gh and git

Map each tree to its account, let gh take its token from omnifob, and make omnifob git's credential helper for the host:

```toml
[directories]
"~/git" = ["gh-me"]
"~/git-acme" = ["gh-acme"]
```

```sh
gh() { fob exec github -- gh "$@"; }
git config --global credential.https://github.com.helper ""
git config --global --add credential.https://github.com.helper "!fob git-credential"
```

`gh` and `git push` then act as the account mapped to the directory, from one token, and refuse to run where no account or several could apply. The token is added to each command, never left in the shell.
