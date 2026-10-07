# Agent Instructions

## Engineering approach

- Before implementing or changing a provider, study its official CLI (how it signs in, stores and refreshes credentials, and which variables its tools read) and the established tools in [docs/tools/README.md](docs/tools/README.md). Adopt proven patterns when they fit, and record what was learned in `docs/landscape.md`, `docs/research.md` or the provider's notes in `docs/providers/`.
- Keep provider code in `omnifob-core` and the command line in `omnifob`, so the core stays usable as a library.
- While the version is `0.x`, backward compatibility is not a default requirement for config keys, state files or commands. Prefer a clean break with a concrete benefit, move callers, tests and docs together, and name the break in the release notes.
- Never print or commit secret values: bootstrap tokens, minted tokens, SSO tokens or role credentials. Write them to a private scratch file when a test needs one, and delete it afterwards.

## Pull requests

Changes go through a pull request, squash-merged after CI passes on Linux, macOS and Windows; `main` carries one commit per PR. A small change (a typo, a log line) may go straight to `main`. Split work into separate PRs when the changes need independent revert, release or bisect boundaries.

Before pushing, run `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. Format Markdown with Prettier.

## Documentation

- `README.md` covers status, installation, configuration and use. Longer guides go in `docs/guides/`, design and research in `docs/`.
- When a provider is added or its handling changes, update the table in `docs/providers/README.md` and the provider's notes.
- Record design decisions with their reasons in `docs/decisions.md`.

## Live tests

Mocks cover the API calls (`wiremock` in `crates/omnifob-core/tests`); confirm provider behaviour live when it matters.

- Point `OMNIFOB_CONFIG` and `XDG_STATE_HOME` at a scratch directory, so the maintainer's config and profiles stay untouched. The keychain is shared, so integration names must match the signed-in ones.
- Use `fob exec --revoke` for Cloudflare tokens a test needs, so none outlive it.
- Delete anything created in a cloud account (buckets, roles, tokens) before finishing, and check that it is gone.
- In committed material and reports, refer to accounts and profiles generically, never by their IDs or names.

## Releasing

Release notes live only in GitHub releases; there is no CHANGELOG.md. They are written once, in the signed tag's message, and the release workflow copies them into the release.

1. Bump `version` in the workspace `Cargo.toml` and the `omnifob-core` requirement in `crates/omnifob/Cargo.toml`; build so `Cargo.lock` follows. Commit and push.
2. Wait for CI to pass on that commit.
3. Write the notes: first line `omnifob vX.Y.Z`, a blank line, then Markdown with `### Added`, `### Changed`, `### Fixed`, `### Security` as needed, written for users rather than as a commit list.
4. Tag with **`--cleanup=verbatim`**, otherwise Git drops every line starting with `#` and the headings disappear:

   ```sh
   git tag -s --cleanup=verbatim -F notes.md vX.Y.Z <commit>
   git push origin vX.Y.Z
   ```

5. The release workflow builds the binaries, publishes them with SHA256SUMS and provenance, and uses the tag message after its first line as the release text. A tag without notes falls back to GitHub's generated notes, with a warning.
6. Check the release page, `sha256sum -c`, `gh attestation verify`, and `mise use github:garysassano/omnifob@X.Y.Z`.

To fix the notes of a published release, edit the release on GitHub (`gh release edit vX.Y.Z --notes-file ...`); tags are not rewritten.
