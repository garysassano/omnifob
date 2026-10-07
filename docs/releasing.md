# Releasing

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
