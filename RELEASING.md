# Releasing dmarcgo

This is the maintainer runbook for publishing the `dmarcgo` Go library. A
release is an immutable semantic-version tag, a GitHub Release, and the matching
public Go module. The project does not publish command-line binaries, archives,
installers, Homebrew formulae, or other GoReleaser-style assets.

The current supported module line is:

```text
github.com/georgestarcher/dmarcgo/v3
```

## Release invariants

- Release only a reviewed commit already merged into `main`.
- Use a semantic `v3.x.x` tag, including an optional valid prerelease suffix.
- Create a signed annotated tag and confirm GitHub verifies its signature.
- Keep the exact matching dated section in `CHANGELOG.md`.
- Run the same complete `make ci` gate locally and in the release workflow.
- Never move, reuse, or silently replace a pushed tag.
- Publish a corrective patch version when released content is wrong.

The GitHub workflow enforces the module path, changelog, tag form, tag type,
signature verification, `main` ancestry, full validation, and release-note
extraction. These checks supplement maintainer review; they do not authorize a
release by themselves.

## 1. Choose the version

Apply semantic versioning to the public Go API and documented contracts:

- **Patch** (`v3.0.1`): compatible fixes or documentation that should appear in
  a new immutable module snapshot.
- **Minor** (`v3.1.0`): backward-compatible public API additions.
- **Major** (`v4.0.0`): source-incompatible public API changes. A new major also
  requires a `/v4` module path and deliberate updates to release validation,
  imports, documentation, schemas where applicable, and migration guidance.

Documentation merged into `main` does not require an immediate patch release.
Use a patch release when consumers need that exact documentation in the module
zip or on the version-specific pkg.go.dev page.

For a prerelease, use a tag such as `v3.1.0-rc.1`. The changelog heading must
contain that exact version, and GitHub marks tags containing a prerelease suffix
as prereleases.

## 2. Prepare the release pull request

1. Start from current `main` and confirm the intended release scope.
2. Move the release notes out of `## Unreleased` into an exact dated heading:

   ```markdown
   ## [3.0.1] - 2026-07-16
   ```

3. Keep an empty `## Unreleased` heading above the new section.
4. Update migration, compatibility, schema, API, or release-audit documentation
   when the release changes those contracts.
5. Run the parameterized release preflight:

   ```shell
   make release-check VERSION=v3.0.1
   ```

The preflight validates the requested tag against the module path and exact
changelog entry, confirms release-note extraction, and runs `make ci`. The
ordinary `release-metadata-check` derives the newest dated changelog release, so
it does not retain a stale hard-coded version after the next release.

Open the release preparation as a focused pull request. Require a clean Codex
review, resolved review threads, and every required GitHub Actions check before
merging.

## 3. Create the signed tag

After the release pull request is merged:

```shell
git switch main
git pull --ff-only origin main
git status --short --untracked-files=no
git tag -s v3.0.1 -m "dmarcgo v3.0.1"
git verify-tag v3.0.1
git show --show-signature --no-patch v3.0.1
```

`git status --short --untracked-files=no` must produce no output. A configured
1Password SSH signing key is the normal maintainer signing path. Do not bypass
signing if the desktop, agent, or authentication session is unavailable; wait
and retry after it is unlocked.

Inspect the tag target and message before publishing it. If an unpushed local
tag is wrong, delete and recreate it locally. If its source or metadata is
wrong, correct the release commit through the normal pull-request path and
create the tag again only after the correction is on `main`.

## 4. Publish the tag

Push only the verified tag:

```shell
git push origin v3.0.1
```

The `dmarcgo Release` workflow then:

1. checks out full history;
2. validates the semantic tag, `/v3` module path, and dated changelog entry;
3. requires an annotated Git tag with a GitHub-verified signature;
4. proves that the tagged commit belongs to `main`;
5. runs `make ci` against the exact tag;
6. extracts only that version's changelog section; and
7. creates the GitHub Release, or leaves an already-created matching release
   unchanged when a safe workflow rerun reaches that step.

Do not create the GitHub Release manually ahead of the workflow. The tag is the
publication trigger and source of truth.

## 5. Verify public publication

After the workflow succeeds, run:

```shell
make post-release-check VERSION=v3.0.1
```

The verifier performs one bounded request, with no automatic retries, to each
of these public channels:

- the GitHub Release API;
- `proxy.golang.org` version and module metadata;
- the Go checksum database; and
- the exact version page on pkg.go.dev.

It verifies the release/tag identity, draft and prerelease state, module path,
module and `go.mod` checksums, and versioned documentation identity. An optional
`GITHUB_TOKEN` environment variable can avoid anonymous GitHub API limits; never
put the token in the command line, repository configuration, or documentation.

Go infrastructure and pkg.go.dev can lag behind the GitHub Release. A pending
public channel is not a reason to move or recreate the tag. Wait, then rerun the
same post-release check for the immutable version.

Also confirm that the version installs in a clean temporary consumer module:

```shell
tmp_dir="$(mktemp -d)"
(
  cd "${tmp_dir}"
  go mod init example.com/dmarcgo-release-check
  go get github.com/georgestarcher/dmarcgo/v3@v3.0.1
  go list -m github.com/georgestarcher/dmarcgo/v3
)
rm -rf "${tmp_dir}"
```

The canonical wiki publishes from trusted `main`, independently of module tags.
Confirm its `main` publication workflow when the release includes wiki changes.

## Failure and recovery

### Release workflow fails before creating the GitHub Release

- For a transient infrastructure failure, rerun the workflow against the exact
  same signed tag.
- For incorrect released source or metadata, do not move or delete the remote
  tag. Correct the repository through a new pull request and publish a new patch
  version.

### GitHub Release exists but a Go channel is pending

Do not retag. Wait for propagation and rerun:

```shell
make post-release-check VERSION=v3.0.1
```

### Published behavior must be rolled back

Tags and module versions are immutable. Revert or correct the behavior on
`main`, document the change, and publish a new patch version. Preserve the
original changelog, tag, GitHub Release, and module history.

### A major module line is required

Do not reuse the v3 workflow unchanged. First land the new `/vN` module path,
version-aware validation, migration guide, release audit, documentation links,
and tag filter as one reviewed release-preparation change. Preserve all earlier
module tags and release history.
