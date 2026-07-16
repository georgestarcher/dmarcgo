# Contributing

Thanks for helping improve `dmarcgo`.

## Scope

`dmarcgo` is a Go library for parsing DMARC aggregate reports. Keep the core package focused on parsing and normalized report data. Ingestion pipelines, mailbox integrations, storage layers, dashboards, and CLI workflows should be added only after the library API remains clean and reusable.

## Development checks

Run the full local check suite before opening a pull request:

```shell
make ci
```

Useful narrower checks:

```shell
go test ./...
go test -race ./...
go vet ./...
python3 scripts/check_readme_examples.py
```

## Fixtures and private data

DMARC reports can expose domains, source IP addresses, provider metadata, and authentication behavior. Do not commit live/private reports. Put real report corpora in `test_dmarc_reports/`, which is ignored by Git.

Use anonymized synthetic fixtures under `testdata/fixtures/` for regression coverage.
When `test_dmarc_reports/` is present locally, the test suite also runs an
ignored-corpus compatibility check; CI skips it because private reports are not
committed.

## API compatibility

This project uses semantic versioning. Version 3 is the current API line and uses
the required `/v3` module path. The historical v1 and v2 APIs are not maintained.
Public API changes must be deliberate and documented in `CHANGELOG.md`.

## Maintainer release process

Go publishes this module when a semantic version tag is pushed. The release
workflow accepts only `v3.x.x` tags, verifies the `/v3` module path and matching
dated changelog entry, requires a GitHub-verified signed annotated tag pointing
to a commit on `main`, runs `make ci`, and then creates the GitHub Release with
the matching `CHANGELOG.md` section as its notes. It does not publish binaries because this repository is a
library. Both CI and release workflows can also be rerun manually from GitHub
Actions; release validation still requires the selected ref to be a valid tag.

1. Update `CHANGELOG.md`, moving release changes out of `Unreleased` into a dated
   version heading such as `## [3.0.0] - 2026-07-16`.
2. Run `make ci` from a clean working tree and merge the release commit to `main`.
3. Create and verify a signed annotated tag:

   ```shell
   git tag -s v3.0.0 -m "dmarcgo v3.0.0"
   git verify-tag v3.0.0
   ```

4. Push the commit, then push the tag:

   ```shell
   git push origin main
   git push origin v3.0.0
   ```

5. Confirm the `dmarcgo Release` workflow passes and that the GitHub Release is
   visible. Do not move or reuse a published tag; issue a new patch version for
   corrections.
