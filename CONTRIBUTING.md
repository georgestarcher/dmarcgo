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

Go publishes this library from semantic-version tags rather than binary release
archives. Follow [RELEASING.md](RELEASING.md) for version selection, release-PR
preflight, signed annotated tagging, GitHub Actions behavior, public Go-module
verification, and recovery rules. Never move or reuse a tag that has been
pushed; publish corrections under a new semantic version.
