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

## API compatibility

This project uses semantic versioning. Until a `v1.0.0` release exists, public APIs may still change, but changes should be deliberate and documented in `CHANGELOG.md`.
