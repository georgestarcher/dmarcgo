# Changelog

All notable changes to this project should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning for public API changes.

## Unreleased

### Added

- Package documentation and executable examples.
- RFC 9990 aggregate-report model fields, including modern metadata, policy, identifier, authentication-result, override-reason, and extension fields.
- Anonymized RFC 9990 synthetic fixture based on newer real-world report shapes.
- Validation findings, multi-report aggregate summaries, CSV output, parser fuzz targets, and helper API benchmarks.
- Strict RFC 9990 validation mode, context-aware reader loading, typed load errors, explicit unauthenticated/passing source helpers, CSV header metadata, and release-tag verification workflow.
- Repository metadata for editor configuration, text normalization, contributing guidance, and security reporting.
- Tests for malformed XML, invalid row counts, nil receivers, empty paths, sorted directory reads, and zip member selection.
- CI checks for formatting, module tidiness, vet, Staticcheck, tests, race tests, README examples, vulnerability checks, coverage, and build.

### Changed

- Simplified the pre-v1 public API around `AggregateReport`, `FeatureRow`, `FileReport`, `LoadFile`, `LoadBytes`, `LoadReader`, `Rows`, and `ValidateStrict`.
- Flattened feature JSON now uses consistent snake_case field names such as `begin_date`, `end_date`, and `source_ip`.
- `Rows()` now returns only record rows, with report metadata copied onto each row; the legacy `Features()` method remains available for callers that need the historical metadata row.
- Test fixtures now live under `testdata/fixtures`, following Go conventions.
- Staticcheck is pinned to `v0.7.0` in local and CI checks.
- The module targets the supported Go 1.25+ toolchain line.
- GitHub Actions now uses read-only permissions, credential persistence disabled on checkout, concurrency cancellation, and job timeouts.

### Fixed

- Zip parsing skips directory entries and prefers XML members.
- Report loading now resets stale content before parsing and returns clearer errors.
- Decompressed payload reads are size-limited by default to reduce archive-bomb risk.
