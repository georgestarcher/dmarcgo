# Changelog

All notable changes to this project should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning for public API changes.

## Unreleased

## [2.0.1] - 2026-07-11

Version 2.0.1 completes the public project and release support around the v2
library without changing its parsing or analysis API.

### Added

- Structured privacy-aware issue forms, pull request guidance, support information, and contributor conduct expectations.
- Reusable changelog extraction so future GitHub Releases publish complete version notes.
- Centralized, longer-running fuzz and benchmark smoke gates to reduce timing-dependent CI failures.

### Changed

- GitHub Actions use `actions/checkout@v7` across CI and release workflows.
- The README and repository community files provide direct support, contribution, security, privacy, and conduct guidance for human and AI consumers.
- Future GitHub Releases use the matching dated changelog section as their release notes.

## [2.0.0] - 2026-07-11

Version 2 replaces the original v1 API and uses the Go module path
`github.com/georgestarcher/dmarcgo/v2`. The historical v1 release is not
maintained.

### Added

- Package documentation and executable examples.
- RFC 9990 aggregate-report model fields, including modern metadata, policy, identifier, authentication-result, override-reason, and extension fields.
- Anonymized RFC 9990 synthetic fixture based on newer real-world report shapes.
- Validation findings, multi-report aggregate summaries, CSV output, parser fuzz targets, and helper API benchmarks.
- Strict RFC 9990 validation mode, context-aware reader loading, typed load errors, explicit unauthenticated/passing source helpers, CSV header metadata, and release-tag verification workflow.
- Attachment filename parsing and exact-IP/CIDR source exclusion helpers.
- Tar archive loading for `.tar`, `.tar.gz`, and `.tgz` report attachments.
- Report identity/deduplication helpers, filename validation, deterministic anonymization, and top-N summary helpers.
- Repository metadata for editor configuration, text normalization, contributing guidance, and security reporting.
- Tests for malformed XML, invalid row counts, nil receivers, empty paths, sorted directory reads, and zip member selection.
- CI checks for formatting, module tidiness, vet, Staticcheck, tests, race tests, README examples, vulnerability checks, coverage, and build.
- Automated v2 tag validation, full release gating, GitHub Release creation, and weekly dependency update checks.
- Manual CI reruns and verified signed-tag ancestry checks for releases.
- Node 24-based GitHub Actions and cross-platform-safe file tests for clean Windows CI.

### Changed

- Replaced the original API with a focused surface around `AggregateReport`, `FeatureRow`, `FileReport`, `LoadFile`, `LoadBytes`, `LoadReader`, `Rows`, and `ValidateStrict`.
- Adopted the required `/v2` module and import path for the redesigned public API.
- Flattened feature JSON now uses consistent snake_case field names such as `begin_date`, `end_date`, and `source_ip`.
- `Rows()` now returns only record rows, with report metadata copied onto each row; the legacy `Features()` method remains available for callers that need the historical metadata row.
- Summary pass/fail counts and rates now reflect DMARC policy-evaluated DKIM/SPF pass/fail rather than treating disposition `none` as an authentication pass.
- Test fixtures now live under `testdata/fixtures`, following Go conventions.
- Staticcheck is pinned to `v0.7.0` in local and CI checks.
- The module targets the supported Go 1.25+ toolchain line.
- GitHub Actions now uses read-only permissions, credential persistence disabled on checkout, concurrency cancellation, and job timeouts.

### Fixed

- `AnonymizeReport` now replaces report IDs and removes raw extension XML by default so real-report fixtures do not accidentally preserve opaque provider metadata.
- Zip parsing skips directory entries and prefers XML members.
- Report loading now resets stale content before parsing and returns clearer errors.
- Decompressed payload reads are size-limited by default to reduce archive-bomb risk.
- File-path loading now shares the canonical loader, supports raw XML, and preserves typed size, format, and malformed-XML errors.
- Invalid or negative record counts no longer reduce summary totals; summaries expose them through `InvalidRecords`.
- Local test runs validate every report in the ignored private corpus when `test_dmarc_reports/` is present.
