# Changelog

All notable changes to this project should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning for public API changes.

## Unreleased

### Added

- Package documentation and executable examples.
- Tests for malformed XML, invalid row counts, nil receivers, empty paths, sorted directory reads, and zip member selection.
- CI checks for formatting, module tidiness, vet, Staticcheck, tests, and build.

### Changed

- Test fixtures now live under `testdata/fixtures`, following Go conventions.
- Staticcheck is pinned to `v0.7.0` in local and CI checks.
- The module targets the supported Go 1.25+ toolchain line.

### Fixed

- Zip parsing skips directory entries and prefers XML members.
- Report loading now resets stale content before parsing and returns clearer errors.
