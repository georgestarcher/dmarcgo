# Changelog

All notable changes to this project should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning for public API changes.

## Unreleased

### Added

- Versioned organization portfolio configuration for entities, domains,
  monitored SPF/DKIM/DMARC names, expected senders, reusable policies,
  ownership, inheritance, and scoped exclusions.
- Strict single-document YAML loading with unknown-field, secret-field, alias,
  size, schema-version, and explicit environment-expansion controls.
- Deterministic internationalized-domain normalization, value-safe diagnostics,
  defensive-copy accessors, portfolio digests, synthetic multi-entity fixtures,
  private record-name compatibility testing, and configuration fuzz coverage.
- Shared analysis-mode, result-metadata, evaluation-state, sensitivity,
  identifier, and clock contracts for independently callable organizational
  analysis stages.
- An architecture guide defining package ownership, dependency direction,
  side-effect boundaries, deterministic identifiers, persistence, and stage
  composition for the organizational email-authentication feature roadmap.
- Explicit, context-aware DNS TXT snapshot collection with bounded concurrency,
  retry and failure policies, shared-name deduplication, immutable evidence,
  deterministic timestamps, fragment-preserving TXT records, and structured
  diagnostics.
- Standard-library and DNS-message resolver adapters. The DNS-message adapter
  preserves TTL, authoritative/recursive source, RCODE, CNAME path, SOA, and
  RFC 2308 negative-cache TTL evidence; limited adapters mark unavailable
  evidence instead of inventing values.
- Side-effect-free SPF, DKIM key, and RFC 9989 DMARC policy parsing over
  reusable DNS snapshots, with typed semantics, deterministic diagnostics,
  bounded SPF dependency analysis, DKIM key-strength metadata, DMARC tree-walk
  planning, IDN normalization, fuzz coverage, and explicit unknown evidence.
- Pure DNS authentication-health evaluation with stable record, domain, entity,
  and portfolio findings; deterministic versioned scoring profiles; complete
  score contributions; partial-evidence and staleness policy; shared-record and
  inheritance-aware rollups; and optional DNSSEC authenticated-data evidence.
- Independent SPF, DKIM, and DMARC grades; a sample-calibrated maturity scale
  with an explicit DNS-only evidence ceiling; maturity distributions and
  coverage; and owned-versus-reference membership for honest portfolio rollups.
- Strict, versioned, embedded email-provider metadata with reviewed first-party
  citations, exact-by-default SPF dependency matching, immutable accessors,
  explicit private overlays, deterministic provenance, review-date checks, and
  context-only semantics that never imply authorization or DNS health.
- Pure normalized report-evidence analysis with stable report and observation
  provenance, explicit unknown values, checked 64-bit counts, deterministic
  duplicate handling, filtering and multi-dimensional aggregation, strict JSON
  persistence, fuzz coverage, and report-only side-effect isolation.
- Pure DNS/report/expected-sender correlation with immutable inventory and
  stream evidence, context-only provider references, explicit temporal and
  threshold semantics, stable onboarding and variance findings, caller-owned
  prior-result drift comparison, preserved DNS snapshot observation time, and
  no hidden collection or attribution.
- Pure, versioned suspicious-source candidate scoring with conservative,
  balanced, sensitive, and custom profiles; exact score recomputation;
  false-positive-sensitive confidence caps; scoped expiring source exclusions;
  expected-sender omission by default; and explicit review-only semantics.
- Normalized policy-override type evidence for forwarding and mailing-list
  counter-signals without retaining reporter-supplied comments.
- Explicit optional IP and ASN enrichment over review-eligible candidates with
  provider-neutral single and batch interfaces, bounded concurrency,
  cancellation, partial failure, deterministic ASN views, freshness and
  conflict evidence, defensive-copy results, and caller-owned caching.
- A default-off source-enrichment security boundary: no bundled provider,
  credentials, retries, PTR lookup, direct source-IP traffic, or global cache;
  committed examples and tests use only deterministic offline fixtures.
- Pure, versioned jurisdiction-context evaluation over completed enrichment,
  with immutable caller policies, all seven evidence states, stable findings,
  policy and assertion provenance, deterministic digests, and no implicit I/O.
- A documented U.S. export-control-inspired policy snapshot derived from
  current BIS/eCFR Country Groups D and E, with explicit source categories,
  review expiry, attribution limitations, and a default-off separate priority
  adjustment capped at 10 that never changes threat scoring or authorizes
  action.
- Independent versioned native JSON, JSONL, and CSV output for DNS health,
  report evidence, DNS/report correlation, threat candidates, source
  enrichment, and jurisdiction context, with embedded mode schemas,
  deterministic streamed records, stable record IDs, spreadsheet-injection
  protection, and public/operational/restricted privacy controls.
- Pure standards-native STIX 2.1 export of completed threat candidates and
  optional source enrichment, defaulting to IP/ASN SCOs plus Observed Data,
  with explicit Indicator promotion, producer and TLP controls, deterministic
  identifiers, a strict embedded evidence-extension schema, official OASIS
  interoperability validation, and no analysis or submission side effects.
- Pure ThreatConnect v3 Indicator request encoding for explicitly selected
  Address candidates and evidence-backed ASN rollups, with inactive/private
  review defaults, exact vendor field validation, opt-in confidence and Threat
  Rating, deterministic tenant metadata, defensive source references,
  owner-scoped duplicate/update documentation, and no credentials, HTTP, or
  submission side effects.

### Changed

- Report-evidence persistence now uses schema version `2` because normalized
  observations include policy-override type codes in content digests and
  evidence identifiers. The strict loader rejects incompatible version `1`
  documents instead of silently reinterpreting them.
- `BuildValidationOutput` now accepts a completed `ReportValidationResult`
  instead of a report plus findings. Use `report.ValidationResult(mode,
  generatedAt)` to perform validation before serialization; output conversion
  no longer reruns report analysis.

### Fixed

- Threat-candidate scoring no longer omits a dual-failure observation when one
  expanded DKIM stream matches an expected sender but another remains
  unattributed, and sender-scoped exclusions no longer suppress that mixed
  evidence.
- DNS-message TXT collection now preserves per-record TTLs and applies the
  RFC 2181 minimum TTL when an explicitly configured resolver returns an RRset
  with inconsistent TTLs, instead of discarding otherwise usable evidence.

## [2.1.0] - 2026-07-11

Version 2.1 adds a versioned, privacy-aware output contract for automation and
AI-agent consumers while keeping report-provided content isolated as data.

### Added

- Versioned automation and AI-agent output envelopes for report validation,
  report summaries, aggregate summaries, flattened rows, and source review.
- Stable finding, evidence, action, provenance, redaction, and truncation
  metadata with a strict embedded JSON Schema and version-discovery helpers.
- Deterministic JSON and JSONL writers, bounded collections, public output
  redaction, and hostile-input tests for downstream AI consumers.
- Fail-closed, mode-aware redaction; explicit evaluation and failure output;
  per-collection truncation; and concurrent non-mutating output builders.

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
