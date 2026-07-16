# v3.0.0 release contract audit

This audit records the release-integration decisions for v3.0.0. It reviews the
completed feature pack as one public Go module without adding a new analysis,
provider, network, or enforcement behavior.

## Go API comparison

The pinned `golang.org/x/exp/cmd/apidiff` comparison in the
[v2.1-to-v3 migration guide](migration-v2.1-to-v3.md) reports nine deliberate
incompatibilities and no other removal or incompatible type change. The module
major changes from `/v2` to `/v3`; no compatibility facade retains the
provisional v2 call shapes.

The compatible additions fall into these independently callable families:

| Family | Primary completed value or builder | Boundary reviewed |
| --- | --- | --- |
| Organization configuration | `Portfolio`, `ConfigurationValidationResult` | Strict bounded input, immutable normalized output, no implicit environment or network access |
| DNS evidence and posture | `DNSSnapshot`, `DNSAuthenticationResult`, `DNSHealthResult`, `DNSPerspectiveResult` | Explicit resolver/provider dependencies, bounded work, deterministic supplied clocks, supplemental perspectives never alter health |
| Report evidence and correlation | `ReportEvidenceResult`, `DNSReportCorrelationResult` | Pure normalization/correlation, checked counts, duplicate conflict handling, DNS and report time kept separate |
| Campaign authorization | `CampaignConfigurationSnapshot`, `CampaignClassificationResult`, `CampaignReportCorrelationResult` | Explicit sources, bounded resolution/classification, body-free evidence, fail-closed authorization, no automatic disposition execution |
| Source review context | `ThreatCandidateResult`, `SourceEnrichmentResult`, `SourceActivityResult`, `PhishingIntelligenceResult`, `JurisdictionContextResult` | Review-only scoring, explicit optional dependencies, no subject-IP contact, no automatic action, score/context separation |
| Output | `OutputEnvelope` and native analysis writers | Completed inputs only, deterministic timestamps, bounded collections, privacy views, untrusted data never becomes generated instruction text |
| Defensive exports | STIX, ThreatConnect, MISP, and ThreatStream builders | Explicit reviewed selection, pure encoding, conservative defaults, no credentials, HTTP, submission, or enforcement |

Each family has an authoritative guide linked from the
[documentation index](README.md), public option/default documentation, focused
tests, defensive-copy tests, and a native or common output contract where
applicable. `make ci` exercises the full API, race, coverage, fuzz, benchmark,
documentation, schema, and cross-mode isolation gates.

## Schema decisions

- Common envelope schema v1 is restored byte-for-byte to the document released
  with v2.1.0 and is locked by a SHA-256 regression test.
- v3 common envelopes emit schema v2 because the post-v2.1 required shape is
  incompatible with schema v1. `OutputSchemaVersions` exposes both versions in
  ascending order.
- Native analysis, campaign, portfolio, provider-catalog, STIX-extension, and
  vendor schemas introduced after v2.1.0 are first published at their existing
  version; the Go module major does not renumber them.
- Report-evidence persistence remains version 2 because its normalized
  observation digest semantics already changed before this first feature-pack
  release. Its strict loader continues to reject version 1 rather than
  reinterpret stored evidence.
- Scoring, maturity, phishing-intelligence, jurisdiction-policy, campaign,
  STIX, and vendor mapping versions remain independent and change only with
  their own semantics.

## Determinism and identity

Representation time remains caller-supplied or derived from a completed result;
serialization never consults the clock. Sorting, stable digests, defensive
copies, checked counts, and explicit truncation remain covered by focused and
cross-mode tests.

The STIX and MISP dmarcgo UUIDv5 namespaces remain frozen at their first
published values. This intentional historical `/v2` string is an identifier
namespace, not an import or package link. Preserving it avoids changing stable
evidence IDs solely because the Go module path becomes `/v3`.

## Release automation

The release workflow accepts only semantic `v3.x.x` tags, requires the exact
`github.com/georgestarcher/dmarcgo/v3` module path and matching dated changelog
entry, and retains signed annotated tag, GitHub verification, main-ancestry,
full-CI, and changelog-derived release-note gates. Regression tests reject a
wrong tag major, non-semantic tags, a wrong module path, and missing dated
release notes.
