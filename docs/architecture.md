# Analysis architecture

This document defines the dependency direction and side-effect boundaries for
the organizational email-authentication features built on `dmarcgo`. The
primitive APIs remain independently callable. An optional application-owned
orchestrator may compose them, but composition is not the foundational API.

## Pipeline

```text
portfolio/configuration -> DNS collection -> DNS parsing -> DNS health
provider catalog + parsed static SPF dependencies -> provider context
reports -> normalized report evidence
portfolio + DNS health + provider context + report evidence -> correlation
portfolio + report evidence + correlation -> threat candidates
threat candidates + optional enrichment -> enriched candidates
completed result values -> output encoders
```

Collection, evaluation, correlation, enrichment, and encoding are separate
stages. A stage consumes completed values from earlier stages. It does not
silently recollect, reparse, or enrich them.

## Result ownership

Every independently callable mode owns a concrete result type. Result types
share `ResultMetadata` and implement `Result`; they do not share one giant data
structure containing every possible input or output.

| Stage | Mode or current result | Owned by |
| --- | --- | --- |
| Report validation | `report_validation`, `ReportValidationResult` | Current report package |
| Report summaries | `report_summary`, `aggregate_summary`, `ReportSummary`, `AggregateSummary` | Current report package |
| Report rows and source review | `report_rows`, `source_review`, `FeatureRow`, `SourceReview` | Current report package |
| Portfolio validation | `configuration_validation`, `ConfigurationValidationResult` | Portfolio feature |
| Portfolio health | `configuration_health` | Portfolio and health features |
| DNS collection | `dns_snapshot`, `DNSSnapshot` | DNS snapshot feature |
| DNS record parsing | `dns_authentication_records`, `DNSAuthenticationResult` | Authentication-record feature |
| DNS health | `dns_health` | DNS health feature |
| Normalized report evidence | `report_evidence` | Report-evidence feature |
| Expected/observed variance | `sender_variance`, correlation findings | Correlation feature |
| DNS/report correlation | `dns_report_correlation`, `DNSReportCorrelationResult` | Correlation feature |
| Suspicious-source candidates | `threat_candidates` | Candidate-scoring feature |
| Optional enrichment | `source_enrichment` | Enrichment feature |
| Campaign configuration | `campaign_configuration_validation` | Campaign-correlation feature |
| Campaign classification | `campaign_classification` | Campaign-correlation feature |
| Serialization | Existing output modes, later extended per completed mode | Output feature |

Future concrete result types should embed `ResultMetadata` and expose their
mode-specific data directly. They should not use `any` as an internal result
model. `OutputEnvelope` implements `Result` as the existing serialized-result
boundary; output schema versions remain independent of
`AnalysisContractVersion`.

`ReportEvidenceResult` now implements the normalized report-evidence stage. It
owns stable report and observation evidence IDs, explicit unknown values,
checked message counts, deterministic filtering/grouping, and a strict
intermediate JSON persistence document. It deliberately does not attach
portfolio entity or expected-sender identities; the correlation stage resolves
those against the same evidence IDs.

`DNSReportCorrelationResult` implements the pure correlation stage. It owns an
effective inventory snapshot, deterministic observed streams, thresholds,
current-DNS versus report-period relationships, stable findings, and optional
prior-result provenance. Provider contexts remain evidence references and never
authorize a stream. The result retains upstream digests without recollecting,
reparsing, enriching, or loading history.

`ThreatCandidateResult` implements the following pure candidate-scoring stage.
It counts distinct report observations directly, uses correlation only for
prepared attribution and counter-evidence, and retains the upstream digests.
Versioned profiles make every score operation and confidence cap inspectable.
Expected-sender-only failures are omitted by default, exclusions remain scoped,
and promotion is always disabled. The stage performs no source enrichment or
network access and never asserts malicious ownership or safe-to-block status.

## Shared contracts

- `AnalysisMode` is the canonical mode vocabulary. `OutputMode` is an alias so
  analysis and serialization cannot drift into separate identifiers.
- `EvaluationState` distinguishes evaluated, not evaluated, unknown, and not
  applicable. Empty data is not proof that a mode was evaluated cleanly.
- Finding and action codes are stable machine contracts. Human titles,
  explanations, and recommendations may improve without changing their codes.
- Evidence and provenance use stable identifiers so findings can reference
  shared evidence without copying it repeatedly.
- Sensitivity is explicit and uses public, operational, or restricted values.
- `StableAnalysisID` uses namespace-separated SHA-256 over length-framed,
  caller-canonicalized parts. A mode owns its canonicalization rules and must
  test identifiers across input orderings.
- Result collections have a documented deterministic order. Map-backed inputs
  are sorted before identifiers, truncation, or serialization are applied.

## Time and reproducibility

Networked or filesystem collection records an observation time supplied by a
`Clock`. Tests and reproducible callers inject `ClockFunc`. Pure evaluation
preserves observation times from its inputs and accepts an explicit generation
time for new result metadata. Encoders copy result times and never replace them
with the current time.

The existing output builders retain their documented `OutputOptions` behavior:
callers set `GeneratedAt` when reproducibility matters. New analysis stages must
not hide calls to `time.Now` inside pure evaluation.

## Allowed side effects

| Mode family | Reports | Filesystem | DNS/network | Enrichment | Significant work |
| --- | ---: | ---: | ---: | ---: | --- |
| Report parsing and analytics | Supplied report only | Only explicit load APIs | No | No | Parsing and report evaluation |
| DNS snapshot collection | No | No | Explicit resolver only | No | Bounded DNS collection |
| DNS parsing and health | No | No | No | No | Evaluation of supplied snapshot |
| Report evidence | Supplied report/results only | No implicit loading | No | No | Evidence normalization |
| Correlation and variance | Supplied completed values only | No | No | No | Correlation |
| Threat candidates | Supplied completed values only | No | No | No | Explainable scoring |
| Source enrichment | No implicit reports | No | Explicit enricher only | Explicit | Bounded enrichment |
| Output encoding | No | Writer supplied by caller | No | No | Representation only |

No stage may use global mutable configuration or a global cache. Caches belong
to callers or explicit dependency instances. Network access requires a
context-aware interface supplied to an explicit collection or enrichment API.

Architecture tests install a resolver that fails on access while exercising
current report and output modes. They also inspect the output implementation to
reject report loading, parsing, evaluation, summarization, and network imports.
Each future collection or enrichment interface must add counting and failing
spies that prove unrelated modes never invoke it.

The provider catalog is inert, versioned context rather than a collection
stage. Catalog loading reads only caller-supplied bytes or the embedded file.
Matching consumes normalized static SPF relationships and never resolves DNS.
Recognition does not authorize a sender, repair broken DNS, grant health points,
or trust an IP range. Health and correlation retain live DNS and the portfolio's
expected-sender inventory as their authoritative inputs.

## Cancellation and failures

Only stages performing cancellable work accept `context.Context`: report reader
loading, DNS collection, enrichment, and future explicit orchestrators. Pure
parsers, evaluators, correlation, and output conversion do not accept a context
merely for API uniformity.

Collection may return an immutable partial snapshot plus structured diagnostics
when its documented failure policy allows it. Later stages consume that snapshot
without retrying collection. Unknown or missing evidence remains distinct from a
negative finding.

`CollectDNSSnapshot` is the only current DNS collection entry point. It plans
lookups solely from a supplied normalized `Portfolio`, deduplicates shared owner
names, and calls only the supplied `TXTResolver`. The snapshot preserves the
collection timestamp, resolver identity, RRset evidence, references back to all
dependent portfolio scopes, and unavailable-evidence markers. It has no global
cache and never loads aggregate reports. DNS parsing and health stages consume
the completed snapshot without initiating new lookups.

`ParseAuthenticationRecords` is the pure DNS parsing stage. It consumes only a
completed `DNSSnapshot`, preserves the snapshot digest and observation time,
and produces deterministic typed SPF, DKIM, and RFC 9989 DMARC semantics.
Direct record parsers and DMARC tree-walk planning also perform no I/O. SPF
graph evidence is limited to relationships present in the snapshot; unavailable
void-lookup and macro-expansion evidence remains indeterminate.

`EvaluateDNSHealth` is the pure posture stage. It consumes a normalized
portfolio, completed authentication result, and explicit provider catalog;
rejects mismatched or incomplete provenance; and rolls deterministic findings
and explainable scores from record to domain, entity, and portfolio. Recognized
static SPF dependencies carry exact-domain inventory context but never change
findings, scores, or sender authorization. Unknown DNS evidence is not a failure
by default.
Optional DNSSEC authenticated-data evidence is preserved without assuming that
an unset flag means validation failure.

DNS health also emits independent mechanism components and categorical maturity.
Maturity rollups preserve a level distribution and use the weakest available
domain as a guardrail. Entities explicitly configured with `membership:
reference` remain fully evaluated but are excluded from organization rollups.
Report outcomes never alter DNS maturity; correlation is a separate later mode.

## Persistence and composition

Intermediate profiles, snapshots, evidence, and results may be persisted by the
calling application. Persisted forms carry their own schema version, observation
times, provenance, and stable identifiers. Loading a persisted result never
causes network access.

`LoadReportEvidenceJSON` validates the report-evidence schema version, common
result metadata, references, counters, summary, and digest. The intermediate
document is separate from later automation and agent output profiles.

Applications may compose stages in a service or command, but authorization,
scheduling, storage, retries, and automatic defensive action remain outside this
library. Output recommendations are advisory until the caller applies its own
policy and authorization checks.
