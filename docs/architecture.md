# Analysis architecture

This document defines the dependency direction and side-effect boundaries for
the organizational email-authentication features built on `dmarcgo`. The
primitive APIs remain independently callable. An optional application-owned
orchestrator may compose them, but composition is not the foundational API.

## Pipeline

```text
portfolio/configuration -> DNS collection -> DNS parsing -> DNS health
reports -> normalized report evidence
portfolio + DNS health + report evidence -> correlation
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
| Portfolio validation | `configuration_validation` | Portfolio feature |
| Portfolio health | `configuration_health` | Portfolio and health features |
| DNS collection | `dns_snapshot` | DNS snapshot feature |
| DNS record parsing | `dns_authentication_records` | Authentication-record feature |
| DNS health | `dns_health` | DNS health feature |
| Normalized report evidence | `report_evidence` | Report-evidence feature |
| Expected/observed variance | `sender_variance` | Correlation feature |
| DNS/report correlation | `dns_report_correlation` | Correlation feature |
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

## Cancellation and failures

Only stages performing cancellable work accept `context.Context`: report reader
loading, DNS collection, enrichment, and future explicit orchestrators. Pure
parsers, evaluators, correlation, and output conversion do not accept a context
merely for API uniformity.

Collection may return an immutable partial snapshot plus structured diagnostics
when its documented failure policy allows it. Later stages consume that snapshot
without retrying collection. Unknown or missing evidence remains distinct from a
negative finding.

## Persistence and composition

Intermediate profiles, snapshots, evidence, and results may be persisted by the
calling application. Persisted forms carry their own schema version, observation
times, provenance, and stable identifiers. Loading a persisted result never
causes network access.

Applications may compose stages in a service or command, but authorization,
scheduling, storage, retries, and automatic defensive action remain outside this
library. Output recommendations are advisory until the caller applies its own
policy and authorization checks.
