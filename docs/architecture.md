# Analysis architecture

This document defines the dependency direction and side-effect boundaries for
the organizational email-authentication features built on `dmarcgo`. The
primitive APIs remain independently callable. An optional application-owned
orchestrator may compose them, but composition is not the foundational API.

## Pipeline

```text
portfolio/configuration -> DNS collection -> DNS parsing -> DNS health
portfolio + completed DNS snapshot + explicit selection/provider -> optional DNS perspectives
provider catalog + parsed static SPF dependencies -> provider context
reports -> normalized report evidence
portfolio + DNS health + provider context + report evidence -> correlation
explicit campaign sources -> immutable campaign snapshot
campaign snapshot + normalized reported-message evidence -> campaign classification
campaign snapshot + report evidence -> aggregate campaign review
completed campaign classification -> privileged or disclosure-safe output
portfolio + report evidence + correlation -> threat candidates
threat candidates + optional enrichment -> enriched candidates
enriched candidates + explicit jurisdiction policy -> jurisdiction context
threat candidates + optional matching enrichment -> STIX 2.1 bundle
explicit threat-candidate/ASN selections + optional matching enrichment -> ThreatConnect v3 request payloads
explicit threat-candidate selections + target-instance capabilities and Event context -> MISP request payloads
explicit threat-candidate selections + versioned tenant contract -> Anomali ThreatStream request payloads
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
| Optional DNS perspectives | `dns_perspectives`, `DNSPerspectiveResult` | DNS-perspective feature |
| Normalized report evidence | `report_evidence` | Report-evidence feature |
| Expected/observed variance | `sender_variance`, correlation findings | Correlation feature |
| DNS/report correlation | `dns_report_correlation`, `DNSReportCorrelationResult` | Correlation feature |
| Suspicious-source candidates | `threat_candidates` | Candidate-scoring feature |
| Optional enrichment | `source_enrichment` | Enrichment feature |
| Jurisdiction context | `jurisdiction_context` | Jurisdiction-context feature |
| STIX 2.1 exchange | `STIXBundle` (standards-native, not an analysis mode) | STIX export feature |
| ThreatConnect v3 exchange | `ThreatConnectIndicatorPayload` (vendor-native, not an analysis mode) | ThreatConnect export feature |
| MISP exchange | `MISPAttributePayload`, `MISPEventPayload` (vendor-native, not analysis modes) | MISP export feature |
| Anomali ThreatStream exchange | `ThreatStreamPayload` (tenant-native, not an analysis mode) | ThreatStream export feature |
| Campaign configuration | `campaign_configuration_validation`, `CampaignConfigurationDocument`, `CampaignConfigurationSnapshot` | Campaign-correlation feature |
| Campaign classification | `campaign_classification`, `CampaignClassificationResult`, `CampaignReportCorrelationResult` | Campaign-correlation feature |
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

`DNSPerspectiveResult` implements an optional collection branch over a
normalized portfolio and its matching completed DNS snapshot. The planner
accepts an explicit owner-name or SPF/DKIM/DMARC role selection, deduplicates
the already declared names, and emits TXT requests only. A caller-supplied
`DNSPerspectiveProvider` owns the remote service and transport; the library
provides no built-in provider. Results preserve terminal success, no-answer,
failure, rate-limit, malformed, unavailable, and cancellation states plus
supplemental answer-set and snapshot comparisons. They never feed back into or
mutate DNS health. A nil provider is a deterministic no-clock, no-network
not-evaluated branch.

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

`SourceEnrichmentResult` implements the optional following collection stage. It
calls only a caller-supplied `IPEnricher` for review-eligible, non-excluded
candidates, deduplicates source IPs, bounds individual lookup concurrency, and
returns immutable per-candidate statuses and ASN views. A nil dependency is a
not-evaluated no-op. The library supplies no provider, credentials, PTR lookup,
retry loop, remote dataset, or global cache. Enrichers must never contact the
subject IP; network-backed adapters may contact only an explicitly selected
third-party service. Successful enrichment replaces the earlier unenriched cap
with a provider-confidence cap; missing confidence retains the original
conservative maximum. It never changes the score, exclusions, review
eligibility, recommended usage, or disabled promotion state.

`JurisdictionContextResult` implements the following pure context stage. It
consumes only a completed `SourceEnrichmentResult` and an explicit immutable
`JurisdictionRiskPolicy`, preserves all country assertions and policy
provenance, and represents match, no-match, unknown, stale, conflicting,
not-eligible, and not-evaluated states directly. The optional bounded priority
adjustment is a separate default-off queue hint; it never changes upstream
candidate scoring or enables promotion or automatic action. Evaluation has no
side-effect interface and cannot refresh policies or contact a source address.

`STIXBundle` is a separate standards-native exchange boundary rather than an
`AnalysisMode` or `OutputEnvelope`. `BuildSTIXBundle` consumes completed threat
candidates and optional matching source enrichment, defaults to SCOs plus
Observed Data, and requires explicit caller policy for any Indicator. It
preserves upstream identifiers in a versioned property extension but does not
rerun analysis, evaluate jurisdiction policy, consult a clock, or submit data.
Serialization validates the supported STIX subset and writes only to the
caller-supplied writer.

`ThreatConnectIndicatorPayload` is a separate vendor-native exchange boundary,
not an `AnalysisMode` or `OutputEnvelope`. The pure builder accepts completed
threat candidates, optional matching source enrichment, and explicit Address
or ASN selections. It applies inactive/private review-oriented defaults,
retains source references outside the native JSON, does not infer Threat
Rating, and performs no credentials, HTTP, owner discovery, duplicate lookup,
submission, clock access, or source-IP activity.

`MISPAttributePayload` and `MISPEventPayload` are separate vendor-native
exchange boundaries, not `AnalysisMode` or `OutputEnvelope` values. The pure
builders accept completed threat candidates, explicit candidate direction and
category mappings, and either an existing Event reference or complete
caller-owned Event context. They retain source references outside native JSON
and perform no capability discovery, Event search or creation, credentials,
HTTP, duplicate or warning-list lookup, submission, publication, retry, clock
access, or source-IP activity.

`ThreatStreamPayload` is a separate tenant-native exchange boundary, not an
`AnalysisMode` or `OutputEnvelope`. `BuildThreatStreamPayloads` accepts a
completed threat-candidate result, explicit candidate/`itype` selections, and
one versioned tenant capability for a direct-observable or reviewed-import
shape. The capability owns endpoint, fields, allowed values, encodings, limits,
private review defaults, and response assumptions because no universal public
ingestion schema is assumed. Payload provenance stays outside the native JSON.
The builder performs no discovery, credentials, HTTP, response parsing,
polling, approval, submission, clock access, or source-IP activity.

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
| Optional DNS perspectives | No | No | Explicit perspective provider only | No | Bounded selected-name collection |
| DNS parsing and health | No | No | No | No | Evaluation of supplied snapshot |
| Report evidence | Supplied report/results only | No implicit loading | No | No | Evidence normalization |
| Correlation and variance | Supplied completed values only | No | No | No | Correlation |
| Campaign source resolution | No | Explicit adapters only | Explicit HTTPS adapter only | No | Bounded loading, verification, and merge |
| Message campaign classification | Caller-supplied normalized evidence only | No | No | No | Bounded pure matching |
| Aggregate campaign review | Supplied report evidence only | No | No | No | Lower-confidence pure correlation |
| Campaign output | No | Writer supplied by caller | No | No | Privacy representation only |
| Threat candidates | Supplied completed values only | No | No | No | Explainable scoring |
| Source enrichment | No implicit reports | No | Explicit enricher only | Explicit | Bounded enrichment |
| STIX export | Supplied completed values only | Writer supplied by caller | No | No | Pure transformation and validation |
| ThreatConnect export | Supplied completed values only | Writer supplied by caller | No | No | Pure transformation and validation |
| MISP export | Supplied completed values only | Writer supplied by caller | No | No | Pure transformation and validation |
| ThreatStream export | Supplied completed values only | Writer supplied by caller | No | No | Pure transformation and validation |
| Output encoding | No | Writer supplied by caller | No | No | Representation only |

No stage may use global mutable configuration or a global cache. Caches belong
to callers or explicit dependency instances. Network access requires a
context-aware interface supplied to an explicit collection or enrichment API.

Architecture tests install a resolver that fails on access while exercising
current report and output modes. They also inspect the output implementation to
reject report loading, parsing, evaluation, summarization, and network imports.
Each future collection or enrichment interface must add counting and failing
spies that prove unrelated modes never invoke it.

The Phase 13 workflow gate adds a complete synthetic evidence chain, generated
metadata samples for every native analysis mode, common-candidate exchange
proof, and a static dependency audit across all pure analysis and export
implementations. See [Independent automation workflows](automation-workflows.md).

The Phase 14 campaign gate adds a separate synthetic commercial/self-hosted
inventory, explicit source resolution, body-free message evidence, pure bounded
classification, and disclosure-safe output proof. The explicit source adapter
file is intentionally outside the pure-stage import audit; campaign
configuration normalization, evidence normalization, matching, aggregate
review, and output remain inside it. See
[Security-simulation campaign correlation](campaign-correlation.md).

The Phase 15 DNS-perspective gate uses synthetic provider fixtures and the
ignored private portfolio record-name collection to prove explicit selection,
TXT-only planning, deduplication, bounded concurrency, no retry, cancellation,
partial failure, deterministic comparison, defensive copies, and isolation
from DNS health. A skipped-by-default one-request DShield compatibility check
is research instrumentation only; ordinary tests and CI perform no live
lookup. See [Optional DNS perspective collection](dns-perspectives.md).

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

`EnrichThreatCandidates` is the source-enrichment entry point. Individual
providers implement `IPEnricher`; an optional `BatchIPEnricher` can consume the
complete sorted, deduplicated address set in one caller-owned batch. The stage
does not retry. Caller cancellation, per-lookup timeouts, collect-all partial
failure, and fail-fast partial results remain explicit. Provider errors are
converted to fixed diagnostics without copying their text. Stale and
conflicting assertions remain visible, and ASN grouping retains every
underlying source IP and assertion rather than selecting a preferred owner.

`EvaluateJurisdictionContext` is the jurisdiction-context entry point. It has
no resolver, provider, filesystem, environment, credential, or clock
dependency. A zero generated time preserves the source-enrichment timestamp;
an explicit time supports reproducible later assessment. Policy expiration and
assertion freshness are evaluated at that timestamp. Policy strings remain
untrusted structured data and are never copied into fixed finding prose.

`BuildSTIXBundle` is the STIX exchange entry point. It accepts no context or
side-effect dependency. A zero generated time preserves the latest input result
timestamp, and `STIXProducer.CreatedAt` controls producer-identity stability.
Raw source IPs and operational context remain present by design; callers own
markings, recipient authorization, minimization, transport, and retention.
Indicator promotion is an explicit export option and never mutates upstream
promotion state.

`BuildThreatConnectIndicatorPayloads` is the ThreatConnect exchange entry
point. It accepts no context or side-effect dependency. A zero generation time
preserves the latest input-result timestamp. Each payload uses native v3 fields
and keeps its dmarcgo evidence references in defensive `Source()` metadata.
Owner-scoped duplicate checks, credentials, HTTP, response handling, and audit
storage belong to the application; a duplicate POST can update an existing
Indicator according to the vendor contract.

`BuildThreatStreamPayloads` is the Anomali ThreatStream exchange entry point.
It accepts no context or side-effect dependency. A zero generation time
preserves the candidate-result timestamp. Each payload matches only the exact
caller-supplied tenant capability and keeps dmarcgo evidence references in
defensive `Source()` metadata. Tenant discovery, credentials, HTTP, live
response parsing, duplicate handling, asynchronous polling, import approval,
retry, and audit storage belong to the application. A valid encoded request is
not proof that a tenant will accept, create, approve, publish, or deduplicate an
observable.

## Persistence and composition

Intermediate profiles, snapshots, evidence, and results may be persisted by the
calling application. Persisted forms carry their own schema version, observation
times, provenance, and stable identifiers. Loading a persisted result never
causes network access.

`LoadReportEvidenceJSON` validates the report-evidence schema version, common
result metadata, references, counters, summary, and digest. The intermediate
document is separate from later automation and agent output profiles.
Report-evidence schema version `2` includes normalized policy-override types in
observation content and intentionally rejects version `1` documents rather
than migrating their incompatible digests and evidence identifiers.

Applications may compose stages in a service or command, but authorization,
scheduling, storage, retries, and automatic defensive action remain outside this
library. Output recommendations are advisory until the caller applies its own
policy and authorization checks.
