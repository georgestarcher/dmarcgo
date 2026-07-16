# Cross-mode automation and agent output

This guide defines the common `OutputEnvelope` used to represent one already
completed `dmarcgo` result for automation or AI-assisted review. Output is a
serialization stage, not an orchestrator: choosing a profile, detail level, or
redaction level never loads reports, resolves DNS, reads campaign sources,
contacts an enrichment service, or reruns analysis.

## Choose the output family

Use the common envelope when a consumer needs consistent findings, evidence,
actions, coverage, provenance, safety metadata, and bounded mode data. Use a
native writer when a consumer needs the complete mode-specific JSON, streaming
JSONL, or tabular CSV contract. Use a standards or vendor encoder only for its
actual target contract; those payloads are not wrapped in the common envelope.

| Need | API | Contract |
| --- | --- | --- |
| Report validation, summaries, rows, or source review | `BuildValidationOutput`, `BuildReportSummaryOutput`, `BuildAggregateSummaryOutput`, `BuildReportRowsOutput`, or `BuildSourceReviewOutput` | Common envelope |
| Any completed organization-analysis, source-context, or campaign result | `BuildAnalysisOutput` | Common envelope |
| A prerequisite failed before a result existed | `BuildFailureOutput` | Common envelope with `status: failed` and `evaluation.state: not_evaluated` |
| Complete mode-native JSON, JSONL, or CSV | The mode's `Write*Output` function | Independent native schema |
| Campaign classification JSON or JSONL | `WriteCampaignClassificationOutput` | Privileged or disclosure-safe campaign schema |
| STIX, ThreatConnect, MISP, or ThreatStream | The target-specific builder | Standards/vendor-native payload |

`BuildAnalysisOutput` accepts only dmarcgo's sealed `OutputResult` set. This
keeps unsupported or partially constructed application types out of the
generic builder while retaining one entry point for completed library results.

## Supported common-envelope modes

Modes are independently callable and appear in dependency order from
`SupportedOutputModes` and `OutputModeDescriptors`.

| Mode | Completed input or builder | Analysis needed before serialization |
| --- | --- | --- |
| `configuration_validation` | `ConfigurationValidationResult` | Portfolio validation only |
| `dns_snapshot` | `DNSSnapshot` | Explicit DNS collection |
| `dns_authentication_records` | `DNSAuthenticationResult` | Parsing a completed snapshot |
| `dns_health` | `DNSHealthResult` | Pure health evaluation |
| `dns_perspectives` | `DNSPerspectiveResult` | Optional explicit provider collection |
| `report_validation` | `BuildValidationOutput` | Report validation |
| `report_summary` | `BuildReportSummaryOutput` | One report summary |
| `aggregate_summary` | `BuildAggregateSummaryOutput` | Multi-report summary |
| `report_rows` | `BuildReportRowsOutput` | Flattened rows |
| `source_review` | `BuildSourceReviewOutput` | Source summary helpers |
| `report_evidence` | `ReportEvidenceResult` | Pure report normalization |
| `dns_report_correlation` | `DNSReportCorrelationResult` | Pure DNS/report correlation |
| `threat_candidates` | `ThreatCandidateResult` | Pure review-priority scoring |
| `source_enrichment` | `SourceEnrichmentResult` | Optional explicit third-party enrichment |
| `source_activity` | `SourceActivityResult` | Optional explicit selected third-party activity lookup |
| `phishing_intelligence` | `PhishingIntelligenceResult` | Pure offline exact-match correlation |
| `jurisdiction_context` | `JurisdictionContextResult` | Pure policy evaluation of completed enrichment |
| `campaign_configuration_validation` | `CampaignConfigurationSnapshot` | Explicit campaign-source resolution |
| `campaign_classification` | `CampaignClassificationResult` or `CampaignReportCorrelationResult` | Pure reported-message or lower-confidence aggregate comparison |

There is no standalone `configuration_health`, `sender_variance`, or combined
`organizational_monitoring` result. Configuration health is expressed through
configuration diagnostics and DNS health. Sender variance is expressed through
DNS/report correlation. A combined monitoring mode would duplicate evidence
and create hidden orchestration, so composition remains application-owned.

## Common envelope

Every envelope declares:

- common schema and schema version;
- mode, profile, detail, generation time, status, evaluation state, and the
  completed result's separate evaluation timestamp when available;
- organization, entity, business-unit, and domain scope when present;
- input counts, immutable artifacts, and collection coverage;
- a fixed-text summary;
- stable findings, evidence, actions, warnings, and errors;
- `data_schema` and mode-specific `data`;
- limitations, provenance, redaction, truncation, and automation policy.

`data_schema` is machine-readable. For completed standard/full output, use
`OutputDataSchemaID` for discovery and `OutputDataSchema` to obtain a defensive
copy of the mode schema. Summary and failed output identify the common
`emptyData` fragment through `OutputEmptyDataSchemaID`; obtain that document
with `OutputSchema` or `OutputSchemaForVersion`.

Finding IDs, evidence IDs, action IDs, and provenance IDs are deterministic.
Finding codes are the stable semantic contract; titles and explanations are
library-controlled presentation text and may improve without changing a code.

## Profile, detail, and redaction

The three choices are orthogonal.

| Choice | Behavior |
| --- | --- |
| `OutputProfileAutomation` | Keeps structured fields and removes narrative summary/finding explanation text. |
| `OutputProfileAgent` | Adds concise fixed-text headlines and explanations; never chain-of-thought. |
| `OutputDetailSummary` | Retains findings, coverage, provenance, actions, and truncation metadata while omitting mode data. |
| `OutputDetailStandard` | Retains mode data but removes bulky raw/restricted free-form evidence. |
| `OutputDetailFull` | Retains the selected redaction view's complete mode data. |
| `OutputRedactionPublic` | Replaces operational identifiers and untrusted strings with deterministic pseudonymous tokens and removes restricted raw text. |
| `OutputRedactionOperational` | Retains defensive identifiers while removing restricted free-form text and provider metadata documented by each mode. |
| `OutputRedactionRestricted` | Retains the completed result inside its full operational trust boundary. |

Public tokens are stable SHA-256-derived pseudonyms with explicit namespaces
and 128 retained bits. Canonical domain values produce stable tokens across
case differences. Tokens are not encryption: low-entropy values can be guessed
by dictionary enumeration and public output must not be treated as anonymous.

## Campaign views

Campaign inventory and privileged classification data are restricted. A
restricted envelope may include campaign identities, periods, infrastructure,
source provenance, factors, and workflow details. Public and operational
campaign envelopes use a disclosure-safe payload that omits those fields.
Disclosure-safe common envelopes also replace the result digest with one
derived only from the safe representation and omit privileged upstream
artifact digests and provenance links. This prevents operational output from
becoming a side channel into the restricted campaign view.

Disclosure-safe reported-message classification retains only neutral routing,
factor counts, confidence, the fixed employee-template identifier, and safety
metadata. Aggregate campaign correlation retains only counts and the explicit
`aggregate_evidence_only` boundary outside the restricted view. Aggregate
reports never prove that an individual message belonged to a campaign.

Automation eligibility is false by default. A reported-message classification
may expose `automation.eligible: true` only when exactly one completed record
already met the caller-enabled disposition policy. The application still owns
authorization, execution, response text, and audit. Serialization never takes
the action.

## Size bounds and deterministic truncation

`OutputOptions` provides three independent positive bounds:

- `MaxItems` limits each top-level mode-data collection;
- `MaxFindings` limits common findings after deterministic severity-first
  sorting;
- `MaxEvidence` limits the combined matched, contradictory, missing, and
  unverifiable evidence retained for each returned finding.

Automation defaults to 1,000 items and agent output to 100. Findings default to
100 and evidence to 50 entries per finding. Every bound has a hard maximum of
1,000,000.

`truncation.collections` reports total and returned counts. Evidence totals
include evidence attached to findings omitted by `MaxFindings`. Contradictory,
missing, and unverifiable evidence are retained before ordinary matched
evidence when the per-finding evidence budget is exhausted. Severe findings
sort before lower-severity findings; ties use stable codes and canonical data.
Summary detail marks omitted data collections as returned zero rather than
silently presenting them as empty analysis.

Summary-detail and failed envelopes carry an empty `data` object and declare
`OutputEmptyDataSchemaID`, the strict `emptyData` fragment of the common
schema. Standard and full completed envelopes declare their mode-specific data
schema. The identifier therefore always validates the payload actually
serialized, while `OutputDataSchemaID` remains the discovery API for a mode's
completed standard/full shape.

For very large results, prefer the mode-native JSONL writer. Each JSONL record
retains schema, mode, generated time, result digest, redaction, record type,
record ID, and complete record data. CSV is a lossy convenience view with a
final `data_json` column containing the complete nested record and a schema
fragment describing every row.

## Mode isolation and side effects

`OutputModeDescriptorFor` publishes required, optional, and prohibited inputs,
analysis-stage side effects, serialization-stage side effects, significant
work, and sensitive outputs. `OutputModeDescriptors` returns defensive copies.

Every serialization descriptor has:

- no network, report-file, DNS, provider-catalog, enrichment, or campaign-source access;
- no subject-IP contact;
- no retry, polling, history discovery, credential lookup, or clock lookup.

When `BuildAnalysisOutput` receives a zero `OutputOptions.GeneratedAt`, it uses
the completed result's generation time. Empty report-evidence results preserve
their intentional zero time instead of consulting the clock. An explicitly
supplied representation time is normalized to UTC without replacing
`evaluation.evaluated_at`, which retains the completed result timestamp.

Analysis descriptors describe only how the completed result may have been
produced. For example, DNS snapshot collection requires an explicit resolver,
but serializing a `DNSSnapshot` does not resolve DNS. Enrichment and activity
providers may contact only their configured third-party services and never the
subject IP.

## Hostile-input boundary

Treat report text, DNS answers, domains, selectors, contacts, map keys,
provider catalog text, enrichment values, activity metrics, feed names,
campaign fields, policy labels, provenance, and extension data as untrusted
data. They remain structured values and never become generated headlines,
explanations, recommendations, actions, error messages, or instructions.

Provider recognition is context, not authorization. Campaign approval does not
repair SPF, DKIM, or DMARC and does not hide authentication failures. Failed
authentication does not prove malicious intent. Enrichment, phishing
intelligence, activity, and jurisdiction context do not change threat scores or
authorize blocking. Unknown and not-evaluated states are not clean results.

Downstream AI consumers should validate the envelope and its `data_schema`,
select only needed structured fields, quote untrusted evidence as data, and use
stable codes for routing. They must not concatenate untrusted values into a
system or developer prompt or execute a recommendation without separate caller
policy.

## Schema evolution

The common envelope, mode-data schemas, native analysis schemas, campaign
schemas, in-memory result contract, scoring profiles, policy snapshots, and
standards/vendor mappings are versioned independently. They are not tied to the
Go module version.

Within one released schema major version, additions must remain compatible and
required-field meaning must not change. Removing or renaming a field, changing
its type, weakening a privacy boundary, or changing a finding code's meaning
requires a new schema major version. New modes and new finding codes may be
added without changing unrelated mode schemas. Persist the schema identifier,
result digest, and relevant non-restricted upstream artifact digests with every
output. Disclosure-safe campaign output deliberately omits privileged artifact
digests.

The v3 contract deliberately replaces the provisional v2 Go API because no
known external consumer depended on those shapes. The released envelope schema
v1 remains discoverable and immutable; v3 output uses envelope schema v2.

## Standards and vendor boundaries

STIX 2.1, ThreatConnect, MISP, and Anomali ThreatStream payloads retain their
native contracts. Output profile selection never changes those payloads. The
application selects reviewed candidates, invokes the target builder, handles
lossy mappings, credentials, HTTP, duplicate policy, responses, submission,
and audit storage. Common findings retain the source result and evidence IDs
needed to make that selection without wrapping the external payload.

## Safe integration patterns

- **Observation only:** build or write a completed result, validate both schema
  layers, persist it, and take no action.
- **Analyst assisted:** route stable finding codes and minimum required evidence
  to a reviewer; keep untrusted data quoted and structurally separate.
- **Bounded automation:** require explicit caller policy, an eligible completed
  result, one unambiguous action, external authorization, and an audit trail.
  The library never executes the action.

See [Independent automation workflows](automation-workflows.md) for stage
composition and [Automation outputs and AI safety](wiki/Automation-Outputs-and-AI-Safety.md)
for task-oriented navigation.
