# dmarcgo [![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/dmarcgo/v2.svg)](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2) [![Report Card](https://goreportcard.com/badge/github.com/georgestarcher/dmarcgo/v2)](https://goreportcard.com/report/github.com/georgestarcher/dmarcgo/v2) [![Build Status](https://github.com/georgestarcher/dmarcgo/workflows/dmarcgo%20CI/badge.svg)](https://github.com/georgestarcher/dmarcgo/actions)

`dmarcgo` is a Go library for parsing DMARC aggregate report files.

It supports older real-world aggregate reports, legacy DMARC RUA XML output, and the current [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html) aggregate-report shape. It intentionally does not parse [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html) DMARC failure/forensic reports.

Written by George Starcher.

MIT license. See [LICENSE](LICENSE) for details.

All text above must be included in any redistribution.

## Install

From another Go module:

```shell
go get github.com/georgestarcher/dmarcgo/v2@latest
```

Then import the library:

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.ReportMetadata.OrgName)
}
```

Version 2 is the supported API line. The historical `v1.0.0` tag contains the
original API and is retained only for Go module history; it is not maintained.

## What this package does

`dmarcgo` is a parser library. It is meant to be imported by other Go code that wants to parse DMARC aggregate report artifacts and then decide how to ingest, store, summarize, or display the results.

It does not provide a mailbox ingester, directory watcher, database, CLI,
dashboard, generic IP-reputation engine, or automatic enforcement system.

The planned organizational-analysis features follow independently callable
stages with explicit side-effect boundaries. See
[Analysis architecture](docs/architecture.md) for result ownership, dependency
direction, deterministic metadata, and the rule that output serialization never
initiates analysis or network access.

Organization portfolios can describe entities, domains, monitored SPF/DKIM/DMARC
record names, expected senders, reusable authentication policies, ownership,
inheritance, and scoped exclusions. See
[Organization portfolio configuration](docs/portfolio-configuration.md).

DNS snapshot collection is an explicit, separate stage. It deduplicates the
portfolio's monitored TXT owner names and records immutable evidence through a
caller-selected resolver. See [DNS snapshot collection](docs/dns-snapshots.md).

Authentication-record parsing is the following side-effect-free stage. It
parses supplied SPF, DKIM, and current RFC 9989 DMARC values without performing
lookups, and preserves missing or unavailable evidence explicitly. See
[Authentication-record parsing](docs/authentication-records.md).

DNS authentication health is the next pure stage. It evaluates configured
records and rolls explainable scores through domains, entities, and the complete
portfolio without reports or additional lookups. Health scores, grades,
evidence coverage, and categorical maturity remain separate. See
[DNS authentication health](docs/dns-health.md).

The reviewed provider catalog adds versioned context for documented SPF and
DKIM setup models without turning recognition into authorization or health
credit. See [Provider catalog](docs/provider-catalog.md).

DNS/report correlation is the following pure stage. It compares declared
sender intent, current DNS health, and historical report evidence while keeping
their observation times separate. See
[DNS and report correlation](docs/dns-report-correlation.md).

Suspicious-source candidate scoring is the next pure stage. It produces
explainable, review-only source candidates from normalized observations and
prepared correlation without malicious attribution, enrichment, or automatic
action. See [Suspicious-source candidate scoring](docs/threat-candidates.md).

Optional source IP and ASN enrichment is a separate, explicitly invoked stage.
It accepts only a caller-supplied context-aware dependency, performs no built-in
network or PTR lookups, and never contacts an observed source IP. See
[Optional source enrichment](docs/source-enrichment.md).

STIX 2.1 export is a pure final transformation of completed threat-candidate
evidence and optional enrichment. It defaults to SCOs plus Observed Data;
Indicators require an explicit caller promotion. See
[STIX 2.1 observed-data export](docs/stix-export.md).

ThreatConnect v3 export is a separate pure final transformation. It converts
only explicitly selected review candidates and enriched ASN rollups into
inactive, private native Indicator request bodies without credentials, HTTP,
submission, or automatic action. See
[ThreatConnect v3 indicator payload export](docs/threatconnect-export.md).

MISP export is another separate pure final transformation. It converts
explicitly selected candidates into review-only native Attribute requests for
an identified Event, or into one complete offline Event body when the caller
supplies all lifecycle context. It performs no capability discovery, HTTP,
event creation, publication, or submission. See
[MISP event and attribute export](docs/misp-export.md).

## Supported report inputs

`dmarcgo` reads DMARC aggregate reports delivered as:

- gzip-compressed XML, usually `.xml.gz`
- zip archives, usually `.zip`
- tar archives, usually `.tar`, `.tar.gz`, or `.tgz`
- zlib-compressed XML

The parser accepts aggregate XML reports using:

- no XML namespace, which is common in older real-world reports
- the historical `http://dmarc.org/dmarc-xml/0.1` namespace
- the RFC 9990 `urn:ietf:params:xml:ns:dmarc-2.0` namespace

Local real-world report corpora should not be committed. DMARC reports can expose domains, provider metadata, source IPs, and authentication behavior. This repository ignores `test_dmarc_reports/` for that reason. Public regression fixtures belong under `testdata/fixtures/` and should be synthetic or anonymized.

## Which API should I use?

| Situation | Use | Notes |
| --- | --- | --- |
| You have a local report artifact path | `dmarcgo.LoadFile(path)` | Accepts compressed archives or raw XML and returns a parsed `*AggregateReport`. |
| You need file-loading metadata or a custom size limit on a reusable loader | `FileReport{MaxDecompressedBytes: ...}.LoadFile(path)` | Most callers can use package-level `LoadFile`. |
| You have attachment bytes from mail, S3, or an upload | `dmarcgo.LoadBytes(data)` | Accepts gzip, zip, tar, zlib, or raw XML bytes. |
| You have an `io.Reader` for an attachment or object | `dmarcgo.LoadReader(reader)` | Reads with the same decompressed-size protection. |
| You know the input is raw XML | `dmarcgo.ParseBytes(data)` or `dmarcgo.ParseReader(reader)` | Skips archive detection. |
| You want easy JSON rows | `report.Rows()` | Returns one flattened row per DMARC record, with report metadata copied onto each row. |
| You want complete structured data | `report.Record` | Preserves RFC 9990 fields such as multiple DKIM results. |
| You want quick counts for one report | `report.Summary()` | Gives totals, pass/fail counts, top sources, and date metadata. |
| You want counts across many reports | `dmarcgo.SummarizeReports(reports)` or `dmarcgo.MergeSummaries(summaries)` | Combines report summaries without adding storage or ingest behavior. |
| You want reusable normalized report evidence | `dmarcgo.AnalyzeReportEvidence(reports, options)` | Produces deterministic, persistable report-only evidence with filtering and aggregation; it performs no DNS, enrichment, or sender-inventory interpretation. |
| You want expected-sender and DNS/report variance | `dmarcgo.CorrelateReportEvidence(portfolio, dnsHealth, reportEvidence, options)` | Correlates already completed values without DNS, parsing, enrichment, storage, or malicious attribution. |
| You want explainable source-review candidates | `dmarcgo.ScoreThreatCandidates(portfolio, reportEvidence, correlation, options)` | Scores distinct normalized observations with versioned profiles, false-positive-sensitive confidence caps, and scoped exclusions; it performs no network access or malicious attribution. |
| You explicitly want optional IP and ASN context | `dmarcgo.EnrichThreatCandidates(ctx, threatCandidates, enricher, options)` | Calls only the supplied dependency for review-eligible, non-excluded candidates; nil is a no-op, PTR is not implicit, and implementations must never contact the subject IP. |
| You want standards-native STIX 2.1 observations | `dmarcgo.BuildSTIXBundle(threatCandidates, enrichment, options)` | Purely emits IP/ASN SCOs and Observed Data by default; Indicator promotion is explicit, markings and timestamps are caller-controlled, and no submission occurs. |
| You want reviewed ThreatConnect v3 request bodies | `dmarcgo.BuildThreatConnectIndicatorPayloads(threatCandidates, enrichment, options)` | Purely encodes explicitly selected Address and enriched ASN requests; defaults are inactive/private, confidence and rating are opt-in, and the application owns submission. |
| You want reviewed MISP Attribute or complete offline Event bodies | `dmarcgo.BuildMISPAttributePayloads(threatCandidates, options)` or `dmarcgo.BuildMISPEventPayload(threatCandidates, options)` | Requires explicit event context and target-instance type/category capabilities; Attributes default to `to_ids: false` with correlation disabled, and the application owns discovery, review, HTTP, and submission. |
| You want versioned jurisdiction review context | `dmarcgo.EvaluateJurisdictionContext(enrichment, policy, options)` | Purely evaluates fresh, unambiguous coarse country assertions against an explicit immutable policy; the optional separate priority adjustment is default-off and never changes threat scoring or authorizes action. |
| You want unauthenticated-source summaries | `report.UnauthenticatedSources(domain)` | Finds rows where `header_from` matches and both DKIM/SPF alignment failed. |
| You want to suppress known source IPs | `dmarcgo.ExcludeUnauthenticatedSources(sources, exclusions)` | Applies caller-owned exact-IP or CIDR exclusions without storing policy state. |
| You want metadata from attachment names | `dmarcgo.ParseReportFilename(name)` | Parses common bang-separated RUA filenames into reporter, domain, dates, unique ID, and compression. |
| You want duplicate-safe importing | `dmarcgo.ReportKey(report)` and `dmarcgo.DeduplicateReports(reports)` | Uses report ID, reporter, policy domain, and date range. |
| You want safe regression fixtures | `dmarcgo.AnonymizeReport(report, options)` | Preserves report shape while replacing domains, source IPs, report IDs, and reporter contact details. Raw extension XML is removed by default. |
| You want dashboard-ready top lists | `dmarcgo.TopSources`, `dmarcgo.TopUnauthenticatedSources`, or `dmarcgo.TopCounts` | Returns sorted top-N slices without storage or scoring policy. |
| You want data-quality checks | `report.Validate()` | Returns structured warnings/errors for malformed or non-standard content. |
| You want spreadsheet-friendly rows | `dmarcgo.WriteFeaturesCSV(writer, features)` | Writes flattened feature rows with a header. |
| You want versioned automation or AI-agent output | `dmarcgo.BuildReportSummaryOutput(summary, options)` | Produces a self-describing envelope with findings, evidence, actions, provenance, redaction, and truncation metadata. |
| You want native JSON, JSONL, or CSV for a completed analysis mode | `dmarcgo.WriteDNSHealthOutput`, `WriteReportEvidenceOutput`, `WriteDNSReportCorrelationOutput`, `WriteThreatCandidatesOutput`, `WriteSourceEnrichmentOutput`, or `WriteJurisdictionContextOutput` | Serializes one immutable result without rerunning analysis or performing I/O beyond the supplied writer. |
| You have strict versioned organization YAML | `dmarcgo.LoadPortfolioYAML(data)` | Rejects unknown and secret-bearing fields and performs no DNS or report access. |
| You construct organization configuration in Go | `dmarcgo.NormalizePortfolio(config)` | Returns a deterministic normalized portfolio with defensive-copy accessors. |
| You want configuration diagnostics | `dmarcgo.ValidatePortfolio(config, generatedAt)` | Returns value-safe structured diagnostics without I/O. |
| You want reusable DNS evidence for a portfolio | `dmarcgo.CollectDNSSnapshot(ctx, portfolio, resolver, options)` | Explicitly queries only configured TXT names; use `DNSMessageResolver` when TTL and authority evidence matter. |
| You want parsed SPF, DKIM, and DMARC semantics | `dmarcgo.ParseAuthenticationRecords(snapshot)` | Purely parses an existing snapshot; performs no DNS, report, filesystem, or time access. |
| You want DNS-only authentication posture, maturity, and explainable scores | `dmarcgo.EvaluateDNSHealth(portfolio, authentication, providerCatalog, options)` | Purely evaluates completed values with independent SPF/DKIM/DMARC scores, grades, coverage, and context-only provider recognition. |
| You need to validate one supplied record string | `dmarcgo.ParseSPFRecord`, `dmarcgo.ParseDKIMKeyRecord`, or `dmarcgo.ParseDMARCPolicyRecord` | Returns typed semantics plus value-safe diagnostics without I/O. |
| You need RFC 9989 DMARC tree-walk names | `dmarcgo.DMARCPolicyDiscoveryNames(domain)` | Computes at most eight owner names but never resolves them. |
| You want reviewed provider context | `dmarcgo.DefaultProviderCatalog()` | Loads the strict embedded catalog without network access. |
| You want to recognize a parsed SPF dependency | `catalog.MatchSPFRelationship(relationship)` | Exact-by-default context only; it never authorizes a sender or validates live DNS. |
| You maintain private provider metadata | `dmarcgo.LoadProviderCatalogYAML(data)` or `dmarcgo.OverlayProviderCatalog(base, overlay)` | Strict, bounded caller data with explicit replacement provenance and no remote updates. |

## Automation and AI-agent output

Use the output builders when results will be consumed by workflow engines,
AI summarizers, or other systems that need a stable, self-describing contract.
The current schema supports report validation, report summaries, aggregate
summaries, flattened rows, and source review.

Output choices are orthogonal:

- `OutputProfileAutomation` keeps explanations terse for deterministic processing.
- `OutputProfileAgent` adds grounded headlines and explanations without chain-of-thought.
- `OutputDetailSummary` omits mode data, `OutputDetailStandard` omits bulky
  per-source or nested authentication detail, and `OutputDetailFull` retains it.
- `OutputRedactionPublic` replaces operational identifiers with stable
  pseudonymous tokens and removes restricted report text.
- `OutputRedactionOperational` retains identifiers needed for defensive work but
  removes free-form contact, error, comment, and human-result text from rows.
- `OutputRedactionRestricted` retains the complete current mode data.
- `MaxItems` bounds each named collection independently. The envelope reports
  total and returned counts for every collection under `truncation.collections`.

Profiles change representation only. They never load reports, rerun analysis,
perform DNS lookups, or access the network. Pass already computed values to the
appropriate builder.

```go
package main

import (
	"log"
	"os"
	"time"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	result, err := dmarcgo.BuildReportSummaryOutput(report.Summary(), dmarcgo.OutputOptions{
		Profile:       dmarcgo.OutputProfileAgent,
		Detail:        dmarcgo.OutputDetailStandard,
		Redaction:     dmarcgo.OutputRedactionOperational,
		GeneratedAt: time.Now(),
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := dmarcgo.WriteOutputJSON(os.Stdout, result); err != nil {
		log.Fatal(err)
	}
}
```

Use these mode-specific builders:

| Mode | Builder | Input is already computed |
| --- | --- | --- |
| `report_validation` | `BuildValidationOutput` | `ReportValidationResult`, usually from `report.ValidationResult(mode, generatedAt)` |
| `report_summary` | `BuildReportSummaryOutput` | `ReportSummary` |
| `aggregate_summary` | `BuildAggregateSummaryOutput` | `AggregateSummary` |
| `report_rows` | `BuildReportRowsOutput` | `[]FeatureRow` |
| `source_review` | `BuildSourceReviewOutput` | `SourceReview` |

Use `BuildFailureOutput` when loading, parsing, or another prerequisite failed
before a mode could be evaluated. Failed envelopes use `status: "failed"`,
`evaluation.state: "not_evaluated"`, and stable error codes and categories. Use
`OutputMessageForError` to classify wrapped loader errors without copying path
context or raw error text into the envelope.

### Native analysis outputs

The six completed organization-analysis modes also have independent native
contracts. These are not sparse variants of one union object. Each JSON
document has its own embedded schema and complete typed collections; JSONL and
CSV emit a metadata record followed by deterministic mode records.

```go
package main

import (
	"io"

	"github.com/georgestarcher/dmarcgo/v2"
)

func writeCandidates(writer io.Writer, threatCandidates dmarcgo.ThreatCandidateResult) error {
	return dmarcgo.WriteThreatCandidatesOutput(
		writer,
		threatCandidates,
		dmarcgo.AnalysisOutputJSONL,
		dmarcgo.AnalysisOutputOptions{Redaction: dmarcgo.OutputRedactionOperational},
	)
}

func main() {}
```

| Mode | Writer | JSONL record types | Useful CSV fields |
| --- | --- | --- | --- |
| `dns_health` | `WriteDNSHealthOutput` | `metadata`, `record`, `domain`, `entity`, `finding`, `provider_context` | entity, domain, record type/status, score, grade, severity |
| `report_evidence` | `WriteReportEvidenceOutput` | `metadata`, `report`, `observation`, `diagnostic` | reporter, target/author domain, source IP, disposition, messages, combined outcome |
| `dns_report_correlation` | `WriteDNSReportCorrelationOutput` | `metadata`, `inventory`, `stream`, `finding` | scope, source/auth identities, messages, classification, severity |
| `threat_candidates` | `WriteThreatCandidatesOutput` | `metadata`, `candidate` | source IP, score, confidence, severity, eligibility, recommended usage |
| `source_enrichment` | `WriteSourceEnrichmentOutput` | `metadata`, `candidate`, `asn`, `diagnostic` | source IP, status, score, ASN, country, organization |
| `jurisdiction_context` | `WriteJurisdictionContextOutput` | `metadata`, `candidate`, `finding` | source IP, status, tier, countries, categories, review-priority adjustment |

Every JSONL line carries `schema`, `schema_version`, `mode`, `generated_at`,
`result_digest`, `redaction`, `record_type`, `record_id`, and `data`. Every CSV
row carries the same context. The final `data_json` CSV column preserves the
complete nested record even when the convenience columns are blank for another
record type. Spreadsheet-capable values are prefixed with an apostrophe; do not
remove that protection before opening untrusted exports in spreadsheet software.
Use `(mode, result_digest, record_type, record_id)` as the deduplication key.
Result items reuse their stable analysis IDs; ID-less diagnostics use a stable
content-derived record ID, and each result has exactly one `metadata` record.

The native JSON shape for each mode begins as follows (collections are abbreviated):

```json
{"schema_version":"1","mode":"dns_health","profile":"native","observed_at":"2026-07-13T12:00:00Z","records":[],"domains":[],"entities":[],"findings":[],"provider_contexts":[]}
{"schema_version":"1","mode":"report_evidence","profile":"native","evidence_schema_version":"2","reports":[],"observations":[],"diagnostics":[]}
{"schema_version":"1","mode":"dns_report_correlation","profile":"native","inventory":[],"streams":[],"findings":[]}
{"schema_version":"1","mode":"threat_candidates","profile":"native","scoring_profile":{},"candidates":[]}
{"schema_version":"1","mode":"source_enrichment","profile":"native","complete":true,"candidates":[],"asns":[],"diagnostics":[]}
{"schema_version":"1","mode":"jurisdiction_context","profile":"native","policy_freshness":"fresh","candidates":[],"findings":[]}
```

Use `SupportedAnalysisOutputModes`, `AnalysisOutputDescriptorForMode`,
`AnalysisOutputSchemaID`, and `AnalysisOutputSchema` for discovery. The
analysis-output schema version is independent of the Go module, in-memory
contract, report-evidence persistence, and common-envelope versions.

`OutputRedactionPublic` replaces source addresses, report/reporting identities,
organization and entity identifiers, domains and selectors, provider metadata,
stable result references, and related values with deterministic pseudonyms.
Those tokens preserve joins but are not encryption and low-entropy inputs may
remain enumerable. `OutputRedactionOperational` retains operational identifiers
but removes invalid raw report values and free-form enrichment provider text.
`OutputRedactionRestricted` retains the complete result inside the full trust
boundary. Encoding never mutates the source result.

Raw TXT records are intentionally not part of these six completed analysis
results: DNS health carries evidence references, parsed status, scores, and
findings rather than copying the upstream snapshot's record values. The native
redactor also drops reserved raw/TXT fields before operational or public output
so a later reviewed schema extension cannot expose them accidentally.

Native output is data, not instructions. Treat all retained report, catalog,
DNS, enrichment, and policy strings as untrusted when feeding a model. No
writer turns those strings into headlines, explanations, recommendations, or
actions. JSON and JSONL preserve the complete result; CSV is intended for
tabular consumption but retains each complete record in `data_json`.

The older `WriteFeaturesJSONL`, `WriteFeaturesCSV`, and `FeatureCSVHeaders`
remain the intentionally simple flattened `report.Rows()` export. The
`report_rows` common-envelope builder maps that same record-level use case.
They do not serialize report-evidence, DNS-health, correlation, candidate,
enrichment, or jurisdiction result contracts. `WriteOutputJSON` and
`WriteOutputJSONL` remain the automation/agent common envelope for current
report modes; later common-envelope expansion is separate from these native
mode contracts.

```json
{
  "schema": "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/output/v1.json",
  "schema_version": "1",
  "mode": "report_summary",
  "profile": "agent",
  "detail": "summary",
  "generated_at": "2026-07-11T12:00:00Z",
  "status": "completed",
  "evaluation": {"state": "evaluated"},
  "scope": {"target_domains": ["example.test"]},
  "input": {"report_count": 1, "record_count": 2, "message_count": 27},
  "summary": {
    "headline": "No authentication failures or invalid records were present in the supplied summary.",
    "severity": "info",
    "confidence": "high"
  },
  "findings": [],
  "data": {},
  "recommended_actions": [],
  "warnings": [],
  "errors": [],
  "limitations": [],
  "provenance": [{"id": "report-1", "type": "aggregate_report", "key": "synthetic-report-id"}],
  "redaction": {"profile": "operational", "operational_fields_changed": false},
  "truncation": {
    "truncated": false,
    "collections": [
      {"name": "data.by_source_ip", "total_items": 0, "returned_items": 0},
      {"name": "data.by_disposition", "total_items": 0, "returned_items": 0},
      {"name": "data.by_header_from", "total_items": 0, "returned_items": 0}
    ]
  }
}
```

Every JSONL line written by `WriteOutputJSONL` is a complete envelope. Use
`OutputSchemaForVersion`, `OutputSchemaVersions`, and `SupportedOutputModes`
for discovery. `OutputSchema()` remains the version-1 convenience accessor.
`ModuleVersion` is caller supplied and omitted when unavailable; do not insert
an imprecise value when reproducibility matters.

Schema v1 becomes immutable at the v2.1.0 release boundary. Additive optional
fields and new modes require a new published schema when they are not accepted
by v1; removing fields, changing meanings, or changing stable codes requires a
new schema version. The output schema version is independent of the Go module
version.

The agent profile treats report-provided text as untrusted structured data. It
does not turn reporter comments, domains, extension XML, or other input values
into instructions. Recommendations are advisory and are never automatically
executed. Authentication failure does not by itself establish spoofing or
malicious intent.

Public redaction tokens are deterministic 128-bit pseudonyms so a consumer can
correlate repeated values. They are not encryption: low-entropy values such as
IPv4 addresses and common domains remain susceptible to dictionary enumeration.
Do not publish public output when that correlation risk is unacceptable.

## Sample outputs

These examples use synthetic, documentation-safe values. Real reports can expose source IPs, domains, reporter metadata, and authentication behavior.

### Aggregate summary

Use `SummarizeReports` or `MergeSummaries` when you want an overall view across many reports.

```json
{
  "reports": 49,
  "total_records": 86,
  "total_messages": 114,
  "passed_messages": 66,
  "failed_messages": 48,
  "rejected_messages": 48,
  "quarantined_messages": 0,
  "none_messages": 66,
  "pass_rate": 0.5789,
  "failure_rate": 0.4211
}
```

### Per-report summary

Use `report.Summary()` when you want counts and source breakdowns for one aggregate report.

```json
{
  "reporting_org": "Example Reporter",
  "target_domain": "example.com",
  "begin_time": "2026-05-21T00:00:00Z",
  "end_time": "2026-05-21T23:59:59Z",
  "total_records": 2,
  "total_messages": 2,
  "passed_messages": 2,
  "failed_messages": 0,
  "pass_rate": 1
}
```

### Flattened row

Use `report.Rows()` when you want one record-oriented row per source/result tuple.

```json
{
  "reporting_org": "Example Reporter",
  "report_id": "example-report-id",
  "begin_date": "1779321600",
  "end_date": "1779407999",
  "target_domain": "example.com",
  "source_ip": "192.0.2.1",
  "mail_count": 1,
  "vendor_action": "none",
  "dkim_policy_evaluated": "pass",
  "spf_policy_evaluated": "pass",
  "header_from": "example.com",
  "dkim_domain": "example.com",
  "dkim_selector": "google",
  "spf_domain": "example.com"
}
```

### JSON Lines

Use `WriteFeaturesJSONL` when each flattened row should be one JSON object per line.

```jsonl
{"reporting_org":"Example Reporter","report_id":"example-report-id","target_domain":"example.com","source_ip":"192.0.2.1","mail_count":1,"dkim_policy_evaluated":"pass","spf_policy_evaluated":"pass"}
{"reporting_org":"Example Reporter","report_id":"example-report-id","target_domain":"example.com","source_ip":"192.0.2.2","mail_count":1,"dkim_policy_evaluated":"pass","spf_policy_evaluated":"pass"}
```

### CSV

Use `WriteFeaturesCSV` for spreadsheet-friendly exports.

```csv
reporting_org,reporting_addr,report_id,begin_date,end_date,target_domain,requested_handling_policy,subdomain_policy_published,nonexistent_subdomain_policy,source_ip,mail_count,vendor_action,dkim_policy_evaluated,spf_policy_evaluated,header_from,envelope_from,envelope_to,dkim_domain,dkim_selector,dkim_result,spf_domain,spf_scope,spf_result
Example Reporter,dmarc@example.net,example-report-id,1779321600,1779407999,example.com,reject,,,192.0.2.1,1,none,pass,pass,example.com,,,example.com,google,pass,example.com,,pass
```

### Filename metadata

Use `ParseReportFilename` before opening an attachment when the filename is useful for ingest metadata.

```json
{
  "raw": "reporter.example!example.com!1779321600!1779407999.xml.gz",
  "reporter": "reporter.example",
  "policy_domain": "example.com",
  "begin": "1779321600",
  "end": "1779407999",
  "begin_time": "2026-05-21T00:00:00Z",
  "end_time": "2026-05-21T23:59:59Z",
  "extension": ".xml.gz",
  "compression": "gzip"
}
```

### Report identity

Use `ReportKey` or `FilenameReportKey` when deduplicating reports from mailbox or object-store imports.

```json
{
  "report_id": "example-report-id",
  "reporting_org": "Example Reporter",
  "policy_domain": "example.com",
  "begin": "1779321600",
  "end": "1779407999"
}
```

### Source review

Use `UnauthenticatedSources`, `RejectedUnauthenticatedSources`, and `PassingSources` to separate failed and authenticated sources.

```json
[
  {
    "source_ip": "198.51.100.25",
    "messages": 4,
    "records": 2,
    "rejected_messages": 4,
    "header_from": {
      "example.com": 4
    }
  }
]
```

```json
[
  {
    "source_ip": "192.0.2.1",
    "messages": 27,
    "passed_messages": 27,
    "pass_rate": 1
  }
]
```

### Top-N lists

Use `TopSources`, `TopUnauthenticatedSources`, or `TopCounts` for dashboard cards.

```json
[
  {
    "source_ip": "192.0.2.1",
    "messages": 27,
    "passed_messages": 27,
    "failed_messages": 0,
    "pass_rate": 1
  },
  {
    "source_ip": "198.51.100.25",
    "messages": 8,
    "passed_messages": 0,
    "failed_messages": 8,
    "failure_rate": 1
  }
]
```

### Anonymized fixture row

Use `AnonymizeReport` before committing fixtures derived from real reports.

```json
{
  "reporting_org": "Example Reporter",
  "reporting_addr": "dmarc@example.net",
  "report_id": "example-report-id",
  "target_domain": "example.com",
  "source_ip": "192.0.2.1",
  "header_from": "example.com",
  "dkim_domain": "example.com",
  "spf_domain": "example.com",
  "mail_count": 1,
  "dkim_policy_evaluated": "pass",
  "spf_policy_evaluated": "pass"
}
```

### Validation findings

Use `Validate`, `ValidateStrict`, and `ValidateReportFilename` when you want non-fatal data-quality findings.

```json
[
  {
    "severity": "error",
    "path": "report_metadata.report_id",
    "message": "missing report id"
  },
  {
    "severity": "warning",
    "path": "record[0].row.source_ip",
    "message": "source IP is not a valid IPv4 or IPv6 address"
  }
]
```

## Quick start: flattened rows

`Rows()` returns a convenient flattened representation that is easy to encode as JSON or feed into another system.

`Rows()` returns one row per DMARC record. Report-level metadata is copied onto each row so downstream JSONL/CSV pipelines do not need to join against separate metadata.

```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	for _, feature := range report.Rows() {
		if err := encoder.Encode(feature); err != nil {
			log.Fatal(err)
		}
	}
}
```

The flattened output keeps simple single-value fields such as `DKIMDomain` and `SPFResult`, while also exposing complete RFC 9990 data such as `DKIMAuthResults`, `SPFAuthResult`, and `PolicyOverrideReasons`. The single-value fields are populated from the first available result for convenience; use the plural/structured fields when correctness depends on every DKIM result or every override reason.

## Structured report access

For applications that need complete data, use the parsed `AggregateReport` model directly. This is the right path for dashboards, enrichment pipelines, policy auditing, or any code that needs every DKIM signature result rather than a flattened convenience view.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	for _, record := range report.Record {
		fmt.Printf("source=%s count=%s disposition=%s\n",
			record.Row.SourceIP,
			record.Row.Count,
			record.Row.PolicyEvaluated.Disposition,
		)

		for _, dkim := range record.AuthResults.DKIM {
			fmt.Printf("  dkim domain=%s selector=%s result=%s\n",
				dkim.Domain,
				dkim.Selector,
				dkim.Result,
			)
		}

		if record.AuthResults.SPF != nil {
			fmt.Printf("  spf domain=%s result=%s\n",
				record.AuthResults.SPF.Domain,
				record.AuthResults.SPF.Result,
			)
		}
	}
}
```

## Parse bytes or readers

Use `LoadBytes` or `LoadReader` when report data comes from an email attachment, object storage, upload, or test fixture instead of a local path. These helpers accept gzip, zip, tar, zlib, or raw XML bytes and apply the same size-limit protections as file loading.

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	attachmentBytes, err := os.ReadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	report, err := dmarcgo.LoadBytes(attachmentBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.ReportMetadata.ReportID)
}
```

Use `ParseBytes` or `ParseReader` only when the input is already raw XML. If you are not sure whether the attachment is compressed, use `LoadBytes` or `LoadReader`.

Use `LoadReaderContext` for request-scoped server work where cancellation should stop reading before parsing begins.

## Processing a directory

`LoadReportsFromDir` processes a local directory and returns one result per file. Per-file errors are stored on the result, so one malformed report does not abort the whole batch. This is useful for local test corpora, scheduled attachment downloads, and one-off report analysis.

```go
package main

import (
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	results, err := dmarcgo.LoadReportsFromDir("reports/dmarc")
	if err != nil {
		log.Fatal(err)
	}

	for _, result := range results {
		if result.Err != nil {
			log.Printf("skipping %s: %v", result.Path, result.Err)
			continue
		}
		log.Printf("%s: %d records", result.Path, len(result.Report.Record))
	}
}
```

## Summaries and source review

`Summary()` gives useful report-level counts without requiring every caller to rebuild the same loops. It includes total messages, DMARC pass/fail counts, disposition counts, DKIM/SPF alignment counts, source-IP summaries, pass/fail rates, and parsed UTC date-range values.

`UnauthenticatedSources(domain)` returns source IPs that used the domain in `header_from` while both DMARC DKIM and SPF alignment failed. `RejectedUnauthenticatedSources(domain)` narrows that list to rejected traffic, and `PassingSources(domain)` shows source IPs that passed at least one DMARC alignment mechanism.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	summary := report.Summary()
	fmt.Printf("messages=%d rejected=%d passed=%d\n",
		summary.TotalMessages,
		summary.RejectedMessages,
		summary.PassedMessages,
	)

	for _, source := range report.UnauthenticatedSources("example.com") {
		fmt.Printf("source=%s rejected=%d\n", source.SourceIP, source.RejectedMessages)
	}
}
```

Use `ExcludeUnauthenticatedSources` for caller-owned allowlists or temporary suppressions. Exclusions accept exact IP addresses and CIDR ranges.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	sources := report.UnauthenticatedSources("example.com")
	filtered, err := dmarcgo.ExcludeUnauthenticatedSources(sources, []dmarcgo.SourceExclusion{
		{Pattern: "198.51.100.0/24", Reason: "known test range"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(filtered))
}
```

## Reusable normalized report evidence

Use `AnalyzeReportEvidence` when multiple later views need the same parsed
corpus. It normalizes source IPs, author and authentication domains, repeated
DKIM results, optional selectors, SPF identity, policy outcomes, dispositions,
reporters, counts, and report periods once. The immutable result can then be
filtered, aggregated, or persisted without retaining or reparsing report files.

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	loaded, err := dmarcgo.LoadReportsFromDir("reports")
	if err != nil {
		log.Fatal(err)
	}
	reports := make([]*dmarcgo.AggregateReport, 0, len(loaded))
	for _, item := range loaded {
		if item.Err == nil {
			reports = append(reports, item.Report)
		}
	}

	evidence, err := dmarcgo.AnalyzeReportEvidence(reports, dmarcgo.ReportEvidenceOptions{
		GeneratedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		log.Fatal(err)
	}
	sources, err := evidence.Aggregate(
		dmarcgo.ReportEvidenceFilter{AuthorDomains: []string{"example.com"}},
		dmarcgo.ReportEvidenceBySourceIP,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reports=%d messages=%d sources=%d\n",
		evidence.Summary().Reports,
		evidence.Summary().Messages,
		len(sources),
	)
}
```

Missing optional evidence remains unknown. Invalid or zero counts are retained
as diagnostic observations but excluded from message totals, and checked
arithmetic prevents wraparound. Identical non-zero report identities and content
are counted once; conflicting content for one identity fails closed. Overlapping
periods from different report identities remain separate receiver observations.

Report evidence is independent of organization configuration. Portfolio entity
and expected-sender attribution belongs to the later correlation stage. See
[`docs/report-evidence.md`](docs/report-evidence.md) for grouping, time-window,
duplicate, persistence, and privacy semantics.

## DNS and report correlation

Use `CorrelateReportEvidence` after portfolio normalization, DNS health, and
report-evidence analysis are complete. It resolves report streams to effective
entity/domain scopes, matches only declared DKIM selectors or unambiguous
monitored SPF identities to expected senders, and emits stable operational
findings for onboarding gaps, sender failures, unknown sources, new identities,
and caller-supplied prior-result drift.

Provider matches remain context-only. A recognized provider never authorizes a
stream, hides authentication failure, or improves health. Missing selectors and
other unavailable report values remain unknown.

Every stream and finding preserves current DNS observation time separately from
historical report bounds. Current DNS is never claimed to be the cause of an
older outcome. Count, duration, reporter-diversity, and recency thresholds are
explicit, and below-threshold streams remain visible as not evaluated.

See [`docs/dns-report-correlation.md`](docs/dns-report-correlation.md) for the
finding taxonomy, prior-result comparisons, temporal semantics, and safe sender
onboarding sequence.

## Suspicious-source candidate scoring

Use `ScoreThreatCandidates` only after report evidence and correlation are
complete. It counts each normalized observation once, then applies an
inspectable conservative, balanced, sensitive, or caller-supplied custom
profile. Supporting evidence and false-positive-sensitive deductions retain
stable codes, fixed generated explanations, evidence references, and exact
before/after arithmetic.

Expected-sender-only failures are omitted by default. Mixed passing traffic,
shared-provider context, forwarding or mailing-list signals, incomplete or
stale evidence, low volume, and single-report observations reduce score or cap
confidence. Source, sender, domain, and subdomain exclusions remain scoped to
their configured portfolio domain and retain owner, reason, and expiration.

Candidates are observed authentication evidence, not indicators of compromise.
They are review-only, monitor-only, or retained-evidence results; they never
authorize blocking or assert malicious ownership. The scoring stage performs no
enrichment or network access. See
[`docs/threat-candidates.md`](docs/threat-candidates.md) for the complete score,
confidence, exclusion, and safety contract.

## STIX 2.1 observed-data export

Use `BuildSTIXBundle` after threat-candidate scoring and, optionally, source
enrichment. The standards-native bundle contains canonical IP SCOs, Observed
Data with report-period bounds and counts, producer identity, versioned dmarcgo
evidence extensions, and optional ASN SCO relationships. It performs no
analysis, enrichment, lookup, clock access, or submission.

The default never creates an Indicator. A caller must explicitly name a
review-eligible, non-excluded candidate in `STIXExportOptions.Promotions` and
supply `valid_from` policy. Optional review notes and Indicator descriptions
contain only fixed safety text; report, provider, domain, and producer values
remain untrusted structured data.

STIX output contains raw source IPs and may contain operational domains and
provider context. It has no public-redaction profile; callers own recipient
authorization, minimization, markings, transport, and retention. Use
`ValidateSTIXBundle` before storage or transport, or `WriteSTIXBundle` to
validate and write one complete bundle. See
[`docs/stix-export.md`](docs/stix-export.md) for object mappings, deterministic
IDs, TLP behavior, the embedded extension schema, count limits, interoperability
validation, and the observation-versus-Indicator boundary.

## ThreatConnect v3 indicator payload export

Use `BuildThreatConnectIndicatorPayloads` only after a caller has explicitly
selected review-eligible, non-excluded candidate IDs or evidence-backed ASN
rollups. Address requests use `ip`; ASN requests use the vendor's exact
`AS Number` field and `ASN`-prefixed value. Report-period bounds become
`firstSeen` and `lastSeen`, and dual-failure message counts become
`observations`.

Payloads default to `active: false`, `privateFlag: true`, fixed review-only
Description and Source Attributes, and fixed human-review Tags. ThreatConnect
confidence is omitted unless the caller explicitly maps evidence confidence or
provides a value. Threat Rating is never inferred and must be supplied
explicitly. Owner, tenant Attributes, Tags, ATT&CK technique IDs, Security
Labels, and expiration remain caller choices.

ThreatConnect documents Indicators as unique per owner and says a duplicate
POST updates the existing Indicator. Encoder success therefore does not prove
that a new object will be created. The application owns credentials, HTTP,
permissions, rate limiting, response inspection, and audit storage. Use
`ValidateThreatConnectIndicatorPayload` before transport and retain the
defensive `Source()` metadata with the submission record. See
[`docs/threatconnect-export.md`](docs/threatconnect-export.md) for the exact
mapping, duplicate semantics, official references, privacy boundary, and safe
caller-owned submission sequence.

## MISP event and attribute export

Use `BuildMISPAttributePayloads` only after the application has selected
review-eligible, non-excluded candidate IDs, identified an existing Event by
numeric ID or UUID, and supplied exact `ip-src` or `ip-dst` type/category
capabilities from the target instance. The encoder performs exact membership
validation and never runs `describeTypes`, searches for an Event, or guesses IP
direction.

Native Attributes default to `to_ids: false`,
`disable_correlation: true`, organization-only distribution, the candidate's
report-period bounds, a deterministic UUID and timestamp, and fixed
review-limitation text. Tags are never invented. Distribution, sharing group,
tags, comments, observation times, IDS behavior, and correlation behavior can
be changed only through explicit caller settings. Distribution `4` requires a
canonical positive numeric sharing-group ID accepted by the target instance.

`BuildMISPEventPayload` additionally requires a complete caller-owned Event
definition: UUID, information, date, distribution, threat and analysis levels,
publication state, and correlation behavior. Embedded Attributes inherit the
Event distribution by default. Candidate score, severity, confidence,
enrichment, and jurisdiction context are not converted into MISP threat
levels, classifications, tags, or IDS decisions.

Both builders emit operational, unredacted native JSON and retain candidate
and evidence references separately through defensive `Source()` metadata.
They perform no credentials, HTTP, duplicate checking, warning-list lookup,
submission, publication, retry, or response handling. See
[`docs/misp-export.md`](docs/misp-export.md) for the reviewed upstream
contract, capability model, exact mappings, deterministic identity, privacy
boundary, and safe caller-owned submission sequence.

## Versioned jurisdiction context

`EvaluateJurisdictionContext` is an explicit pure stage after source
enrichment. It retains every country assertion, freshness state, conflict,
candidate reference, policy-entry reference, and policy provenance value. It
performs no lookup or other I/O.

`BuiltinJurisdictionRiskPolicy` returns a reviewed snapshot derived from all
Country Groups D and E in Supplement No. 1 to 15 CFR Part 740 as of July 8,
2026. Those are export-control categories, not cyber-threat or actor
classifications. A match describes only coarse infrastructure geography and
does not establish identity, nationality, intent, government affiliation,
compromise, or a legal conclusion.

The optional review-priority adjustment is disabled by default and capped at
10. Only fresh, unambiguous matches can receive it. It remains separate from
the candidate score, confidence, severity, exclusions, review eligibility,
promotion state, and recommended usage, and it never authorizes automatic
action. Callers can normalize their own immutable policy when the built-in
source context is not appropriate.

See [`docs/jurisdiction-context.md`](docs/jurisdiction-context.md) for the exact
built-in membership and tier mapping, authoritative BIS/eCFR sources,
expiration and replacement rules, state model, attribution limitations, and
hostile-input boundary.

## Attachment filename metadata

Many DMARC aggregate report attachments use a bang-separated filename containing the reporting organization, policy domain, begin epoch, end epoch, optional unique ID, and compression extension. Use `ParseReportFilename` when you want that delivery metadata without opening the archive.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	info, err := dmarcgo.ParseReportFilename("google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("reporter=%s domain=%s compression=%s\n",
		info.Reporter,
		info.PolicyDomain,
		info.Compression,
	)
}
```

Use `ValidateReportFilename` when you want to distinguish practical compatibility from strict RFC 9990 filename expectations. Compatibility mode accepts common real-world zip and tar reports; strict mode expects `.xml` or `.xml.gz`.

```go
package main

import (
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	info, err := dmarcgo.ParseReportFilename("google.com!example.com!1700000000!1700086399.zip")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range dmarcgo.ValidateReportFilename(info, dmarcgo.ValidationModeCompatibility) {
		log.Printf("%s %s: %s", finding.Severity, finding.Path, finding.Message)
	}
}
```

## Deduplication and safe fixtures

Use `ReportKey`, `FilenameReportKey`, `SameReport`, and `DeduplicateReports` when importing reports from email or object storage where retransmission can create duplicates.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	results, err := dmarcgo.LoadReportsFromDir("reports/dmarc")
	if err != nil {
		log.Fatal(err)
	}

	var reports []*dmarcgo.AggregateReport
	for _, result := range results {
		if result.Err == nil {
			reports = append(reports, result.Report)
		}
	}

	reports = dmarcgo.DeduplicateReports(reports)
	fmt.Println(dmarcgo.SummarizeReports(reports).Reports)
}
```

Use `AnonymizeReport` before committing new fixtures derived from real reports. It replaces reporter contact details, report IDs, domains, and source IPs with documentation-safe values while preserving counts, dispositions, report dates, and DMARC pass/fail shape. It removes raw extension XML by default because extensions can contain provider-specific data; set `PreserveExtensions` only after reviewing the source report.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	safe := dmarcgo.AnonymizeReport(*report, dmarcgo.AnonymizeOptions{})
	fmt.Println(len(safe.Rows()))
}
```

Use `TopSources`, `TopUnauthenticatedSources`, and `TopCounts` for dashboard-oriented summaries without adding storage or alerting policy to the parser.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	summary := report.Summary()
	fmt.Println(dmarcgo.TopSources(summary.BySourceIP, 10))
	fmt.Println(dmarcgo.TopCounts(summary.ByHeaderFrom, 10))
}
```

## Validation

Parsing accepts real-world reports, including older reports that may not be perfectly RFC 9990-shaped. Use `Validate()` when you want pragmatic data-quality findings after parsing. Use `ValidateStrict()` for producers or fixtures that claim the current RFC 9990 shape. Validation does not mutate the report and does not reject legacy reports by itself.

Strict validation is expected to flag many current real-world aggregate reports because large providers still emit legacy/no-namespace XML even when the report data itself is useful. Use strict mode for producer conformance checks, not for deciding whether legacy reports are worth ingesting.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range report.Validate() {
		fmt.Printf("%s %s: %s\n", finding.Severity, finding.Path, finding.Message)
	}
}
```

## Summaries across many reports

Use `SummarizeReports` when you have several parsed `AggregateReport` values and want combined counts. Nil reports are skipped.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	results, err := dmarcgo.LoadReportsFromDir("reports/dmarc")
	if err != nil {
		log.Fatal(err)
	}

	var reports []*dmarcgo.AggregateReport
	for _, result := range results {
		if result.Err == nil {
			reports = append(reports, result.Report)
		}
	}

	summary := dmarcgo.SummarizeReports(reports)
	fmt.Printf("reports=%d messages=%d rejected=%d\n",
		summary.Reports,
		summary.TotalMessages,
		summary.RejectedMessages,
	)
}
```

## JSON Lines output

Use `WriteFeaturesJSONL` when sending flattened rows into logs, queues, data lakes, or SIEM-style tooling. Pass `features` when you only want record rows and do not want the metadata-only first element.

```go
package main

import (
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	features := report.Rows()
	if err := dmarcgo.WriteFeaturesJSONL(os.Stdout, features); err != nil {
		log.Fatal(err)
	}
}
```

## CSV output

Use `WriteFeaturesCSV` when you want spreadsheet-friendly flattened rows. Like JSONL output, pass `features` if you want only record rows.

```go
package main

import (
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo/v2"
)

func main() {
	report, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	features := report.Rows()
	if err := dmarcgo.WriteFeaturesCSV(os.Stdout, features); err != nil {
		log.Fatal(err)
	}
}
```

## Error handling and size limits

The most useful exported errors are:

- `dmarcgo.ErrNoFilePath` for empty path input.
- `dmarcgo.ErrMalformedXML` when bytes were readable but not valid DMARC XML.
- `dmarcgo.ErrUnsupportedReportFormat` when bytes cannot be treated as gzip XML, gzip-compressed tar, zip, tar, zlib, or raw XML.
- `utilities.ErrPayloadTooLarge` when decompressed data exceeds the configured limit.

Use `errors.Is` for checks because errors may include path or parser context.

```go
package main

import (
	"errors"
	"log"

	"github.com/georgestarcher/dmarcgo/v2"
	"github.com/georgestarcher/dmarcgo/v2/utilities"
)

func main() {
	_, err := dmarcgo.LoadFile("reports/example-dmarc-report.xml.gz",
		dmarcgo.WithMaxDecompressedBytes(10<<20),
	)
	if err == nil {
		return
	}

	switch {
	case errors.Is(err, utilities.ErrPayloadTooLarge):
		log.Fatal("report is larger than the configured limit")
	case errors.Is(err, dmarcgo.ErrMalformedXML):
		log.Fatal("report payload is not valid DMARC XML")
	default:
		log.Fatal(err)
	}
}
```

## Behavior and safety notes

- `LoadFile()` accepts the same gzip XML, gzip-compressed tar, zip, tar, zlib, and raw XML formats as `LoadReader()`.
- `LoadBytes()`, `LoadReader()`, and `LoadReaderContext()` accept gzip XML, gzip-compressed tar, zip, tar, zlib, or raw XML.
- `ParseBytes()` and `ParseReader()` parse raw XML only.
- Decompressed payload reads are size-limited to `50 MiB` by default to reduce archive-bomb risk.
- Set `FileReport.MaxDecompressedBytes` or use `WithMaxDecompressedBytes` if your deployment needs a different decompressed-size limit.
- Malformed XML returns a parse-specific error.
- Invalid or negative `<count>` values are surfaced as `dmarcgo.InvalidMailCount` in rows. Summaries count them in `InvalidRecords` but exclude them from message totals and source groupings.
- `utilities.ReadZip()` skips directory entries, prefers `.xml` members, and returns an error if an archive has no regular files.
- `Summary()`, `SummarizeReports()`, `AnalyzeReportEvidence()`, `UnauthenticatedSources()`, `RejectedUnauthenticatedSources()`, and `PassingSources()` provide report-only analysis without turning the package into an ingest system.
- `ReportKey()`, `FilenameReportKey()`, `SameReport()`, and `DeduplicateReports()` support duplicate-safe importing without adding storage.
- `AnonymizeReport()` creates deterministic fixture-safe report copies using documentation IP/domain ranges, replaces report IDs, and removes raw extension XML by default.
- `TopSources()`, `TopUnauthenticatedSources()`, and `TopCounts()` return sorted top-N lists for dashboards and summaries.
- `Validate()` reports compatibility-mode data-quality findings after parsing; `ValidateStrict()` adds stricter current-standard checks.
- `ValidateReportFilename()` checks parsed filename metadata in compatibility or strict RFC 9990 mode.
- `WriteFeaturesJSONL()` and `WriteFeaturesCSV()` provide simple pipeline and spreadsheet output formats. `FeatureCSVHeaders()` exposes the CSV header order.
- Parsing does not perform DNS lookups or network access.

## Pipeline integration recipe

For a mailbox, object-storage, or upload-backed processing pipeline:

1. Read each attachment into bytes and record the original filename, message ID, and a content hash in your application.
2. Parse attachment bytes with `LoadBytes`, or parse local backfills with `LoadFile` or `LoadReportsFromDir`.
3. Run `Validate()` and store any findings with the import result.
4. Build an identity with `ReportKey(report)` and, when useful, `FilenameReportKey(filename)`.
5. Deduplicate in your application storage using report identity plus your attachment hash.
6. Store `report.Rows()` for record-oriented reporting, or store the full `AggregateReport` when you need every structured DKIM/SPF result.
7. Use `Summary()` and `SummarizeReports()` for lightweight reporting views, or normalize a reusable corpus once with `AnalyzeReportEvidence()` for filtering, correlation, and later analysis.
8. Export analyst-friendly output with `WriteFeaturesJSONL` or `WriteFeaturesCSV`.

Recommended fields to persist outside this library include the original filename, attachment hash, message/source identifier, parsed report identity, compatibility validation findings, flattened rows, and import timestamp. Avoid logging raw report XML or raw attachments by default because reports can contain domains, source IPs, provider metadata, and authentication behavior.

## Standards coverage

`dmarcgo` is scoped to DMARC aggregate reports. The current aggregate-report standard is [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html), which replaces the aggregate-report portions of RFC 7489.

The package preserves RFC 9990 fields including:

- `version`
- `extra_contact_info`
- `error`
- `generator`
- `np`
- `discovery_method`
- `testing`
- `envelope_from`
- `envelope_to`
- DKIM selectors
- SPF scope
- multiple DKIM authentication results
- multiple policy override reasons
- extension XML

DMARC failure reports are separate. They are described by [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html), use an ARF/MARF email feedback format, and can include message headers, message bodies, and personally identifiable information. They are intentionally out of scope for this package.

## Support and contributing

- Read [SUPPORT.md](SUPPORT.md) before opening a usage or bug report.
- Use the structured GitHub issue forms and never attach a live DMARC report.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for development and release checks.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development

Run the full local check suite:

```shell
make ci
```

Useful individual checks:

```shell
go test ./...
go test -race ./...
go vet ./...
python3 scripts/check_readme_examples.py
```

The module targets supported Go toolchains starting at Go 1.25. CI currently runs on Go 1.25 and Go 1.26.
