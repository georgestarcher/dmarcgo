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

It does not provide a mailbox ingester, directory watcher, database, CLI, dashboard, or spoofing-risk scoring engine.

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
| You want unauthenticated-source summaries | `report.UnauthenticatedSources(domain)` | Finds rows where `header_from` matches and both DKIM/SPF alignment failed. |
| You want to suppress known source IPs | `dmarcgo.ExcludeUnauthenticatedSources(sources, exclusions)` | Applies caller-owned exact-IP or CIDR exclusions without storing policy state. |
| You want metadata from attachment names | `dmarcgo.ParseReportFilename(name)` | Parses common bang-separated RUA filenames into reporter, domain, dates, unique ID, and compression. |
| You want duplicate-safe importing | `dmarcgo.ReportKey(report)` and `dmarcgo.DeduplicateReports(reports)` | Uses report ID, reporter, policy domain, and date range. |
| You want safe regression fixtures | `dmarcgo.AnonymizeReport(report, options)` | Preserves report shape while replacing domains, source IPs, report IDs, and reporter contact details. Raw extension XML is removed by default. |
| You want dashboard-ready top lists | `dmarcgo.TopSources`, `dmarcgo.TopUnauthenticatedSources`, or `dmarcgo.TopCounts` | Returns sorted top-N slices without storage or scoring policy. |
| You want data-quality checks | `report.Validate()` | Returns structured warnings/errors for malformed or non-standard content. |
| You want spreadsheet-friendly rows | `dmarcgo.WriteFeaturesCSV(writer, features)` | Writes flattened feature rows with a header. |
| You want versioned automation or AI-agent output | `dmarcgo.BuildReportSummaryOutput(summary, options)` | Produces a self-describing envelope with findings, evidence, actions, provenance, redaction, and truncation metadata. |
| You have strict versioned organization YAML | `dmarcgo.LoadPortfolioYAML(data)` | Rejects unknown and secret-bearing fields and performs no DNS or report access. |
| You construct organization configuration in Go | `dmarcgo.NormalizePortfolio(config)` | Returns a deterministic normalized portfolio with defensive-copy accessors. |
| You want configuration diagnostics | `dmarcgo.ValidatePortfolio(config, generatedAt)` | Returns value-safe structured diagnostics without I/O. |
| You want reusable DNS evidence for a portfolio | `dmarcgo.CollectDNSSnapshot(ctx, portfolio, resolver, options)` | Explicitly queries only configured TXT names; use `DNSMessageResolver` when TTL and authority evidence matter. |
| You want parsed SPF, DKIM, and DMARC semantics | `dmarcgo.ParseAuthenticationRecords(snapshot)` | Purely parses an existing snapshot; performs no DNS, report, filesystem, or time access. |
| You need to validate one supplied record string | `dmarcgo.ParseSPFRecord`, `dmarcgo.ParseDKIMKeyRecord`, or `dmarcgo.ParseDMARCPolicyRecord` | Returns typed semantics plus value-safe diagnostics without I/O. |
| You need RFC 9989 DMARC tree-walk names | `dmarcgo.DMARCPolicyDiscoveryNames(domain)` | Computes at most eight owner names but never resolves them. |

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
- `Summary()`, `SummarizeReports()`, `UnauthenticatedSources()`, `RejectedUnauthenticatedSources()`, and `PassingSources()` provide lightweight analysis helpers without turning the package into an ingest system.
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
7. Use `Summary()`, `SummarizeReports()`, top-N helpers, and source-review helpers for reporting views.
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
