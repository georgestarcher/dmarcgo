# dmarcgo [![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/dmarcgo.svg)](https://pkg.go.dev/github.com/georgestarcher/dmarcgo) [![Report Card](https://goreportcard.com/badge/github.com/georgestarcher/dmarcgo)](https://goreportcard.com/report/github.com/georgestarcher/dmarcgo) [![Build Status](https://github.com/georgestarcher/dmarcgo/workflows/dmarcgo%20CI/badge.svg)](https://github.com/georgestarcher/dmarcgo/actions)

`dmarcgo` is a Go library for parsing DMARC aggregate report files.

It supports older real-world aggregate reports, legacy DMARC RUA XML output, and the current [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html) aggregate-report shape. It intentionally does not parse [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html) DMARC failure/forensic reports.

Written by George Starcher.

MIT license. See [LICENSE](LICENSE) for details.

All text above must be included in any redistribution.

## Install

From another Go module:

```shell
go get github.com/georgestarcher/dmarcgo@latest
```

Then import the library:

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	var report dmarcgo.Report
	if err := report.LoadReportFileFromPath("reports/example-dmarc-report.xml.gz"); err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.Content.ReportMetadata.OrgName)
}
```

Before the first stable `v1.0.0` release, prefer pinning a tag or commit for production use once one is available.

## What this package does

`dmarcgo` is a parser library. It is meant to be imported by other Go code that wants to parse DMARC aggregate report artifacts and then decide how to ingest, store, summarize, or display the results.

It does not provide a mailbox ingester, directory watcher, database, CLI, dashboard, or spoofing-risk scoring engine.

## Supported report inputs

`dmarcgo` reads DMARC aggregate reports delivered as:

- gzip-compressed XML, usually `.xml.gz`
- zip archives, usually `.zip`
- zlib-compressed XML

The parser accepts aggregate XML reports using:

- no XML namespace, which is common in older real-world reports
- the historical `http://dmarc.org/dmarc-xml/0.1` namespace
- the RFC 9990 `urn:ietf:params:xml:ns:dmarc-2.0` namespace

Local real-world report corpora should not be committed. DMARC reports can expose domains, provider metadata, source IPs, and authentication behavior. This repository ignores `test_dmarc_reports/` for that reason. Public regression fixtures belong under `testdata/fixtures/` and should be synthetic or anonymized.


## Which API should I use?

| Situation | Use | Notes |
| --- | --- | --- |
| You have a local report archive path | `dmarcgo.LoadReportFile(path)` | Convenience constructor that returns `*Report`. |
| You already created a `Report` value | `report.LoadReportFileFromPath(path)` | Useful when setting `Report.MaxDecompressedBytes` directly. |
| You have attachment bytes from mail, S3, or an upload | `dmarcgo.LoadReportBytes(data)` | Accepts gzip, zip, zlib, or raw XML bytes. |
| You have an `io.Reader` for an attachment or object | `dmarcgo.LoadReportReader(reader)` | Reads with the same decompressed-size protection. |
| You know the input is raw XML | `dmarcgo.ParseBytes(data)` or `dmarcgo.ParseReader(reader)` | Skips archive detection. |
| You want easy JSON rows | `report.Content.Features()` | Returns one metadata row first, then one row per DMARC record. |
| You want complete structured data | `report.Content.Record` | Preserves RFC 9990 fields such as multiple DKIM results. |
| You want quick counts for one report | `report.Content.Summary()` | Gives totals, pass/fail counts, top sources, and date metadata. |
| You want counts across many reports | `dmarcgo.SummarizeReports(reports)` or `dmarcgo.MergeSummaries(summaries)` | Combines report summaries without adding storage or ingest behavior. |
| You want obvious spoofing candidates | `report.Content.SuspiciousSources(domain)` | Finds rows where `header_from` matches and both DKIM/SPF alignment failed. |
| You want data-quality checks | `report.Content.Validate()` | Returns structured warnings/errors for malformed or non-standard content. |
| You want spreadsheet-friendly rows | `dmarcgo.WriteFeaturesCSV(writer, features)` | Writes flattened feature rows with a header. |

## Quick start: flattened rows

`Features()` returns a convenient flattened representation that is easy to encode as JSON or feed into another system.

The first returned element contains report-level metadata. Subsequent elements contain one row per DMARC record. Most pipelines should skip index `0` when exporting record data, but keeping the metadata row is useful when callers want report-level values without separately inspecting `ReportMetadata`.

```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	var report dmarcgo.Report
	if err := report.LoadReportFileFromPath("reports/google.com!example.com!1700000000!1700086399.zip"); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	for i, feature := range report.Content.Features() {
		if i == 0 {
			continue // metadata-only row
		}
		if err := encoder.Encode(feature); err != nil {
			log.Fatal(err)
		}
	}
}
```

The flattened output keeps simple single-value fields such as `DkimDomain` and `SpfResult`, while also exposing complete RFC 9990 data such as `DkimAuthResults`, `SpfAuthResult`, and `PolicyOverrideReasons`. The single-value fields are populated from the first available result for convenience; use the plural/structured fields when correctness depends on every DKIM result or every override reason.

## Structured report access

For applications that need complete data, use the parsed `DmarcReport` model directly. This is the right path for dashboards, enrichment pipelines, policy auditing, or any code that needs every DKIM signature result rather than a flattened convenience view.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	var report dmarcgo.Report
	if err := report.LoadReportFileFromPath("reports/example-dmarc-report.xml.gz"); err != nil {
		log.Fatal(err)
	}

	for _, record := range report.Content.Record {
		fmt.Printf("source=%s count=%s disposition=%s\n",
			record.Row.SourceIp,
			record.Row.Count,
			record.Row.PolicyEvaluated.Disposition,
		)

		for _, dkim := range record.AuthResults.Dkim {
			fmt.Printf("  dkim domain=%s selector=%s result=%s\n",
				dkim.Domain,
				dkim.Selector,
				dkim.Result,
			)
		}

		if record.AuthResults.Spf != nil {
			fmt.Printf("  spf domain=%s result=%s\n",
				record.AuthResults.Spf.Domain,
				record.AuthResults.Spf.Result,
			)
		}
	}
}
```

## Parse bytes or readers

Use `LoadReportBytes` or `LoadReportReader` when report data comes from an email attachment, object storage, upload, or test fixture instead of a local path. These helpers accept gzip, zip, zlib, or raw XML bytes and apply the same size-limit protections as file loading.

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	attachmentBytes, err := os.ReadFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	report, err := dmarcgo.LoadReportBytes(attachmentBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(report.ReportMetadata.ReportID)
}
```

Use `ParseBytes` or `ParseReader` only when the input is already raw XML. If you are not sure whether the attachment is compressed, use `LoadReportBytes` or `LoadReportReader`.

## Processing a directory

`LoadReportsFromDir` processes a local directory and returns one result per file. Per-file errors are stored on the result, so one malformed report does not abort the whole batch. This is useful for local test corpora, scheduled attachment downloads, and one-off report analysis.

```go
package main

import (
	"log"

	"github.com/georgestarcher/dmarcgo"
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
		log.Printf("%s: %d records", result.Path, len(result.Report.Content.Record))
	}
}
```

## Summaries and suspicious sources

`Summary()` gives useful report-level counts without requiring every caller to rebuild the same loops. It includes total messages, disposition counts, DKIM/SPF alignment counts, source-IP summaries, and parsed UTC date-range values.

`SuspiciousSources(domain)` returns source IPs that used the domain in `header_from` while both DMARC DKIM and SPF alignment failed. It is intentionally factual rather than a risk score: a row is suspicious because it failed authentication while claiming the target domain.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	report, err := dmarcgo.LoadReportFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	summary := report.Content.Summary()
	fmt.Printf("messages=%d rejected=%d passed=%d\n",
		summary.TotalMessages,
		summary.RejectedMessages,
		summary.PassedMessages,
	)

	for _, source := range report.Content.SuspiciousSources("example.com") {
		fmt.Printf("source=%s rejected=%d\n", source.SourceIP, source.RejectedMessages)
	}
}
```


## Validation

Parsing accepts real-world reports, including older reports that may not be perfectly RFC 9990-shaped. Use `Validate()` when you want structured data-quality findings after parsing. Validation does not mutate the report and does not reject legacy reports by itself.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	report, err := dmarcgo.LoadReportFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range report.Content.Validate() {
		fmt.Printf("%s %s: %s\n", finding.Severity, finding.Path, finding.Message)
	}
}
```

## Summaries across many reports

Use `SummarizeReports` when you have several parsed `Report` values and want combined counts. Nil reports are skipped.

```go
package main

import (
	"fmt"
	"log"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	results, err := dmarcgo.LoadReportsFromDir("reports/dmarc")
	if err != nil {
		log.Fatal(err)
	}

	var reports []*dmarcgo.Report
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

Use `WriteFeaturesJSONL` when sending flattened rows into logs, queues, data lakes, or SIEM-style tooling. Pass `features[1:]` when you only want record rows and do not want the metadata-only first element.

```go
package main

import (
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	report, err := dmarcgo.LoadReportFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	features := report.Content.Features()
	if err := dmarcgo.WriteFeaturesJSONL(os.Stdout, features[1:]); err != nil {
		log.Fatal(err)
	}
}
```



## CSV output

Use `WriteFeaturesCSV` when you want spreadsheet-friendly flattened rows. Like JSONL output, pass `features[1:]` if you want only record rows.

```go
package main

import (
	"log"
	"os"

	"github.com/georgestarcher/dmarcgo"
)

func main() {
	report, err := dmarcgo.LoadReportFile("reports/example-dmarc-report.xml.gz")
	if err != nil {
		log.Fatal(err)
	}

	features := report.Content.Features()
	if err := dmarcgo.WriteFeaturesCSV(os.Stdout, features[1:]); err != nil {
		log.Fatal(err)
	}
}
```

## Error handling and size limits

The most useful exported errors are:

- `dmarcgo.ErrNoFilePath` for empty path input.
- `dmarcgo.ErrMalformedXML` when bytes were readable but not valid DMARC XML.
- `dmarcgo.ErrUnsupportedReportFormat` when bytes cannot be treated as gzip, zip, zlib, or raw XML.
- `utilities.ErrPayloadTooLarge` when decompressed data exceeds the configured limit.

Use `errors.Is` for checks because errors may include path or parser context.

```go
package main

import (
	"errors"
	"log"

	"github.com/georgestarcher/dmarcgo"
	"github.com/georgestarcher/dmarcgo/utilities"
)

func main() {
	_, err := dmarcgo.LoadReportFile("reports/example-dmarc-report.xml.gz",
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

- `LoadReportFile()` tries gzip, zip, then zlib.
- `LoadReportBytes()` and `LoadReportReader()` accept gzip, zip, zlib, or raw XML.
- `ParseBytes()` and `ParseReader()` parse raw XML only.
- Decompressed payload reads are size-limited by default to reduce archive-bomb risk.
- Set `Report.MaxDecompressedBytes` if your deployment needs a different decompressed-size limit.
- Malformed XML returns a parse-specific error.
- Invalid `<count>` values are surfaced as `dmarcgo.InvalidMailCount` instead of silently becoming zero.
- `utilities.ReadZip()` skips directory entries, prefers `.xml` members, and returns an error if an archive has no regular files.
- `Summary()`, `SummarizeReports()`, and `SuspiciousSources()` provide lightweight analysis helpers without turning the package into an ingest system.
- `Validate()` reports data-quality findings after parsing rather than rejecting legacy reports upfront.
- `WriteFeaturesJSONL()` and `WriteFeaturesCSV()` provide simple pipeline and spreadsheet output formats.
- Parsing does not perform DNS lookups or network access.

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
