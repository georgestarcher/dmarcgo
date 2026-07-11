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

## Quick start: flattened rows

`Features()` returns a convenient flattened representation that is easy to encode as JSON or feed into another system.

The first returned element contains report-level metadata. Subsequent elements contain one row per DMARC record.

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

The flattened output keeps simple single-value fields such as `DkimDomain` and `SpfResult`, while also exposing complete RFC 9990 data such as `DkimAuthResults`, `SpfAuthResult`, and `PolicyOverrideReasons`.

## Structured report access

For applications that need complete data, use the parsed `DmarcReport` model directly.

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

## Processing a directory

The `utilities` subpackage includes small file/archive helpers. You can use it to process a local directory of report archives.

```go
package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/georgestarcher/dmarcgo"
	"github.com/georgestarcher/dmarcgo/utilities"
)

func main() {
	reportDirectory := "reports/dmarc"

	reportFiles, err := utilities.GetFiles(reportDirectory)
	if err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	for _, name := range reportFiles {
		var report dmarcgo.Report
		if err := report.LoadReportFileFromPath(filepath.Join(reportDirectory, name)); err != nil {
			log.Fatal(err)
		}

		for i, feature := range report.Content.Features() {
			if i == 0 {
				continue // metadata-only row
			}
			if err := encoder.Encode(feature); err != nil {
				log.Fatal(err)
			}
		}
	}
}
```

## Behavior and safety notes

- `LoadReportFile()` tries gzip, zip, then zlib.
- Decompressed payload reads are size-limited by default to reduce archive-bomb risk.
- Set `Report.MaxDecompressedBytes` if your deployment needs a different decompressed-size limit.
- Malformed XML returns a parse-specific error.
- Invalid `<count>` values are surfaced as `dmarcgo.InvalidMailCount` instead of silently becoming zero.
- `utilities.ReadZip()` skips directory entries, prefers `.xml` members, and returns an error if an archive has no regular files.
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
