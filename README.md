# dmarcgo [![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/dmarcgo.svg)](https://pkg.go.dev/github.com/georgestarcher/dmarcgo) [![Report Card](https://goreportcard.com/badge/github.com/georgestarcher/dmarcgo)](https://goreportcard.com/report/github.com/georgestarcher/dmarcgo) [![Build Status](https://github.com/georgestarcher/dmarcgo/workflows/dmarcgo%20CI/badge.svg)](https://github.com/georgestarcher/dmarcgo/actions)

A Go module for parsing [DMARC](https://dmarc.org) aggregate report files. It supports legacy aggregate reports and the current RFC 9990 aggregate-report shape while intentionally excluding RFC 9991 failure/forensic reports.

Written by George Starcher

MIT license, check [LICENSE](LICENSE) for more information.

All text above must be included in any redistribution


## Module status and versioning

`dmarcgo` is a library package, not an ingest pipeline or reporting application.
It is intended to be imported by other Go code that wants to parse DMARC
aggregate report artifacts and decide for itself how to ingest, store, summarize,
or display the results.

This project follows semantic versioning. Before `v1.0.0`, public APIs may still
change as the aggregate-report model settles around RFC 9990 and real-world
legacy report compatibility. Prefer a tagged release for downstream use once one
is available.

## Installation

```shell
go get github.com/georgestarcher/dmarcgo
```

## Supported inputs

`dmarcgo` reads DMARC aggregate reports delivered as:

- gzip-compressed XML (`.xml.gz`)
- zip archives (`.zip`)
- zlib-compressed XML

The parser accepts aggregate XML reports using legacy no-namespace output, the older `http://dmarc.org/dmarc-xml/0.1` namespace, and the RFC 9990 `urn:ietf:params:xml:ns:dmarc-2.0` namespace.

Test fixtures live in `testdata/fixtures`. Local real-world report corpora, such
as `test_dmarc_reports/`, are intentionally ignored because DMARC reports can
expose domain, provider, source IP, and mail authentication metadata.

## Usage

Create a `Report`, load a DMARC report archive, then call `Features()` to get
flattened rows that are easy to marshal to JSON or send to another system. The flattened output keeps the original single-value fields for compatibility and also exposes newer plural fields, such as all DKIM authentication results and all policy override reasons.

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
	for _, feature := range report.Content.Features() {
		if err := encoder.Encode(feature); err != nil {
			log.Fatal(err)
		}
	}
}
```

To process a directory of report archives:

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

		for _, feature := range report.Content.Features() {
			if err := encoder.Encode(feature); err != nil {
				log.Fatal(err)
			}
		}
	}
}
```

### Behavior notes

- `LoadReportFile()` tries, in order: gzip, zip, then zlib.
- Decompressed payload reads are size-limited by default to reduce archive-bomb risk. Set `Report.MaxDecompressedBytes` when a different limit is needed.
- If parsing succeeds for a supported format but XML is malformed, an error is returned.
- `Features()` marks invalid `<count>` values as `InvalidMailCount` (`-1`) so malformed row counts are explicit.
- `LoadReportFileFromPath()` validates the report path and returns a clear error for empty paths.
- `go test` + `go vet` + pinned `staticcheck` are expected checks; CI also enforces `gofmt` and `go mod tidy` cleanliness.
- `utilities.ReadZip()` skips directory entries, prefers `.xml` members when available, and returns an error when no regular files are in the archive.

### Standards coverage

`dmarcgo` is scoped to DMARC aggregate reports. The current standards reference is [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html), which replaces the aggregate-report portions of RFC 7489. The parser also keeps compatibility with older real-world reports that still follow RFC 7489-era output or the historical dmarc.org RUA XSD.

The module preserves RFC 9990 fields such as `version`, `extra_contact_info`, `generator`, `np`, `discovery_method`, `testing`, `envelope_from`, `envelope_to`, DKIM selectors, SPF scope, multiple DKIM authentication results, multiple policy override reasons, and extension elements.

DMARC failure reports are different. They are described by [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991.html), use an ARF/MARF email feedback format, and can include message headers, message bodies, and personally identifiable information. They are intentionally not parsed by this package.

## Development

```shell
make ci
```

The module targets supported Go toolchains starting at Go 1.25. CI currently
runs on Go 1.25 and Go 1.26.
