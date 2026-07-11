# Support

## Usage questions

Start with the [README](README.md), package examples, and
[Go package documentation](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2).
When opening an issue, include the exact dmarcgo version, Go version, input
format, expected behavior, actual behavior, and a minimal reproduction.

## Bug reports

Use the structured bug-report form. Never attach a live DMARC report. Aggregate
reports can expose domains, source IPs, report IDs, contact details, provider
metadata, and authentication behavior. Reduce the input to a synthetic example
or use `AnonymizeReport` before sharing it.

## Project scope

This project supports reusable parsing and analysis of DMARC aggregate reports.
Mailbox ingestion, scheduling, storage, dashboards, DNS lookups, risk scoring,
and RFC 9991 failure/forensic reports belong in consuming applications or
separate modules.

## Security issues

Follow [SECURITY.md](SECURITY.md) and report vulnerabilities privately. Do not
include sensitive report data in a public issue.
