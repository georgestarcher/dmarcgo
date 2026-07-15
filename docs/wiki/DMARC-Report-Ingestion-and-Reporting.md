# DMARC report ingestion and reporting

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. The linked repository guides and Go documentation define behavior.

## Who this is for

Application developers who already have DMARC aggregate report artifacts or
bytes and need to parse, validate, deduplicate, summarize, normalize, or export
them.

## Question this workflow answers

What did participating receivers report about message volume, authentication,
policy disposition, domains, and observed sources during the report periods?

## Inputs

Raw aggregate XML or gzip, zip, tar, or zlib payloads obtained by the caller.
The library does not retrieve mail or watch a directory automatically.

## Activity and side effects

Loading reads only the supplied path, bytes, or reader. Parsing, validation,
summarization, deduplication, and report-evidence analysis perform no DNS,
enrichment, mailbox access, storage, or system-clock lookup.

## Starting APIs

1. `LoadFile`, `LoadBytes`, `LoadReader`, or `ParseBytes`
2. `Validate` for compatibility-oriented data quality
3. `ReportKey` or `DeduplicateReports`
4. `Summary`, `SummarizeReports`, or `AnalyzeReportEvidence`
5. `Rows`, feature writers, report-output builders, or `WriteReportEvidenceOutput`

## Outputs

Structured reports, flattened rows, summaries, data-quality findings, and
immutable normalized evidence suitable for later filtering, aggregation,
correlation, or persistence.

## What this does not prove

One report or one successful path does not prove that every account, sender,
receiver, or system is secure. Aggregate reports do not contain exact
per-message timestamps and are not RFC 9991 forensic reports.

## Sensitive data

Real reports can expose source IPs, domains, provider metadata, authentication
behavior, and reporter contacts. Do not commit real corpora. Use
`AnonymizeReport` before deriving a public fixture and review the result.

## Safe next steps

Begin with the runnable
[report-directory journey](https://github.com/georgestarcher/dmarcgo/blob/main/docs/getting-started-report-directory.md).
Persist the immutable evidence with its metadata, keep report-period bounds
distinct from exact event times, and introduce portfolio or DNS context only in
the dedicated correlation stage.

## Authoritative references

- [Runnable report-directory journey](https://github.com/georgestarcher/dmarcgo/blob/main/docs/getting-started-report-directory.md)
- [Complete Go example](https://github.com/georgestarcher/dmarcgo/tree/main/examples/go/report-directory)
- [README input and API guide](https://github.com/georgestarcher/dmarcgo/blob/main/README.md)
- [Report evidence](https://github.com/georgestarcher/dmarcgo/blob/main/docs/report-evidence.md)
- [Automation workflows](https://github.com/georgestarcher/dmarcgo/blob/main/docs/automation-workflows.md)
