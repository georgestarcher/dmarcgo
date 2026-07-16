# DMARC report ingestion and reporting

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v3. The linked repository guides and Go documentation define behavior.

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

## Five-minute owner-authorized example

The repository includes a three-report point-in-time mini corpus for
`georgestarcher.com` with the domain owner's explicit permission. Running the
complete example produces:

```text
Files: 3; loaded: 3; skipped: 0; duplicates removed: 0
Corpus: reports=3 messages=3 pass=2 fail=1 rejected=1 sources=3 reporters=3
Review context: unauthenticated_sources=1 compatibility_findings=0
```

The raw samples contain operational source and authentication evidence. They
are documentation inputs, not deterministic tests or a continuing claim about
the domain or any source. Follow the
[runnable report-directory journey](https://github.com/georgestarcher/dmarcgo/blob/main/docs/getting-started-report-directory.md)
for the exact command, output files, privacy boundary, and the aggregate
summary of the larger local corpus.

## What reports can power next

| Stage | What a newcomer learns | Additional input |
| --- | --- | --- |
| Corpus summary | Reports, messages, pass/fail, disposition, sources, reporters, and data-quality diagnostics | None |
| Source behavior | Volume, repetition, report-period bounds, reporter diversity, SPF/DKIM identities, dispositions, and overrides | None |
| DNS/report correlation | Expected healthy streams, expected-sender failures, onboarding gaps, and unattributed failures | Completed portfolio and DNS health |
| Candidate scoring | Explainable source-review priority, confidence caps, exclusions, and safe recommended usage | Completed correlation |
| Source enrichment | Caller-provider ASN, network, organization, and coarse country assertions with provenance and conflicts | Explicit `IPEnricher` |
| Source activity | Selected third-party activity metrics and feed memberships | Explicit selection and `SourceActivityProvider` |
| Phishing intelligence | Exact source-IP or exact DMARC domain-role matches against caller-owned offline intelligence | Normalized snapshots |
| Jurisdiction context | Versioned policy context over completed country assertions | Enrichment and explicit policy |
| Campaign review | Lower-confidence aggregate overlap with an authorized simulation inventory | Campaign snapshot |
| Defensive export | STIX or target-native payload objects for explicitly reviewed selections | Target capabilities and caller authorization |

Each stage consumes an already completed result. Selecting an output format or
optional context does not silently rerun parsing, DNS, enrichment, or network
activity. The library ships no source-enrichment, source-activity, phishing-feed,
or remote-DNS provider and never contacts an observed source IP.

## What this does not prove

One report or one successful path does not prove that every account, sender,
receiver, or system is secure. Aggregate reports do not contain exact
per-message timestamps and are not RFC 9991 forensic reports.

## Sensitive data

Real reports can expose source IPs, domains, provider metadata, authentication
behavior, and reporter contacts. Do not commit them without artifact-level
owner approval. Use `AnonymizeReport` before deriving an ordinary public fixture
and review the result. The included mini corpus is a narrowly documented
owner-authorized exception, not general publication permission.

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
