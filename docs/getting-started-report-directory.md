# Getting started with a report directory

This journey starts with application-collected DMARC aggregate-report
artifacts and ends with a corpus summary, flattened rows, and reusable
normalized evidence. The complete compile-tested program is in
[`examples/go/report-directory`](../examples/go/report-directory).

`dmarcgo` does not retrieve mailbox attachments, watch a directory, schedule a
run, move files, persist history, or choose an output destination. This example
uses application-owned locations:

```text
your-application/
  data/dmarc-reports/
  output/
  main.go
```

Use an attachments-only input directory when possible. If a directory is
mixed, `LoadReportsFromDir` returns one `ReportFileResult` per regular file;
the directory-level call can succeed while individual files have `Err` set.
Handle every per-file result before analyzing the successfully loaded reports.

## 1. Copy and run the program

Copy [`examples/go/report-directory/main.go`](../examples/go/report-directory/main.go)
into a small Go application, add `dmarcgo`, put aggregate XML, gzip, zip, tar,
or zlib artifacts in `data/dmarc-reports`, and run:

```shell
go get github.com/georgestarcher/dmarcgo/v2@latest
go run . \
  -reports data/dmarc-reports \
  -evidence-output output/report-evidence.json \
  -jsonl-output output/report-rows.jsonl \
  -csv-output output/report-rows.csv \
  -agent-output output/report-evidence-agent.json
```

The program:

1. calls `LoadReportsFromDir` and reports each per-file error;
2. retains only successfully loaded `AggregateReport` values;
3. parses common attachment filenames with `ParseReportFilename` without
   treating the filename as authoritative report content;
4. runs compatibility validation for ordinary real-world ingestion;
5. calls `UnauthenticatedSources` for a simple review view;
6. calls `AnalyzeReportEvidence` over every successfully loaded report so an
   identity conflict fails closed before display deduplication;
7. deduplicates non-zero identities with `DeduplicateReports` for the corpus
   display and row exports;
8. calls `Summary` for one report and `SummarizeReports` for the corpus;
9. flattens rows and writes them with `WriteFeaturesJSONL` and
   `WriteFeaturesCSV`;
10. writes complete native report-evidence JSON and a separately selected
    public agent envelope; and
11. propagates write and close errors because either can indicate incomplete
    output.

Use `ValidateStrict` for synthetic fixtures or a producer that claims current
RFC 9990 conformance. Compatibility validation is intentionally more tolerant
of common legacy reports and is the normal ingestion choice.

The included directory contains one supported report and one unrelated text
file. The test adds an identical second report to exercise deduplication. Its
representative display is:

```text
Skipped file="notes.txt" error="..."
Files: 3; loaded: 2; skipped: 1; duplicates removed: 1
First successfully loaded report: records=2 messages=7 validation_findings=0
Corpus: reports=1 messages=7 pass=6 fail=1 rejected=1 sources=2 reporters=1
Review context: unauthenticated_sources=1 compatibility_findings=0 filename_findings=0 evidence_diagnostics=1
Outputs: evidence=output/report-evidence.json rows_jsonl=output/report-rows.jsonl rows_csv=output/report-rows.csv agent=output/report-evidence-agent.json
```

One bad file does not erase successful results, but it must remain visible in
the application's ingestion inventory. Likewise, a duplicate or invalid count
must not silently become new zero-message evidence.

## 2. Read the result

- **Report periods** are receiver-supplied begin and end bounds, not exact
  per-message timestamps.
- **Message totals** sum valid non-negative record counts. Invalid counts stay
  diagnostic and are excluded from success and failure totals.
- **Pass and fail totals** describe the receiver's reported alignment result,
  not whether a source is benign or malicious.
- **Source diversity** counts distinct observed source IPs; **reporter
  diversity** counts distinct reporting organizations.
- **Duplicates** are removed only when a non-zero report identity repeats.
  Conflicting normalized content claiming the same identity fails closed in
  `AnalyzeReportEvidence`.
- **Evidence diagnostics** preserve invalid observations and duplicate counts
  rather than hiding them.

Real report output contains domains, source IPs, reporters, authentication
identities, selectors, dispositions, report periods, and provenance. Treat
native output as operational data. Choose public redaction before sending a
common envelope outside that trust boundary.

## 3. Optionally correlate completed results

Do this only when the application has also completed the
[domain-portfolio journey](getting-started-domain-health.md) for the same
organization. Correlation performs no new DNS or file loading:

```go
correlation, err := dmarcgo.CorrelateReportEvidence(
    portfolio,
    health,
    evidence,
    dmarcgo.DNSReportCorrelationOptions{},
)
if err != nil {
    return err
}

defaultReview, err := dmarcgo.ScoreThreatCandidates(
    portfolio,
    evidence,
    correlation,
    dmarcgo.ThreatCandidateOptions{
        Profile: dmarcgo.ThreatCandidateProfileBalanced,
    },
)
if err != nil {
    return err
}

expectedSenderReview, err := dmarcgo.ScoreThreatCandidates(
    portfolio,
    evidence,
    correlation,
    dmarcgo.ThreatCandidateOptions{
        Profile:                dmarcgo.ThreatCandidateProfileBalanced,
        IncludeExpectedSenders: true,
    },
)
if err != nil {
    return err
}
```

The compile-tested form is
[`optional_correlation.go`](../examples/go/report-directory/optional_correlation.go).
Expected-sender-only failures remain correlation and configuration findings by
default. Including them is an explicit review decision: conservative scoring
requires stronger evidence, balanced scoring is the normal review baseline,
and sensitive scoring surfaces more low-volume or incomplete observations.
Every profile keeps confidence caps and counter-evidence visible. A candidate
is neutral review evidence, not a malicious verdict or permission to block.

> **Zero threat candidates does not mean zero authentication failures. Inspect
> `expected_sender_sources_omitted` and `expected_sender_messages_omitted`
> before concluding that no source requires attention.**

Inspect those two fields in `defaultReview.Summary()` and keep the underlying
correlation findings visible.

## 4. Choose an output

| Need | Application choice |
| --- | --- |
| Concise human display | Assemble the report, message, pass/fail, source, reporter, and diagnostic values the audience needs |
| Complete typed evidence | `WriteReportEvidenceOutput` with native JSON |
| Streamed native evidence | `WriteReportEvidenceOutput` with native JSONL |
| Tabular native evidence | `WriteReportEvidenceOutput` with native CSV |
| Record-shaped analysis | `WriteFeaturesJSONL` or `WriteFeaturesCSV` over `report.Rows()` |
| AI or cross-mode automation | `BuildAnalysisOutput` with an explicit public, operational, or restricted redaction profile |
| Defensive platform payload | Build STIX or a vendor-native payload only after explicit human-reviewed selection and target capability configuration |

Output builders serialize an already completed result. They do not reparse
reports or rerun analysis. `dmarcgo` does not create a polished prose report,
choose a default path, submit to a platform, or send email.

## 5. Add context only after candidate review

The portfolio YAML and report directory do not configure DNS perspectives,
source enrichment, source activity, phishing intelligence, or jurisdiction
context. [Optional context configuration](optional-context-configuration.md)
defines the complete fields and limits. At the decision point, the boundaries
are:

| Optional stage | Caller supplies | Network or disclosure boundary |
| --- | --- | --- |
| DNS perspectives | `DNSPerspectiveProvider` and an explicit name or role selection | Discloses only selected declared TXT names and snapshot answers to that provider |
| Source enrichment | `IPEnricher` or `BatchIPEnricher` | A network-backed adapter may disclose eligible candidate IPs only to its configured third party |
| Source activity | `SourceActivityProvider` and explicit candidate or IP selection | Discloses only the selected candidate IPs to its configured third party |
| Phishing intelligence | Offline `PhishingIntelligenceSnapshotConfig` values | Pure correlation; retrieval, licensing, refresh, and storage remain application-owned |
| Jurisdiction context | Completed enrichment plus an immutable built-in or normalized policy | Pure evaluation; it performs no lookup and makes no legal or malicious determination |

The library ships none of these network providers. No adapter may contact an
observed subject source IP.

Campaign classification remains a separate workflow. Aggregate reports do not
provide an authorized campaign inventory, exact message time, or sufficient
message-level evidence to prove that one message belonged to an exercise.

Continue with [report evidence](report-evidence.md),
[DNS/report correlation](dns-report-correlation.md), or
[threat candidates](threat-candidates.md) for the field-level contracts.
