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
go get github.com/georgestarcher/dmarcgo/v3@latest
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

### Try the included owner-authorized mini corpus

From a clone of this repository, a newcomer can run the same program over
three real point-in-time reports published with the domain owner's permission:

```shell
go run ./examples/go/report-directory \
  -reports examples/go/report-directory/samples/georgestarcher.com \
  -evidence-output output/report-evidence.json \
  -jsonl-output output/report-rows.jsonl \
  -csv-output output/report-rows.csv \
  -agent-output output/report-evidence-agent.json
```

That command currently produces:

```text
Files: 3; loaded: 3; skipped: 0; duplicates removed: 0
First successfully loaded report: records=1 messages=1 validation_findings=0
Corpus: reports=3 messages=3 pass=2 fail=1 rejected=1 sources=3 reporters=3
Review context: unauthenticated_sources=1 compatibility_findings=0 filename_findings=0 evidence_diagnostics=0
Outputs: evidence=output/report-evidence.json rows_jsonl=output/report-rows.jsonl rows_csv=output/report-rows.csv agent=output/report-evidence-agent.json
```

The mini corpus is deliberately separate from deterministic synthetic test
fixtures. Read its
[`README`](../examples/go/report-directory/samples/README.md)
before reusing it or publishing reports for another domain.

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

### Inspect source behavior

The first run already contains a source-oriented view; DNS and enrichment are
not required. Grouping normalized observations by source can show:

| Feature | What it means |
| --- | --- |
| Messages and reports | Volume and repeated appearance in distinct aggregate reports |
| First and last seen | Receiver-supplied report-period bounds, not exact message times |
| Reporter diversity | How many reporting organizations observed the source |
| SPF and DKIM outcomes | Whether the receiver reported aligned authentication for the messages |
| Authentication identities | Reported SPF domains, DKIM domains, and DKIM selectors when present |
| Dispositions | `none`, `quarantine`, or `reject` actions reported by receivers |
| Policy overrides | Receiver-reported counter-evidence such as forwarding or mailing-list handling |

### Point-in-time corpus example

The project maintainer authorized the following aggregate summary of the full
local report archive for `georgestarcher.com`. Only the three-report mini
corpus described above is published; the remainder of the archive and its full
source-IP inventory stay local. This is an illustration of the output at the
time of the run, not a continuing claim about the domain or any source.

```text
Report period: 2026-04-25 through 2026-07-09
Reports: 49; messages: 114; sources: 55; reporters: 4
Authentication: pass=66; fail=48
Unauthenticated review: messages=48; sources=22
Failed SPF and DKIM together: 48
Receiver disposition for those failures: reject=48
Policy overrides on those failures: 0
Most repeated failing source: messages=8; reports=5
```

Those 48 observations claimed the protected domain but had neither aligned SPF
nor aligned DKIM. That is consistent with attempted unauthorized use of the
domain on the observed paths, but aggregate reports do not establish actor
identity or intent. The library retains neutral evidence and does not label the
sources malicious or safe to block.

The public agent envelope for the report-evidence stage can still say that no
structured review findings were produced. That statement means parsing and
normalization produced no data-quality findings; it does **not** mean that no
messages failed authentication. Always display the pass/fail and disposition
totals beside the envelope status.

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

Correlation answers whether an observed stream matches declared organization
intent. Candidate scoring then turns unexplained source behavior into an
inspectable review queue. A candidate includes message and dual-failure counts,
report and reporter diversity, report-period bounds, dispositions, score
contributions, confidence caps, exclusions, severity, and recommended usage.
It never authorizes blocking or claims maliciousness.

A newcomer should read this stage as:

```text
Expected sender and passing stream -> configuration or normal-flow context
Expected sender failure            -> configuration finding by default
Unattributed authentication failure -> eligible for neutral source review
Candidate score                     -> review priority, not attack probability
Confidence                          -> evidence sufficiency, not certainty of intent
```

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

### Source enrichment example

Use `EnrichThreatCandidates` when the application has an explicit offline
dataset or third-party `IPEnricher` that can assert ASN, network prefix,
organization, or coarse country context.

```text
Input:  selected review-eligible candidates + caller-supplied IPEnricher
Output: per-source assertions, provider provenance, freshness, conflicts,
        unavailable/failed status, and ASN rollups
Effect: may refine a confidence cap; never changes the threat score or action policy
```

The adapter may contact only its configured third-party service. It must never
ping, scan, perform hidden PTR, or otherwise connect to the subject source IP.

### Source activity example

Use `CollectSourceActivity` when a human or application explicitly selects
candidate IDs or source IPs and supplies a `SourceActivityProvider`.

```text
Input:  explicit candidate/IP selection + caller-supplied third-party provider
Output: time-qualified activity metrics, feed memberships, provenance,
        conflicts, rate limits, and incomplete or stale states
Effect: supplemental context only; absence is not evidence of safety
```

Each eligible address is attempted at most once. The library does not retry,
sleep, poll, discover more addresses, or ship a DShield adapter.

### Phishing-intelligence example

Use `NormalizePhishingIntelligenceSnapshot` and
`CorrelatePhishingIntelligence` when the caller already owns licensed,
validated offline intelligence.

```text
Input:  candidates + matching report evidence + offline normalized snapshots
Match:  exact source IP or exact DMARC domain-role equality only
Output: matched, conflicting, stale, future, withdrawn, expired, or no-match context
Effect: never changes candidate score, eligibility, or action policy
```

The library does not download OpenPhish or another feed. Retrieval, licensing,
schema mapping, refresh, removal, and storage remain application-owned.

### Jurisdiction-context example

Use `EvaluateJurisdictionContext` only after source enrichment supplied country
assertions and the application selected an immutable policy.

```text
Input:  completed enrichment + built-in or caller-normalized policy
Output: versioned country-policy matches, conflicts, freshness, attribution
        limitations, and an optional default-off review-priority adjustment
Effect: no score or severity change and no legal, nationality, or threat verdict
```

### Aggregate campaign-review example

Use `CorrelateCampaignReportEvidence` when the application also has a completed
authorized security-simulation campaign snapshot.

```text
Input:  campaign snapshot + report evidence
Output: lower-confidence campaign-related aggregate observations and coverage
Limit:  a report period cannot prove that one message belonged to a campaign
```

Message-level campaign classification is a separate workflow using body-free
reported-message evidence. Provider recognition alone never authorizes a
campaign or suppresses a suspicious source.

### Defensive-export example

After explicit human-reviewed candidate selection, an application can create a
STIX 2.1 bundle or encode payloads for ThreatConnect, MISP, or Anomali
ThreatStream.

```text
Input:  explicitly selected completed candidates and target capabilities
Output: local payload objects only
Effect: no target discovery, credential use, HTTP submission, retry, or approval
```

Defaults remain private and review-oriented. The consuming application owns
the destination, credentials, submission, responses, and audit history.

Campaign classification remains a separate workflow. Aggregate reports do not
provide an authorized campaign inventory, exact message time, or sufficient
message-level evidence to prove that one message belonged to an exercise.

Continue with [report evidence](report-evidence.md),
[DNS/report correlation](dns-report-correlation.md), or
[threat candidates](threat-candidates.md) for the field-level contracts.
