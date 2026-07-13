# Normalized report evidence

`AnalyzeReportEvidence` converts already parsed DMARC aggregate reports into an
immutable `ReportEvidenceResult`. The result is the report-only input for later
correlation and suspicious-source analysis. Normalization performs no DNS,
filesystem, IP/ASN enrichment, portfolio lookup, or expected-sender matching.

## Data model

Each accepted report produces `ReportEvidenceReport` provenance and one
`ReportEvidenceObservation` per aggregate-report row. Observations retain:

- canonical IPv4 or IPv6 source identity;
- author domain (`header_from`) and report policy domain;
- policy-evaluated DKIM, SPF, and combined DMARC outcomes;
- every DKIM signing domain, selector when supplied, and result;
- the optional SPF domain, scope, and result;
- disposition, positive message count, reporter, and report period;
- recognized normalized policy-override type codes, without reporter comments;
- stable report and observation evidence identifiers.

`ReportEvidenceValue`, `ReportEvidenceCount`, and `ReportEvidencePeriod` make
unavailable values explicit. A missing selector, missing authentication result,
invalid source address, invalid period, or invalid count never becomes an
authentication failure. Invalid and zero counts remain visible as observations
and diagnostics but do not contribute to message totals.

Valid domains are canonical lowercase IDNA A-labels and valid source addresses
use canonical IPv4 or IPv6 text without zone identifiers. When normalization
fails, the trimmed report value remains only in `raw_value` while `value` stays
unavailable. Raw values are untrusted evidence and are never copied into
diagnostic prose.

Report-controlled domains, selectors, reporter names, dispositions, and result
tokens remain data. Standard policy-override types are retained as structured,
reporter-supplied counter-evidence for later forwarding and mailing-list review;
they are not proof of benignness. Unknown types and policy-override comments
are intentionally discarded; the parsed report still retains its raw reason
values. Diagnostic prose is library-controlled and never includes supplied values.

## Duplicate and overlap semantics

Reports are normalized and sorted before IDs or totals are built. Input report
and record order therefore does not affect the digest or serialized document.

- Identical content with the same non-zero `ReportIdentity` is counted once and
  produces `report.evidence.duplicate_report_ignored`.
- Different normalized content claiming the same non-zero identity returns
  `ErrConflictingReportIdentity`; selecting an arbitrary first report would make
  results order-dependent.
- Reports with a zero identity are retained as separate occurrences because the
  library cannot prove they are duplicates.
- Different report identities are accumulated even when their report
  periods overlap. Report periods describe observation bounds, not exact
  per-message timestamps, and overlapping receiver reports are not evidence of
  duplicate messages.

Counts use checked signed 64-bit arithmetic. This analysis contract treats zero
as invalid because it describes no observed messages, although RFC 9990's XSD
uses the broader `xs:integer` type. A single value outside the positive range is
unavailable evidence. A valid set whose total exceeds `math.MaxInt64` returns
`ErrReportEvidenceOverflow` instead of wrapping.

## Filtering and aggregation

`result.Filter` selects already normalized observations by report evidence ID,
source IP, report or author domain, SPF domain, DKIM domain or selector,
reporter, disposition, combined outcome, and an overlapping time window.
It can also select the independent policy-evaluated DKIM and SPF outcomes.
The caller window is `[PeriodStart, PeriodEnd)`; a report's supplied end bound is
treated as inclusive because RFC 9990 does not declare a half-open interval and
its example uses the final second of a day. Time-window filtering excludes
observations whose report period is unknown.

`result.Aggregate` applies the same filter and supports deterministic grouping
by source, report domain, author domain, SPF domain, DKIM domain, DKIM selector,
reporter, disposition, and policy outcome. Each aggregate includes:

- record, valid-record, invalid-record, and message counts;
- distinct report and reporter counts;
- earliest begin and latest end report-period bounds;
- pass, fail, and unknown totals for combined DMARC, DKIM, and SPF;
- DKIM/SPF outcome combinations and dispositions.

When grouping by DKIM domain or selector, one row with multiple DKIM results can
contribute to multiple groups. Within each group its message count is counted
once. Filtering by both a DKIM domain and selector requires both to occur in the
same observation, but not necessarily in the same repeated DKIM result entry.

Portfolio entity and expected-sender attribution intentionally remains outside
this mode. The later correlation stage consumes stable evidence IDs together
with a normalized portfolio and DNS health result. This prevents report-only
analysis from prematurely interpreting sender inventory.

## Reproducibility and persistence

Set `ReportEvidenceOptions.GeneratedAt` for fully caller-controlled metadata.
When it is zero, normalization deterministically uses the latest valid report
period end; an empty or entirely invalid corpus retains the zero time rather
than consulting the system clock.

`ReportEvidenceResult` implements `json.Marshaler` as a strict intermediate
document with `schema_version`, shared result metadata, a content digest,
reports, observations, summary, and diagnostics. `LoadReportEvidenceJSON`
rejects unknown fields, trailing values, broken references, inconsistent
counters or summaries, and digest mismatches. This persistence contract is not
the automation-output profile introduced for completed user-facing modes.

The current report-evidence persistence schema is version `2`. Version `2`
adds normalized `policy_override_types` to observation content, so its content
digests and evidence identifiers are intentionally distinct from version `1`.
The strict loader rejects version `1` documents; regenerate them from their
source reports rather than reinterpreting old digests under the new contract.

## Example

```go
evidence, err := dmarcgo.AnalyzeReportEvidence(reports, dmarcgo.ReportEvidenceOptions{
    GeneratedAt: generatedAt,
})
if err != nil {
    return err
}

sources, err := evidence.Aggregate(
    dmarcgo.ReportEvidenceFilter{AuthorDomains: []string{"example.test"}},
    dmarcgo.ReportEvidenceBySourceIP,
)
if err != nil {
    return err
}
```

The result owns normalized values and does not retain the original report files
or initiate any later pipeline stage.
