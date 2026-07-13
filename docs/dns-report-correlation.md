# DNS and report correlation

`CorrelateReportEvidence` compares three already completed truths:

1. declared sender intent in a normalized `Portfolio`;
2. current authentication posture in a `DNSHealthResult`; and
3. historical receiver observations in a `ReportEvidenceResult`.

The function performs no DNS queries, report parsing, filesystem access, IP or
ASN enrichment, storage, retries, or clock access. Applications collect and
prepare each input explicitly, then decide whether and when to persist the
immutable result.

## Temporal boundary

Current DNS is not historical proof. Every stream and finding retains the DNS
observation time, report-period bounds, and one of these relationships:

- `dns_before_reports`;
- `dns_during_reports`;
- `dns_after_reports`; or
- `unknown`.

Report bounds are observation windows rather than exact message times. Even a
DNS snapshot inside a report window does not prove that a specific record value
caused a reported outcome. When current DNS is healthy but an older stream
failed, the result emits `current_dns_historical_variance` and recommends
time-matched evidence rather than rewriting history.

## Stream identity and sender candidates

Correlation deterministically aggregates report rows by resolved entity/domain,
target and author domains, source IP, SPF identity, DKIM signing domain, and
DKIM selector. Repeated DKIM results can therefore create more than one stream
view for one report row; the top-level summary copies the distinct report
evidence totals and never double-counts those expanded views.

An expected sender becomes a direct candidate only when supplied evidence
matches declared inventory:

- a reported DKIM selector matches that sender's `allowed_selectors`; or
- a reported SPF identity matches a monitored SPF name and exactly one sender
  in that domain requires SPF or either authentication path.

A missing selector remains unknown. The library does not invent one or assign a
stream merely because a domain has only one configured sender.

Provider contexts from DNS health are copied as evidence references for the
resolved domain scope. Provider recognition never becomes candidate matching,
sender authorization, a healthy verdict, or suppression. This preserves useful
shared-infrastructure and onboarding context for later review without treating
catalog membership as trust.

## Finding categories

Stable classifications distinguish operational configuration from unattributed
traffic:

- expected sender healthy;
- expected sender configuration failure;
- probable onboarding gap;
- unknown-source authentication failure;
- unknown passing stream;
- new selector, signing domain, SPF identity, source, or inherited subdomain;
- configured selector not observed;
- retired configuration still observed;
- expected sender began failing;
- current-DNS/historical-report variance; and
- insufficient evidence.

`unknown_source_authentication_failure` means both policy-evaluated SPF and DKIM
failed for an unattributed stream. It does not mean malicious, compromised,
botnet, or safe to block. A declared selector or unambiguous SPF identity that
fails its required policy remains an operational sender finding instead.

Finding summaries and recommendations are fixed library text. Domains, source
IPs, selectors, owner IDs, provider metadata, DNS values, reporter values, and
other supplied strings remain structured data and never become instructions.

## Thresholds

`DNSReportCorrelationThresholds` can require minimum messages, reports,
reporters, report-window duration, and recency. Zero count thresholds default to
one; zero duration and maximum age disable those constraints. Streams below a
threshold remain visible with `not_evaluated` threshold state and an
`insufficient_evidence` finding. Absence findings such as a configured selector
not observed are emitted only when the domain corpus itself satisfies the same
thresholds.

This makes threshold behavior inspectable and prevents a small or stale sample
from silently becoming an operational conclusion.

## Drift without storage

Pass a caller-owned prior `DNSReportCorrelationResult` in `Previous` to compare
two completed analyses. The current result records its digest and can identify:

- a previously passing stream that now includes failures;
- a source address absent from the prior result; and
- a selector retained in report evidence after removal from current inventory.

The library does not discover, load, save, or select prior results. Changing the
portfolio within the same organization between runs is allowed for
retired-configuration comparison. A prior result from another organization or
newer than the requested evaluation is rejected.

## Example

```go
correlation, err := dmarcgo.CorrelateReportEvidence(
    portfolio,
    dnsHealth,
    reportEvidence,
    dmarcgo.DNSReportCorrelationOptions{
        GeneratedAt: assessmentTime,
        Thresholds: dmarcgo.DNSReportCorrelationThresholds{
            MinMessages:  10,
            MinReports:   2,
            MinReporters: 2,
            MinDuration:  24 * time.Hour,
            MaxReportAge: 30 * 24 * time.Hour,
        },
        Previous: previousCorrelation,
    },
)
if err != nil {
    return err
}

for _, finding := range correlation.Findings() {
    log.Printf("%s %s", finding.Severity, finding.Code)
}
```

The result retains portfolio, DNS-health, DNS-snapshot, parsed-authentication,
provider-catalog, report-evidence, and optional prior-result digests. Its
inventory, stream, finding, and summary accessors return defensive copies.

## Safe onboarding review sequence

For a probable onboarding gap:

1. confirm the service and owner outside report-controlled data;
2. review the declared sender policy and complete monitored record names;
3. compare report periods with the separate DNS observation time;
4. validate current SPF and DKIM through explicit collection and health stages;
5. send a controlled test through the intended stream;
6. review new aggregate evidence before tightening enforcement; and
7. retain rollback ownership and DNS TTL timing in the calling application's
   change process.

Correlation is advisory. It never mutates DNS, authorizes a service, initiates
remediation, enriches a source, or recommends direct traffic to a source IP.
