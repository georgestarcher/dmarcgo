# DNS authentication health

DNS health is a pure evaluation stage over a normalized `Portfolio`, a
completed `DNSAuthenticationResult`, and an explicit `ProviderCatalog`. It does
not accept reports, perform DNS queries, read files, reparse TXT text, or
consult the current clock. Provider recognition adds inventory context only;
it never changes scores or sender authorization.

## Pipeline

```text
NormalizePortfolio -> CollectDNSSnapshot -> ParseAuthenticationRecords --+
       pure                explicit I/O               pure               +-> EvaluateDNSHealth
ProviderCatalog ---------------------------------------------------------+          pure
```

The result retains the portfolio, snapshot, authentication-result, and provider
catalog digests needed to reproduce and validate its inputs. `EvaluateDNSHealth`
defaults its generation time to the DNS observation time. Set
`DNSHealthOptions.GeneratedAt` explicitly when evaluating staleness or creating
a later reproducible assessment. `DNSHealthResult.ObservedAt()` always retains
the underlying snapshot time separately from that later evaluation time.

## Scopes and evidence

The result contains:

- one record assessment per configured record name and domain scope;
- domain rollups that retain inherited and shared record references;
- entity rollups for subsidiaries, acquisitions, and sister organizations;
- a portfolio rollup;
- stable findings linked to evidence IDs from authentication parsing;
- recognized static SPF dependencies with exact-domain expected-sender context;
- complete score contributions for deterministic recomputation.

A shared DKIM selector produces a distinct record-scope assessment for every
dependent domain while retaining the same underlying evidence ID. This avoids
losing ownership and organizational context without duplicating DNS collection.

## Scoring profiles

`DNSHealthScoringProfiles` and `DNSHealthScoringProfileForName` expose every
deduction as data. Profiles share algorithm version
`DNSHealthScoringVersion == "1"` and a maximum score of 100.

| Profile | Intended use |
| --- | --- |
| `conservative` | Low-noise posture monitoring with smaller deductions for weak or incomplete configurations. |
| `balanced` | Default operational posture assessment. |
| `sensitive` | Stricter review where weak, permissive, stale, or incomplete configurations require more attention. |

Record scores begin at 100 and apply their listed finding deductions. Each
available score also carries a stable grade: A+ (95-100), A (90-94), B
(80-89), C (70-79), D (60-69), or F (below 60); unavailable scores use U. A domain
first averages available records within each mechanism, then combines SPF at
30%, DKIM at 35%, and DMARC at 35%. If a mechanism is not applicable, remaining
available weights are normalized; a required but unmonitored mechanism receives
its own domain deduction. Entity and portfolio scores are the rounded mean of
available child scores, followed by findings owned directly by that scope.
Every deduction and rollup appears in `DNSHealthScore.Contributions`.

The balanced profile preserves the established DMARC component interpretation:
monitoring-only policy is 70/100, absent DMARC is 30/100, and healthy enforcement
can reach 100/100. Quarantine deducts 12 points, absent aggregate reporting
deducts 10, and testing or obsolete tags apply their separately inspectable
deductions. A 1024-bit RSA DKIM key receives a 15-point maturity deduction;
SPF soft-fail and neutral terminal policies deduct 10 and 30 respectively.
SPF and DKIM absence produce zero for those configured components in the
balanced profile. SPF scoring uses the first `all` mechanism because it always
matches and makes every later mechanism unreachable. A valid `redirect`
modifier supplies the fallback result when no mechanism matches, so a
redirect-only policy is not treated as missing a terminal result.

For a configured domain using an inherited parent DMARC record, scoring and
maturity apply the record's `sp` policy, falling back to `p` when `sp` is
absent. The `np` policy is evaluated separately when determining whether the
published record enforces all descendant scopes. Because this stage performs no
DNS queries beyond the supplied snapshot, it does not infer that a configured
domain is nonexistent.

DMARC discovery falls back to an inherited owner only when the closer configured
owner has conclusively missing record evidence. Invalid, conflicting, or
unavailable exact records block fallback so a parent policy cannot conceal the
closer owner's failure or uncertainty. When multiple configured ancestors are
available, discovery evaluates them from the closest DNS parent outward rather
than using their lexical configuration order. Configured DMARC owners outside
the evaluated domain's ancestor tree are excluded from policy fallback.

Scores are posture indicators, not proof of compromise, sender authorization,
or malicious activity. Applications should use finding codes and evidence,
not score alone, for decisions.

## Maturity scale

Maturity is categorical and independent of the numeric health score. The scale
is based on the observable separation in the private live calibration set and
on the full-participation requirements in RFC 9989. It is not a conversion of
score bands into labels.

| Level | Name | DNS-health interpretation |
| ---: | --- | --- |
| 0 | `unmanaged` | No usable configured authentication record is conclusively published. |
| 1 | `basic` | At least one usable control is published, but a complete monitored SPF, DKIM, and DMARC posture is not established. |
| 2 | `monitored` | Usable SPF and DKIM are present, an applicable DMARC policy is published, and aggregate reporting is configured, but DMARC remains monitoring-only. |
| 3 | `enforced` | Usable SPF and DKIM are present and the applicable DMARC policy is quarantine or reject. This is the highest level DNS-only evidence can establish. |
| 4 | `managed` | Requires separate evidence that both aligned paths operate across all intended streams and aggregate reports are received, retained, and reviewed. |
| 5 | `adaptive` | Requires separate evidence of automated drift detection, tested rotation, expiring exceptions, and reviewed report/DNS correlation. |

`DNSHealthMaturity` exposes the level, evidence coverage, stable prerequisite
signals, and complete domain distribution. Entity and portfolio maturity use
the lowest available child level as a guardrail and retain the distribution so
stronger domains cannot average away a weaker one.

RFC 9989 full participation requires domain owners to send with both aligned
SPF and DKIM, publish applicable DMARC policy, and collect and analyze aggregate
reports. DNS can demonstrate configuration prerequisites but cannot prove
universal alignment or report handling. `MaximumObservableLevel` is therefore
`enforced`; managed and adaptive signals remain unknown until a later stage
receives explicit operational evidence. See [RFC 9989 section 8](https://www.rfc-editor.org/rfc/rfc9989.html#section-8).

Managed-readiness signals also reflect published protocol guidance:

- SPF evaluation must remain within the ten DNS-term limit in [RFC 7208 section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4).
- DKIM RSA keys must be at least 1024 bits and should be at least 2048 bits under [RFC 8301 section 3.2](https://www.rfc-editor.org/rfc/rfc8301.html#section-3.2).
- Aggregate feedback provides policy-decision visibility under [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990.html).
- Strict alignment receives no automatic maturity bonus; applicable policy and actual stream alignment matter.

The calibration set currently spans one basic SPF-only domain, five monitored
domains, and twelve enforced domains. The SPF-only baseline has SPF 100,
confirmed absent DMARC at 30, unknown DKIM inventory, and a weighted health
score of 62/D. This demonstrates why healthy SPF and organizational maturity
must remain separate.

## Ownership and reference entities

`EntityConfig.Membership` defaults to `owned`. Set it to `reference` for
external comparison domains. Reference entities retain complete record,
domain, entity, score, and maturity output but do not participate in portfolio
score or maturity rollups. This is explicit configuration; free-form tags never
silently change rollup membership.

## Unknown and partial evidence

The default `DNSHealthUnknownPreserve` policy keeps timeout, cancellation,
temporary failure, and otherwise unavailable evidence in the `unknown` state.
Unknown child scores are excluded from rollup means rather than treated as
zero or failure. `DNSHealthUnknownPenalize` is an explicit caller choice that
applies the selected profile's documented unknown-evidence deduction.

Missing records remain known negative evidence: an authoritative successful,
NXDOMAIN, NODATA, or not-found observation is different from a resolver timeout.
One unavailable record does not corrupt or erase unaffected results.

Set `MaxSnapshotAge` to emit a reproducible stale-snapshot finding relative to
`GeneratedAt`. A zero maximum age disables staleness evaluation.

## DNSSEC metadata

`DNSMessageResolver` preserves whether the DNS authenticated-data flag was set.
Limited resolvers leave `DNSSECEvidence.Available` false. The health evaluator
retains this distinction. An available but unset flag produces an informational
unknown-state finding, not a failure or deduction, because the flag is meaningful
only when the caller trusts the selected validating resolver.

## Finding boundaries

Finding summaries and recommendations are fixed library text. Record values,
reporting destinations, DKIM notes, resolver errors, owner contacts, and other
untrusted strings remain data fields and never enter generated instructions.

The evaluator reports, among other conditions:

- missing, malformed, invalid, conflicting, unsupported, weak, and unknown records;
- permissive or incomplete SPF terminal policy and incomplete dependency evidence;
- revoked, weak, or testing DKIM selectors;
- monitoring-only or testing DMARC policy, reporting visibility, and alignment posture;
- required mechanisms or selectors absent from monitoring configuration;
- child-domain DMARC policy weaker than its configured parent;
- stale snapshots and degraded or unknown rollups.

## Example

```go
catalog, err := dmarcgo.DefaultProviderCatalog()
if err != nil {
    return err
}
result, err := dmarcgo.EvaluateDNSHealth(portfolio, authentication, catalog,
    dmarcgo.DNSHealthOptions{
        Profile:        dmarcgo.DNSHealthProfileBalanced,
        GeneratedAt:    assessmentTime,
        MaxSnapshotAge: 24 * time.Hour,
        UnknownPolicy:  dmarcgo.DNSHealthUnknownPreserve,
    })
if err != nil {
    return err
}

score := result.PortfolioScore()
maturity := result.PortfolioMaturity()
for _, finding := range result.Findings() {
    log.Printf("%s %s", finding.Severity, finding.Code)
}
_ = maturity
```

Callers that need current evidence must explicitly collect a new snapshot. DNS
health never refreshes, retries, mutates DNS, reads reports, or submits actions.
