# Versioned jurisdiction context

`EvaluateJurisdictionContext` is a pure, offline stage after optional source
enrichment. It compares the coarse country assertions already present in a
completed `SourceEnrichmentResult` with an explicit, immutable
`JurisdictionRiskPolicy`.

This feature is review context only. A country code attributed to observed
infrastructure does not establish the location, nationality, identity, intent,
or government affiliation of a sender or operator. A policy match is not a
malicious verdict, compromise claim, sanctions determination, export-license
decision, or authorization to block a source.

## Authoritative sources and built-in snapshot

The built-in `us_export_control_inspired` policy version `2026-07-08` was
reviewed against these primary sources:

- [BIS Country Guidance](https://www.bis.gov/licensing/country-guidance), which
  explains the role of Country Groups A, B, D, and E in export-control and
  license-exception decisions;
- [15 CFR Part 740, Supplement No. 1 — Country Groups](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-740/appendix-Supplement%20No.%201%20to%20Part%20740),
  which supplies the membership table used by the snapshot.

The snapshot includes every current member of Country Groups D:1 through D:5
and E:1 through E:2 as of July 8, 2026. The exact ISO 3166-1 alpha-2 membership
retained for each category is:

| Category | Source meaning | ISO country codes |
| --- | --- | --- |
| D:1 | National Security | AM, AZ, BY, CN, GE, IQ, KG, KH, KP, KZ, LA, LY, MD, MM, MN, MO, NI, RU, TJ, TM, UZ, VE, VN, YE |
| D:2 | Nuclear | BY, CU, IL, IQ, IR, KP, LY, PK, RU, VE |
| D:3 | Chemical & Biological | AE, AF, AM, AZ, BH, BY, CN, CU, EG, GE, IL, IQ, IR, JO, KG, KP, KW, KZ, LB, LY, MD, MM, MN, MO, OM, PK, QA, RU, SA, SY, TJ, TM, TW, UZ, VE, VN, YE |
| D:4 | Missile Technology | AE, BH, BY, CN, EG, IL, IQ, IR, JO, KP, KW, LB, LY, MO, OM, PK, QA, RU, SA, SY, VE, YE |
| D:5 | U.S. Arms Embargoed Countries | AF, BY, CD, CF, CN, CU, ER, HT, IQ, IR, KP, LB, LY, MM, NI, RU, SD, SO, SS, SY, VE, ZW |
| E:1 | Terrorist supporting countries | IR, KP, SY |
| E:2 | Unilateral embargo | CU |

Those are export-control categories, not cyber-threat categories. The library
therefore describes the policy as **U.S. export-control-inspired jurisdiction
context**, not “the U.S. Export Control List,” a high-risk actor list, or legal
compliance advice.

The snapshot expires for review on January 8, 2027. That date is a library
freshness guardrail, not an official expiration of the regulation. An expired
snapshot produces `stale` context and no priority adjustment. The library never
downloads an update: policy changes require an explicit library release or a
caller-supplied replacement policy.

## Policy tiers and optional priority

The built-in policy maps the source categories into three library-owned review
tiers. These tiers are not official BIS categories and are not severity bands:

| Tier | Membership rule | Optional adjustment |
| --- | --- | ---: |
| `export_control_context` | At least one D category, but no D:5 or E category | 3 |
| `arms_embargo_context` | D:5, but no E category | 6 |
| `embargo_context` | E:1 or E:2 | 10 |

The adjustment is disabled by default. A caller must set
`EnableReviewPriorityAdjustment` explicitly. Even then, it is a separate
additive review-queue hint capped by the policy at 10; it does not modify
`ThreatCandidate.Score`, confidence, severity, review eligibility, exclusions,
promotion eligibility, or recommended usage. It cannot independently authorize
blocking, promotion, submission, scanning, or any other defensive action.

Only a `match` based on at least one fresh, unambiguous country assertion can
receive an adjustment. `unknown`, `stale`, `conflicting`, `not_eligible`, and
`not_evaluated` results receive zero. A fresh country outside the policy is
`no_match` and also receives zero.

## Evidence and state model

Every result retains:

- the source-enrichment digest and organization ID;
- the complete immutable policy and its digest, version, dates, sources, and
  maximum adjustment;
- the policy freshness at the caller-controlled result timestamp;
- candidate IDs and restricted source IPs;
- every metadata assertion ID, country code, and freshness state;
- every matched policy-entry ID, tier, category code, and reason code;
- stable library-owned finding codes and fixed explanatory text; and
- deterministic summary counts and result digest.

Country disagreements are never collapsed into a preferred provider. Any two
different non-empty asserted country codes produce `conflicting`, including
when one assertion is stale. If all country-bearing assertions are stale, the
result is `stale`. If no assertion supplies a country, or no country assertion
has proven freshness, the result is `unknown`.

Cloud hosting, shared infrastructure, compromised systems, proxies, VPNs,
anycast, provider lag, and dataset disagreement all limit the signal. A country
code describes only the coarse location attributed to infrastructure by the
selected enrichment dataset.

## Custom policies and versioning

Callers can construct a `JurisdictionRiskPolicyConfig` and pass it through
`NormalizeJurisdictionRiskPolicy`. Normalization requires:

- stable policy ID and version;
- name and description;
- effective, as-of, and optional expiration timestamps;
- at least one canonical HTTPS provenance source;
- unique, real ISO 3166-1 alpha-2 entries;
- explicit machine-safe tier, category, and reason codes; and
- per-entry adjustments no greater than the policy maximum or the hard
  10-point library cap.

Normalization sorts sources, entries, categories, and reasons, assigns stable
entry IDs, computes a content-sensitive digest, and returns defensive copies.
It performs no network or environment access. Applications should persist the
policy ID, version, digest, as-of date, expiration, and result timestamp so a
later policy revision cannot silently reinterpret an older assessment.

## Hostile-input and network boundary

Policy names, descriptions, source titles, source URIs, custom tiers,
categories, and reasons are untrusted structured data. The evaluator never
interpolates them into findings, explanations, recommendations, headlines, or
instructions. Finding messages are selected only from fixed library text.

Evaluation receives already-normalized values and has no resolver, HTTP client,
GeoIP reader, environment loader, or credential interface. It never performs
DNS, HTTP, PTR, WHOIS, SMTP, ICMP, filesystem, or direct source-IP activity.
The source-enrichment security boundary remains unchanged: an enricher must not
contact the subject IP, and PTR remains a separate explicit opt-in operation.

## Example

```go
contextResult, err := dmarcgo.EvaluateJurisdictionContext(
    enrichedCandidates,
    dmarcgo.BuiltinJurisdictionRiskPolicy(),
    dmarcgo.JurisdictionContextOptions{
        GeneratedAt:                    assessmentTime,
        EnableReviewPriorityAdjustment: true,
    },
)
if err != nil {
    return err
}

for _, candidate := range contextResult.Candidates() {
    if candidate.Status == dmarcgo.JurisdictionContextMatch {
        queueForHumanReview(candidate.CandidateID, candidate.ReviewPriorityAdjustment)
    }
}
```

The caller remains responsible for the queue policy and for displaying the
limitations alongside any match. The library does not turn the adjustment into
an action.
