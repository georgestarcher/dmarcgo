# Optional phishing-intelligence correlation

`NormalizePhishingIntelligenceSnapshot` and
`CorrelatePhishingIntelligence` provide an explicit, offline boundary for
comparing completed DMARC review evidence with caller-owned phishing
intelligence. The feature is provider neutral. It does not download feeds,
query a service, contact a source address, or turn an intelligence relation
into a malicious verdict.

## Safe workflow

1. Complete report-evidence normalization, DNS/report correlation, and
   threat-candidate scoring.
2. Obtain intelligence under terms that permit the application's intended
   use, storage, output, and recipients.
3. Convert only understood fields into a
   `PhishingIntelligenceSnapshotConfig` and normalize it.
4. Correlate the immutable snapshot with the matching
   `ThreatCandidateResult` and `ReportEvidenceResult`.
5. Review exact matches together with their DMARC role, report-period bounds,
   provider state, freshness, provenance, and infrastructure-reuse limits.

```go
snapshot, err := dmarcgo.NormalizePhishingIntelligenceSnapshot(
    dmarcgo.PhishingIntelligenceSnapshotConfig{
        Provider:      "licensed-offline-source",
        Dataset:       "snapshot-2026-07-14",
        SchemaVersion: "provider-contract-v1",
        CollectedAt:   collectedAt,
        AsOf:          asOf,
        License: dmarcgo.PhishingIntelligenceLicense{
            Name:           "caller-reviewed terms",
            TermsURI:       "https://provider.example/terms",
            CommercialUse:  dmarcgo.PhishingIntelligenceUsageRestricted,
            Redistribution: dmarcgo.PhishingIntelligenceUsageProhibited,
        },
        Indicators: []dmarcgo.PhishingIntelligenceIndicatorConfig{
            {
                Type:      dmarcgo.PhishingIntelligenceSourceIP,
                Value:     "192.0.2.10",
                State:     dmarcgo.PhishingIntelligenceIndicatorActive,
                FirstSeen: &firstSeen,
                LastSeen:  &lastSeen,
            },
        },
    },
)
if err != nil {
    return err
}

result, err := dmarcgo.CorrelatePhishingIntelligence(
    threatCandidates,
    reportEvidence,
    []dmarcgo.PhishingIntelligenceSnapshot{snapshot},
    dmarcgo.PhishingIntelligenceOptions{GeneratedAt: assessmentTime},
)
```

Both functions are pure. The caller owns feed retrieval, authentication,
licensing, parsing, refresh, caching, storage, and removal policy.

## Exact matching contract

Version 1 supports two canonical indicator types:

- `source_ip`: exact canonical IPv4 or IPv6 equality;
- `domain`: exact canonical IDNA A-label equality.

Domain matches retain the role that supplied the value:

- report target domain;
- visible author/header-from domain;
- SPF authentication domain; or
- DKIM signing domain.

Suffix, substring, registrable-domain, ASN, country, provider, brand, and sector
comparisons never create a match. Brand describes an impersonated target, not
the malicious hostname. ASN, country, infrastructure provider, brand, and
sector values are retained only as untrusted structured context.

DMARC aggregate reports do not contain message bodies or phishing URLs. Version
1 therefore does not expose a URL indicator type or infer URLs from domains.
A future upstream mode must supply a complete normalized URL before URL
correlation can be designed.

Excluded and non-review-eligible candidates remain visible as `not_eligible`
and are not correlated. The stage does not bypass candidate exclusions or
expected-sender safeguards.

## Time and provider-state semantics

Exact equality alone is not an active match. When indicator times exist, a
source-IP relation uses the threat candidate's aggregate dual-failure period,
while each domain-role relation uses only the aggregate report periods of the
observations that supplied that exact domain and role. The indicator window
must overlap at least one of those role-specific periods; disjoint periods are
not collapsed into an envelope that bridges the gap. Report bounds are not
exact per-message timestamps.

Each retained relation records one of these states:

- `active_match`: exact value, active provider state, usable snapshot, and an
  overlapping evidence window;
- `time_unknown`: exact value but insufficient time bounds;
- `not_overlapping`: exact value whose known window did not overlap;
- `withdrawn`: the provider record was explicitly withdrawn;
- `expired` or `stale`: the caller's evidence is no longer current;
- `future`: a snapshot or indicator timestamp is after the assessment time;
- `state_unknown`: the provider's current state was not established.

An active and withdrawn assertion for the same exact value and evidence role is
reported as `conflicting`. Every assertion is retained and no provider is
preferred. A missing feed relation never proves that an address or domain is
safe.

`GeneratedAt` defaults to the latest completed DMARC input timestamp and never
uses the system clock. `StaleAfter` is caller-owned and disabled when zero.
Snapshot and per-indicator expiration remain explicit. `MaxMatches` bounds
retained exact relations; a limit failure returns no partial result.

## OpenPhish research gate

The historical
[georgestarcher/TA-Openphish](https://github.com/georgestarcher/TA-Openphish)
Splunk add-on is design context only. It demonstrates an older normalization
idea, but none of its endpoints, authentication, schemas, cadence, Python 2
code, or operational assumptions are used as a current integration contract.

Current first-party material was reviewed on **2026-07-14**:

- [OpenPhish Phishing Feeds](https://www.openphish.com/phishing_feeds.html)
- [OpenPhish Database](https://www.openphish.com/phishing_database.html)
- [OpenPhish Knowledge Base](https://www.openphish.com/kb.html)
- [OpenPhish Terms of Use](https://www.openphish.com/terms.html)
- [OpenPhish `pyopdb` offline module](https://github.com/openphish/pyopdb)

The public product pages currently describe:

- a Community URL feed refreshed every 12 hours and delivered as text;
- commercial feeds refreshed every five minutes and delivered as CSV or JSON,
  while the knowledge base also describes TXT delivery, a 24-hour feed, and a
  30-day archive;
- feed metadata that can include URL, targeted brand, IP, ASN, geography,
  sector, page language, and TLS/SSL context depending on tier;
- licensed SQLite databases intended for offline queries, with hostname, page,
  path, language, TLS/SSL, IP, ASN, country, impersonated brand, and drop-account
  context; and
- an official MIT-licensed Python module that queries a local database but
  requires a valid production or trial database license.

The public material describes Community, trial, and paid delivery but does not
publish one authentication and account-access contract suitable for a bundled
provider-neutral adapter. Applications own current account access, credential
handling, endpoint allowlisting, and licensed artifact retrieval.

OpenPhish states that it does not offer a remote URL-verdict query API. Its
offline database path is the privacy-preserving supported query model. The
separate REST API mentioned in the knowledge base is for submitting URLs to
OpenPhish, not checking DMARC evidence, and is outside this feature.

The current public pages do not form a sufficiently stable built-in adapter
contract:

- feed tier names and database history figures differ between the product pages
  and knowledge base;
- no public page establishes one stable schema covering all feed/database
  tiers, confidence fields, active/withdrawn fields, or indicator-removal
  semantics;
- update frequency is documented, but a general downloader polling/rate-limit
  contract is not; and
- the general terms restrict commercial use, redistribution, disclosure, and
  derivative works without prior written permission. Customer-specific terms
  may add different permissions and remain caller-owned.

For those reasons `dmarcgo` ships no OpenPhish client, parser, endpoint,
credential handling, feed content, or derived fixture. An application may map
licensed OpenPhish data into this provider-neutral contract only after reviewing
its exact current product schema and agreement.

The knowledge base says feeds focus on new and active URLs, avoid reporting the
same URL more than once within 14 days, remove dead/inactive URLs, and publish
confirmed false positives to a separate false-positive feed. Those statements
are useful limitations, not a versioned state-machine contract. Callers should
map `active`, `withdrawn`, timestamps, confidence, and category only when their
licensed format defines those fields unambiguously.

## Security and prompt-injection boundary

Provider, dataset, schema, license, category, reference, brand, provider, and
sector strings are untrusted data. They remain structured fields. Findings,
titles, explanations, and recommendations use only fixed library text and never
interpolate those values.

Snapshot normalization rejects invalid UTF-8, control characters, oversized
fields, invalid IPs/domains, impossible windows, invalid country codes, invalid
confidence values, unsupported indicator types, excessive indicators, and
excessive total data. Snapshot count, per-snapshot and aggregate indicators,
context lists, and retained matches are bounded. Identical normalized records
are deduplicated. Conflicting records remain separate evidence.

The result never changes threat-candidate score, confidence, severity,
eligibility, exclusions, promotion state, or recommended usage. It never
authorizes blocking, quarantine, takedown, notification, submission, or any
other automatic action.

## Collision and attribution limitations

An exact IP or domain relation does not prove that the reviewed SMTP source:

- hosted the phishing page;
- controlled the mail system;
- was compromised;
- is still assigned to the same operator; or
- participated in the provider-observed activity.

Shared hosting, CDNs, cloud services, NAT, proxies, VPNs, anycast, reassignment,
compromise, stale data, report-period imprecision, and provider disagreement can
all create collisions. Review the retained evidence and time relationship; do
not convert a relation into actor attribution.

## Output boundary

`BuildAnalysisOutput` serializes a completed `PhishingIntelligenceResult` into
the common automation/agent envelope, and `WritePhishingIntelligenceOutput`
writes its native JSON, JSONL, or CSV contract. Both paths support explicit
public, operational, or restricted redaction and never load, retrieve, or
correlate an intelligence snapshot during serialization. Direct generic JSON
encoding of result accessors is restricted operational data and is not a
disclosure-safe output path.
