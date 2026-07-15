# Optional context configuration

This guide explains how an application enables the optional context stages that
follow DNS health or suspicious-source scoring. These stages are deliberately
separate from the organization portfolio. Adding a domain, expected sender, or
provider-catalog entry does not enable enrichment, retrieve intelligence, or
send a source address to a service.

There is no global `dmarcgo` configuration file and no generic provider name,
endpoint, or API-key setting. A consuming application must choose each optional
stage explicitly and supply either an immutable offline input or a bounded
provider implementation.

## Start here

| Question | API | Application supplies | Built-in provider | Network behavior |
| --- | --- | --- | --- | --- |
| Which ASN, network, organization, or coarse country did a selected dataset assert for a candidate IP? | `EnrichThreatCandidates` | `IPEnricher` or `BatchIPEnricher` and `SourceEnrichmentOptions` | None | Only the supplied adapter; it must never contact the subject IP |
| Does a selected third party report time-qualified activity for an explicit candidate IP? | `CollectSourceActivity` | `SourceActivityProvider`, explicit selection, and `SourceActivityOptions` | None; no DShield adapter | Only the supplied third-party adapter |
| Does caller-owned intelligence contain an exact candidate IP or exact DMARC domain-role value? | `NormalizePhishingIntelligenceSnapshot`, then `CorrelatePhishingIntelligence` | Programmatic snapshot data and correlation options | None; no OpenPhish client or parser | None |
| Does completed country enrichment match a reviewed jurisdiction policy? | `EvaluateJurisdictionContext` | Built-in or normalized custom policy and options | A versioned offline policy only | None |
| Do selected remote DNS perspectives return the same TXT answer set? | `CollectDNSPerspectives` | `DNSPerspectiveProvider`, explicit names or roles, and options | None; no DShield adapter | Only the supplied remote-perspective adapter |

If the requirement is only to recognize a documented SPF dependency, use the
[provider catalog](provider-catalog.md). Provider recognition is configuration
context, not source enrichment, sender authorization, or reputation.

## Configuration forms

`dmarcgo` uses three deliberately different configuration forms:

| Form | Examples | Library behavior |
| --- | --- | --- |
| Strict organization files | Portfolio YAML, campaign YAML/JSON, private provider-catalog YAML | The named loader validates bytes already supplied by the application |
| Programmatic offline inputs | `PhishingIntelligenceSnapshotConfig`, `JurisdictionRiskPolicyConfig` | The named normalizer validates mutable Go values and returns an immutable snapshot or policy |
| Caller-supplied interfaces | `IPEnricher`, `SourceActivityProvider`, `DNSPerspectiveProvider` | The named collection stage calls only that dependency within explicit bounds |

The phishing-intelligence and jurisdiction-policy types do not have a library
file loader or file schema. If an application stores those inputs in JSON,
YAML, a database, or an intelligence platform, that application owns strict
decoding, raw-size limits, authentication, credential handling, source
allowlisting, schema mapping, and storage. Construct the public Go input only
after the external format has been validated.

Never store API keys, passwords, access tokens, private URLs, or contact-bearing
User-Agent values in a portfolio, provider catalog, offline snapshot, policy,
or normalized result. Keep them in the application boundary that constructs the
adapter. Provider error bodies and free-form errors must not enter normalized
evidence or generated prose.

## Prerequisites and order

Optional source context starts only after the application has completed report
evidence, DNS/report correlation, and threat-candidate scoring:

```text
reports -> report evidence -> DNS/report correlation -> threat candidates
                                                        |        |
                                                        |        +-> source enrichment -> jurisdiction context
                                                        +----------> selected source activity
                                                        +----------> offline phishing-intelligence correlation

portfolio -> DNS snapshot -> optional selected DNS perspectives
```

Phishing-intelligence correlation also requires the exact
`ReportEvidenceResult` used by the candidate result. Jurisdiction context
requires a completed `SourceEnrichmentResult`. Source activity may accept the
matching enrichment result for evidence continuity, but it remains an
independent explicitly selected stage.

## Configure source enrichment

Source enrichment has no YAML setting and no bundled network provider. Supply
an offline lookup or a third-party adapter that implements:

```go
type IPEnricher interface {
    EnrichIP(context.Context, netip.Addr) (IPMetadata, error)
}
```

An adapter may also implement `BatchIPEnricher`. The library supplies the
complete sorted, deduplicated eligible address set in one call. The adapter
owns bounded concurrency inside that batch call.

### Source-enrichment options

| `SourceEnrichmentOptions` field | Zero-value behavior | Allowed or hard limit |
| --- | --- | --- |
| `MaxConcurrency` | 4 | 1 through 256; ignored by a batch adapter |
| `LookupTimeout` | 5 seconds | Any positive duration; the application should impose its own reasonable maximum |
| `FailurePolicy` | `collect_all` | `collect_all` or `fail_fast` |
| `Clock` | System time when a non-nil provider is used | Supply a `Clock` for reproducible lookup and freshness timestamps; a nil provider does not consult it |

Each canonical IP is supplied at most once. The library does not retry. At most
64 assertions may be returned for one address, and every untrusted text field
is limited to 2 KiB.

### Source-enrichment response fields

| Input type and field | What the adapter supplies |
| --- | --- |
| `IPMetadata.Assertions` | Independent provider assertions; an empty slice means unavailable metadata |
| `IPMetadata.ConflictFields` | Leave empty; normalization recomputes ASN and country conflicts |
| `IPMetadataAssertion.ID` | Leave empty; normalization assigns a stable ID |
| `IPMetadataAssertion.ASN` | Optional non-zero autonomous-system number |
| `IPMetadataAssertion.ASNName` | Optional provider-supplied ASN name |
| `IPMetadataAssertion.NetworkPrefix` | Optional canonical prefix that must contain the subject IP |
| `IPMetadataAssertion.Organization` | Optional provider-supplied organization |
| `IPMetadataAssertion.CountryCode` | Optional real ISO 3166-1 alpha-2 code; coarse context only |
| `IPMetadataAssertion.Provenance` | Required provider and lookup provenance |
| `IPMetadataAssertion.Freshness` | Leave empty; normalization derives it from expiry and result time |
| `IPMetadataAssertion.Sensitivity` | Leave empty; normalization sets restricted sensitivity |
| `IPMetadataProvenance.Provider` | Required stable provider identity |
| `IPMetadataProvenance.Source` | Optional dataset or source identity |
| `IPMetadataProvenance.LookupAt` | Required provider lookup or dataset observation time |
| `IPMetadataProvenance.ExpiresAt` | Optional expiry, not earlier than `LookupAt` |
| `IPMetadataProvenance.Confidence` | Optional confidence availability and value |
| `IPMetadataProvenance.ReferenceID` | Optional provider reference; untrusted data |
| `IPMetadataConfidence.Available` | `false` when the provider supplies no confidence |
| `IPMetadataConfidence.Value` | 0 through 100 when available; must be zero when unavailable |

Every assertion must contain at least one metadata value among ASN, ASN name,
network prefix, organization, or country. Provider confidence can cap candidate
confidence, but no enrichment field changes the threat score or authorizes an
action.

Return `ErrIPMetadataUnavailable` when the adapter completed a supported lookup
but has no usable metadata. Preserve `context.Canceled` or
`context.DeadlineExceeded` when the context ends. Other errors become a stable
failed status without copying provider-controlled error text.

The compile-checked `ExampleEnrichThreatCandidates` uses an in-memory synthetic
`IPEnricher`. A production adapter must additionally allowlist its third-party
destination, bound raw responses before parsing, honor context cancellation,
keep credentials private, and avoid PTR or any direct connection to the subject
address. See [source enrichment](source-enrichment.md) for result and confidence
semantics.

## Configure source activity

Source activity requires an explicit candidate-ID or source-IP selection. An
empty `SourceActivitySelection` makes no provider call. Implement:

```go
type SourceActivityProvider interface {
    LookupSourceActivity(context.Context, netip.Addr) (SourceActivityResponse, error)
}
```

### Source-activity selection and options

`SourceActivitySelection.CandidateIDs` and `SourceActivitySelection.SourceIPs`
are unioned, canonicalized, deduplicated, and sorted. Every selected value must
already exist in the completed candidate result. Ineligible or excluded values
remain visible but do not reach the provider or consume `MaxQueries`.

| `SourceActivityOptions` field | Default | Hard limit |
| --- | ---: | ---: |
| `Selection` | Empty; no lookup | Existing candidate IDs or source IPs only |
| `MaxQueries` | 16 | 64 |
| `MaxConcurrency` | 1 | 4 |
| `LookupTimeout` | 10 seconds | 5 minutes; minimum 1 millisecond |
| `MaxMetrics` | 32 | 256 |
| `MaxThreatFeeds` | 64 | 256 |
| `MaxAssertions` | 16 | 256 |
| `MaxTextBytes` | 2 KiB per field | 64 KiB |
| `MaxTotalTextBytes` | 256 KiB per response | 4 MiB |
| `MaxRetryAfter` | 1 hour | 7 days |
| `Clock` | System time when a provider is used | Supply a `Clock` for reproducible results; empty selection and nil provider do not consult it |

### Source-activity response fields

| Input type and field | What the adapter supplies |
| --- | --- |
| `SourceActivityResponse.Provider` | Required stable provider identity |
| `SourceActivityResponse.Dataset` | Required dataset or contract identity |
| `SourceActivityResponse.EndpointIdentity` | Required configured third-party endpoint identity, not the subject IP |
| `SourceActivityResponse.ReferenceID` | Optional provider reference |
| `SourceActivityResponse.ActivityObserved` | Whether the provider described activity; false is not evidence of safety |
| `SourceActivityResponse.FirstSeen` | Optional provider activity-window start |
| `SourceActivityResponse.LastSeen` | Optional provider activity-window end, not before `FirstSeen` |
| `SourceActivityResponse.UpdatedAt` | Optional provider update time |
| `SourceActivityResponse.ExpiresAt` | Optional evidence expiry |
| `SourceActivityResponse.Metrics` | Bounded provider-described quantities |
| `SourceActivityResponse.ThreatFeeds` | Bounded provider-described memberships |
| `SourceActivityResponse.Assertions` | Optional ASN, network, organization, and country context |
| `SourceActivityResponse.RetryAfter` | Optional scheduling metadata; the library never sleeps or retries |
| `SourceActivityResponse.Truncated` | Whether the adapter deliberately omitted provider data |
| `SourceActivityMetric.Name` | Required metric identity, unique with `Unit` |
| `SourceActivityMetric.Value` | Provider-described non-negative quantity |
| `SourceActivityMetric.Unit` | Required unit; do not invent an undocumented time window |
| `SourceActivityMetric.Semantics` | Optional provider-described meaning |
| `SourceActivityMetric.Sensitivity` | Leave empty; normalization sets restricted sensitivity |
| `SourceActivityThreatFeed.Name` | Required unique provider feed identity |
| `SourceActivityThreatFeed.FirstSeen` | Optional membership-window start |
| `SourceActivityThreatFeed.LastSeen` | Optional membership-window end |
| `SourceActivityThreatFeed.Sensitivity` | Leave empty; normalization sets restricted sensitivity |
| `SourceActivityNetworkAssertion.ASN` | Optional non-zero ASN |
| `SourceActivityNetworkAssertion.ASNName` | Optional provider-supplied name |
| `SourceActivityNetworkAssertion.NetworkPrefix` | Optional valid canonical prefix |
| `SourceActivityNetworkAssertion.Organization` | Optional provider-supplied organization |
| `SourceActivityNetworkAssertion.CountryCode` | Optional ISO 3166-1 alpha-2 code |
| `SourceActivityNetworkAssertion.Sensitivity` | Leave empty; normalization sets restricted sensitivity |

When `ActivityObserved` is false, do not return activity dates, metrics, or
threat-feed memberships. Network assertions and provider update or expiry
metadata may still describe the successful no-activity lookup.

Return `ErrSourceActivityRateLimited` with bounded `RetryAfter`,
`ErrSourceActivityUnavailable` for a supported lookup with no usable response,
or `ErrSourceActivityMalformed` for an unsafe provider response. Preserve
context errors. Do not return provider response bodies as errors or normalized
fields.

The library does not ship a DShield adapter. The
[source-activity guide](source-activity.md) documents current first-party
research and a conservative mapping pattern. `ExampleCollectSourceActivity`
is the compile-checked offline provider example.

## Configure phishing intelligence

Phishing-intelligence correlation is programmatic and offline. It has no
library feed URL, account setting, downloader, parser, file loader, or file
schema. Retrieve and parse licensed data at the application boundary, map only
fields whose provider semantics are understood, then normalize the Go value.

```go
snapshot, err := dmarcgo.NormalizePhishingIntelligenceSnapshot(
    dmarcgo.PhishingIntelligenceSnapshotConfig{
        Provider:      "offline-example",
        Dataset:       "synthetic-snapshot-v1",
        SchemaVersion: "provider-contract-v1",
        CollectedAt:   collectedAt,
        AsOf:          asOf,
        ExpiresAt:     &expiresAt,
        License: dmarcgo.PhishingIntelligenceLicense{
            Name:           "caller-reviewed synthetic terms",
            TermsURI:       "https://provider.example.test/terms",
            CommercialUse:  dmarcgo.PhishingIntelligenceUsageRestricted,
            Redistribution: dmarcgo.PhishingIntelligenceUsageProhibited,
        },
        Indicators: []dmarcgo.PhishingIntelligenceIndicatorConfig{{
            Type:      dmarcgo.PhishingIntelligenceSourceIP,
            Value:     "192.0.2.10",
            State:     dmarcgo.PhishingIntelligenceIndicatorActive,
            FirstSeen: &firstSeen,
            LastSeen:  &lastSeen,
            ProviderConfidence: dmarcgo.PhishingIntelligenceConfidence{
                Available: true,
                Value:     80,
            },
            Category:    "synthetic-phishing-context",
            ReferenceID: "fixture-1",
            Context: dmarcgo.PhishingIntelligenceContext{
                ASNs:         []uint32{64500},
                CountryCodes: []string{"US"},
                Brands:       []string{"Example Brand"},
                Sectors:      []string{"Example Sector"},
            },
        }},
    },
)
```

### Phishing snapshot fields

| `PhishingIntelligenceSnapshotConfig` field | Requirement and meaning |
| --- | --- |
| `Provider` | Required stable provider identity; untrusted data |
| `Dataset` | Required dataset or snapshot identity |
| `SchemaVersion` | Required version of the caller-understood external mapping |
| `CollectedAt` | Required time the application obtained the snapshot |
| `AsOf` | Required provider evidence time; cannot be after `CollectedAt` |
| `ExpiresAt` | Optional snapshot expiry, after `AsOf` |
| `License` | Required caller-reviewed terms metadata |
| `Indicators` | Zero through 100,000 normalized indicators in one snapshot |

At correlation time, at most 32 distinct snapshots and 250,000 total
indicators are accepted. Normalization bounds individual text fields at 4 KiB,
each context list at 1,024 items, and total normalized snapshot text at 32 MiB.

### License, indicator, and context fields

| Input type and field | Requirement and meaning |
| --- | --- |
| `PhishingIntelligenceLicense.Name` | Required caller-reviewed license or terms identity |
| `PhishingIntelligenceLicense.TermsURI` | Optional canonical HTTPS URI without credentials or fragment |
| `PhishingIntelligenceLicense.CommercialUse` | `unknown` by default; `unknown`, `permitted`, `restricted`, or `prohibited` |
| `PhishingIntelligenceLicense.Redistribution` | Same allowed values and default |
| `PhishingIntelligenceLicense.Sensitivity` | Leave empty; normalization sets restricted sensitivity |
| `PhishingIntelligenceIndicatorConfig.Type` | Required `source_ip` or `domain` |
| `PhishingIntelligenceIndicatorConfig.Value` | Required canonicalizable IP or domain for the selected type |
| `PhishingIntelligenceIndicatorConfig.State` | `unknown` by default; `active`, `withdrawn`, or `unknown` |
| `PhishingIntelligenceIndicatorConfig.FirstSeen` | Optional provider observation-window start |
| `PhishingIntelligenceIndicatorConfig.LastSeen` | Optional end, not before `FirstSeen` |
| `PhishingIntelligenceIndicatorConfig.ExpiresAt` | Optional expiry after supplied first/last times |
| `PhishingIntelligenceIndicatorConfig.ProviderConfidence` | Optional availability and 0-through-100 provider value |
| `PhishingIntelligenceIndicatorConfig.Category` | Optional untrusted provider category; never creates a match |
| `PhishingIntelligenceIndicatorConfig.ReferenceID` | Optional untrusted provider reference |
| `PhishingIntelligenceIndicatorConfig.Context` | Optional non-matching context |
| `PhishingIntelligenceConfidence.Available` | False when confidence is absent |
| `PhishingIntelligenceConfidence.Value` | 0 through 100 when available; exactly zero otherwise |
| `PhishingIntelligenceContext.ASNs` | Optional non-zero ASNs; never matching evidence |
| `PhishingIntelligenceContext.CountryCodes` | Optional ISO 3166-1 alpha-2 codes; never matching evidence |
| `PhishingIntelligenceContext.InfrastructureProviders` | Optional untrusted context only |
| `PhishingIntelligenceContext.Brands` | Optional impersonated-brand context only |
| `PhishingIntelligenceContext.Sectors` | Optional sector context only |
| `PhishingIntelligenceContext.Sensitivity` | Leave empty; normalization sets restricted sensitivity |

### Phishing correlation options

| `PhishingIntelligenceOptions` field | Zero-value behavior | Hard limit |
| --- | --- | --- |
| `GeneratedAt` | Latest completed candidate/report-evidence timestamp | Must be representable and not earlier than completed input |
| `StaleAfter` | Disabled | Must not be negative |
| `MaxMatches` | 100,000 | 250,000 |

An exact value is not automatically an active match. Provider state, snapshot
freshness, indicator windows, and the exact report-evidence role remain part of
the result. Context fields never create or strengthen a relation. See
[phishing intelligence](phishing-intelligence.md) for exact matching and the
current OpenPhish research decision. `ExampleCorrelatePhishingIntelligence` is
the compile-checked synthetic workflow.

## Configure jurisdiction context

The simplest supported configuration is the built-in immutable policy:

```go
policy := dmarcgo.BuiltinJurisdictionRiskPolicy()
result, err := dmarcgo.EvaluateJurisdictionContext(
    enrichment,
    policy,
    dmarcgo.JurisdictionContextOptions{},
)
```

The optional priority adjustment is disabled in that example. Enable it only by
setting `EnableReviewPriorityAdjustment: true` and only after the application
has defined how the separate queue hint will be displayed with its limitations.

Custom policies are programmatic inputs. The library has no policy-file loader
or file schema. Construct `JurisdictionRiskPolicyConfig`, normalize it, and
persist the resulting policy ID, version, digest, dates, and sources with the
assessment.

### Jurisdiction policy fields

| `JurisdictionRiskPolicyConfig` field | Requirement and meaning |
| --- | --- |
| `ID` | Required machine-safe policy ID; normalized to lowercase |
| `Version` | Required machine-safe version, up to 64 characters |
| `Name` | Required untrusted display name |
| `Description` | Required untrusted description |
| `EffectiveAt` | Required policy effective time |
| `AsOf` | Required review time, not before `EffectiveAt` |
| `ExpiresAt` | Optional review expiry, after `AsOf` |
| `Sources` | 1 through 16 unique HTTPS provenance sources |
| `Entries` | 1 through 512 unique ISO-country entries |
| `MaxReviewPriorityAdjustment` | 0 through 10 |

| Nested type and field | Requirement and meaning |
| --- | --- |
| `JurisdictionRiskPolicySource.Title` | Required untrusted source title |
| `JurisdictionRiskPolicySource.URI` | Required unique canonical HTTPS URI without credentials or fragment |
| `JurisdictionRiskPolicyEntry.ID` | Leave empty; normalization assigns a stable ID |
| `JurisdictionRiskPolicyEntry.CountryCode` | Required unique real ISO 3166-1 alpha-2 code |
| `JurisdictionRiskPolicyEntry.Tier` | Required machine-safe tier code; built-in constants are available but custom codes are allowed |
| `JurisdictionRiskPolicyEntry.Categories` | 1 through 32 unique machine-safe category codes |
| `JurisdictionRiskPolicyEntry.Reasons` | 1 through 32 unique machine-safe reason codes |
| `JurisdictionRiskPolicyEntry.ReviewPriorityAdjustment` | 0 through the policy maximum |

Individual policy text fields are limited to 2 KiB. Categories, reasons, tier,
policy text, and source titles remain untrusted structured data and never enter
library-generated instructions.

### Jurisdiction evaluation options

| `JurisdictionContextOptions` field | Zero-value behavior |
| --- | --- |
| `GeneratedAt` | Preserve the completed source-enrichment timestamp |
| `EnableReviewPriorityAdjustment` | False; no adjustment |

`ExampleNormalizeJurisdictionRiskPolicy` is the compile-checked complete custom
policy example. `ExampleEvaluateJurisdictionContext` demonstrates evaluation.
See [jurisdiction context](jurisdiction-context.md) for the built-in policy
sources, expiry, tier meanings, and attribution limitations.

## Configure DNS perspectives

DNS perspectives are separate from source-IP enrichment. They disclose only
explicit portfolio and snapshot TXT owner names. Supply:

- `DNSPerspectiveSelection.Names` for exact declared owner names;
- `DNSPerspectiveSelection.Roles` for selected SPF, DKIM, or DMARC roles; and
- a `DNSPerspectiveProvider` that returns independently identified observations.

Names and roles are unioned. An empty selection is invalid for a real provider
call. A nil provider returns a deterministic not-evaluated result and performs
no lookup.

### DNS-perspective options

| `DNSPerspectiveOptions` field | Default | Hard limit |
| --- | ---: | ---: |
| `Selection` | No implicit selection | Declared portfolio/snapshot TXT names only |
| `MaxQueries` | 64 | 256 |
| `MaxConcurrency` | 1 | 4 |
| `LookupTimeout` | 10 seconds | 5 minutes |
| `MaxObservationsPerQuery` | 256 | 1,024 |
| `MaxAnswersPerObservation` | 32 | 256 |
| `MaxTextBytes` | 4 KiB per field | 64 KiB |
| `MaxTotalTextBytes` | 1 MiB per query | 8 MiB |
| `MaxRetryAfter` | 1 hour | 7 days |
| `Clock` | System time when a provider is used | Supply for reproducible collection; nil provider does not consult it |

### DNS-perspective response fields

| Input type and field | What the adapter supplies |
| --- | --- |
| `DNSPerspectiveResponse.Provider` | Required stable provider identity |
| `DNSPerspectiveResponse.Dataset` | Required dataset or contract identity |
| `DNSPerspectiveResponse.ReferenceID` | Optional provider reference |
| `DNSPerspectiveResponse.Observations` | Bounded independently identified perspectives |
| `DNSPerspectiveResponse.RetryAfter` | Optional bounded scheduling metadata |
| `DNSPerspectiveResponse.Truncated` | Whether the adapter omitted provider data |
| `DNSPerspectiveProviderObservation.PerspectiveID` | Required unique stable identity within one response |
| `DNSPerspectiveProviderObservation.Perspective` | Optional untrusted display or country label |
| `DNSPerspectiveProviderObservation.Status` | Optional untrusted provider status |
| `DNSPerspectiveProviderObservation.Outcome` | `success`, `no_answer`, `failed`, `rate_limited`, `malformed`, `unavailable`, or `canceled` |
| `DNSPerspectiveProviderObservation.Answers` | Present only for `success`; at least one answer |
| `DNSPerspectiveAnswer.Fragments` | TXT character-string fragments when available |
| `DNSPerspectiveAnswer.FragmentsAvailable` | Whether fragment boundaries are known |
| `DNSPerspectiveAnswer.Joined` | Complete TXT value; must equal joined fragments when both are supplied |
| `DNSPerspectiveAnswer.Sensitivity` | Leave empty; normalization sets operational sensitivity |

Return `ErrDNSPerspectiveRateLimited`, `ErrDNSPerspectiveUnavailable`, or
`ErrDNSPerspectiveMalformed` for stable provider outcomes, and preserve context
errors. The library does not ship a DShield adapter because current research did
not establish usable TXT behavior for authentication owner names. See
[DNS perspectives](dns-perspectives.md) for agreement semantics and disclosure
limits. `ExampleCollectDNSPerspectives` is the compile-checked offline example.

## Outputs and storage

Optional context remains a separate completed result. Use the applicable native
writer:

- `WriteSourceEnrichmentOutput`;
- `WriteSourceActivityOutput`;
- `WritePhishingIntelligenceOutput`;
- `WriteJurisdictionContextOutput`; or
- `WriteDNSPerspectivesOutput`.

Use `BuildAnalysisOutput` only when the common automation or agent envelope is
needed. Choose public, operational, or restricted redaction for the destination
and inspect truncation metadata. Direct result accessors contain operational or
restricted evidence and are not a disclosure-safe serialization path.

Serialization never invokes an adapter, reloads a snapshot, refreshes a policy,
or contacts a source address. Persist input and result digests, versions,
collection/evaluation times, provider or policy provenance, freshness, and
incomplete states so later runs cannot silently reinterpret older evidence.

## New-adopter checklist

- [ ] Start with threat candidates or a completed DNS snapshot, not raw provider data.
- [ ] Choose only the optional stage that answers the application question.
- [ ] Confirm whether the stage is offline or discloses selected values to a third party.
- [ ] Keep credentials, retrieval, parsing, caching, scheduling, and retention in the application.
- [ ] Use an offline dataset where practical.
- [ ] Never contact, ping, scan, resolve, or open a connection to the subject source IP.
- [ ] Allowlist third-party destinations and bound raw responses before decoding.
- [ ] Supply a reproducible clock where timestamps affect persisted results.
- [ ] Preserve stable sentinel errors and discard provider-controlled error bodies.
- [ ] Treat absence, staleness, conflicts, and non-matches as unknown context, not safety.
- [ ] Keep provider text in structured data and out of prompts or generated instructions.
- [ ] Use the destination-appropriate output redaction and inspect truncation.
- [ ] Test adapters with synthetic offline fixtures; do not make live provider calls in CI.

## Next references

- [Source enrichment](source-enrichment.md)
- [Source activity](source-activity.md)
- [Phishing intelligence](phishing-intelligence.md)
- [Jurisdiction context](jurisdiction-context.md)
- [DNS perspectives](dns-perspectives.md)
- [Operations and troubleshooting](operations-and-troubleshooting.md)
- [Automation workflows](automation-workflows.md)
