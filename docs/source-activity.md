# Optional source-activity context

`CollectSourceActivity` is an explicit, optional collection stage for adding
third-party activity context to selected source addresses that already exist in
a completed `ThreatCandidateResult`. It is not reputation scoring, malicious
attribution, or an enforcement decision.

The stage is provider neutral. `dmarcgo` does not ship a DShield client,
credentials, endpoint, scheduler, cache, or background updater.

## Safe workflow

1. Complete report evidence, DNS/report correlation, and threat-candidate
   scoring.
2. Let a human or caller policy explicitly select candidate IDs or canonical
   source IPs.
3. Decide whether disclosing those addresses and a contact-bearing User-Agent
   to a third party is permitted.
4. Supply a bounded `SourceActivityProvider` and an injected clock.
5. Review the returned activity, time-window, freshness, conflict, truncation,
   and partial-failure states alongside the original DMARC evidence.

Empty selection performs no provider call. A nil provider is a supported
no-clock, no-network result. Selected addresses that are excluded, not review
eligible, or expected-sender-only remain visible as `not_eligible` and are not
sent to the provider.

```go
result, err := dmarcgo.CollectSourceActivity(
    ctx,
    threatCandidates,
    optionalEnrichment,
    provider,
    dmarcgo.SourceActivityOptions{
        Selection: dmarcgo.SourceActivitySelection{
            CandidateIDs: []dmarcgo.AnalysisID{candidate.ID},
        },
        MaxQueries:     1,
        MaxConcurrency: 1,
        LookupTimeout:  10 * time.Second,
        Clock:          clock,
    },
)
```

The provider receives each selected canonical IP at most once, in deterministic
order. The library never retries, sleeps, polls, follows redirects, looks up
additional addresses, or contacts the subject IP.

## Provider contract

`SourceActivityProvider.LookupSourceActivity` is the only side-effect boundary.
A network-backed implementation may contact only its explicitly configured
third-party service. It must:

- honor the supplied context and per-call timeout;
- enforce a raw response-size limit before decoding;
- restrict redirect destinations or disable redirects;
- validate response status and content type;
- keep credentials and the contact-bearing User-Agent caller-owned;
- return stable sentinel errors instead of response or error-body text;
- preserve `Retry-After` in `SourceActivityResponse.RetryAfter`; and
- never ping, scan, resolve, connect to, or otherwise probe the subject IP.

Normalized responses have separate typed collections for metrics, threat-feed
memberships, and network assertions. They do not overload `IPMetadataAssertion`
or use an untyped map. Field, item, total-text, query, concurrency, timeout, and
retry-after limits are enforced again at the library boundary.

Provider, dataset, endpoint, reference, metric, feed, organization, and network
strings are untrusted data. They remain structured fields and never enter
library-generated titles, explanations, recommendations, actions, or
instructions.

## DShield research gate

Current first-party material was reviewed on **2026-07-14**:

- [ISC/DShield API documentation](https://isc.sans.edu/api/)
- [ISC/DShield data-feed documentation](https://isc.sans.edu/feeds_doc.html)

The documented IP endpoint is `/api/ip/{address}` and the API documentation
describes JSON selection with `?json`. The documentation describes `count` as
packets blocked from the address and `attacks` as unique destination addresses.
It also shows first/last/updated dates, AS/network/country context, comments,
and threat-feed fields. It does not establish a stable rolling window,
deduplication, or sampling contract for every count, so an adapter must retain
provider-described units and semantics rather than inventing them.

The current service documentation also says:

- the API is best effort and may return `429`;
- clients should honor `Retry-After` and stop for the documented interval;
- a contact-bearing custom User-Agent is required and default tool User-Agents
  may be blocked;
- bulk feeds are preferred for large address sets;
- there is currently no API authentication requirement, but that can change;
- the API page identifies a CC BY-NC-SA 4.0 data license, while the feed page
  separately says not to resell the data and permits other commercial use;
- static feeds should not be downloaded more than once per hour; and
- attribution should identify SANS Technology Institute, Internet Storm Center,
  and `https://isc.sans.edu`.

Those first-party statements require context-specific review rather than a
library interpretation of whether a particular deployment is commercial or a
redistribution. Callers must review the current terms before deployment. They
own attribution, license compliance, caching, commercial-use analysis,
redistribution, service availability, and any authentication change.

## Why there is no built-in DShield adapter

Bounded compatibility research on 2026-07-14 did not establish a sufficiently
stable address-family contract for a built-in adapter:

- a reserved documentation IPv4 address returned a threat-feed membership,
  demonstrating that a match can collide with non-malicious or unrelated
  context; and
- a reserved documentation IPv6 address returned a response whose address
  field and activity data did not coherently describe the requested address.

These observations are not claims about the service as a whole. They are a
release-design reason to keep transport and live response interpretation in a
caller-owned adapter until current first-party documentation establishes the
necessary semantics. Committed tests use synthetic provider responses only.

An application adapter should initially restrict itself to address families
and fields it has independently validated, reject any response that does not
identify the requested canonical address, and map only documented fields into
`SourceActivityResponse`.

A conservative current DShield adapter pattern is:

- construct exactly one `/api/ip/{escaped-address}?json` request against a
  configured HTTPS origin;
- disable redirects or require every redirect to remain on that exact allowed
  origin;
- set the caller-chosen contact-bearing User-Agent;
- bound the response body before JSON decoding and reject HTML or unrelated
  content types rather than retaining an error body;
- require the returned `number` to equal the requested canonical address;
- map documented non-null `count` to a metric whose unit states packets and
  whose semantics state the provider-described total;
- map documented non-null `attacks` to a separate metric whose unit states
  unique destination addresses;
- map `mindate`, `maxdate`, and `updated` only after strict timestamp parsing;
- map `as`, `asname`, `network`, and `ascountry` to a network assertion without
  treating it as preferred ownership truth;
- map each bounded `threatfeeds` entry to structured membership with its own
  supported first/last dates; and
- omit comments, abuse contacts, undocumented fields, and ambiguous values
  unless a later adapter contract defines their necessity and handling.

On `429`, parse either supported `Retry-After` form into a duration, return
`ErrSourceActivityRateLimited`, and do not retry. Map a valid empty response to
`ActivityObserved: false`; map transport/service absence to
`ErrSourceActivityUnavailable`; and map invalid identity, content, or schema to
`ErrSourceActivityMalformed`. Provider error strings and bodies must not be
returned as normalized values or copied into logs.

## Interpretation

A successful lookup means only that the selected third-party provider returned
context for the address. Activity membership does not prove that the address:

- sent malicious email;
- controlled the SMTP system;
- hosted phishing content;
- was compromised; or
- is currently assigned to the same operator.

Absence is not evidence of safety. Shared hosting, cloud egress, NAT,
forwarders, mailing lists, VPNs, proxies, reassignment, compromise, anycast,
sampling, and non-overlapping time windows can all limit the signal.

The result never changes candidate score, confidence, severity, eligibility,
exclusion, promotion, or recommended usage. It never authorizes blocking,
quarantine, takedown, notification, or escalation. Fixed findings recommend
human review, monitoring, or evidence retention only.

## Time and failure semantics

Provider first/last activity bounds are compared with the candidate's aggregate
report-period bounds as `overlaps`, `before_reports`, `after_reports`, or
`unknown`. These bounds are not exact message timestamps and do not establish
causation.

Expiry produces `stale`; provider timestamps after collection produce `future`;
contradictory network assertions produce `conflicting` without choosing a
preferred value. Rate-limited, unavailable, malformed, failed, timed-out, and
canceled lookups remain explicit. A successful lookup for one IP is retained
when another IP fails.

## Privacy and output

Selected source addresses are disclosed to the caller-selected service and may
be logged under that service's policies. The required contact-bearing User-Agent
can identify the consuming person or organization. Callers must make that
disclosure decision explicitly and must not embed maintainer contact details,
credentials, or private candidate lists in reusable library code.

Source activity is operational or restricted evidence. Output integration and
cross-profile redaction belong to the later output-contract work. Existing
reporting, serialization, and export builders never invoke this stage or
perform a lookup.
