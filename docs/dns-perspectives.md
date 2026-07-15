# Optional DNS perspective collection

`CollectDNSPerspectives` is an explicit, supplemental collection stage for
comparing selected authentication TXT owner names across resolver perspectives
reported by a caller-supplied service. It does not replace the authoritative
and trusted-recursive evidence in `DNSSnapshot`, and it never changes DNS
health scores, grades, coverage, or maturity.

Use this stage when the question is: “Do several remote resolver perspectives
currently return the same answer set for these exact monitored names?” Do not
use it to decide that a record is broken, to measure a country-wide outage, or
to infer exact DNS propagation timing.

New adopters can compare this provider interface with the other optional
context forms in
[optional context configuration](optional-context-configuration.md). DNS
perspectives disclose selected record names; they are not source-IP enrichment
and are never enabled by a portfolio alone.

## Explicit workflow

```text
normalized Portfolio + completed DNSSnapshot
        + explicit owner-name or SPF/DKIM/DMARC role selection
        + caller-supplied DNSPerspectiveProvider
        -> CollectDNSPerspectives
        -> immutable DNSPerspectiveResult
```

The planner takes names only from the normalized portfolio and its matching
completed snapshot. `DNSPerspectiveSelection.Names` and
`DNSPerspectiveSelection.Roles` are unioned, canonical duplicate names are
removed, and the resulting plan is sorted. The initial planner emits `TXT`
queries only. It never discovers or derives MX, NS, A, AAAA, CNAME, PTR, SOA,
SRV, CAA, DNSKEY, or RRSIG queries.

The function cannot accept report-derived source addresses, reporter strings,
extension values, or arbitrary domains as query inputs. It performs no PTR,
WHOIS, geolocation, reputation, source enrichment, or direct source-IP
activity.

```go
result, err := dmarcgo.CollectDNSPerspectives(
    ctx,
    portfolio,
    snapshot,
    provider,
    dmarcgo.DNSPerspectiveOptions{
        Selection: dmarcgo.DNSPerspectiveSelection{
            Roles: []dmarcgo.DNSRecordType{
                dmarcgo.DNSRecordSPF,
                dmarcgo.DNSRecordDKIM,
                dmarcgo.DNSRecordDMARC,
            },
        },
        Clock: dmarcgo.ClockFunc(func() time.Time { return collectedAt }),
    },
)
```

The application supplies the `DNSPerspectiveProvider`. Its adapter owns HTTPS,
authentication, contact identity, raw response-size enforcement, redirect
policy, content-type validation, response parsing, and destination control.
The library supplies each selected name/type query at most once per invocation.

Passing a nil or typed-nil provider is a supported no-op. It returns a stable
`not_evaluated` result using the snapshot timestamp and does not consult the
configured clock or perform network access. A disclosure selection is still
required so the result records the exact scope that would have been evaluated.

## Provider contract

```go
type DNSPerspectiveProvider interface {
    LookupDNSPerspective(
        context.Context,
        DNSPerspectiveQuery,
    ) (DNSPerspectiveResponse, error)
}
```

An adapter returns a stable provider and dataset identity plus zero or more
independently identified observations. `PerspectiveID` must be unique within
one response. A country or display label belongs in `Perspective`; it is
untrusted descriptive data and is not used as the unique identity.

Adapters normalize their service into these outcomes:

- `success`: one or more complete TXT answers are available;
- `no_answer`: the perspective returned no TXT answer;
- `failed`: a lookup failed without a more specific stable classification;
- `rate_limited`: the service refused the request for rate reasons;
- `malformed`: the provider response could not be safely interpreted;
- `unavailable`: the provider supports the request but supplied no usable
  perspective evidence; and
- `canceled`: the caller or lookup context canceled the request.

The adapter may return `ErrDNSPerspectiveRateLimited`,
`ErrDNSPerspectiveUnavailable`, or `ErrDNSPerspectiveMalformed` instead of
inventing provider-independent meanings from error text. Provider error text
is never retained. A positive `RetryAfter` is rounded up to seconds and capped
for caller-owned scheduling; the library never sleeps or retries.

Provider, dataset, reference, perspective, status, TXT fragments, and joined
answers are untrusted structured data. They never enter generated finding or
diagnostic prose. Adapters must not interpret these values as instructions.

## Agreement and completion

Answer fingerprints are deterministic hashes of the sorted, deduplicated
joined TXT answer set. TXT fragment boundaries remain available separately
when the adapter can preserve them.

- Resolver `agreement` requires at least two successful perspectives with the
  same answer-set fingerprint.
- One successful perspective is `unknown`, not agreement.
- Any different successful answer-set fingerprint is `disagreement`.
- Snapshot agreement compares each successful remote answer set with the
  supplied snapshot only when that snapshot observation was successful.
- No successful remote answer or unavailable snapshot evidence is `unknown`.

`DNSPerspectiveResult.Complete()` means every selected query reached a terminal
outcome. It does not mean that every perspective succeeded. A failed, malformed,
unavailable, rate-limited, or per-query timed-out request can still be a
complete terminal result. Caller cancellation before all queries finish makes
the result incomplete and returns a partial result with an error that preserves
`context.Canceled` or `context.DeadlineExceeded` through `errors.Is`.

Successful answer disagreement produces neutral, library-controlled review
findings. It is supplemental consistency evidence only. The stage does not
mutate the portfolio or snapshot and has no input through which it could mutate
`DNSHealthResult`.

## Request and evidence limits

Zero-valued options select conservative defaults:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Selected queries | 64 | 256 |
| Concurrent provider calls | 1 | 4 |
| Per-query timeout | 10 seconds | 5 minutes |
| Observations per query | 256 | 1,024 |
| Answers per observation | 32 | 256 |
| Bytes per untrusted text field | 4 KiB | 64 KiB |
| Total normalized text per query | 1 MiB | 8 MiB |
| Retained retry-after value | 1 hour | 7 days |

The total normalized-text limit is defense in depth after the adapter has
parsed a response. It cannot replace a raw HTTP body limit in a network-backed
adapter. There are no automatic retries, backoff sleeps, polling loops, caches,
global clients, or global credentials.

## Privacy and disclosure

Opting in discloses each selected public DNS owner name to the configured
provider, the recursive resolvers it selects, and potentially the
authoritative DNS infrastructure reached by those resolvers. DKIM selector
names may reveal providers or operating choices even though DNS records are
public. Do not select private operational names unless that disclosure is
authorized.

All normalized perspective evidence is classified as operational. Later native
output integration is owned by the cross-mode output work; output builders must
serialize a completed result only and must never initiate perspective lookups.

## DShield research decision

Research was performed on **2026-07-14** against these first-party sources:

- [DShield DNS Looking Glass](https://www.dshield.org/tools/dnslookup/index.html)
- [ISC/DShield API documentation](https://isc.sans.edu/api/)
- [DShield data-feed and use documentation](https://isc.sans.edu/feeds_doc.html)

The looking-glass page described three selected resolvers per country and a
`GLOBAL` grouping for Cloudflare, Google, and Quad9. Its browser client called
the following form, although the surrounding API prose documented a shorter
hostname-only form:

```text
https://isc.sans.edu/api/dnslookup/{hostname}/{record-type}?json
```

Bounded compatibility requests found that the JSON response can be an array of
country/status/answer rows. Country labels may repeat, and the response did not
expose a stable resolver identifier, TTL, DNS RCODE, negative-cache SOA,
authenticated DNSSEC validation, or authoritative status. A country label
therefore describes only the provider-selected perspective; it cannot support
a country-wide availability claim.

More importantly for this feature, bounded `TXT` checks returned empty arrays
for ordinary public names, and an authentication owner name containing
`_dmarc` was rejected as a malformed hostname. The observed record-type
behavior was not sufficient to collect the exact SPF, DKIM, and DMARC TXT owner
names required by this stage. The library therefore does **not** ship a DShield
adapter. The provider-neutral interface and offline fixtures remain available
for a caller-owned service with a verified TXT contract.

The ISC API documentation described the service as best effort, requested a
non-default contact-bearing User-Agent, warned that requests may receive HTTP
429, and required callers to obey `Retry-After` or pause before trying again.
It also documented attribution, licensing, commercial-use, redistribution, and
resale constraints. Any caller-owned DShield experiment must re-check the live
terms, identify itself appropriately, issue only explicitly authorized bounded
requests, and own caching or scheduling policy.

The repository contains one skipped-by-default, explicitly enabled compatibility
test that makes exactly one request for the reserved `example.com` name. It
requires both `DMARCGO_DSHIELD_LIVE=1` and a contact-bearing
`DMARCGO_DSHIELD_USER_AGENT`. It is research instrumentation, not a supported
adapter or CI dependency.

## Operational interpretation

- A mismatch can result from cache state, propagation, split behavior,
  provider parsing, or different observation times.
- A no-answer or timeout from one perspective is incomplete coverage, not
  proof that users in that country cannot resolve the record.
- Current remote answers do not prove what a receiver saw during an older DMARC
  report period.
- Remote agreement does not prove every sender is configured, every message
  authenticates, or the domain is free of abuse.
- Confirm important changes through trusted recursive and authoritative DNS
  evidence with TTL and negative-cache context before modifying DNS.
