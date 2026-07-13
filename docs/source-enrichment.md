# Optional source IP and ASN enrichment

`EnrichThreatCandidates` is an explicitly invoked, post-scoring stage. It
accepts a completed `ThreatCandidateResult` and a caller-supplied `IPEnricher`.
The library ships no reputation provider, credentials, network client, remote
dataset, global cache, or automatic lookup behavior.

Threat-candidate scoring remains fully usable without enrichment. Passing a
nil enricher returns a deterministic `source_enrichment` result with
`evaluation.state: not_evaluated`; it does not consult a clock or initiate any
network activity.

## Security boundary

Observed source IPs may belong to hostile infrastructure. An `IPEnricher`
implementation must never ping, scan, connect to, or otherwise send traffic to
the subject IP. A network-backed implementation may contact only a third-party
service that the application explicitly selected and configured. Offline or
local datasets are preferred where practical.

PTR/reverse-DNS lookup is not part of `IPEnricher`. Although PTR normally sends
traffic to DNS infrastructure rather than the subject host, recursive and
authoritative DNS logs can disclose investigative interest. Applications that
need PTR data must implement it as a separate, explicit opt-in capability and
document that observability. Supplying an `IPEnricher` does not enable PTR.

The library calls an enricher only for candidates that are both
`ReviewEligible` and not excluded. It deduplicates canonical IPv4 and IPv6
addresses, sorts them deterministically, and supplies each address at most once
per invocation. There are no automatic retries.

## Interfaces and caller ownership

The minimal interface is context-aware:

```go
type IPEnricher interface {
    EnrichIP(context.Context, netip.Addr) (IPMetadata, error)
}
```

An implementation may also implement `BatchIPEnricher`. The library then makes
one batch call with the complete sorted, deduplicated address set. A batch
implementation owns and must bound any concurrency within that call. Missing,
duplicate, or unrequested batch results are treated as invalid provider
responses rather than guessed or silently preferred.

Callers own cross-invocation caching. A caching adapter can implement
`IPEnricher` or `BatchIPEnricher` around an offline database or remote service.
The library keeps no process-global cache and does not persist enrichment.

`SourceEnrichmentOptions` controls:

- `MaxConcurrency` for individual lookups; the default is 4 and the maximum is
  256;
- `LookupTimeout`; the default is 5 seconds;
- `FailurePolicy`, either `collect_all` (default) or `fail_fast`; and
- a `Clock` for reproducible result timestamps and freshness evaluation.

Timeouts and cancellation depend on implementations honoring the supplied
context. A provider that ignores context can prevent its own call from
returning promptly.

## Metadata and provenance

`IPMetadata` contains one or more `IPMetadataAssertion` values. Each assertion
may preserve:

- ASN number and name;
- a canonical network prefix that contains the subject IP;
- organization;
- optional two-letter country code as coarse context only;
- provider and source/dataset identifiers;
- lookup and expiration times;
- optional numeric confidence; and
- a provider reference ID.

Exact geolocation is intentionally unsupported. A country code is coarse,
provider-supplied context and must not be interpreted as the location of a
person, device, or operator.

Provider names, source names, organization names, reference IDs, and other
metadata strings are untrusted data. The library normalizes and retains them in
structured fields but never interpolates them—or provider error text—into
generated explanations, recommendations, or instructions. It also rejects
oversized assertion sets, invalid UTF-8, and control-bearing or oversized text.
All source enrichment is classified as restricted data.

Assertion IDs are deterministic. Assertions are sorted and exact duplicates
are collapsed. Freshness is evaluated against the result timestamp:

- `fresh` means the expiration time is later than the result timestamp;
- `stale` means the expiration time has passed; and
- `unknown` means the provider supplied no expiration time.

Multiple non-zero ASN values or multiple country codes are retained and marked
as conflicts. The stage does not select a winner.

## Candidate outcomes

Every input candidate remains present in `SourceEnrichmentResult` with one
status:

- `success`: current or freshness-unknown, non-conflicting metadata exists;
- `unavailable`: the provider returned no metadata or
  `ErrIPMetadataUnavailable`;
- `stale`: every assertion has expired;
- `conflicting`: assertions disagree on ASN or country code;
- `failed`: the provider failed or returned invalid metadata;
- `timeout` or `canceled`: the lookup did not complete;
- `not_eligible`: the candidate was not review-eligible or was excluded; or
- `not_evaluated`: no enricher was supplied.

For `success`, the enriched candidate copy replaces
`threat_candidate.unenriched` with an explicit enrichment-confidence cap and
recomputes the complete cap sequence and severity. When every assertion
provides confidence, the lowest provider value is the maximum; provider values
can remove the prior unenriched cap or impose a lower ceiling, but they never
change the candidate's threat score. If any assertion omits confidence, the
original profile's conservative unenriched maximum remains in effect under a
new `threat_candidate.enrichment_confidence_unknown` code. The stage does not
change review eligibility, exclusions, recommended usage, or evidence. For
every status, `PromotionEligible` remains false. Stale, conflicting,
unavailable, and failed metadata do not increase confidence.

The original `ThreatCandidateResult` is never mutated.

## Partial failure and diagnostics

`collect_all` converts independent failures into per-candidate statuses and
value-safe diagnostics, then returns the completed result without copying
provider error text. `fail_fast` cancels outstanding work after the first
provider failure and returns an immutable partial result plus
`ErrSourceEnrichmentFailed`. Caller cancellation and deadline errors are
available through `errors.Is` on `SourceEnrichmentError`.

`Complete` is false when fail-fast cancellation, caller cancellation, or an
invalid/missing batch response prevented planned addresses from producing
ordinary terminal responses. The partial result still retains every input
candidate.

## ASN views

`SourceEnrichmentResult.ASNs` groups normalized ASN assertions without hiding
the underlying evidence. Every ASN view retains:

- source IPs;
- candidate and assertion IDs;
- names, organizations, prefixes, countries, and providers;
- source IPs backed only by stale assertions; and
- source IPs with conflicting assertions.

If one source has conflicting ASN assertions, it appears in every asserted ASN
view and in each view's `ConflictingSourceIPs` collection. An ASN view is
context for review, not attribution, reputation, or a blocking recommendation.

## Offline example

```go
enriched, err := dmarcgo.EnrichThreatCandidates(
    ctx,
    threatCandidates,
    offlineEnricher,
    dmarcgo.SourceEnrichmentOptions{
        MaxConcurrency: 4,
        Clock:          fixedClock,
    },
)
```

The executable `ExampleEnrichThreatCandidates` uses only an in-memory synthetic
fixture. Production applications must make provider selection, credentials,
network policy, caching, retention, and disclosure controls explicit.
