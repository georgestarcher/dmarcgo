# DNS snapshot collection

DNS collection is explicit and separate from report parsing, portfolio loading,
record evaluation, and output serialization. `CollectDNSSnapshot` queries only
the complete SPF, DKIM, and DMARC TXT owner names already present in a normalized
`Portfolio`. It never discovers selectors, loads reports, reads environment
variables, or uses a hidden resolver.

```go
resolver := dmarcgo.DNSMessageResolver{
	Server:     "192.0.2.53:53",
	ResolverID: "organization-recursive-dns",
}

snapshot, err := dmarcgo.CollectDNSSnapshot(
	ctx,
	portfolio,
	resolver,
	dmarcgo.DNSCollectionOptions{
		MaxConcurrency: 4,
		MaxAttempts:    2,
		QueryTimeout:   5 * time.Second,
		FailurePolicy:  dmarcgo.DNSFailureCollectAll,
		Clock:          dmarcgo.ClockFunc(time.Now),
	},
)
```

The collection plan deduplicates shared owner names and retains references to
every entity, domain, and record type that requested each name. Observations and
references have deterministic ordering. TXT records retain their DNS fragment
boundaries and a joined value; RRset order is canonicalized because DNS does not
define it. Set `Clock` when the snapshot timestamp must be reproducible.

## Resolver choices

- `DNSMessageResolver` sends DNS messages to one explicit server. It preserves
  positive TTL, RCODE, authoritative versus recursive response source, CNAME
  paths, SOA evidence, and RFC 2308 negative-cache TTL. The server is required;
  the network defaults to UDP and retries a truncated response over TCP.
- `NetTXTResolver` adapts a caller-supplied `net.Resolver`. The standard API
  exposes TXT strings but not their original fragments, TTL, RCODE, CNAME path,
  authority, or negative-cache SOA. Those fields remain explicitly unavailable.
  `Resolver` is required; pass `net.DefaultResolver` explicitly when desired.
- Applications may implement `TXTResolver` for another DNS client, recorded
  evidence, or deterministic tests. Implementations must honor cancellation and
  must not invent unavailable evidence.

## Failure and retry behavior

Concurrency, per-attempt timeout, attempts, retry delay, and failure policy are
bounded by `DNSCollectionOptions`. Timeouts and temporary failures are retryable;
NXDOMAIN, NODATA, malformed responses, and cancellation are terminal.

The DNS-message adapter preserves each TXT RR's received TTL. If a configured
resolver returns different TTLs within one RRset, the snapshot uses the lowest
TTL for the RRset while retaining the per-record values, following RFC 2181
Section 5.2 for clients configured to use that resolver. This produces usable
evidence on the first response and does not trigger a retry.
Before concurrent fan-out, collection resolves the first deterministic planned
name serially. A resolver-wide configuration error therefore stops collection
after one call and returns no snapshot evidence.

`DNSFailureCollectAll` records every terminal outcome and returns a complete
snapshot with value-safe diagnostics. `DNSFailureFailFast` stops remaining
work after the first failed observation and resolves serially so no new query
can begin after that failure. It returns the immutable partial
snapshot with an error matching `ErrDNSCollectionFailed`. Parent cancellation
returns a partial snapshot with an error matching the context error. Timeout or
cancellation observations never contain invented TTL evidence.

Snapshots do not cache or refresh themselves. Applications own persistence,
refresh policy, scheduling, and any cache. Later parsing and health stages must
consume the supplied snapshot rather than recollecting DNS.

When an application deliberately needs supplemental remote resolver-consistency
context, it may pass this completed snapshot to
[`CollectDNSPerspectives`](dns-perspectives.md) with an explicit disclosure
selection and caller-supplied provider. That optional branch does not replace
or mutate the snapshot and never changes DNS health or maturity.
