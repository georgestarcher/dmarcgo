# Authentication-record parsing

Authentication-record parsing is a pure stage after DNS collection:

```text
Portfolio -> CollectDNSSnapshot -> ParseAuthenticationRecords -> DNS health
```

`ParseAuthenticationRecords(snapshot)` consumes only immutable TXT evidence
already present in a `DNSSnapshot`. It performs no DNS queries, report parsing,
filesystem access, enrichment, or time lookup. The resulting
`DNSAuthenticationResult` preserves the snapshot digest and observation time,
uses deterministic ordering and identifiers, and returns defensive copies.

The direct `ParseSPFRecord`, `ParseDKIMKeyRecord`, and
`ParseDMARCPolicyRecord` helpers accept supplied strings for focused validation.
`DMARCPolicyDiscoveryNames` computes the bounded RFC 9989 tree-walk owner names
without resolving them.

## Result states

Record sets distinguish:

- `valid`: syntax and supported semantics are usable;
- `missing`: the snapshot proves NXDOMAIN/NODATA/not-found or contains no
  candidate record;
- `malformed`: the textual representation cannot be parsed safely;
- `invalid`: a recognized construct violates the applicable standard;
- `unsupported`: a mechanism, key type, service, or flag is not implemented;
- `weak`: usable evidence has a deprecated, revoked, testing, or cryptographic
  weakness;
- `conflicting`: more than one candidate SPF or DMARC policy record exists;
- `indeterminate`: collection did not supply conclusive evidence.

Unknown extensibility tags are preserved as data and ignored where the
standards require that behavior. Parser diagnostics contain stable codes and
library-generated messages; record-controlled notes, URI text, modifiers, and
other values never become instructions or explanatory prose.

## SPF

The SPF parser follows RFC 7208 and preserves ordered qualifiers, mechanisms,
modifiers, arguments, CIDRs, include/redirect relationships, and unknown
modifiers. It counts the direct DNS-querying terms (`include`, `a`, `mx`,
`ptr`, `exists`, and `redirect`) against the limit of ten. When all referenced
SPF records are present in the supplied snapshot, it also computes expanded
lookup evidence and detects include/redirect cycles.

No additional A, AAAA, MX, PTR, or TXT queries occur. Consequently, void-lookup
counts remain explicitly unavailable, and macro-dependent relationships make
expanded lookup evidence indeterminate. The deprecated `ptr` mechanism is
retained with a weakness diagnostic.

## DKIM

The DKIM key parser follows RFC 6376 tag-list behavior, preserves original key
and note data, recognizes RSA and RFC 8463 Ed25519 keys, detects revoked keys,
and validates decoded public-key shape. It accepts the RFC PKCS#1 key form and
the SubjectPublicKeyInfo DER form used by major providers. RSA keys shorter than 1024 bits are
invalid under RFC 8301; 1024-bit keys are accepted as weak, and 2048 bits or
more is the recommended baseline.

This stage never handles private keys or verifies message signatures. Selector
and signing-domain metadata are derived only from the configured
`selector._domainkey.domain` owner name.

## DMARC

The DMARC parser implements the current RFC 9989 policy vocabulary, including
`p`, `sp`, `np`, `adkim`, `aspf`, `t`, `psd`, `rua`, `ruf`, and `fo`.
`pct`, `ri`, and `rf` are treated as removed legacy tags, not current policy.
Unknown registered-future tags are preserved and ignored. A missing or invalid
`p` with at least one valid `rua` destination is represented as RFC 9989
monitoring fallback rather than invented enforcement.

Reporting destinations remain untrusted data. Syntax validation does not
authorize external report delivery and does not prove that a destination has
published the required external-reporting authorization record.

RFC 9989 tree walking is not public-suffix-list lookup. The pure discovery
helper returns at most eight candidate `_dmarc` names, including the exact
Author Domain lookup and the bounded parent walk. Only a later explicit DNS
collection can obtain evidence for those names.

## Internationalized domains and limits

Domain inputs are normalized to DNS A-labels consistently with RFC 8616. Raw
record strings remain available as evidence. Each direct parser rejects values
larger than 65,535 bytes, and all graph work is bounded by the supplied
snapshot; parsing never expands macros or follows network dependencies.

## References

- [RFC 7208: SPF](https://www.rfc-editor.org/rfc/rfc7208.html)
- [RFC 6376: DKIM](https://www.rfc-editor.org/rfc/rfc6376.html)
- [RFC 8301: DKIM cryptographic updates](https://www.rfc-editor.org/rfc/rfc8301.html)
- [RFC 8463: Ed25519-SHA256 for DKIM](https://www.rfc-editor.org/rfc/rfc8463.html)
- [RFC 8616: Email authentication for internationalized mail](https://www.rfc-editor.org/rfc/rfc8616.html)
- [RFC 9989: DMARC](https://www.rfc-editor.org/rfc/rfc9989.html)
