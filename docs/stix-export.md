# STIX 2.1 observed-data export

`BuildSTIXBundle` is a pure, standards-native export of a completed
`ThreatCandidateResult` and an optional matching `SourceEnrichmentResult`.
It performs no report parsing, DNS, enrichment, policy evaluation, filesystem
access, clock lookup, TAXII submission, or other network activity.

The default representation is evidence, not a verdict. A DMARC authentication
failure is exported as an IP address Cyber-observable Object (SCO) referenced
by `observed-data`. It is not automatically represented as an Indicator and
never becomes a safe-to-block instruction.

## Object mapping

| dmarcgo input | STIX 2.1 representation |
| --- | --- |
| Canonical source IPv4 or IPv6 | `ipv4-addr` or `ipv6-addr` SCO |
| Candidate report-period bounds and dual-failure count | `observed-data.first_observed`, `last_observed`, and `number_observed` |
| Candidate confidence | `observed-data.confidence` |
| Candidate and evidence identifiers, domains, entities, counts, review state, and enrichment state | Versioned dmarcgo property extension |
| Enriched ASN assertions | `autonomous-system` SCOs and IP `belongs_to_refs` |
| Optional review limitation | `note` containing only fixed library text |
| Explicit caller promotion | `indicator` plus a `based-on` relationship to the observation |

One Observed Data object represents each candidate. Its first and last times
remain report-period bounds, not exact per-message event times. Repeated report
observations are not expanded into duplicate objects: the candidate retains its
source evidence IDs and the aggregate dual-failure message count.

STIX 2.1 limits `number_observed` to 999,999,999. The exporter returns a typed
`STIXObservationCountError` when a candidate exceeds that limit rather than
truncating, capping, splitting, or silently changing the evidence.

## Explicit Indicator promotion

Indicators appear only when the caller supplies a `STIXIndicatorPromotion` for
a review-eligible, non-excluded candidate. The caller must choose `ValidFrom`
and may choose a later `ValidUntil`. The generated pattern contains only the
candidate's canonical IP address.

Promotion is an export decision. It does not change the candidate score,
confidence, exclusion, recommendation, `PromotionEligible` field, or any
upstream result. The resulting Indicator retains fixed review-oriented labels
and text and still does not assert malicious ownership or authorize blocking.

## Producer identity, timestamps, and deterministic IDs

The caller supplies a producer name and may select an identity class. Producer
names remain untrusted data in the Identity object and never enter generated
notes, labels, descriptions, patterns, or instructions.

`GeneratedAt` defaults to the latest supplied result timestamp; it never uses
the system clock. Set `STIXProducer.CreatedAt` to the producer identity's real,
stable creation time when the same Identity ID should be reused across exports.
If it is zero, it defaults to `GeneratedAt` and therefore describes an
export-specific identity. The selected marking is also part of the producer
object identity, so changing TLP intentionally produces a different Identity
ID.

IP and ASN SCO identifiers use the STIX 2.1 UUIDv5 namespace and only the
standard ID-contributing properties (`value` or `number`). Golden tests include
the OASIS deterministic examples. Other objects and bundles use a private
dmarcgo UUIDv5 namespace over their complete semantic identity so repeated
exports with the same inputs are byte-for-byte reproducible.

STIX 2.1 recommends UUIDv4 for those non-SCO objects but does not require it.
The deterministic UUIDv5 choice is deliberate and causes advisory UUID-version
warnings in the OASIS validator; the bundle remains schema-valid. These IDs are
stable correlation keys, not cryptographic secrets or collision-resistant
security tokens.

## Markings and privacy

`STIXTLPWhite`, `STIXTLPGreen`, `STIXTLPAmber`, and `STIXTLPRed` emit the fixed
TLP marking definitions specified by STIX 2.1 and apply the selected marking to
the producer and exported evidence objects. A zero value emits no marking.
Those fixed STIX definitions use the TLP vocabulary incorporated into STIX 2.1;
callers must not infer that selecting one satisfies every recipient's current
sharing policy.

STIX export intentionally retains raw source IPs and can retain organization
domains, entity IDs, ASN context, and provider provenance. It is an operational
exchange format and has no public-redaction mode. Apply an appropriate marking,
recipient authorization, transport protection, retention policy, and any
caller-owned pre-export minimization before sharing a bundle outside the
operational trust boundary.

Provider names, reference IDs, organization names, domains, and other retained
values are untrusted structured data. Only absolute HTTPS provenance sources
become clickable `external_references.url` values; other sources remain
non-clickable identifiers where possible. No provider or report text enters
generated descriptions, notes, recommendations, labels, patterns, or
instructions.

Optional jurisdiction context is not converted into a STIX threat assertion.
It remains a separate coarse, policy-dependent review signal with the
limitations documented in [Versioned jurisdiction context](jurisdiction-context.md).

## Extension and validation

Every bundle includes an `extension-definition` for the dmarcgo evidence
mapping. Its version-1 JSON Schema is embedded and available through
`STIXEvidenceExtensionSchema`; the repository copy is
[`schemas/stix/dmarcgo-evidence/v1.json`](../schemas/stix/dmarcgo-evidence/v1.json).
The schema validates the complete STIX object containing one of three strict
extension shapes: candidate evidence, ASN context, or a candidate reference.

`ValidateSTIXBundle` validates the complete subset emitted by this package,
including object shapes, identifiers, timestamps, counts, extension data,
markings, ordering, and intra-bundle references. It is intentionally not a
general parser for arbitrary third-party STIX extensions. `WriteSTIXBundle`
validates before writing and propagates writer and short-write failures.

The golden fixture is also checked with the pinned official OASIS
[`stix2-validator`](https://github.com/oasis-open/cti-stix-validator) in CI.
Run the local checks with:

```shell
make stix-check
make stix-validator-check # requires stix2-validator 3.3.1
```

The mapping follows [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html),
including current `object_refs` rather than the deprecated embedded Observed
Data `objects` dictionary. STIX is kept standards-native and is not wrapped in
the dmarcgo automation/agent envelope. Applications may report export metadata
or errors separately without changing the STIX payload.
