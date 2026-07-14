# ThreatConnect v3 indicator payload export

`BuildThreatConnectIndicatorPayloads` is a pure final transformation from a
completed `ThreatCandidateResult` and optional matching
`SourceEnrichmentResult` into individual ThreatConnect v3 Indicator request
bodies. It performs no HTTP request, authentication, owner discovery, lookup,
retry, rate-limit handling, persistence, or direct communication with an
observed source IP.

The output contract is the current first-party
[ThreatConnect v3 Indicators API](https://docs.threatconnect.com/en/latest/rest_api/v3/indicators/indicators.html),
reviewed July 13, 2026. The relative submission endpoint is exposed as
`ThreatConnectIndicatorsEndpoint` (`/api/v3/indicators`). Applications own the
base URL, credentials, authorization, transport, audit logging, response
handling, and any later update or deletion.

## Explicit selection and safe defaults

The encoder creates no payload unless the caller explicitly supplies at least
one candidate or ASN selection. An Address selection must name a
review-eligible, non-excluded threat candidate. An ASN selection must name a
rollup in the matching completed enrichment result and that rollup must retain
source-IP, candidate, and assertion evidence.

Every payload defaults to:

- `active: false`
- `privateFlag: true`
- no ThreatConnect Confidence Rating
- no Threat Rating
- a fixed Description Attribute that says the value is selected for human
  review and does not assert malicious activity or authorize blocking
- a fixed Source Attribute with value `dmarcgo`
- fixed `DMARC Aggregate`, `Human Review Required`, and `dmarcgo` Tags

ThreatConnect does not document a generic Indicator review-state field. The
encoder therefore represents the review boundary through inactive/private
defaults and the fixed human-review Tag. A caller can override the active or
privacy values only by setting the corresponding pointer explicitly.

## Vendor mapping

| dmarcgo selection | ThreatConnect type | Required type field | Value |
| --- | --- | --- | --- |
| IPv4 or IPv6 threat candidate | `Address` | `ip` | Canonical unzoned address text |
| Enriched ASN rollup | `ASN` | `AS Number` | `ASN` plus the decimal number, for example `ASN64500` |

The capitalized, space-containing `AS Number` property is intentional and is
validated exactly. Unsupported candidate address types return
`ErrUnsupportedThreatConnectIndicatorType` and a
`ThreatConnectUnsupportedTypeError` that retains the stable candidate ID and
unsupported normalized type without including the source address in the error
message.

`firstSeen` and `lastSeen` are the earliest and latest aggregate-report period
bounds for the selected evidence. They are not exact message timestamps.
`observations` is the candidate's dual-authentication-failure message count; an
ASN payload uses the checked sum across its selected rollup candidates. Counts
are never silently capped.

`externalDateExpires`, when supplied, must be later than the deterministic
export generation time. `GeneratedAt` defaults to the latest completed-input
timestamp and never reads the system clock.

## Confidence and rating are different decisions

The dmarcgo candidate confidence value describes how strongly the available
evidence supports review. It is not confidence that an address or ASN is
malicious. For that reason the encoder omits ThreatConnect `confidence` by
default. A caller may either:

- provide an explicit value from 1 through 100; or
- explicitly set `MapEvidenceConfidence` to copy the selected evidence
  confidence.

Those choices are mutually exclusive. ASN confidence mapping uses the lowest
candidate evidence confidence in the rollup.

The ThreatConnect `rating` field is a Threat Rating, so dmarcgo never derives it
from candidate score, severity, jurisdiction context, or any enrichment value.
A caller must explicitly choose an integer from 1 through 5.

## Owner and tenant metadata

`ThreatConnectOwner` accepts either a positive `ID` or a non-empty `Name`, never
both. When both are omitted, the payload omits owner fields. According to the
vendor contract, a later API call then uses the API user's Organization.
Applications should set an owner explicitly whenever that implicit destination
is not intended.

Tenant-supported Attributes, Tags, ATT&CK technique IDs, and Security Labels
can be added through `ThreatConnectIndicatorSettings`. Metadata collections are
bounded to 64 entries each, deduplicated, and sorted deterministically.
Description and Source are emitted
as Attributes because the vendor documents the similarly named top-level
fields as read-only. Attribute types remain tenant-dependent; the encoder does
not perform an OPTIONS request or claim that a custom Attribute type exists in
the target instance. See the first-party documentation for
[Indicator Attributes](https://docs.threatconnect.com/en/latest/rest_api/v3/indicator_attributes/indicator_attributes.html),
[Tags](https://docs.threatconnect.com/en/latest/rest_api/v3/tags/tags.html), and
[Security Labels](https://docs.threatconnect.com/en/latest/rest_api/v3/security_labels/security_labels.html).

## Duplicate and update semantics

ThreatConnect documents Indicators as unique within an owner. A POST for an
Indicator that already exists in the destination owner updates the existing
Indicator instead of guaranteeing creation of a second object. Consequently:

- an encoded payload is a request value, not proof that a new Indicator will be
  created;
- owner selection is part of the uniqueness and update boundary;
- callers must review overwrite/update consequences before submission; and
- callers must retain and inspect the API response rather than inferring the
  result from encoder success.

The library deliberately does not simulate server state, perform duplicate
lookups, or add idempotency claims beyond deterministic encoding.

## Validation, evidence references, and lossy fields

`ValidateThreatConnectIndicatorPayload` validates the exact supported request
shape, field ranges, required type-specific property, timestamps, safe fixed
metadata, deterministic ordering, and source-reference consistency.
`WriteThreatConnectIndicatorPayload` validates and writes one request body plus
a newline; it does not create a vendor batch envelope.

`ThreatConnectIndicatorPayload.Source()` returns defensive export metadata that
is deliberately excluded from the native vendor JSON. It includes:

- mapping version and deterministic generation time;
- threat-candidate and optional source-enrichment digests;
- candidate, observation, report-evidence, correlation-finding, and enrichment
  assertion IDs;
- source IPs and per-IP enrichment status; and
- stale and conflicting source-IP lists.

Applications can retain that metadata beside a submission result or map
selected IDs into tenant-specific Attributes. dmarcgo does not invent vendor
Attribute types for provenance. Provider names, organizations, countries,
jurisdiction context, candidate score adjustments, exclusions, and raw report
text are not copied into the request automatically.

## Untrusted-data and privacy boundary

ThreatConnect output is operational and unredacted. Address payloads contain a
raw source IP; ASN source metadata retains its contributing source IPs. Callers
own recipient authorization, minimization, transport security, retention, and
any redaction performed outside this standards-native contract.

Caller-supplied Description, Source, Attribute, Tag, technique, owner, and
Security Label strings are untrusted tenant data. The encoder validates length,
UTF-8, and control characters, but it does not treat those strings as
instructions. No report-provided domain, provider text, enrichment metadata,
or other untrusted evidence is interpolated into generated descriptions, Tags,
headlines, actions, or guidance.

An encoded candidate remains authentication-failure evidence selected for
review. It is not a compromise claim, malicious attribution, automatic block
decision, or authorization to contact the source IP.

## Caller-owned submission sequence

1. Review the completed candidate and optional enrichment evidence.
2. Select only the candidate IDs and ASN numbers intended for the destination.
3. Choose owner, privacy, activity, expiration, Confidence Rating, Threat
   Rating, and tenant metadata explicitly.
4. Build and locally validate every payload.
5. Retain each payload's `Source()` metadata with the review record.
6. Submit each JSON body through the application's authenticated client to
   `ThreatConnectIndicatorsEndpoint`.
7. Respect server rate limits and permissions, and inspect whether the response
   reports creation or update.
8. Preserve response IDs and audit evidence in caller-owned storage.

`ThreatConnectAPIContractVersion` identifies the vendor contract and
`ThreatConnectExportVersion` identifies the dmarcgo mapping. They are versioned
independently of the Go module so a future vendor-contract update can be made
explicit.
