# Anomali ThreatStream payload export

`BuildThreatStreamPayloads` is a pure final transformation from a completed
`ThreatCandidateResult` into tenant-native JSON request bodies. It does not
discover a tenant contract, access credentials, call Anomali, parse a response,
poll an import job, approve an import, retry, or contact an observed source IP.

The default is deliberately conservative: every selected source must already
be review eligible and not excluded, the caller must supply an exact `itype`,
and the tenant contract must define a private classification and conservative
review defaults. A reviewed-import contract must also define a pending-review
state.

## Contract research and why capabilities are mandatory

The public contract was reviewed on 2026-07-14 against current first-party
Anomali material:

- the [Anomali SDK marketplace](https://www.anomali.com/marketplace/sdks),
  which confirms supported integration and SDK surfaces;
- Anomali's [Importing Observables](https://www.anomali.com/resources/videos/importing-observables)
  resource;
- the current [Anomali Copilot import workflow](https://www.anomali.com/blog/anomali-copilot-the-next-level-of-ai-powered-security-operations),
  which describes import sessions that are reviewed and approved; and
- Anomali's older [direct API import example](https://www.anomali.com/blog/importing-intelligence-data-directly-from-ios-12),
  which illustrates confidence, threat type, tags, and classification but is
  not treated as a current request schema.

Those sources confirm the product concepts but do not publish one current,
complete, tenant-independent ingestion schema with stable endpoint, field,
`itype`, limit, and response definitions. The public
[`api.threatstream.com`](https://api.threatstream.com/) root also does not
provide that contract without tenant access. Consequently, dmarcgo does not
publish a global ThreatStream API-contract constant or hard-code mirrored
integration documentation.

Before constructing `ThreatStreamTenantCapabilities`, obtain the exact request
and response contract from the target tenant's current first-party
documentation or support channel. Give that contract an application-owned
version and update it deliberately when the tenant changes. Encoder success
means only that the request matches the supplied capability; it is not evidence
that Anomali accepted, created, deduplicated, approved, or published anything.

## Supported request shapes

Each capability describes exactly one variant.

### Direct observable

`ThreatStreamDirectObservable` emits one flat JSON object per selected
candidate. `ItemsField` must be empty and every declared field uses
`ThreatStreamFieldRoot`.

Direct ingestion is an explicit caller decision. The payload still defaults to
the tenant-confirmed private classification and conservative confidence,
severity, TLP, tags, and expiration. If the direct contract supports a review
state, declare that field and a pending value; otherwise both remain empty.

### Reviewed import

`ThreatStreamReviewedImport` emits one request per selected candidate. The
canonical source address and tenant `itype` appear in one item under the exact
tenant `ItemsField`. Other fields may be placed at the root or item scope as
declared. A review-state field and tenant-confirmed pending value are required.

One observable per request avoids inventing unverified tenant batching,
partial-acceptance, or per-item error semantics. An application may submit
requests in a bounded caller-owned sequence after its own review and transport
policy.

## Tenant capability checklist

`ThreatStreamTenantCapabilities` fails closed unless it declares:

- an application-owned `ContractVersion`;
- one variant and a relative endpoint path without credentials or query data;
- exact, non-colliding JSON property names and field scopes;
- every allowed IP `itype` and the IPv4/IPv6 families for which it is valid;
- the inclusive confidence range;
- supported severity values and any explicit dmarcgo-to-tenant mappings;
- supported classification, TLP, and review-state values;
- tag and expiration encodings;
- maximum string, tag-count, and complete-payload sizes;
- a conservative confidence and severity, private classification, TLP, tags,
  expiration duration, and where applicable pending-review state; and
- response contract version, synchronous or asynchronous mode, and any
  tenant-confirmed identifier, status, and accepted-status fields.

Endpoints are relative paths because the application owns the destination
host, TLS policy, authentication, routing, and tenant boundary. Query strings
are rejected so credentials and mutable request state cannot be embedded in a
reusable capability.

The response assumptions are returned defensively through
`ThreatStreamPayload.ResponseAssumptions()`. The library does not parse a live
response or decide whether a status means success. Applications must validate
the actual response against their tenant documentation and retain it with their
submission audit record.

## Safe mapping behavior

Every selection supplies a candidate ID and exact tenant `itype`. The builder
rejects an `itype` that is absent from the capability or is not valid for the
candidate's address family.

The tenant's review confidence is not the same as dmarcgo evidence confidence.
The conservative tenant value is used by default. Set
`MapEvidenceConfidence` to true only after the application deliberately decides
that the tenant field has compatible meaning. An explicit confidence value and
evidence mapping are mutually exclusive.

Candidate severity is also a review-priority signal rather than a malicious
verdict. It is not mapped unless `MapCandidateSeverity` is true and the tenant
capability contains an exact mapping for that candidate severity. An explicit
severity and automatic mapping are mutually exclusive.

Classification, TLP, review state, tags, and expiration are caller policy.
Every string value must be in the supplied allowlist where applicable. Default
and selection tags are trimmed, deduplicated, and sorted. Expiration must be
after the payload generation time. Unsupported values return
`ErrUnsupportedThreatStreamCapability` and a
`ThreatStreamUnsupportedCapabilityError`; invalid or conflicting settings
return `ErrInvalidThreatStreamExportOptions`.

## Native JSON and defensive provenance

`json.Marshal(payload)` and `WriteThreatStreamPayload` emit only fields declared
by the tenant contract. They do not wrap the request in a dmarcgo automation or
agent envelope. `ValidateThreatStreamPayload` reconstructs the exact native
shape from the immutable contract and settings, checks all configured limits,
and rejects tampering or mismatched provenance.

`ThreatStreamPayload.Source()` separately retains:

- dmarcgo mapping version;
- tenant request and response contract versions;
- variant, relative endpoint, and generation time;
- threat-candidate digest, candidate ID, tenant `itype`, and canonical source
  IP;
- original report-period first/last bounds; and
- observation, report-evidence, and correlation-finding references.

Keep this metadata with the caller's request and response audit record. Native
payloads are intentionally operational and unredacted; they contain raw source
IP addresses and tenant-controlled metadata.

## Untrusted data and AI consumers

Tenant field names, `itype` values, classifications, TLP values, review states,
tags, endpoints, response fields, and all source evidence are untrusted data.
They are never interpolated into library-generated explanations,
recommendations, actions, headlines, or instructions. A prompt-like tag or
classification remains a JSON value and has no authority over an AI consumer.

Do not wrap a native request in an AI prompt and let the model decide whether
to submit it. Keep candidate selection, tenant capability approval,
authentication, transport, response validation, import approval, and any later
distribution behind application-owned authorization.

## Synthetic fixture contract

The golden files
`testdata/golden/threatstream_direct_fixture_contract_v1.json` and
`testdata/golden/threatstream_reviewed_fixture_contract_v1.json` validate the
dmarcgo mapping against synthetic contract versions
`fixture-direct-2026-07` and `fixture-reviewed-2026-07`. Their field names,
endpoints, `itype`, limits, and response assumptions are test data, not a claim
about any real Anomali tenant or release.

Use `ExampleBuildThreatStreamPayloads` for a compile-checked reviewed-import
example. Replace every example capability value with the exact contract
confirmed for the target tenant before using the output.

## Caller-owned submission sequence

1. Complete report evidence, correlation, and threat-candidate scoring.
2. Review a candidate and confirm that it remains review eligible and not
   excluded.
3. Obtain the current request/response contract from the destination tenant.
4. Construct and independently validate one versioned capability.
5. Select an exact tenant IP `itype` and review-oriented metadata.
6. Build and validate the native payload offline.
7. Retain `Source()` and `ResponseAssumptions()` with the audit record.
8. Apply application-owned destination, credential, rate-limit, duplicate,
   retry, and approval policy.
9. Submit through a caller-owned authenticated client.
10. Validate and retain the actual response; for asynchronous imports, poll
    only according to the tenant contract and application limits.

No step authorizes automatic blocking or malicious attribution from DMARC
authentication failure alone.
