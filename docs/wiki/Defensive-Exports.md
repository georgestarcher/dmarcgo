# Defensive exports

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v3. The linked repository guides and Go documentation define behavior.

## Who this is for

Applications that have completed review evidence and need deterministic offline
payloads for standards-based or vendor-specific defensive systems.

## Question this workflow answers

How can explicitly selected, reviewed evidence be represented as STIX 2.1,
ThreatConnect v3, MISP, or Anomali ThreatStream payloads without coupling the
library to credentials or submission?

## Inputs

Completed threat candidates, optional matching enrichment where supported,
explicit selections, caller-provided timestamps and destination capabilities,
and every vendor lifecycle field required by the selected builder.

## Activity and side effects

All export builders are pure. They perform no HTTP, credentials, destination
discovery, duplicate search, capability lookup, publication, polling, retry,
or subject-IP access.

## Encoder versus service client

These are local encoders, not authenticated service integrations:

| Output | What `dmarcgo` produces | Secret used by `dmarcgo` | What the application must supply before submission |
| --- | --- | --- | --- |
| STIX 2.1 | A local standards-native bundle | None | A chosen destination, markings and sharing policy, authenticated transport if applicable, review, and response handling |
| ThreatConnect v3 | Local Indicator request bodies for explicit selections | None | Base URL, credentials, permissions, duplicate and update policy, HTTP client, review, submission, and audit storage |
| MISP | Local Attribute request bodies or a complete offline Event body | None | Instance capabilities, target Event context where required, base URL, API key, warning-list and duplicate policy, review, submission, and response handling |
| Anomali ThreatStream | Local request bodies under a caller-declared tenant capability | None | Validated tenant contract, base URL, credentials, endpoint and type selections, HTTP client, review, polling where required, and audit storage |

Encoder success proves only that the local payload satisfies the selected
builder contract. Never place destination credentials in a capability object,
payload, portfolio, evidence result, or reusable documentation fixture.

## Starting APIs

- `BuildSTIXBundle`
- `BuildThreatConnectIndicatorPayloads`
- `BuildMISPAttributePayloads` or `BuildMISPEventPayload`
- `BuildThreatStreamPayloads`

## Outputs

Standards-native or vendor-native JSON plus separate defensive provenance
metadata where documented. Defaults remain review oriented: no automatic
promotion, IDS use, correlation, publication, or active indicator state.

## What this does not prove

Successful encoding does not prove destination acceptance, uniqueness,
authorization, threat status, or safe-to-block policy. The application owns
review, submission, response handling, audit storage, and later lifecycle.

## Sensitive data

Export payloads are operational and unredacted. They can contain raw source IPs,
organization context, and evidence identifiers. The caller owns minimization,
markings, recipient authorization, distribution, transport, and retention.

## Safe next steps

Validate against the target instance's current contract, review each explicit
selection, preserve the builder's source metadata, submit through a separate
authorized component, and record the response without feeding it back as an
instruction.

## Authoritative references

- [STIX 2.1 export](https://github.com/georgestarcher/dmarcgo/blob/main/docs/stix-export.md)
- [ThreatConnect export](https://github.com/georgestarcher/dmarcgo/blob/main/docs/threatconnect-export.md)
- [MISP export](https://github.com/georgestarcher/dmarcgo/blob/main/docs/misp-export.md)
- [ThreatStream export](https://github.com/georgestarcher/dmarcgo/blob/main/docs/threatstream-export.md)
