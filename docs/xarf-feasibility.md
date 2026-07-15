# XARF v4 feasibility decision

This document records the Phase 16B research decision for issue #67. It is not
an XARF implementation guide and does not add an export mode.

## Decision

`dmarcgo` does **not** build XARF reports from DMARC aggregate evidence.

DMARC aggregate reports describe authentication results for counted streams
over a reporting period. They do not describe one abuse incident or one
captured message. The current XARF `messaging/spam` contract requires
message- and connection-specific values that aggregate reports do not contain.
Choosing another XARF category would misstate authentication-review evidence as
spam, phishing content, compromise, or threat intelligence.

An application that independently captures a specific message and all required
incident fields can use the official XARF implementation directly. Adding a
second partial XARF builder here would duplicate that implementation while
encouraging unsafe field inference.

## Research baseline

The first-party sources were reviewed on **2026-07-15**.

- The current specification release is
  [XARF v4.2.0](https://github.com/xarf/xarf-spec/releases/tag/v4.2.0),
  commit `37820dace8ac6a9495d33886abc9f94e3d1691fe`.
- The release's
  [core schema](https://github.com/xarf/xarf-spec/blob/v4.2.0/schemas/v4/xarf-core.json),
  [master schema](https://github.com/xarf/xarf-spec/blob/v4.2.0/schemas/v4/xarf-v4-master.json),
  and
  [`messaging/spam` schema](https://github.com/xarf/xarf-spec/blob/v4.2.0/schemas/v4/types/messaging-spam.json)
  use JSON Schema Draft 2020-12.
- The specification and schemas are available under the
  [MIT license](https://github.com/xarf/xarf-spec/blob/v4.2.0/LICENSE).
- The first-party
  [conformance guide](https://github.com/xarf/xarf-spec/blob/v4.2.0/docs/implementation-guide.md)
  requires generators to create a UUIDv4 report ID, supply an incident
  timestamp, validate required type-specific fields, and self-validate output.
- The current first-party Go implementation is
  [`xarf-go` v1.1.1](https://github.com/xarf/xarf-go/releases/tag/v1.1.1).
  It bundles the v4.2.0 schemas and already parses, validates, and generates
  XARF reports.
- The first-party
  [parser conformance suite](https://github.com/xarf/xarf-parser-tests) provides
  language-independent validation fixtures. A future application integration
  should use that suite in addition to the pinned schema.
- The current
  [email-transport guide](https://xarf.org/docs/email-transport/) describes an
  unofficial `Feedback-Type: xarf` extension to ARF plus a JSON attachment. It
  also states that ordinary ARF receivers can reject or ignore that extension.
- The [Abusix overview](https://abusix.com/xarf-abuse-reporting-standard/) and
  the [deprecated v3 repository](https://github.com/abusix/xarf) are useful
  historical context, not the pinned v4.2.0 contract.

The XARF website still contains pages and examples labeled `4.0.0`, while the
specification repository and first-party libraries identify `4.2.0` as the
current release. This decision therefore pins the tagged v4.2.0 schemas rather
than treating changing website examples as normative.

The specification describes semantic versioning, but the core schema accepts
any `4.x.y` version string. Applications must therefore bind validation to the
exact schema release they support rather than assuming every v4 minor version
has identical fields.

The project owner's historical
[`send_xarf`](https://github.com/georgestarcher/send_xarf) repository predates
v4. It is not a source for current field mappings, transport behavior,
recipient policy, or security assumptions.

## Field mapping

The table uses the standard v4.2.0 schema rules. Recommended fields become
required only in XARF strict validation, but their absence can still make an
abuse report operationally weak.

| XARF value | v4.2.0 role | DMARC aggregate availability | Decision |
| --- | --- | --- | --- |
| `xarf_version` | Required schema version | Not report evidence | A dedicated XARF implementation can pin it. |
| `report_id` | Required UUID; the specification says UUIDv4 | Unavailable | Caller randomness is required. A deterministic dmarcgo evidence digest is not a UUIDv4 report ID. |
| `timestamp` | Required time of the abuse incident | Unavailable | Report-period bounds are not an exact message or incident time. |
| `reporter` | Required complainant identity and contact | Unavailable | The DMARC report producer is not automatically the XARF complainant. |
| `sender` | Required transmitting identity and contact | Unavailable | Must come from the application authorized to send the complaint. |
| `source_identifier` | Required abuse-source identifier | Source IP is available | A source IP identifies an observed sending path, not malicious ownership or intent. |
| `category` / `type` | Required abuse classification | Unavailable | Authentication failure does not establish `messaging/spam` or another abuse type. |
| `protocol` | Required for `messaging/spam` | Only the aggregate email context is known | It does not make the observation an individual SMTP incident. |
| `source_port` | Required when `protocol` is `smtp` | Unavailable | Never invent port 25 or another value; the observed client port can differ. |
| `smtp_from` | Required when `protocol` is `smtp` | Unavailable | Aggregate SPF identities are domains, not complete envelope-sender mailboxes. |
| `subject` | Recommended | Unavailable | Aggregate reports contain no message subject. |
| `smtp_to` | Recommended | Unavailable | Aggregate reports contain no envelope recipient. |
| `message_id` | Recommended | Unavailable | Aggregate reports contain no Message-ID. |
| `evidence` | Recommended structured evidence | Only aggregate observations are available | An aggregate row cannot stand in for the captured message or connection evidence described by the messaging schema. |

DMARC row counts are message counts for an aggregated authentication stream.
They are not XARF `recipient_count`, and they do not prove that messages were
unsolicited. Report-period first/last bounds are likewise not an incident
timestamp.

Standard schema validation can omit recommended evidence, subject, recipient,
and Message-ID fields. That does not solve the mapping: SMTP still requires
`source_port` and `smtp_from`, and a truthful `messaging/spam` classification
still requires independent evidence that the message was spam. Syntactic
validity is not responsible attribution.

## Why other XARF types do not fit

- `messaging/spam` and `messaging/bulk_messaging` assert message-abuse
  classifications and require SMTP data unavailable in aggregate reports.
- `content/phishing` describes hosted phishing content and requires a URL.
  Aggregate reports contain no URL or message body.
- `infrastructure/compromised_server` requires a compromise method. Failed
  authentication does not prove compromise.
- `reputation/threat_intelligence` requires a threat type and represents threat
  intelligence sharing. A review-only candidate is not a malicious reputation
  assertion.
- Connection categories describe observed network attacks against a target,
  not an aggregate email-authentication stream.

Unknown extension fields are allowed by the core schema, but extensions cannot
repair missing required fields or make an inaccurate category truthful.

## Interoperability and lifecycle limits

The v4.2.0 JSON schema defines payload validity, not a complete abuse-desk
lifecycle. It does not discover or authorize a recipient, prove that a
recipient accepts XARF, define a correction or retraction transaction, deliver
the report, or define an acknowledgment response. The core `report_id` provides
an identifier that an application can use for tracking and deduplication, but
the application still owns duplicate and correction policy.

The current email guide uses an unofficial ARF feedback type and explicitly
requires receiver support. It leaves bounces, retries, alternate contacts, and
delivery monitoring to the sender. A schema-valid JSON document is therefore
not evidence that a real abuse desk will accept or act on it.

This is enough interoperability for an application with a confirmed recipient
contract to use a first-party XARF library. It is not enough to justify a
generic dmarcgo export from aggregate evidence.

## Optional context does not close the gap

Threat-candidate score, source enrichment, source activity, jurisdiction
context, and phishing-intelligence correlation remain review context. None of
them proves that a particular message was unsolicited, that a source system was
compromised, or that the observed source controlled the asserted identity.

Expected-sender configuration findings and approved security simulations are
not abuse-report candidates. Provider recognition never authorizes or condemns
a sender. Conflicting, stale, or non-overlapping intelligence cannot be used to
manufacture missing per-message evidence.

## What a separate reporting application would need

A caller that has independently confirmed a specific incident would need, at a
minimum:

- an explicitly authorized reporter and transmitting sender identity;
- a caller-generated UUIDv4 report ID, kept separate from stable evidence IDs;
- an exact incident timestamp;
- the exact source IP and observed SMTP source port;
- the complete SMTP envelope sender and the recipient information required by
  recipient policy;
- the message subject, Message-ID, and privacy-reviewed headers or RFC 822
  evidence appropriate to the recipient;
- a truthful abuse category based on independent evidence, not a dmarcgo score;
- a current pinned XARF schema and conforming validator; and
- caller-owned recipient discovery, authorization, legal/privacy review,
  deduplication, correction, delivery, bounce handling, rate limiting,
  retention, and audit records.

At that point the application already owns the material facts and can use
`xarf-go` or another current first-party implementation. `dmarcgo` should remain
an input to human review, not the component that converts aggregate ambiguity
into an abuse allegation.

## Revisit criteria

Reconsider this decision only if a later XARF release defines a type that
truthfully represents aggregate email-authentication observations without
invented per-message fields, or if a separately approved dmarcgo scope adds
privacy-reviewed per-message evidence. Any reconsideration must re-pin the
current schemas, verify real recipient interoperability, preserve the
no-submission boundary, and repeat the attribution and false-positive review.
