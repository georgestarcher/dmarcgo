# MISP event and attribute export

`BuildMISPAttributePayloads` and `BuildMISPEventPayload` are pure,
vendor-native transformations of a completed `ThreatCandidateResult`. They do
not parse reports, run analysis, resolve DNS, perform enrichment, read a clock
or filesystem, access credentials, call MISP, search or create an event, query
warning lists, retry a request, or contact an observed source IP.

The default representation is a review-only MISP Attribute, not a confirmed
indicator of compromise. DMARC authentication failure does not establish
malicious ownership, compromise, intent, or that an address is safe to block.

## Reviewed upstream contract

The mapping was reviewed on 2026-07-13 against the first-party MISP 2.5
sources at commit `f63f85106b9235b7109aeaba9393dc30f86a4e5a`:

- the [MISP 2.5 OpenAPI definition](https://github.com/MISP/MISP/blob/f63f85106b9235b7109aeaba9393dc30f86a4e5a/app/webroot/doc/openapi.yaml);
- the instance [type/category definitions](https://github.com/MISP/MISP/blob/f63f85106b9235b7109aeaba9393dc30f86a4e5a/describeTypes.json);
- the normal [Event add path](https://github.com/MISP/MISP/blob/f63f85106b9235b7109aeaba9393dc30f86a4e5a/app/Controller/EventsController.php) and [sharing-group authorization model](https://github.com/MISP/MISP/blob/f63f85106b9235b7109aeaba9393dc30f86a4e5a/app/Model/SharingGroup.php);
- the official [MISP automation guide](https://www.circl.lu/doc/misp/automation/); and
- the official PyMISP [`MISPAttribute` and `MISPEvent` models](https://github.com/MISP/PyMISP/blob/ff8834fcaf7592bf5c275c7035dc2dd9f687758f/pymisp/mispevent.py) and [submission methods](https://github.com/MISP/PyMISP/blob/ff8834fcaf7592bf5c275c7035dc2dd9f687758f/pymisp/api.py).

`MISPAPIContractVersion` identifies the reviewed upstream API family.
`MISPExportVersion` independently identifies this library's mapping. A future
MISP contract change does not silently reinterpret an existing mapping.

## Target-instance capabilities and explicit direction

MISP type/category combinations are instance data. Fetch the target instance's
`/attributes/describeTypes` response in the application, review it, and pass
the exact accepted pairs through `MISPInstanceCapabilities`. The library never
does that discovery itself.

```go
mapping := dmarcgo.MISPAttributeMapping{
    Type:     dmarcgo.MISPAttributeTypeIPSource,
    Category: "Network activity",
}
capabilities := dmarcgo.MISPInstanceCapabilities{
    ContractVersion:   "2.5.42",
    AttributeMappings: []dmarcgo.MISPAttributeMapping{mapping},
}
```

Every selection must choose `ip-src` or `ip-dst` explicitly. The encoder does
not guess direction from the fact that DMARC called the address a source. An
exact type/category pair absent from the supplied capability set returns
`ErrUnsupportedMISPAttributeMapping` and a structured
`MISPUnsupportedMappingError`. The untrusted category is retained in the typed
error but not interpolated into its error message.

At review time, the upstream default type definitions allowed both IP types in
`Payload delivery`, `Network activity`, and `External analysis`, with
`Network activity` as their default category. Those values are context, not a
built-in allowlist; use the actual destination instance's response.

## Existing event requests

`BuildMISPAttributePayloads` requires one explicit `MISPEventReference` using a
canonical positive numeric ID or UUID. Each payload's `Endpoint()` returns
`/attributes/add/{event identifier}`. The event is neither searched for nor
validated remotely, and the body does not duplicate an `event_id` field that
could disagree with the path.

The review-oriented Attribute defaults are:

| Field | Existing-event default | Reason |
| --- | --- | --- |
| `to_ids` | `false` | Keep authentication evidence contextual rather than enabling IDS export. |
| `disable_correlation` | `true` | Avoid adding unreviewed shared-provider or indirect-mail addresses to automatic correlation. |
| `distribution` | `0` | Limit the new Attribute to the submitting organization unless the caller deliberately broadens it. |
| `comment` | Fixed library review limitation | Do not turn report or provider text into a generated narrative. |
| `first_seen`, `last_seen` | Candidate report-period bounds | Preserve the available observation window without claiming per-message timestamps. |
| `timestamp` | Caller-controlled `GeneratedAt` | Make output reproducible without consulting the clock. |
| `uuid` | Deterministic UUIDv5 | Make repeated encoding for the same event, mapping, and IP stable. |
| `Tag` | Omitted | Do not invent tenant tags or classifications. |

The caller may deliberately override distribution, sharing group, comment,
tags, observation window, `to_ids`, and correlation behavior. Distribution `4`
requires a canonical positive numeric sharing-group ID. A sharing-group ID is
rejected for every other distribution. Although the generic MISP OpenAPI type
also permits a UUID, normal Event and Attribute add authorization uses local
numeric sharing-group IDs. Nested `SharingGroup` UUID data belongs to sync or
import flows and is deliberately outside this request encoder. Caller-controlled
text must be valid UTF-8, contain no Unicode control characters, and fit within
the encoder's conservative 4 KiB per-field limit. Caller strings remain
untrusted data.

## Complete offline event requests

`BuildMISPEventPayload` is available only with a complete
`MISPEventDefinition`. The caller must supply:

- a non-zero UUID;
- event information and date;
- distribution and any required sharing group;
- an explicit threat level and analysis level;
- explicit published/unpublished state; and
- explicit event correlation behavior.

The builder never derives threat level from candidate severity and never
chooses publication, distribution, analysis maturity, or event identity. Event
tags are also caller-owned. Selected Attributes inherit the Event distribution
by default (`distribution: "5"`) while keeping `to_ids: false` and
`disable_correlation: true` unless explicitly overridden.

`MISPEventPayload.Endpoint()` returns `/events/add`. Building the JSON is not
event creation or publication. If the caller supplies `published: true`, later
submission can have broader consequences; the application must review that
choice and the target instance's permissions before transport.

## Native fields and detached source metadata

Native payload JSON contains only supported MISP fields. It is not wrapped in
the dmarcgo automation or agent envelope. `ValidateMISPAttributePayload` and
`ValidateMISPEventPayload` reject unknown native fields, inconsistent UUIDs,
invalid distributions, incomplete sharing-group context, unsorted duplicate
tags, invalid timestamps, and source/payload mismatches.

`Source()` returns a defensive, separately serializable record containing:

- mapping, reviewed API-family, and target-instance contract versions;
- deterministic generation time and threat-candidate digest;
- event, candidate, observation, report-evidence, and correlation-finding
  references;
- original candidate and emitted observation windows; and
- the canonical source IP and selected mapping.

Candidate score, confidence, severity, message counts, domains, entities,
exclusions, recommendation, enrichment, and jurisdiction context are not
silently converted into MISP threat levels, IDS flags, tags, comments, or
classifications. Retain the source metadata or the original immutable result
when that context is needed. This intentional loss prevents unlike scoring and
tenant concepts from being presented as equivalent.

## Untrusted-data and privacy boundary

MISP output is operational and unredacted. It contains raw source IPs and can
contain caller event text, comments, tags, sharing information, and evidence
references. Callers own recipient authorization, minimization, distribution,
transport security, retention, and any redaction outside this native contract.

Event information, categories, comments, tags, contract labels, event IDs, and
all retained evidence are data, not instructions. Prompt-like strings remain
only in their declared fields. The library does not interpolate report text,
provider metadata, enrichment results, policy text, or caller tags into
generated headlines, recommendations, actions, or instructions.

## Caller-owned submission sequence

1. Review the completed candidate and its false-positive limitations.
2. Query and review the target instance's current type/category capabilities.
3. Choose source or destination semantics and the exact Event destination.
4. Keep review defaults or explicitly approve every broader distribution,
   correlation, IDS, tag, comment, timestamp, and publication choice.
5. Build and validate each payload locally.
6. Retain the defensive `Source()` metadata with the review record.
7. Submit through a caller-owned authenticated MISP client.
8. Inspect duplicate, validation, permission, warning-list, and publication
   responses and retain the resulting server IDs in caller-owned audit storage.

The library owns none of the credentials, HTTP behavior, event lifecycle,
tenant discovery, warning-list policy, duplicate handling, approval, retry,
submission, publication, response processing, or audit storage in that flow.
