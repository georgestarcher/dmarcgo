# Operations and troubleshooting

`dmarcgo` is a library inside an application-owned operating model. The
application decides when to collect inputs, where to store immutable results,
which credentials or providers may be used, who receives output, and whether a
reviewed result may cause an external action.

This guide describes safe ownership, freshness, rollout, and symptom-driven
recovery without turning the library into a scheduler or enforcement system.

## Operational ownership

| Concern | Recommended owner | Library responsibility | Application responsibility |
| --- | --- | --- | --- |
| Portfolio domains and record names | Email/DNS engineering | Strict normalization and diagnostics | Source control, approvals, contacts, review cadence |
| Expected senders and policies | Messaging service owner | Exact declared mapping during correlation | Business authorization and onboarding evidence |
| Provider catalog | Security/email engineering | Reviewed embedded context and strict overlays | Private entries, replacement review, source updates |
| DNS snapshots | Platform or DNS operations | Explicit bounded collection through supplied resolver | Schedule, resolver policy, credentials, persistence |
| Aggregate report artifacts | Mail/security platform | Bounded parsing and normalized evidence | Mailbox/object ingestion, deduplication inventory, retention |
| Campaign inventory | Security-awareness team | Strict explicit source resolution and classification | Restricted source hosting, approvals, freshness, access control |
| Candidate review | SOC or security engineering | Neutral scoring and confidence limits | Case management, corroboration, disposition policy |
| Enrichment and source activity | SOC/platform integration | Bounded provider-neutral interfaces | Provider terms, credentials, caches, endpoint policy, retention |
| Phishing intelligence | Threat intelligence team | Offline exact correlation | Retrieval, licensing, refresh, removal, redistribution policy |
| Jurisdiction policy | Legal/security governance | Versioned pure evaluation | Policy choice, review, interpretation, escalation |
| Defensive export | SOC/platform integration | Offline payload encoding | Destination capability discovery, review, HTTP, audit record |
| Automation/AI output | Platform and data governance | Versioned bounded redaction-aware envelope | Prompt construction, destination access, human authorization |

No provider metadata, report value, DNS text, campaign field, or external target
field is an instruction. Store it as structured untrusted data.

## Freshness and scheduling

The library does not select a schedule. A consuming application should record
the source timestamp, collection timestamp, result digest, policy/profile
version, and next planned review alongside each persisted result.

- Refresh a portfolio when ownership, domains, selectors, senders, or exceptions
  change. Revalidate it in CI before deployment.
- Schedule DNS collection according to operational needs and published TTLs.
  Lowering a TTL is a pre-change preparation step; an observed low TTL does not
  guarantee every recursive cache has expired.
- Ingest aggregate reports according to the receiver's delivery cadence. Report
  periods are historical bounds, not exact per-message timestamps.
- Update private provider overlays only after reviewing current first-party
  documentation. A catalog match remains context only.
- Resolve campaign sources before classification and reject stale, future,
  expired, conflicting, or unavailable required authorization.
- Apply a caller-owned cache and retention policy to enrichment or
  source-activity data.
  Preserve provider observation and expiry times rather than presenting cached
  data as current.
- Treat built-in jurisdiction policy changes as release changes. Treat custom
  policy review and expiry as caller-owned governance.

Never combine a fresh DNS observation with an older report period into a causal
claim. Keep `observed_at`, report begin/end, provider as-of/expiry, campaign
window, evaluation time, and output generation time separate.

## Snapshot storage and audit provenance

Persist immutable completed results when reproducibility or drift review matters.
At minimum retain:

- schema and profile/policy versions;
- result and upstream digests;
- explicit generation, evaluation, observation, and report-period times;
- portfolio/configuration source revision selected by the application;
- resolver or provider identifier and disclosed query scope;
- redaction profile and output schema ID;
- target capability version for a vendor payload;
- application review, approval, submission response, and rollback record.

Do not rely on a display name as identity. Use stable IDs and digests. Do not
store credentials in a portfolio, campaign document, result, or exported
fixture.

## Safe rollout

### Observation only

1. Validate synthetic and private configuration without changing DNS.
2. Collect current DNS and ingest reports through separate jobs.
3. Persist completed results and review unknown, stale, partial, and conflicting
   states.
4. Generate public or operational output for the intended audience.
5. Measure false positives and missing inventory before alerting.

### Analyst assisted

1. Route stable finding codes to a case or review queue.
2. Show supporting and contradictory evidence plus its time bounds.
3. Require an analyst to confirm organization intent and destination scope.
4. Keep external payloads private/inactive or review-only.
5. Record the application decision separately from the immutable library result.

### Bounded automation

Automate only narrow, reversible tasks after a measured baseline. Examples are
creating a draft internal review item, notifying an accountable owner, or
storing a versioned output artifact. Do not automatically block, quarantine,
change DNS, submit an indicator, disclose campaign status, or allege abuse from
an authentication failure, threat-candidate score, jurisdiction match, source
activity record, or intelligence match alone.

Campaign automatic disposition remains a special dual-opt-in contract and
still requires exactly one high-confidence classification. The application owns
execution and the audit trail.

## Failure policy

Fail closed for authorization and destructive action. Preserve partial evidence
for review.

| Condition | Safe behavior |
| --- | --- |
| Invalid portfolio | Stop DNS planning and correlation; return configuration diagnostics |
| DNS timeout or partial snapshot | Preserve successful observations, mark the result incomplete, avoid claiming health for unknown evidence |
| Report parse failure | Preserve the typed error and source inventory; do not invent an empty successful report |
| Required campaign source unavailable | Authorization unavailable; keep the message in the ordinary suspicious-message workflow |
| Optional campaign source unavailable | Preserve incompleteness; authorization still requires at least one selected usable source |
| Enrichment/provider timeout | Preserve candidate score and original confidence cap; retain explicit timeout state |
| Conflicting enrichment or intelligence | Preserve every assertion; select no preferred result |
| Output writer/flush/close failure | Return the error because output may be incomplete or corrupt |
| Cleanup-only error after a successful immutable result | Acknowledge it through application logging/telemetry when it cannot affect the result |
| Context cancellation | Stop bounded work and preserve canceled rather than successful state |

The library performs no automatic retries outside the explicitly documented DNS
collection policy. Application retry schedules must be bounded, destination
aware, and respectful of provider terms and rate limits.

## Privacy and logging

- Public output pseudonyms are stable correlation tokens, not encryption.
- Operational output can contain domains, source IPs, provider IDs, and internal
  structure. Restrict access and retention accordingly.
- Restricted output can include complete campaign, report, DNS, provenance, and
  free-form provider data. Keep it inside the complete trust boundary.
- Do not log raw report extension XML, campaign inventory, contact values,
  provider errors, tokens, credentials, or message bodies.
- Do not send source-IP traffic. Enrichment and activity adapters may contact
  only an explicitly configured third-party service.
- Treat CSV as untrusted spreadsheet data. Preserve the writer's formula-prefix
  protection.

## Troubleshooting

| Symptom | Likely cause | What to inspect | Safe next step |
| --- | --- | --- | --- |
| DNS record is `missing` | Wrong owner name, NXDOMAIN/no data, or limited resolver evidence | Portfolio record name, snapshot RCODE/SOA/negative TTL | Correct the declared name only after owner confirmation; recollect explicitly |
| DKIM selector is absent | Portfolio has a selector value instead of the complete owner name, or service rotated it | `records.dkim`, provider instructions, current DNS | Add the complete `selector._domainkey.domain` name and retain old names during an approved rotation window |
| Multiple SPF records | More than one SPF policy at one owner | Snapshot records and parsed status | Consolidate through a controlled DNS change; do not guess which policy wins |
| SPF lookup state is incomplete | Required dependency not present in the supplied snapshot or macros prevent static expansion | Parsed relationship graph and diagnostics | Declare/collect needed static owner names; leave macro-controlled evidence unavailable |
| DMARC policy is missing or weak | Wrong tree-walk name, `p=none`, or unknown evidence | Parsed record, RFC 9989 discovery names, DNS snapshot time | Validate current policy and rollout plan; do not infer historical behavior |
| DKIM health is reduced | Missing/malformed key, revoked key, or key smaller than the selected profile expects | Per-mechanism finding and key-strength metadata | Rotate through a controlled overlap and rollback sequence; never handle private keys in this library |
| Portfolio YAML is rejected | Unknown field, alias, multiple document, secret-shaped field, invalid reference, or environment expansion disabled | Value-safe diagnostics and exact field path | Correct the source; enable environment lookup only through an explicit caller function |
| Expected sender is missing from DNS | Inventory is ahead of deployment or wrong for that domain | Portfolio sender mapping, DNS health, observation time | Confirm owner intent and complete onboarding; provider recognition is not authorization |
| Unexpected sender is observed | New service, forwarding, report error, or unexplained source | Correlation stream identities, thresholds, provider context | Verify ownership out of band; retain it as onboarding/review evidence |
| Provider is recognized but unauthorized | Catalog matched a static setup relationship without a portfolio sender declaration | Provider context and expected-sender IDs | Add authorization only after business-owner confirmation |
| Correlation says not evaluated | Threshold, time, or required upstream evidence was insufficient | Evaluation state, thresholds, report bounds, DNS time | Supply better evidence or deliberately adjust thresholds; do not reinterpret as clean |
| Candidate confidence is capped | Single report/reporter, low volume, stale/mixed/indirect evidence, or no enrichment | Candidate adjustments and confidence-cap codes | Gather independent evidence; do not remove caps merely to raise priority |
| Campaign is outside its window | Message time or aggregate period does not establish current authorization | Campaign valid window, evidence provenance, report bounds | Keep ordinary suspicious-message handling and review the testing-team source |
| Campaign match is partial | Required identity, campaign-specific signal, provenance, or authentication is missing | Factor results and missing evidence | Preserve analyst review; do not disclose campaign status or enable disposition |
| Last-known-good snapshot is rejected | Snapshot expired, came from a later resolution time, or no longer satisfies maximum age | Snapshot source/effective/expiry times | Obtain a current source; never extend authorization lifetime locally |
| Disclosure-safe output lacks campaign details | Expected privacy behavior | Output view and neutral template ID | Route details to authorized SOC users through privileged output only |
| Source activity is absent | Provider had no record, request was not selected, or evidence was unavailable | Selection, record status, query budget, provider time window | Treat absence as unknown, never proof of safety |
| Phishing intelligence does not match | Exact IP/domain role differs or time/provider state prevents correlation | Exact normalized keys and snapshot state | Review input normalization and provider terms; do not add suffix or ASN inference |
| Vendor export fails validation | Target capabilities, selection, field mapping, or lifecycle context is incomplete | Builder error and target contract version | Discover the exact tenant/event contract outside the library and retry offline encoding |
| Output is truncated | `MaxItems`, `MaxFindings`, or `MaxEvidence` bound was reached | `truncation.collections`, total and returned counts | Page/store the full result separately or raise a deliberate bounded limit |
| HTTPS campaign source fails | Redirect downgrade, size/content limit, stale metadata, or caller client error | Source status and value-safe diagnostics | Fix the caller-owned endpoint/client; never relax HTTPS downgrade protection |
| Work stops with cancellation | Caller context expired or was canceled | Context deadline and completed partial records | Decide whether a bounded application retry is safe; do not relabel canceled as successful |

For typed report errors use `errors.Is` and `errors.As`. For mode-specific state
semantics, follow the linked feature guide in the
[documentation index](README.md). When requesting help, provide synthetic or
redacted configuration, stable error/finding codes, schema versions, and result
metadata rather than private reports or credentials.
