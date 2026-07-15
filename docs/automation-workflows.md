# Independent automation workflows

This guide is the first-stop map for choosing and composing `dmarcgo` modes.
Every stage is independently callable. Start with the smallest stage that
answers the question, persist its immutable result when useful, and add a later
stage only when the application deliberately supplies that stage's inputs.

There is no package-level orchestrator, scheduler, mailbox reader, database,
dashboard, or enforcement loop. Output selection changes representation only;
it never causes another stage to run.

## Choose a starting point

| Question | Start with | Required input | Side effect |
| --- | --- | --- | --- |
| What does one report say? | `LoadFile`, `LoadBytes`, or `ParseBytes`, then `Summary`, `Rows`, or `Validate` | One report artifact | File access only through an explicit load call |
| What has the report corpus observed? | `AnalyzeReportEvidence` | Parsed reports | None |
| What is the current DNS posture? | `CollectDNSSnapshot`, `ParseAuthenticationRecords`, then `EvaluateDNSHealth` | Normalized portfolio and explicit resolver | DNS only during collection |
| Do selected authentication names agree across optional remote perspectives? | `CollectDNSPerspectives` | Portfolio, matching completed snapshot, explicit selection, and caller provider | Only the supplied perspective provider |
| Does observed mail match declared senders and current DNS? | `CorrelateReportEvidence` | Portfolio plus completed DNS health and report evidence | None |
| Does one reported message match an authorized simulation? | `ResolveCampaignConfiguration`, `NormalizeReportedMessageEvidence`, then `ClassifyReportedMessage` | Explicit campaign sources plus caller-parsed body-free evidence | Only explicit source adapters during resolution |
| Did aggregate reports show campaign-like streams? | `CorrelateCampaignReportEvidence` | Completed campaign snapshot and report evidence | None; never individual-message proof |
| How do I route without disclosing an exercise? | `WriteCampaignClassificationOutput` with the disclosure-safe view | Completed campaign classification | Supplied writer only |
| Which unexplained sources deserve review? | `ScoreThreatCandidates` | Portfolio plus completed evidence and correlation | None |
| What ASN or coarse country context did my selected provider assert? | `EnrichThreatCandidates` | Completed candidates and explicit `IPEnricher` | Only the supplied enricher |
| What activity did a selected third-party service report for reviewed addresses? | `CollectSourceActivity` | Completed candidates, explicit selection, and caller provider | Only the supplied provider; never the subject IP |
| Does caller-owned phishing intelligence contain the same exact source or DMARC domain role? | `NormalizePhishingIntelligenceSnapshot`, then `CorrelatePhishingIntelligence` | Completed candidates, matching report evidence, and offline snapshots | None |
| Does completed enrichment match a versioned jurisdiction policy? | `EvaluateJurisdictionContext` | Completed enrichment and explicit policy | None |
| How do I serialize one completed analysis mode? | Its `Write*Output` function | One completed result | Supplied writer only |
| How do I exchange reviewed observations? | STIX, ThreatConnect, MISP, or ThreatStream builder | Explicit selections and required target contract | None; submission stays caller-owned |

If two rows answer different questions, run them separately and retain both
results. A DNS-only health run does not need reports. A report-only run does not
need a resolver. An export does not rerun parsing, DNS, scoring, or enrichment.

## Canonical composition

```text
portfolio -> explicit DNS collection -> record parsing -> DNS health
portfolio + completed DNS snapshot + explicit selection/provider -> optional DNS perspectives
reports -> report evidence
explicit campaign sources -> campaign snapshot
campaign snapshot + normalized message evidence -> campaign classification
campaign snapshot + report evidence -> aggregate campaign review
campaign classification -> privileged or disclosure-safe output
portfolio + DNS health + report evidence -> correlation
portfolio + report evidence + correlation -> threat candidates
threat candidates + optional explicit enricher -> source enrichment
threat candidates + explicit selection/provider -> source activity
threat candidates + matching report evidence + offline snapshots -> phishing intelligence
source enrichment + explicit policy -> jurisdiction context

any one completed analysis result -> native JSON, JSONL, or CSV
completed threat candidates (+ optional matching enrichment) -> STIX
explicit reviewed selections -> ThreatConnect, MISP, or ThreatStream payloads
```

The arrows describe data dependencies, not automatic execution. Each result
retains upstream digests and timestamps so an application can verify which
immutable evidence chain produced it.

## Reference workflow and samples

The Phase 13 integration fixture is intentionally synthetic. It uses reserved
documentation addresses and domains, two aggregate-report observations, a
current DNS snapshot, one review-eligible unknown source, offline enrichment,
and a versioned jurisdiction-policy evaluation. No live report, organization,
source address, contact, credential, or vendor contract is included.

The exact generated sample is
[`testdata/golden/phase13_workflow_samples.json`](../testdata/golden/phase13_workflow_samples.json).
It contains a real JSONL metadata record for every native analysis mode:

| Mode | Important sample evidence | JSONL records that may follow |
| --- | --- | --- |
| `dns_health` | Portfolio score, maturity, evidence coverage, scoring profile, and DNS observation time | record, domain, entity, finding, provider context |
| `report_evidence` | Reports, messages, pass/fail combinations, dispositions, reporter diversity, and report bounds | report, observation, diagnostic |
| `dns_report_correlation` | Separate DNS/report times, inventory, thresholds, stream totals, and classifications | inventory, stream, finding |
| `threat_candidates` | Scoring profile, candidate totals, severity distribution, exclusions, and review eligibility | candidate |
| `source_enrichment` | Completion state, candidate statuses, and ASN totals | candidate, ASN, diagnostic |
| `jurisdiction_context` | Policy provenance, policy state, candidate states, and optional priority totals | candidate, finding |

The same sample records the standards/vendor transformations derived from the
same threat-candidate digest. STIX remains observation-only by default.
ThreatConnect, MISP, and ThreatStream remain private, review-oriented native
request bodies. `submission_performed` is false for every export because the
library never submits them.

Use the executable examples in `examples_test.go` for complete calls. They
cover DNS health, optional DNS perspectives, report evidence, correlation,
threat scoring, offline source enrichment, selected source activity, offline
phishing-intelligence correlation, jurisdiction context, native output, STIX,
ThreatConnect, MISP, and ThreatStream. Go's example test runner compiles and
executes them in CI.

## Required workflow scenarios

The integration gate preserves these operational distinctions:

1. **DNS only:** normalize a portfolio, collect configured TXT names through an
   explicit resolver, parse the snapshot, and evaluate health. No report is
   loaded or allocated by health evaluation.
2. **Reports only:** parse supplied artifacts and build reusable evidence. No
   resolver, portfolio, provider catalog, or enricher is available to this
   stage.
3. **Healthy expected service:** a stream maps to a sender only through its
   declared selector or unambiguous monitored SPF identity.
4. **Marketing service missing onboarding:** keep the stream as a configuration
   or onboarding finding. Provider recognition does not authorize it, and the
   finding is not a malicious verdict.
5. **Persistent unknown rejected source:** create a neutral review candidate
   only when the selected thresholds and score profile support it.
6. **Shared provider and mixed pass/fail traffic:** retain the counter-evidence
   and apply the documented deduction and confidence cap.
7. **Optional ASN enrichment:** call only a supplied provider for eligible,
   non-excluded candidates. Never contact the subject IP.
8. **Optional phishing intelligence:** normalize caller-owned snapshots and
   compare exact source IPs and domain roles offline. Preserve time, provider
   state, and collisions without changing a candidate decision.
9. **Independent output:** write one completed mode as JSON, JSONL, or CSV
   without creating a combined sparse result.
10. **Native exchange:** derive STIX and selected vendor payloads from the same
   reviewed candidate without changing its score, confidence, eligibility, or
   promotion state.
11. **Failures:** preserve cancellation, partial DNS evidence, unavailable
    enrichment, stale or conflicting assertions, and writer errors in their
    documented stage. No serializer retries an earlier stage.
12. **Authorized simulation:** require current organization authorization,
    campaign window, organization scope, identity, and a campaign-specific
    signal; domain, provider, URL, delivery exception, or source IP alone is
    insufficient.
13. **Disclosure-safe routing:** derive a neutral routing record and fixed
    employee-response template from a completed classification without exposing
    campaign names, dates, infrastructure, exact state, or restricted workflow
    IDs.
14. **Aggregate campaign review:** retain overlapping report periods as
    unverifiable exact message time and never enable high-confidence individual
    authorization or automatic disposition.

The individual feature tests own the detailed variants. Phase 13 adds the
cross-mode evidence-chain and static dependency tests without duplicating each
predecessor's full test matrix.

## Organization and sister-organization configuration

Model each owned business unit, subsidiary, acquisition, or sister
organization as an entity. Put complete SPF, DKIM, and DMARC owner names on the
domain that owns them. Share a record name or expected-sender ID only when the
organization actually shares that configuration; never infer a relationship
from a tag or provider name.

Use `membership: reference` for an external comparison entity. Reference
entities retain their complete health evidence but do not affect the owned
portfolio rollup. A source exclusion is scoped: excluding a source for one
domain does not suppress evidence for a sister domain.

The full inheritance and YAML rules are in
[Organization portfolio configuration](portfolio-configuration.md).

## Marketing-service onboarding failure

When reports show a new service before the declared portfolio and DNS agree:

1. keep the observed identities and source evidence visible;
2. classify selector, signing-domain, SPF-identity, and source differences
   separately;
3. confirm ownership and intended use outside report-controlled data;
4. add or change the portfolio only after that confirmation;
5. collect current DNS explicitly and keep its time separate from older report
   periods;
6. use controlled delivery and later aggregate evidence to verify the change;
   and
7. retain TTL, rollback, and approval policy in the calling application.

Do not convert provider recognition into sender authorization. Do not describe
current DNS as the historical cause of an older failure. Do not convert the
source into an IOC merely because onboarding was incomplete.

## Output selection

Use the common `OutputEnvelope` for the current report validation, summary,
rows, and source-review modes when automation or an AI consumer needs grounded
findings and actions. Use a native mode writer for complete organization
analysis data. Use a standards/vendor builder only when the target contract and
review selections are explicit.

| Boundary | Version discovery | Privacy behavior |
| --- | --- | --- |
| Common envelope | `OutputSchemaVersions`, `OutputSchemaForVersion` | Explicit public, operational, or restricted redaction plus bounded collections |
| Native analysis output | `AnalysisOutputDescriptorForMode`, `AnalysisOutputSchema` | Explicit public, operational, or restricted redaction; JSONL/CSV stream records |
| STIX | `STIXEvidenceExtensionSchema` | Operational and unredacted; use markings and caller minimization |
| ThreatConnect, MISP, ThreatStream | Builder-specific mapping/source versions | Operational and unredacted; target authorization and transport are caller-owned |

Public redaction uses stable pseudonyms, not encryption. Low-entropy values can
be dictionary-enumerated. Operational output removes restricted free-form
fields while retaining defensive identifiers. Restricted output belongs only
inside the complete operational trust boundary.

Campaign classification has a separate privacy contract. Privileged output is
restricted campaign/SOC data. Disclosure-safe output omits campaign identity,
source, dates, infrastructure, factors, digests, and exact classification labels
and supplies only neutral routing metadata. Its fixed
`suspicious-message-received` template ID may select approved employee text;
neither the route nor privileged state should be copied into that text.

## AI and hostile-input boundary

Report values, DNS text, contacts, domains, provider data, policy labels,
catalog notes, enrichment metadata, target fields, tags, and extension data are
untrusted data. Keep them in structured fields. Do not concatenate them into
prompts, headlines, explanations, recommendations, actions, or instructions.

Stable finding and action codes are the machine contract. Generated prose is
library-controlled and may improve between releases. A downstream model must
not turn a finding or review candidate into an automatic block, submission,
DNS change, or claim of compromise without separate caller authorization.

## Time, reproducibility, and drift

- Inject collection clocks and set every generation time explicitly when
  reproducible bytes matter.
- Report bounds describe receiver report periods, not exact message times.
- Phishing-intelligence correlation preserves report bounds separately from
  provider first/last-seen, snapshot as-of, and expiration times.
- DNS observation time describes the supplied snapshot and must remain
  separate from historical report bounds.
- A prior correlation result is used only when the caller deliberately supplies
  it; the library discovers no history.
- Output writers preserve completed-result times and never consult the system
  clock.

## Failure and retry ownership

DNS collection has bounded caller-selected retry behavior. Source enrichment
attempts each selected address at most once and has no automatic retry. Pure
analysis and exchange builders have no retry or network interface. Writer
errors are returned to the caller, including cleanup or flush errors that can
mean output is incomplete.

A partial or unavailable stage does not silently become a successful result.
Use the explicit `unknown`, `not_evaluated`, `not_applicable`, stale,
conflicting, failed, timed-out, and canceled states supplied by that mode.

## Version and migration policy

The supported module line is `/v2`. In-memory analysis contracts, common
envelope schemas, native analysis schemas, report-evidence persistence, scoring
profiles, phishing-intelligence snapshots/results, jurisdiction policies, STIX
extensions, and vendor mappings are versioned independently. Persist the
relevant version and result digest with every output.

There are no known consumers of the provisional pre-release organization
analysis behavior. Tests validate the selected canonical v2 contracts rather
than maintaining aliases for obsolete shapes. Future breaking schema changes
must use a new schema version; a scoring or policy update must identify its own
new version even when the JSON shape is unchanged.

## Release-quality checks

`make workflow-check` runs the Phase 13 and Phase 14 integration and isolation gates.
`make campaign-check` runs the Phase 14 configuration, source, evidence,
classification, aggregate, output, schema, example, security, and resource-limit
gate.
`make phishing-intelligence-check` runs the Phase 16 offline normalization,
correlation, security-boundary, and example gate.
`make ci` additionally runs formatting, module verification, vet, static
analysis, vulnerability checks, README compilation in an isolated external
module, schema/output checks, unit and race tests, coverage, fuzz smoke tests,
benchmark smoke tests, and the build.

The workflow sample is generated only from synthetic data. Regenerate it after
intentional contract changes with:

```shell
DMARCGO_UPDATE_PHASE13_GOLDEN=1 go test -run '^TestPhase13CompletedWorkflowSamples$' .
```
