# Organization adoption guide

This guide turns the independently callable `dmarcgo` APIs into practical
application designs. It is for Go developers, email and DNS administrators,
security engineering teams, security-awareness teams, and reviewers deciding
which evidence may cross a trust boundary.

Start with one question and one completed result. The library has no hidden
orchestrator: it does not read a mailbox, schedule work, store history, discover
credentials, submit exports, or execute a defensive action.

## Choose a workflow

| Your first question | Start here | Add later only when needed |
| --- | --- | --- |
| What is in one aggregate report? | `LoadFile`, `LoadBytes`, or `ParseBytes`, then `Validate`, `Summary`, or `Rows` | Report-evidence normalization |
| What did a report corpus observe? | `AnalyzeReportEvidence` over already parsed reports | Portfolio correlation |
| What do our authentication records publish now? | Portfolio -> `CollectDNSSnapshot` -> `ParseAuthenticationRecords` -> `EvaluateDNSHealth` | Optional remote perspectives |
| Does observed mail match declared senders? | Completed portfolio, DNS health, and report evidence -> `CorrelateReportEvidence` | Threat-candidate review |
| Which unexplained sources deserve review? | Completed evidence and correlation -> `ScoreThreatCandidates` | Explicit enrichment, source activity, or phishing intelligence |
| Does one reported message match an approved exercise? | Explicit campaign sources -> snapshot; body-free evidence -> `ClassifyReportedMessage` | Privileged or disclosure-safe output |
| How do automation or AI consumers receive one result? | `BuildAnalysisOutput` or a report-specific output builder | Native JSON, JSONL, or CSV when the complete typed result is needed |
| How do reviewed observations reach another platform? | STIX, ThreatConnect, MISP, or ThreatStream builder | Caller-owned HTTP, review, and audit storage |

The [automation workflow guide](automation-workflows.md) gives the complete
stage graph. The [consumer-agent guide](consumer-agent-guide.md) is a compact
decision tree for an AI coding assistant integrating the module from another
repository.

## Fifteen-minute first integration

1. Add `github.com/georgestarcher/dmarcgo/v2` to an application using Go 1.25
   or newer.
2. Choose one input boundary: a supplied report artifact or a caller-owned
   organization portfolio. Do not start with both unless the question requires
   correlation.
3. Call one analysis path and preserve its returned error or completed result.
4. Choose output only after analysis. Use the common envelope for automation or
   AI processing and a native writer for the complete typed mode result.
5. Set collection and output times explicitly when reproducible bytes matter.
6. Begin in observation-only mode. Review findings before adding application
   policy, alert routing, or any external submission.

The executable functions in [`examples_test.go`](../examples_test.go) cover
report loading, portfolio normalization, explicit DNS collection, DNS health,
report evidence, correlation, candidate scoring, campaign classification,
optional context, common output, native output, and defensive exports. Go runs
those examples during `go test`.

If optional context is the next step, read
[Optional context configuration](optional-context-configuration.md) before
writing integration code. It separates strict repository configuration from
programmatic offline snapshots and caller-supplied network adapters, and lists
the complete public fields, safe defaults, hard limits, and credential
boundary. A portfolio does not activate enrichment or configure a provider.

## Reference architectures

### Small organization

```text
synthetic or private portfolio
        |
        v
explicit DNS collection -> authentication parsing -> DNS health -> operator report

local aggregate reports -> report summary/evidence -> operator report
```

Keep the DNS schedule and report-ingestion schedule in the application. Store
DNS observation time separately from receiver report periods. A healthy current
record is not proof that the same record existed during an older report period.

### Multi-organization portfolio

```text
organization root
  +-- owned corporate entity
  +-- owned subsidiary
  +-- owned acquired unit
  +-- reference-only comparison entity
```

Represent business units, subsidiaries, acquisitions, and sister organizations
as explicit entities. Use `membership: reference` for external comparisons so
their evidence remains visible without affecting the owned portfolio rollup.
Resolve only the complete SPF, DKIM, and DMARC owner names declared for those
domains. Provider recognition adds setup context but never sender authorization.

The public adoption example is
[`testdata/portfolio/adoption-synthetic.yaml`](../testdata/portfolio/adoption-synthetic.yaml).
The larger feature-test fixture remains
[`testdata/portfolio/large-synthetic.yaml`](../testdata/portfolio/large-synthetic.yaml).

### SOC review pipeline

```text
reports -> report evidence -> DNS/report correlation -> threat candidates
                                                   |             |
                                                   |             +-> optional third-party context
                                                   +-> onboarding and drift findings

reviewed candidate selection -> native export builder -> caller submission
```

Candidate score and confidence describe review priority and evidence sufficiency,
not malicious certainty. Optional enrichment, source activity, phishing
intelligence, and jurisdiction context remain separate completed results and do
not change the candidate score or authorize blocking.

### Security-awareness integration

```text
testing-team sources -> explicit campaign resolution -> immutable snapshot
caller-parsed message headers/digests --------------------------+-> classification
                                                                 |
                         +---------------------------------------+
                         v
          privileged SOC view or disclosure-safe neutral route
```

Keep campaign sources restricted. A provider, sending IP, domain, URL, delivery
exception, or campaign-like aggregate stream is never sufficient on its own.
Automatic disposition remains dual-opt-in and unique-high-confidence-only. The
library returns workflow metadata but does not send an employee response.

### Offline or restricted environment

Supply an already completed `DNSSnapshot`, report-evidence result, campaign
snapshot, or offline context snapshot from the application boundary. Pure
parsers, evaluators, correlators, output builders, and export encoders perform
no network access. Do not instantiate resolver, HTTPS-source, enrichment, or
source-activity adapters in the restricted process.

## Mode and side-effect matrix

| Mode or result | Required input | Primary API | Library side effect | Typical sensitivity | Important incomplete state |
| --- | --- | --- | --- | --- | --- |
| Report validation | Parsed report | `ValidationResult` or `Validate` | None | Operational report metadata | Invalid or unsupported report evidence |
| Report summary and rows | Parsed report | `Summary`, `Rows` | None | Domains, reporters, source IPs | Invalid counts remain explicit |
| Aggregate summary | Parsed reports or summaries | `SummarizeReports`, `MergeSummaries` | None | Cross-report source and domain totals | Missing reports are caller inventory gaps |
| Configuration validation | `PortfolioConfig` | `ValidatePortfolio` | None | Owners and internal structure | Invalid configuration diagnostics |
| DNS snapshot | Normalized portfolio and resolver | `CollectDNSSnapshot` | Explicit DNS only | Record names, answers, resolver evidence | Partial, unavailable, canceled, or timed out |
| DNS perspectives | Portfolio, matching snapshot, selection, provider | `CollectDNSPerspectives` | Explicit provider only | Selected record names and answers | Insufficient perspectives or disagreement |
| Authentication records | Completed DNS snapshot | `ParseAuthenticationRecords` | None | Raw and parsed DNS evidence | Missing, malformed, weak, or indeterminate |
| DNS health | Portfolio, parsed records, provider catalog | `EvaluateDNSHealth` | None | Organization posture and findings | Unknown evidence or stale snapshot |
| Report evidence | Parsed reports | `AnalyzeReportEvidence` | None | Historical source and authentication data | Invalid observations and explicit diagnostics |
| DNS/report correlation | Portfolio, DNS health, report evidence | `CorrelateReportEvidence` | None | Sender inventory and historical variance | Below-threshold or temporally limited evidence |
| Campaign configuration | Explicit source set | `ResolveCampaignConfiguration` | Only selected adapters | Restricted campaign inventory | Missing, stale, expired, conflicting, or unavailable source |
| Reported-message campaign classification | Campaign snapshot and body-free evidence | `ClassifyReportedMessage` | None | Potentially restricted campaign match | Partial, possible, unavailable, or conflicting match |
| Aggregate campaign review | Campaign snapshot and report evidence | `CorrelateCampaignReportEvidence` | None | Lower-confidence campaign context | Aggregate periods cannot prove one message |
| Threat candidates | Portfolio, report evidence, correlation | `ScoreThreatCandidates` | None | Source IPs and review rationale | Excluded, capped, or not review eligible |
| Source enrichment | Threat candidates and caller enricher | `EnrichThreatCandidates` | Explicit provider only | Source IP, ASN, country, provider provenance | Stale, conflicting, unavailable, timed out |
| Source activity | Threat candidates, selection, provider | `CollectSourceActivity` | Explicit third party only | Disclosed selected source IPs | Rate limited, truncated, stale, future, unavailable |
| Phishing intelligence | Candidates, matching evidence, offline snapshots | `CorrelatePhishingIntelligence` | None | Licensed/provider intelligence context | Non-match, conflict, stale, future, withdrawn |
| Jurisdiction context | Source enrichment and policy | `EvaluateJurisdictionContext` | None | Coarse country assertions | Unknown, stale, conflicting, not eligible |
| Common automation/agent output | One completed result | `BuildAnalysisOutput` | None | Selected redaction profile | Failed input uses a separate failure envelope |
| Native JSON/JSONL/CSV | One completed native result | Mode-specific `Write*Output` | Supplied writer only | Public, operational, or restricted | Writer errors can mean incomplete output |
| STIX or vendor payload | Explicit reviewed selection | Builder-specific API | None | Operational and unredacted | Unsupported target contract or selection |

There is no combined `organizational_monitoring` result. The application may
store or present several completed results together, but it must not collapse
current DNS posture, historical report evidence, campaign authorization, and
source-review context into one verdict.

## Output and AI boundary

- Use `OutputProfileAutomation` for terse deterministic processing and
  `OutputProfileAgent` for grounded library-controlled explanations.
- Use public redaction before crossing the operational trust boundary.
  Pseudonymous tokens preserve joins but are not encryption.
- Inspect truncation metadata before concluding that a collection was empty.
- Keep untrusted report, DNS, provider, enrichment, campaign, and target-system
  values in structured data fields. Do not concatenate them into instructions.
- Use stable finding and action codes as the machine contract. Explanatory prose
  may improve between releases.
- Treat every recommendation as advisory until the application applies its own
  authorization and review policy.

See [cross-mode output](output-contract.md) for the exact profile, detail,
redaction, schema, and deterministic truncation contracts.

## Adoption checklist

- [ ] The application uses the `/v2` module path and a supported Go version.
- [ ] Each workflow starts from the smallest required input set.
- [ ] DNS, campaign retrieval, enrichment, and source activity are explicit.
- [ ] Every optional context stage uses the documented input form: strict file,
      programmatic snapshot or policy, or caller-supplied adapter.
- [ ] Provider credentials and endpoints remain in the application, not in a
      portfolio, catalog, snapshot, result, or output.
- [ ] No adapter contacts an observed source IP.
- [ ] Portfolio and campaign files validate before operational use.
- [ ] Collection time, report periods, and output time remain distinct.
- [ ] Provider recognition is not treated as sender authorization.
- [ ] Campaign classification preserves privileged and disclosure-safe views.
- [ ] Threat candidates remain human-review evidence, not malicious verdicts.
- [ ] Output redaction matches the destination trust boundary.
- [ ] Truncation, stale, unknown, and not-evaluated states are handled.
- [ ] External payloads are reviewed before caller-owned submission.
- [ ] Tests use synthetic or anonymized data only.
- [ ] The integration begins in observation-only mode.

Continue with the [configuration reference](configuration-reference.md),
[operations and troubleshooting](operations-and-troubleshooting.md), or the
feature guide linked from the [documentation index](README.md).
