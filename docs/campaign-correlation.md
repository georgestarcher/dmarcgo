# Security-simulation campaign correlation

This feature lets an application compare caller-normalized reported-message
evidence with a current, organization-owned inventory of authorized phishing or
security-awareness campaigns. It is a bounded classification library, not a
mailbox reader, allowlist, response sender, incident-response system, or
enforcement engine.

## Three independent kinds of evidence

Keep these concepts separate:

1. **Provider knowledge** describes documented behavior of a commercial service.
   A provider-catalog match is context only.
2. **Organization authorization** is a time-bounded campaign definition supplied
   by an approved organization source. It identifies owner, approval, scope,
   expected identities, campaign-specific signals, and handling policy.
3. **Observed evidence** is a normalized message/header observation or a clearly
   marked aggregate-report observation supplied by the application.

No one layer substitutes for another. Provider recognition does not authorize a
campaign. A campaign definition does not prove that a message matched it. A
domain, display name, provider name, hostname, or source address alone never
produces high-confidence authorization.

Microsoft documents both that simulations can produce false security activity
and that its Attack Simulation Training service does not use one static source-IP
list. Microsoft also recommends narrowly scoped advanced-delivery configuration
for third-party simulations. These are practical reasons not to implement a
global IP allowlist. See the official
[Attack Simulation Training overview](https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-get-started),
[FAQ](https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-faq),
and [advanced-delivery guidance](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure).
[Cofense's PhishMe overview](https://cofense.com/getmedia/c059b744-b25b-4a72-9d93-5f5d8685faa9/Cofense-SolutionBrief_PhishingSimulations.pdf)
is an example of an independently operated commercial simulation workflow.

## Configuration contract

`CampaignConfigurationConfig` is mutable input. `LoadCampaignConfiguration`
strictly parses YAML or JSON, while `NormalizeCampaignConfiguration` accepts a
programmatic value. Both return an immutable
`CampaignConfigurationDocument` with defensive-copy accessors.

The configuration schema is versioned independently:

- version: `CampaignConfigurationSchemaVersion`;
- identifier: `CampaignConfigurationSchemaID`;
- embedded schema: `CampaignConfigurationSchema()`;
- source file: [`schemas/campaign/configuration/v1.json`](../schemas/campaign/configuration/v1.json).

Version 1 uses exact canonical domains, selectors, source CIDRs, hostnames,
infrastructure IDs, scope IDs, and complete `sha256:` digests. It intentionally
has no regular-expression or pattern language, which avoids regex denial of
service and ambiguous partial matching. Raw campaign tokens and credentials are
not accepted. YAML aliases, anchors, duplicate keys, unknown fields,
environment placeholders, multiple documents, and secret-bearing fields are
rejected.
IPv4-mapped IPv6 source CIDRs are canonicalized to equivalent IPv4 prefixes so
they use the same address family as normalized message evidence.

Every campaign contains:

- a stable campaign ID and commercial-catalog or self-hosted provider identity;
- organization, optional entity and business-unit scope;
- owner, approval reference, lifecycle state, and campaign window;
- optional recipient, identity, infrastructure, URL, delivery-exception, token,
  and content-fingerprint evidence;
- expected SPF, DKIM, and DMARC outcomes;
- restricted response and handling policy; and
- required factors plus a bounded partial-match threshold.

Authentication evidence retention is mandatory. The field may be omitted or
set to `true`; explicit `false` is invalid. Campaign configuration cannot
suppress SPF, DKIM, or DMARC variance.

Canceled campaigns retain restricted audit context, but matching evidence stays
in the ordinary suspicious-message workflow. A canceled campaign can never be
possible or high-confidence authorization.

The library enforces a non-bypassable high-confidence invariant: current
authorization, campaign time, organization scope, a message identity, and a
campaign-specific signal must match. Required-factor configuration may make
this stricter but cannot weaken it. Exact DKIM domain/selector, an
infrastructure ID, a token digest, or a content fingerprint can be a
campaign-specific signal. Source IP, sender domain, provider name, and URL
domain alone cannot.

The committed
[`security-simulations.yaml`](../testdata/fixtures/campaigns/security-simulations.yaml)
is fully synthetic and shows both a commercial provider reference and a
self-hosted subsidiary campaign.

## Explicit source resolution

`CampaignConfigurationSource` is the application-facing interface:

```go
type CampaignConfigurationSource interface {
    Load(context.Context) ([]byte, CampaignConfigurationMetadata, error)
}
```

An application can implement Git, object storage, a database, a configuration
service, or a secret-manager-backed transport without adding those dependencies
to this module. The library supplies optional adapters for:

- already available bytes with `NewCampaignBytesSource`;
- one local file with `NewCampaignFileSource`;
- deterministic `.yaml`, `.yml`, and `.json` directory fragments with
  `CampaignConfigurationSourcesFromDirectory`;
- one explicitly selected environment lookup and interpretation with
  `NewCampaignEnvironmentSource`; and
- explicit HTTPS using a caller-controlled client with
  `NewCampaignHTTPSSource`.

The module never reads process environment variables by itself. The HTTPS
adapter copies the supplied `http.Client` and rejects any redirect target that
would leave HTTPS before that request is sent; same-scheme redirect, proxy,
credential, caching, retry, TLS, and rate policy otherwise remain caller-owned.
Directory discovery does not follow symlinks. File and HTTP read/close errors
that could mean incomplete input are returned.

`ResolveCampaignConfiguration` loads only the supplied source specifications
and import IDs. Imports never discover a location. Resolution is deterministic,
bounded, context-aware, and records source digests, document digests, ETags,
Last-Modified values, retrieval times, freshness states, and optional detached
signature verification results. Restricted provenance also retains the exact
replacement-ID allowlist so the snapshot digest covers the merge policy that
produced the inventory.

Higher priority is not an implicit trust override. A higher-priority source may
replace an exact campaign ID only when that ID is listed in its
`ReplaceCampaignIDs`. Otherwise conflicting definitions are excluded and a
diagnostic is retained. This supports independently maintained parent,
subsidiary, acquisition, sister-organization, and regional feeds without
silently broadening authorization.

### Failure and last-known-good policy

The default `CampaignSourceFailOpen` means ordinary suspicious-message analysis
may continue, but missing, invalid, future, stale, expired, or unavailable
required authorization disables campaign authorization. It does not mean
"trust on error." `CampaignSourceFailClosed` returns the same immutable partial
snapshot plus `ErrCampaignSourceFailed`.

Last-known-good reuse is explicit. The caller must set `UseLastKnownGood` and
supply a complete, authorization-capable, unexpired prior snapshot. The library
does not discover or persist history. The new snapshot retains the previous
digest and failure diagnostics, remains `Complete() == false`, and may authorize
only while that prior snapshot is still within its declared lifetime.

## Reported-message evidence

`NormalizeReportedMessageEvidence` accepts caller-parsed fields without a
message body. It canonicalizes organization scope, From/envelope/Message-ID and
SPF domains, DKIM identities, authentication outcomes, IP addresses, hostnames,
infrastructure and delivery-exception IDs, recipient scopes, URL domains,
complete token/content digests, exact message time or aggregate period bounds,
and provenance.

All values remain untrusted structured data. Raw tokens are never accepted or
exported. A caller that recognizes a token should hash it before normalization
or supply only its verified-match digest. `ReportedMessageEvidence` is
immutable and deterministic and can be reused concurrently.

## Classification

`ClassifyReportedMessage` is pure. It consumes one immutable snapshot and one
normalized evidence object and performs no source loading, DNS, HTTP, file,
environment, enrichment, mailbox, clock, or retry operation.

The classifier rechecks the snapshot's effective and expiry bounds at the
explicit `GeneratedAt` evaluation time. A reused expired snapshot cannot yield
high-confidence classification or automatic-disposition eligibility, and an
evaluation time before the snapshot was resolved is rejected.

When source resolution uses `MaximumAge`, the snapshot authorization expiry is
the earlier of each document's declared expiry and its freshness deadline.

Each relevant campaign record exposes every factor as `matched`, `mismatched`,
`missing`, or `unverifiable`. The result retains the exact snapshot and evidence
digests, a stable record/finding graph, the original authentication variance,
and an explicit overall privileged classification. No relevant campaign yields
`unknown_suspicious_message`.

High-confidence classification also requires high-confidence provenance for the
message identity and the matched campaign-specific signal. Header or gateway
provenance supports exact message identities, verified-token provenance supports
token digests, content-scanner provenance supports content fingerprints, and
gateway provenance supports infrastructure IDs. A reporting user's assertion
alone remains reviewable evidence but cannot establish high-confidence
authorization.

When required authentication has an expected envelope domain or exact DKIM
domain/selector, a pass from a different SPF or DKIM identity cannot mask that
expected identity's failure or absence.
An exact DKIM domain/selector is a matching identity only when that signature
passes. A campaign can explicitly describe a deliberately failing DKIM path
with `authentication.dkim: not_expected`; the default `optional` expectation
does not turn a failed signature into a campaign-specific signal.

Supported result states include:

- `authorized_simulation_high_confidence`;
- `possible_authorized_simulation`;
- `simulation_configuration_mismatch`;
- `simulation_outside_campaign_window`;
- `simulation_authorization_expired`;
- `simulation_authorization_unavailable`; and
- `unknown_suspicious_message`.

Version 1 does not infer `confirmed_non_simulation`; that conclusion needs an
independent caller-owned assertion not represented by this contract. More than
one high-confidence match is treated as ambiguous: every such record is reduced
to possible, automatic disposition is disabled, and a high-severity definition
conflict finding is emitted.

Automatic-disposition eligibility requires all of the following:

1. one and only one high-confidence campaign match;
2. `automatic_disposition_eligible: true` in that campaign; and
3. `AllowAutomaticDisposition: true` in classification options.

Even then, the library performs no disposition and every finding has
`AutomaticAction: false`. The consuming application owns authorization,
retention, incident policy, and action execution.

The classifier rejects an inventory beyond `MaximumCampaignsEvaluated` and a
result beyond `MaximumRelevantRecords`. Defaults are 1,024 evaluated campaigns
and 64 relevant records. It fails without returning a partial authorization
decision.

## Privileged and disclosure-safe output

Use `WriteCampaignClassificationOutput` with JSON or JSONL. Output conversion
does not rerun classification or retrieve a source.

`CampaignOutputPrivileged` includes campaign IDs, source IDs, factor names,
classification, snapshot/evidence digests, restricted workflow identifiers,
and detailed findings. Keep it inside the campaign/SOC authorization boundary.

`CampaignOutputDisclosureSafe` is derived from the completed result without
rerunning matching. It omits campaign names and IDs, source details, exact
classifications, dates, domains, identities, infrastructure, factors, token and
content digests, and privileged workflow/template IDs. It provides neutral SOC
routing plus the fixed employee-response template ID
`suspicious-message-received`. Routing metadata itself is not employee-facing
text and must not be copied into a response.

Disclosure-safe record IDs and its result digest are derived only from the safe
representation. They are not the privileged result digest and cannot be used as
an automatic cross-boundary join key. An authorized application that needs such
a mapping must retain it separately inside the restricted boundary.

The output contract is independently versioned through
`CampaignOutputSchemaVersion`, `CampaignOutputSchemaID`, and
`CampaignClassificationOutputSchema`. The default writer view is
disclosure-safe. `CampaignClassificationResult` deliberately has no implicit
JSON marshaling contract; callers must choose the privacy view explicitly.

```go
result, err := dmarcgo.ClassifyReportedMessage(snapshot, evidence,
    dmarcgo.CampaignClassificationOptions{})
if err != nil {
    return err
}

safe, err := result.DisclosureSafe()
if err != nil {
    return err
}

// The application may map this fixed neutral template ID to approved text.
templateID := safe.Records[0].NeutralEmployeeTemplateID
_ = templateID

return dmarcgo.WriteCampaignClassificationOutput(
    writer,
    result,
    dmarcgo.CampaignOutputJSON,
    dmarcgo.CampaignOutputOptions{View: dmarcgo.CampaignOutputDisclosureSafe},
)
```

## Aggregate-report correlation

`CorrelateCampaignReportEvidence` is a separate pure path over normalized DMARC
aggregate evidence. Aggregate report periods are receiver-defined windows, not
exact per-message timestamps. Therefore aggregate results can never be
high-confidence individual-message authorization and can never be eligible for
automatic disposition.

The caller may set `CoverageSufficient` only when it knows the supplied corpus
is complete enough for a declared-not-observed diagnostic. The library never
infers corpus completeness. Aggregate evidence can support review of identity,
source, authentication variance, timing overlap, and declared campaign
visibility, but an individual reported message still needs message-level
evidence.

## Independent workflows

- **DNS only:** portfolio, explicit DNS collection, authentication parsing, and
  DNS health. No campaign data is loaded.
- **Reports only:** parsed reports and `AnalyzeReportEvidence`. No campaign or
  DNS input is required.
- **Aggregate campaign review:** completed report evidence plus a completed
  campaign snapshot through `CorrelateCampaignReportEvidence`.
- **Reported-message classification:** caller-parsed message evidence plus a
  completed campaign snapshot through `ClassifyReportedMessage`.
- **Disclosure-safe routing:** a completed classification through
  `DisclosureSafe` or `WriteCampaignClassificationOutput`.

These are composition choices in the application. None initiates another path
implicitly.

## Security and privacy checklist

- Treat configuration, provider names, source metadata, message fields,
  domains, tickets, workflow IDs, and provenance as untrusted data.
- Never concatenate retained values into prompts, explanations, headlines,
  recommendations, employee messages, actions, or instructions.
- Store privileged outputs only where campaign timing and identity are
  authorized to be known.
- Do not log raw campaign tokens, message bodies, credentials, provider errors,
  or unrestricted configuration documents.
- Do not convert a provider, domain, URL, source IP, or delivery exception into
  blanket trust.
- Preserve authentication failures and IOC/threat evidence even when a
  campaign match is high confidence.
- Keep automatic handling default-off and enforce caller-owned access control,
  audit, retention, and rollback policy.
- Never infer compromise, maliciousness, or employee behavior from a campaign
  classification alone.
