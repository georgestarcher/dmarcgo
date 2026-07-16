# Approved campaign classification

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v3. The linked repository guides and Go documentation define behavior.

## Who this is for

Security teams that run approved phishing simulations and need to compare a
reported message or lower-confidence aggregate evidence with an externally
maintained campaign inventory.

## Question this workflow answers

Does bounded message-header evidence match an active, explicitly configured
security-simulation campaign strongly enough for the caller's review policy?

## Inputs

Strict campaign YAML or JSON supplied through explicit byte, file, directory,
environment, HTTPS, or custom sources; a completed immutable campaign snapshot;
and normalized header-focused reported-message evidence or completed aggregate
report evidence.

## Activity and side effects

Configuration normalization and classification are pure. Source resolution is
explicit and bounded. Classification retrieves no body, performs no DNS, sends
no response, and takes no enforcement action.

## Starting APIs

1. `LoadCampaignConfiguration`, `NormalizeCampaignConfiguration`, or
   `ResolveCampaignConfiguration`
2. `NormalizeReportedMessageEvidence`
3. `ClassifyReportedMessage` for an individual report
4. `CorrelateCampaignReportEvidence` for aggregate review
5. `WriteCampaignClassificationOutput` with an explicit privacy view

## Outputs

Deterministic classification evidence, source freshness and provenance,
privileged or disclosure-safe views, and neutral response-routing information.

## What this does not prove

A provider, domain, or source address is not an allowlist. Aggregate evidence
cannot prove that one individual message belongs to a campaign. Automatic
disposition requires deliberate caller policy and all required opt-ins.

## Sensitive data

Campaign names, infrastructure, windows, recipients, and operator notes may be
highly sensitive. Do not publish real inventories. Default to the
disclosure-safe view outside the privileged security boundary.

## Safe next steps

Resolve required sources before a review window, fail closed when required data
is stale or unavailable, and route employee responses without disclosing
campaign details unless the caller explicitly authorizes that disclosure.

## Authoritative references

- [Security-simulation campaign correlation](https://github.com/georgestarcher/dmarcgo/blob/main/docs/campaign-correlation.md)
- [Automation workflows](https://github.com/georgestarcher/dmarcgo/blob/main/docs/automation-workflows.md)
