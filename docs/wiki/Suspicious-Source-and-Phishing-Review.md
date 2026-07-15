# Suspicious-source and phishing review

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. The linked repository guides and Go documentation define behavior.

## Who this is for

Defensive analysts who need a bounded, explainable queue of unexplained source
addresses for human review after sender-inventory and correlation findings have
already been considered.

## Question this workflow answers

Which neutral source candidates have enough repeated, recent, and sufficiently
independent authentication-failure evidence to deserve review?

## Inputs

A normalized portfolio, completed report evidence, completed DNS/report
correlation, a versioned scoring profile, and optional scoped caller-owned
exclusions.

## Activity and side effects

`ScoreThreatCandidates` is pure and performs no DNS, PTR, HTTP, SMTP, ICMP,
scanning, enrichment, storage, retries, clock lookup, or other source-IP
activity. Optional enrichment and optional source-activity context are separate
explicit stages and may use only caller-selected third-party services, never
the subject IP.

## Starting APIs

1. `ScoreThreatCandidates`
2. Optionally `EnrichThreatCandidates` with a caller-supplied safe dependency
3. Optionally `CollectSourceActivity` for an explicit candidate/IP selection
4. Optionally `EvaluateJurisdictionContext` with an immutable policy
5. Inspect the immutable `SourceActivityResult` when that branch was requested
6. `WriteThreatCandidatesOutput`, `WriteSourceEnrichmentOutput`, or
   `WriteJurisdictionContextOutput`

## Outputs

Review-only candidates with inspectable score contributions, confidence caps,
severity, exclusions, recommendation codes, optional provider assertions, and
optional coarse jurisdiction context.

Source-activity context is a time-qualified third-party observation, not a
reputation score. It never changes candidate scoring, and absence never proves
that an address is safe. Selecting it can disclose the source IP and a
contact-bearing User-Agent to the provider.
Current output writers do not serialize this result and never initiate its
lookups; cross-mode output integration is a separate contract change.

## What this does not prove

DMARC failure, candidate score, hosting geography, ASN, or provider recognition
does not prove phishing, compromise, actor identity, nationality, or malicious
intent. `PromotionEligible` remains false and no result is safe-to-block advice.

## Sensitive data

Operational output contains source IPs and organization context. Enrichment
provenance is untrusted data. Apply recipient authorization, minimization,
transport security, retention, and the appropriate output redaction.

## Safe next steps

Investigate candidates through approved defensive workflows, preserve evidence,
and use explicit exclusions for understood sources. Keep direct interaction
with a potentially adversarial source address out of the default path.

## Authoritative references

- [Suspicious-source candidate scoring](https://github.com/georgestarcher/dmarcgo/blob/main/docs/threat-candidates.md)
- [Optional source enrichment](https://github.com/georgestarcher/dmarcgo/blob/main/docs/source-enrichment.md)
- [Optional source-activity context](https://github.com/georgestarcher/dmarcgo/blob/main/docs/source-activity.md)
- [Jurisdiction context](https://github.com/georgestarcher/dmarcgo/blob/main/docs/jurisdiction-context.md)
