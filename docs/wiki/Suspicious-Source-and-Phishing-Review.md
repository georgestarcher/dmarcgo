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
the subject IP. Phishing-intelligence correlation is a separate pure offline
stage over caller-owned snapshots and performs no provider or source-IP lookup.

## Starting APIs

1. `ScoreThreatCandidates`
2. Optionally `EnrichThreatCandidates` with a caller-supplied safe dependency
3. Optionally `CollectSourceActivity` for an explicit candidate/IP selection
4. Optionally `NormalizePhishingIntelligenceSnapshot`, then
   `CorrelatePhishingIntelligence` with the matching report evidence
5. Optionally `EvaluateJurisdictionContext` with an immutable policy
6. Inspect the immutable `SourceActivityResult` or
   `PhishingIntelligenceResult` when those branches were requested
7. Use the matching native writer, including `WriteSourceActivityOutput` or
   `WritePhishingIntelligenceOutput`, or build one common automation envelope
   from the completed result

## Outputs

Review-only candidates with inspectable score contributions, confidence caps,
severity, exclusions, recommendation codes, optional provider assertions, and
optional coarse jurisdiction context.

Source-activity context is a time-qualified third-party observation, not a
reputation score. It never changes candidate scoring, and absence never proves
that an address is safe. Selecting it can disclose the source IP and a
contact-bearing User-Agent to the provider.
`WriteSourceActivityOutput` and `BuildAnalysisOutput` serialize a completed
result only; neither initiates a lookup.

Phishing-intelligence context retains only exact source-IP and exact target,
author, SPF, or DKIM domain relations from normalized caller-owned snapshots.
It preserves time, provider state, provenance, terms, and conflicts; it never
uses brand or infrastructure context to create a match, changes no score, and
does not authorize action. `WritePhishingIntelligenceOutput` and
`BuildAnalysisOutput` serialize a completed result only and never retrieve or
refresh intelligence.

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

- [Optional context configuration](https://github.com/georgestarcher/dmarcgo/blob/main/docs/optional-context-configuration.md)
- [Suspicious-source candidate scoring](https://github.com/georgestarcher/dmarcgo/blob/main/docs/threat-candidates.md)
- [Optional source enrichment](https://github.com/georgestarcher/dmarcgo/blob/main/docs/source-enrichment.md)
- [Optional source-activity context](https://github.com/georgestarcher/dmarcgo/blob/main/docs/source-activity.md)
- [Optional phishing-intelligence correlation](https://github.com/georgestarcher/dmarcgo/blob/main/docs/phishing-intelligence.md)
- [Jurisdiction context](https://github.com/georgestarcher/dmarcgo/blob/main/docs/jurisdiction-context.md)
