# Scoring, confidence, and maturity

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v3. The linked repository guides and Go documentation define behavior.

## Who this is for

Users interpreting DNS-health scores, DNS maturity, suspicious-source scores,
candidate confidence, or optional jurisdiction priority adjustment.

## Question this workflow answers

What does each numeric or categorical result mean, and which concepts must not
be combined into a single risk verdict?

## Inputs

Completed results from the workflow that produced the value, including its
named versioned profile, contributions, evidence coverage, caps, and metadata.

## Activity and side effects

The scoring and maturity evaluators are pure. Reading or serializing their
results triggers no new collection or enrichment.

## Starting APIs

- `EvaluateDNSHealth` for independent SPF, DKIM, DMARC, and rollup posture.
- `ScoreThreatCandidates` for review-priority candidates.
- `EvaluateJurisdictionContext` for a separate, default-off priority adjustment.

## Outputs

- DNS health: explainable posture score, grade, coverage, and categorical
  maturity. DNS-only evidence can establish at most `enforced` maturity.
- Candidate scoring: review priority with explicit contributions and
  false-positive-sensitive confidence caps.
- Jurisdiction context: a separate optional adjustment capped at 10; it never
  changes the threat score.

## What this does not prove

A score is not a compromise probability, maliciousness verdict, sender
authorization, legal determination, or enforcement instruction. Confidence
describes evidence sufficiency, not certainty that a source is hostile.

## Sensitive data

Contribution evidence may contain operational identifiers even when generated
explanations are controlled. Choose the correct privacy view and inspect the
serialized schema rather than copying raw fields into prose.

## Safe next steps

Display the profile, evidence coverage, deductions or contributions, caps, and
limitations beside every score. Compare like versions and keep DNS posture,
candidate priority, and jurisdiction context visually distinct.

## Authoritative references

- [DNS authentication health](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-health.md)
- [Suspicious-source candidate scoring](https://github.com/georgestarcher/dmarcgo/blob/main/docs/threat-candidates.md)
- [Jurisdiction context](https://github.com/georgestarcher/dmarcgo/blob/main/docs/jurisdiction-context.md)
