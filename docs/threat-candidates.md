# Suspicious-source candidate scoring

`ScoreThreatCandidates` converts completed normalized report evidence and
completed DNS/report correlation into neutral, reviewable source candidates.
It consumes a normalized `Portfolio`, `ReportEvidenceResult`, and
`DNSReportCorrelationResult`; it performs no DNS queries, report parsing,
source enrichment, filesystem access, clock access, storage, or retries.

A candidate means that supplied receivers observed policy-evaluated aligned
DKIM and SPF failures from one source address. It is not a claim that the
address, its owner, or every message from it is malicious, compromised, part of
a botnet, or safe to block. `PromotionEligible` is always false in this stage.

## Evidence model

Each canonical source address is counted directly from distinct normalized
`ReportEvidenceObservation` values. Correlation streams can expand one row into
multiple DKIM identity views, so their message counters are never summed into a
candidate. Correlation contributes only prepared organization attribution,
expected-sender identity, provider context, threshold state, and evidence
references.

Candidates retain:

- stable organization-and-source identity plus canonical IPv4 or IPv6 type;
- total observed, aligned dual-failure, passing, unknown, and expected-sender
  failure message counts;
- distinct reports and reporters, report-period bounds, affected author
  domains, entities, dispositions, and evidence references;
- every score operation, confidence cap, and before/after value;
- normalized policy-override type codes and shared-provider context as
  counter-evidence;
- every relevant active, expired, future, matched, and unmatched portfolio
  exclusion; and
- review eligibility, explicit non-promotion status, and advisory usage.

Reporter-supplied override comments and unknown types are discarded during
report-evidence normalization. Recognized types such as `mailing_list` and
`trusted_forwarder` remain structured untrusted data. They lower score and
confidence because indirect mail can create legitimate DMARC interoperability
failures, but they do not prove that traffic is benign.

## Score and confidence

Scores and confidence are independent integers from 0 through 100. Supporting
score features are applied first, followed by deductions, with every operation
clamped to that range. `RecomputeThreatCandidateScore` and
`RecomputeThreatCandidateConfidence` validate the complete explanation and
reproduce the final values.

Supporting score features are:

- policy-evaluated aligned DKIM and SPF failure;
- failures in multiple reports;
- persistence across the configured report-period duration;
- failure volume at or above the configured threshold;
- multiple independent reporters;
- receiver-reported reject or quarantine disposition; and
- the same source failing for multiple author domains.

Counter-evidence and uncertainty features are:

- mixed DMARC-passing traffic from the same source;
- declared expected-sender attribution when a caller explicitly includes it;
- prepared shared-provider context;
- forwarding or mailing-list policy-override types;
- incomplete report or correlation evidence;
- low failure volume; and
- stale report periods.

Confidence begins at 100 and receives inspectable caps for each applicable
uncertainty, including an unconditional unenriched cap. Single-report and
single-reporter caps prevent a large row from appearing independently
corroborated. Severity is derived from the lower of score and confidence, so a
high raw score cannot bypass an evidence-quality cap. This stage never emits
critical severity.

## Profiles

The built-in conservative, balanced, and sensitive profiles use scoring
version `1`. Zero-value options select balanced. Use
`ThreatCandidateScoringProfiles` or
`ThreatCandidateScoringProfileForName` to inspect every threshold, weight,
deduction, severity band, and confidence cap.

- Conservative requires stronger corroboration and applies the lowest
  confidence caps.
- Balanced is the default review policy.
- Sensitive promotes more low-volume evidence to human review but does not
  change the non-promotion safety boundary.

For a custom profile, copy a built-in value or construct the full
`ThreatCandidateScoringProfile`, set `Name` to `custom`, retain the current
version, and pass it through `ThreatCandidateOptions.CustomProfile`. Invalid
weights, caps, threshold ordering, negative durations, and incompatible
versions fail with `ErrInvalidThreatCandidateOptions`.

## Expected senders and exclusions

Expected-sender-only failures are omitted by default and counted in
`ThreatCandidateSummary` instead. Correlation retains them as configuration
findings. Set `IncludeExpectedSenders` only when an application intentionally
wants those failures in candidate review; expected-sender deductions and caps
then remain visible.

Portfolio exclusions require owner, reason, creation time, scope, and optional
expiration. The `source` scope accepts a canonical IP address or network
prefix. A source, sender, domain, or subdomain exclusion applies only within
the portfolio domain where it is declared. A cross-domain source candidate is
excluded from review only when active matching exclusions cover every affected
domain. Expired exclusions remain visible but inactive. Scores are preserved
even when review is excluded, so caller policy never erases evidence.

Exclusion reasons are caller-owned restricted text. Applications must keep them
as data and must not convert them into generated instructions.

## Safe use

`ReviewEligible` means only that the candidate reached the selected human-review
threshold and is not fully excluded. Recommended usage is one of
`review_only`, `monitor_only`, or `retain_evidence_only`. None authorizes an
automatic block, allowlist, scan, abuse submission, or direct connection to the
observed source address.

Future enrichment is a separate explicitly invoked stage. Candidate scoring
marks enrichment `not_evaluated`, performs no PTR lookup, and sends no DNS,
HTTP, SMTP, ICMP, or other traffic to or about the source.

## Example

```go
candidates, err := dmarcgo.ScoreThreatCandidates(
    portfolio,
    reportEvidence,
    correlation,
    dmarcgo.ThreatCandidateOptions{
        Profile:     dmarcgo.ThreatCandidateProfileBalanced,
        GeneratedAt: assessmentTime,
    },
)
if err != nil {
    return err
}

for _, candidate := range candidates.Candidates() {
    if candidate.ReviewEligible {
        queueForHumanReview(candidate)
    }
}
```

The result retains portfolio, report-evidence, and correlation digests. Its
candidate and summary accessors return defensive copies.
