# DNS and report correlation

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v3. The linked repository guides and Go documentation define behavior.

## Who this is for

Operators reviewing sender onboarding, configuration drift, or differences
between declared intent, current authentication DNS, and historical receiver
observations.

## Question this workflow answers

Which observed streams map unambiguously to declared expected senders, and
where does the completed evidence show aligned, failing, unknown, or changed
behavior?

## Inputs

A normalized `Portfolio`, a completed `DNSHealthResult`, a completed
`ReportEvidenceResult`, explicit thresholds, and optionally one caller-selected
prior correlation result.

## Activity and side effects

`CorrelateReportEvidence` is pure. It performs no DNS, parsing, enrichment,
filesystem access, history discovery, storage, retries, or clock lookup.

## Starting APIs

1. Complete the portfolio/DNS workflow.
2. Complete report-evidence analysis.
3. Call `CorrelateReportEvidence` with explicit options.
4. Serialize with `WriteDNSReportCorrelationOutput` if required.

## Outputs

Stream classifications, inventory evidence, thresholds, temporal context,
stable findings, and optional caller-directed drift comparisons.

## What this does not prove

Current DNS cannot be claimed as the cause of older report outcomes. An unknown
authentication failure is reviewable evidence, not malicious attribution.
Provider recognition never authorizes or suppresses a source.

## Sensitive data

Correlation can combine internal sender inventory with observed domains,
selectors, reporter identities, and source IPs. Select output redaction for the
recipient and retain raw operational results only inside the intended boundary.

## Safe next steps

Review configuration findings before treating a stream as unexplained. Apply
explicit message, report, reporter, duration, and recency thresholds, and keep
below-threshold streams visible as not evaluated.

## Authoritative references

- [DNS and report correlation](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-report-correlation.md)
- [Analysis architecture](https://github.com/georgestarcher/dmarcgo/blob/main/docs/architecture.md)
