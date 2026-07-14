# Domain portfolio and DNS monitoring

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. The linked repository guides and Go documentation define behavior.

## Who this is for

Operators who own a set of domains and want a repeatable view of their current
SPF, DKIM, and DMARC posture without first ingesting aggregate reports.

## Question this workflow answers

Are the explicitly monitored authentication record names present, parseable,
current enough for the selected policy, and consistent with the organization's
declared sender inventory?

## Inputs

- Versioned organization portfolio YAML or a programmatic `PortfolioConfig`.
- Complete SPF, DKIM, and DMARC TXT owner names, including full DKIM
  `_domainkey` names. Store names, never live TXT values or credentials.
- An explicit `TXTResolver` selected by the application.
- An explicit provider catalog and DNS-health options.

## Activity and side effects

Loading and normalizing the portfolio is offline. `CollectDNSSnapshot` is the
only DNS collection stage and queries only normalized, declared owner names.
Record parsing and health evaluation are pure operations over completed values.

## Starting APIs

1. `LoadPortfolioYAML` or `NormalizePortfolio`
2. `CollectDNSSnapshot`
3. `ParseAuthenticationRecords`
4. `EvaluateDNSHealth`
5. `WriteDNSHealthOutput` when serialization is needed

## Outputs

Immutable DNS evidence, parsed authentication-record semantics, independent
SPF/DKIM/DMARC mechanism health, findings, coverage, scores, grades, categorical
maturity, and entity/portfolio rollups.

## What this does not prove

A healthy DNS snapshot does not prove that every sending system uses the
records, that every message authenticates, or that an organization is free of
abuse. Provider recognition supplies context only and never authorizes a sender.

## Sensitive data

Operational portfolios can reveal private domains, selectors, providers, and
ownership. Keep private portfolios outside the repository. Public examples must
be synthetic.

## Safe next steps

Review low-coverage and unhealthy mechanisms, correct the declared inventory or
DNS through a caller-owned change process, then collect a new snapshot. Add
historical report evidence only when the question requires observed mail flows.

## Authoritative references

- [Portfolio configuration](https://github.com/georgestarcher/dmarcgo/blob/main/docs/portfolio-configuration.md)
- [DNS snapshot collection](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-snapshots.md)
- [Authentication-record parsing](https://github.com/georgestarcher/dmarcgo/blob/main/docs/authentication-records.md)
- [DNS authentication health](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-health.md)
- [Provider catalog](https://github.com/georgestarcher/dmarcgo/blob/main/docs/provider-catalog.md)
