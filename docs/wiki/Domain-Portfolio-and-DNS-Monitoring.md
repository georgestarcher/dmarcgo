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
- Optionally, an explicit `DNSPerspectiveProvider` and exact owner-name or
  SPF/DKIM/DMARC role selection when remote resolver-consistency context is
  authorized.

## Activity and side effects

Loading and normalizing the portfolio is offline. `CollectDNSSnapshot` is the
only DNS collection stage and queries only normalized, declared owner names.
Record parsing and health evaluation are pure operations over completed values.

`CollectDNSPerspectives` is a separate optional networked branch. It discloses
only the selected portfolio/snapshot TXT owner names to a caller-supplied
provider. It does not discover names, retry, query source IPs, or change DNS
health. The library ships no DShield adapter because current research did not
establish usable authentication-owner TXT behavior.

## Starting APIs

1. `LoadPortfolioYAML` or `NormalizePortfolio`
2. `CollectDNSSnapshot`
3. `ParseAuthenticationRecords`
4. `EvaluateDNSHealth`
5. Optionally, `CollectDNSPerspectives` with an explicit disclosure selection
6. `WriteDNSHealthOutput` when serialization is needed

## Outputs

Immutable DNS evidence, parsed authentication-record semantics, independent
SPF/DKIM/DMARC mechanism health, findings, coverage, scores, grades, categorical
maturity, and entity/portfolio rollups.

The optional perspective result adds answer-set agreement, disagreement, and
incomplete-coverage context. It is not authoritative DNS evidence and does not
alter those posture outputs.

## Point-in-time example

The project maintainer authorized this real-domain summary for illustration.
It is a point-in-time observation of public DNS for `georgestarcher.com`, not a
fixture or a continuing claim about the domain. A run at
`2026-07-15T23:53:44Z` using the balanced scoring profile version 1 produced:

| Result | Score | Grade |
| --- | ---: | --- |
| SPF | 100/100 | A+ |
| DKIM | 85/100 | B |
| DMARC | 100/100 | A+ |
| Weighted domain and portfolio result | 95/100 | A+ |

The calculation was `(100 x 30%) + (85 x 35%) + (100 x 35%) = 94.75`,
rounded to 95. The domain reached `enforced` DNS maturity with 100% collection
coverage across its three explicitly declared record names. The 15-point DKIM
component deduction reflected a published 1024-bit RSA key rather than the
recommended 2048-bit minimum.

This example also demonstrates why the surrounding evidence matters. Complete
collection coverage means every declared record name had a conclusive outcome;
it does not mean that every SPF dependency was collected or that every sender
uses the records correctly. DNS alone also cannot verify that aggregate reports
are received, retained, and reviewed. Scores and findings may differ on a later
run as DNS, the declared portfolio, or the selected versioned profile changes.

## What this does not prove

A healthy DNS snapshot does not prove that every sending system uses the
records, that every message authenticates, or that an organization is free of
abuse. Provider recognition supplies context only and never authorizes a sender.

## Sensitive data

Operational portfolios can reveal private domains, selectors, providers, and
ownership. Keep private portfolios outside the repository. Public examples
should normally be synthetic; the point-in-time example above is a narrowly
scoped exception published with the domain owner's explicit permission and does
not include the portfolio file or TXT record values.

## Safe next steps

Begin with the runnable
[portfolio-to-health journey](https://github.com/georgestarcher/dmarcgo/blob/main/docs/getting-started-domain-health.md).
Review low-coverage and unhealthy mechanisms, correct the declared inventory
or DNS through a caller-owned change process, then collect a new snapshot. Add
historical report evidence only when the question requires observed mail flows.

## Authoritative references

- [Runnable portfolio-to-health journey](https://github.com/georgestarcher/dmarcgo/blob/main/docs/getting-started-domain-health.md)
- [Complete Go example](https://github.com/georgestarcher/dmarcgo/tree/main/examples/go/domain-health)
- [Portfolio configuration](https://github.com/georgestarcher/dmarcgo/blob/main/docs/portfolio-configuration.md)
- [DNS snapshot collection](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-snapshots.md)
- [Optional DNS perspective collection](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-perspectives.md)
- [Authentication-record parsing](https://github.com/georgestarcher/dmarcgo/blob/main/docs/authentication-records.md)
- [DNS authentication health](https://github.com/georgestarcher/dmarcgo/blob/main/docs/dns-health.md)
- [Provider catalog](https://github.com/georgestarcher/dmarcgo/blob/main/docs/provider-catalog.md)
