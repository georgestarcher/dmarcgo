# dmarcgo project wiki

> **Navigation guide, not a versioned contract.** This wiki tracks the current `dmarcgo` v2 line. The repository's Go documentation, schemas, and focused guides are authoritative.

`dmarcgo` is a Go library for parsing DMARC aggregate reports and performing
explicit, independently callable analysis stages. It is not a mailbox ingester,
scheduler, dashboard, reputation service, or automatic enforcement system.

## Choose the question you need to answer

| Question | Start here |
| --- | --- |
| What SPF, DKIM, and DMARC records do our domains publish now? | [Domain portfolio and DNS monitoring](Domain-Portfolio-and-DNS-Monitoring) |
| Do selected authentication names look consistent from optional remote resolver perspectives? | [Domain portfolio and DNS monitoring](Domain-Portfolio-and-DNS-Monitoring) |
| What did receivers observe in our aggregate reports? | [DMARC report ingestion and reporting](DMARC-Report-Ingestion-and-Reporting) |
| Do current DNS and historical report evidence agree with declared senders? | [DNS and report correlation](DNS-and-Report-Correlation) |
| Which unexplained source addresses deserve human review? | [Suspicious-source and phishing review](Suspicious-Source-and-Phishing-Review) |
| Does a reported message match an approved security simulation? | [Approved campaign classification](Approved-Campaign-Classification) |
| How should I interpret scores, confidence, and maturity? | [Scoring, confidence, and maturity](Scoring-Confidence-and-Maturity) |
| How can reviewed evidence be encoded for another defensive platform? | [Defensive exports](Defensive-Exports) |
| How can automation or an AI consumer use outputs safely? | [Automation outputs and AI safety](Automation-Outputs-and-AI-Safety) |
| Where are the API, schema, standards, and versioning contracts? | [API, schemas, standards, and versioning](API-Schemas-Standards-and-Versioning) |

## Safety model

- Parsing a report performs no DNS or other network access.
- DNS collection occurs only through an explicitly supplied resolver and only
  for record names declared in a normalized portfolio.
- Source enrichment is optional, caller supplied, and must not contact the
  observed source IP.
- Authentication failure is review evidence, not proof of malicious activity.
- Export builders create offline payloads; they do not submit, publish, block,
  or enforce.
- Real domains, source addresses, report corpora, campaign inventories, and
  credentials do not belong in this public repository or wiki.

## Repository documentation

Use the [documentation index](https://github.com/georgestarcher/dmarcgo/blob/main/docs/README.md)
to find the authoritative guide for each workflow. Start with the
[README](https://github.com/georgestarcher/dmarcgo/blob/main/README.md) and
[Go package documentation](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2)
for installation and API discovery. Maintainers should follow the
[wiki maintenance workflow](Wiki-Maintenance).
