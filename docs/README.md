# dmarcgo documentation

The project wiki is a task-oriented navigation layer for new users. These
repository guides, the Go documentation, and embedded schemas are the
authoritative, versioned sources for behavior.

## Choose a workflow

| Goal | Authoritative guide |
| --- | --- |
| Understand stage ownership and side effects | [Analysis architecture](architecture.md) |
| Define organizations, domains, records, and expected senders | [Portfolio configuration](portfolio-configuration.md) |
| Collect declared DNS evidence | [DNS snapshots](dns-snapshots.md) |
| Compare selected names across optional remote resolver perspectives | [DNS perspectives](dns-perspectives.md) |
| Parse SPF, DKIM, and DMARC records | [Authentication records](authentication-records.md) |
| Evaluate DNS posture and maturity | [DNS health](dns-health.md) |
| Add context-only provider recognition | [Provider catalog](provider-catalog.md) |
| Normalize aggregate-report evidence | [Report evidence](report-evidence.md) |
| Compare DNS, declared senders, and reports | [DNS/report correlation](dns-report-correlation.md) |
| Classify approved security simulations | [Campaign correlation](campaign-correlation.md) |
| Score neutral sources for human review | [Threat candidates](threat-candidates.md) |
| Add optional source and ASN context | [Source enrichment](source-enrichment.md) |
| Add coarse, qualified jurisdiction context | [Jurisdiction context](jurisdiction-context.md) |
| Build STIX 2.1 observations | [STIX export](stix-export.md) |
| Build ThreatConnect v3 request payloads | [ThreatConnect export](threatconnect-export.md) |
| Build MISP Attribute or Event payloads | [MISP export](misp-export.md) |
| Build tenant-contract ThreatStream payloads | [ThreatStream export](threatstream-export.md) |
| Compose independent stages and outputs | [Automation workflows](automation-workflows.md) |

## Other contracts

- [README](../README.md): installation, API chooser, and package overview
- [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2)
- [Output schemas](../schemas)
- [Changelog](../CHANGELOG.md)
- [Task-oriented project wiki](https://github.com/georgestarcher/dmarcgo/wiki)

Wiki source is maintained under [`docs/wiki`](wiki) and published only from
trusted `main` after pull-request validation. See
[wiki maintenance](wiki/Wiki-Maintenance.md) for the contribution and privacy
boundary.
