# dmarcgo documentation

The project wiki is a task-oriented navigation layer for new users. These
repository guides, the Go documentation, and embedded schemas are the
authoritative, versioned sources for behavior.

## Recommended reading paths

| Audience | Start here | Continue with |
| --- | --- | --- |
| New Go application developer | [Organization adoption](adoption-guide.md) | [Consumer-agent guide](consumer-agent-guide.md), then the selected feature guide |
| Email or DNS administrator | [Configuration reference](configuration-reference.md) | [Portfolio configuration](portfolio-configuration.md), [DNS snapshots](dns-snapshots.md), and [DNS health](dns-health.md) |
| SOC or security engineering | [Automation workflows](automation-workflows.md) | [Optional context configuration](optional-context-configuration.md), then correlation, threat-candidate, and export guides |
| Security-awareness team | [Campaign correlation](campaign-correlation.md) | [Configuration reference](configuration-reference.md) and disclosure-safe output guidance |
| Platform operator or reviewer | [Operations and troubleshooting](operations-and-troubleshooting.md) | [Analysis architecture](architecture.md) and [output contract](output-contract.md) |
| AI coding assistant integrating the module | [Consumer-agent guide](consumer-agent-guide.md) | [Organization adoption](adoption-guide.md) and machine-readable schemas |

## Choose a workflow

| Goal | Authoritative guide |
| --- | --- |
| Adopt the complete library safely | [Organization adoption](adoption-guide.md) |
| Look up exact portfolio and campaign fields | [Configuration reference](configuration-reference.md) |
| Integrate from an AI coding assistant | [Consumer-agent guide](consumer-agent-guide.md) |
| Operate, roll out, and troubleshoot an integration | [Operations and troubleshooting](operations-and-troubleshooting.md) |
| Configure optional enrichment, activity, intelligence, jurisdiction, or DNS perspectives | [Optional context configuration](optional-context-configuration.md) |
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
| Add selected third-party source-activity context | [Source activity](source-activity.md) |
| Correlate caller-owned phishing intelligence offline | [Phishing intelligence](phishing-intelligence.md) |
| Add coarse, qualified jurisdiction context | [Jurisdiction context](jurisdiction-context.md) |
| Build STIX 2.1 observations | [STIX export](stix-export.md) |
| Build ThreatConnect v3 request payloads | [ThreatConnect export](threatconnect-export.md) |
| Build MISP Attribute or Event payloads | [MISP export](misp-export.md) |
| Build tenant-contract ThreatStream payloads | [ThreatStream export](threatstream-export.md) |
| Understand why aggregate evidence is not exported as XARF | [XARF v4 feasibility decision](xarf-feasibility.md) |
| Compose independent stages and outputs | [Automation workflows](automation-workflows.md) |

## Other contracts

- [README](../README.md): installation, API chooser, and package overview
- [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2)
- [Output schemas](../schemas)
- [Changelog](../CHANGELOG.md)
- [Task-oriented project wiki](https://github.com/georgestarcher/dmarcgo/wiki)

## Documentation validation

Run the complete local documentation gate with:

```shell
make docs-check
```

The gate compiles README code blocks in an isolated consumer module, executes
all Go examples, loads the public portfolio and campaign fixtures through the
strict APIs, validates the canonical wiki source, checks exact internal paths
and Markdown anchors, rejects formatting and curated spelling regressions, and
scans public samples for credential/private-data markers and non-reserved
domains or addresses. Go examples have one narrow exception: an exact public
provider DNS name already present in a reviewed DNS field of the embedded
provider catalog may demonstrate catalog matching. Organization domains and
source addresses must still use reserved documentation values.

Intentional spelling exceptions belong in
[`scripts/docs_spelling_allowlist.txt`](../scripts/docs_spelling_allowlist.txt),
one literal word per line with a short comment explaining unusual additions.
The checker deliberately does not probe external links during CI; external
availability and first-party contract review remain part of the relevant
feature-maintenance process.

Wiki source is maintained under [`docs/wiki`](wiki) and published only from
trusted `main` after pull-request validation. See
[wiki maintenance](wiki/Wiki-Maintenance.md) for the contribution and privacy
boundary.
