# Getting started with a domain portfolio

This journey starts with a strict application-owned YAML file and ends with a
current DNS-authentication health result. The complete compile-tested program
is in [`examples/go/domain-health`](../examples/go/domain-health).

`dmarcgo` has no global configuration directory. Your application chooses the
path, owns access control, and decides where every output goes. This example
uses:

```text
your-application/
  config/dmarcgo/portfolio.yaml
  output/
  main.go
```

## 1. Create the portfolio

Save this as `config/dmarcgo/portfolio.yaml`:

```yaml
schema_version: 1
organization:
  id: example-organization
  name: Example Organization
expected_senders:
  - id: hosted-mail
    name: Hosted Mail
    require_either: true
entities:
  - id: primary
    name: Primary Organization
    domains:
      - name: example.test
        records:
          spf:
            - example.test
          dkim:
            - selector1._domainkey.example.test
          dmarc:
            - _dmarc.example.test
        expected_senders:
          - hosted-mail
```

The file contains organization intent and complete TXT owner names. It does
not contain TXT values, credentials, API endpoints, private provider settings,
scoring calibration, or output destinations. Keep local notes in a separate
application file; strict loading rejects unknown fields rather than silently
ignoring them. The [portfolio guide](portfolio-configuration.md) defines every
field and ownership rule.

## 2. Copy and run the program

Copy [`examples/go/domain-health/main.go`](../examples/go/domain-health/main.go)
into a small Go application, add `dmarcgo`, and run it:

```shell
go get github.com/georgestarcher/dmarcgo/v3@latest
go run . \
  -portfolio config/dmarcgo/portfolio.yaml \
  -native-output output/dns-health.json \
  -agent-output output/dns-health-agent.json
```

The program deliberately performs these steps in order:

1. reads the application-owned file with `os.ReadFile`;
2. strictly loads and normalizes it with `LoadPortfolioYAML`;
3. prints the exact deduplicated TXT owner names before network access;
4. supplies `NetTXTResolver` explicitly with bounded concurrency, attempts,
   timeout, delay, failure policy, resolver ID, and collection clock;
5. calls `CollectDNSSnapshot`;
6. calls `ParseAuthenticationRecords` over the completed snapshot;
7. loads the reviewed provider catalog and calls `EvaluateDNSHealth` with the
   balanced profile; and
8. writes complete operational native JSON and a separately selected public
   agent envelope.

The library never chooses these paths, prints the display, or sends the output.
Those are application decisions visible in the program.

The synthetic fixture test produces this representative display:

```text
Planned TXT lookups (3):
 - _dmarc.example.test
 - example.test
 - selector1._domainkey.example.test
Portfolio score: 100/100 (A+); maturity: enforced; coverage: 100%; findings: 0
Native output: output/dns-health.json
Public agent output: output/dns-health-agent.json
```

Real DNS can instead produce missing, malformed, unavailable, timed-out, or
otherwise unknown evidence. Collect-all mode preserves those observations and
diagnostics so a partial run is not presented as a clean result.

## 3. Read the result

- **Score** is the weighted health calculation for observed SPF, DKIM, and
  DMARC evidence. It is not a delivery guarantee.
- **Grade** is the display band for an available score.
- **Maturity** describes how completely the domain operates authentication.
  DNS-only evidence can establish at most `enforced`; operational practices are
  required for higher levels.
- **Coverage** distinguishes conclusive observations from unknown evidence.
  Missing records are evaluated evidence, while a timeout is unknown evidence.
- **Reference membership** keeps a sister organization or comparison domain
  visible without adding it to the owned portfolio rollup.
- **Findings** are evidence-linked, library-controlled explanations and
  recommendations. Review their evidence and time before changing DNS.

A healthy current snapshot does not prove that every sender authenticates or
that the same records existed during an older report period.

## 4. Choose an output

| Need | Application choice |
| --- | --- |
| Concise human display | Assemble the few score, grade, maturity, coverage, and finding values the audience needs |
| Complete typed result | `WriteDNSHealthOutput` with native JSON |
| Streamed native records | `WriteDNSHealthOutput` with native JSONL |
| Tabular analysis | `WriteDNSHealthOutput` with native CSV |
| AI or cross-mode automation | `BuildAnalysisOutput` with an explicit public, operational, or restricted redaction profile |
| Defensive platform payload | Build STIX or a vendor-native payload only after explicit human-reviewed selection and target capability configuration |

Output builders serialize an already completed result. They do not repeat DNS
collection or analysis. `dmarcgo` does not create a polished prose report,
choose a default path, submit to a platform, or send email.

## 5. Add context only after the core result

The portfolio YAML does not configure DNS perspectives, source enrichment,
selected source activity, phishing-intelligence snapshots, or jurisdiction
context. [Optional context configuration](optional-context-configuration.md)
explains the separate caller-supplied interfaces and offline programmatic
inputs, credentials, disclosure previews, and limits.

DNS perspectives can disclose an explicit selection of declared owner names to
a caller-supplied provider. The source stages begin only after report evidence,
correlation, and candidate scoring. The library ships no general enrichment,
activity, phishing-feed, or DNS-perspective provider, and no adapter may contact
an observed subject source IP.

Campaign classification is a separate workflow. A portfolio and DNS snapshot
do not provide an authorized campaign inventory or message-level evidence.
The [report-directory journey](getting-started-report-directory.md#5-add-context-only-after-candidate-review)
has the compact interface, offline-input, and disclosure table used when those
stages become relevant.

Continue with [DNS snapshots](dns-snapshots.md),
[authentication records](authentication-records.md), or
[DNS health](dns-health.md) when field-level behavior is needed.
