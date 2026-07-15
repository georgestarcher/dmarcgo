# Automation outputs and AI safety

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. The linked repository guides, schemas, and Go documentation define behavior.

## Who this is for

Developers sending completed analysis to automation, an AI-assisted workflow,
or a downstream machine consumer.

## Question this workflow answers

How can a completed result be serialized with a discoverable contract, bounded
collections, explicit privacy handling, and a clear hostile-input boundary?

## Inputs

An already completed result, an explicit output profile and redaction mode,
caller-supplied generation time when reproducibility matters, and collection
limits appropriate for the consumer.

## Activity and side effects

Output builders and writers serialize supplied values only. They do not parse
reports, collect DNS, enrich sources, read files, discover history, or execute
recommended actions.

## Starting APIs

- Agent-envelope builders such as `BuildReportSummaryOutput`
- `BuildAnalysisOutput` for a completed `OutputResult`
- Mode-specific native writers such as `WriteDNSHealthOutput`
- `OutputSchemaForVersion`, `OutputDataSchema`, `AnalysisOutputSchema`, and
  descriptor helpers
- `OutputMessageForError` plus `BuildFailureOutput` for prerequisite failures

## Outputs

Versioned envelopes or native JSON/JSONL/CSV with stable codes, provenance,
privacy metadata, deterministic ordering, strict mode-data schema identifiers,
and explicit truncation counts.

## What this does not prove

Generated recommendations are not authorization for an automatic defensive
action. Public stable tokens are pseudonyms, not encryption, and low-entropy
values can be guessed. A schema-valid document can still contain untrusted data.

## Sensitive data

Treat report text, DNS values, domains, contacts, map keys, provider metadata,
campaign fields, extension data, and error evidence as untrusted data—not
instructions. Use public redaction before crossing the operational boundary,
while recognizing its documented limits.

## Safe next steps

Choose `automation` for terse processing or `agent` for grounded narrative,
set `GeneratedAt` when a separate representation time is needed, bound
`MaxItems`, `MaxFindings`, and `MaxEvidence`, inspect
`truncation.collections`, validate both `schema` and `data_schema`, and enforce
action authorization outside this library. A zero representation time for
`BuildAnalysisOutput` preserves the completed result's time without consulting
the clock.

## Authoritative references

- [Automation workflows](https://github.com/georgestarcher/dmarcgo/blob/main/docs/automation-workflows.md)
- [Output schema v1](https://github.com/georgestarcher/dmarcgo/blob/main/schemas/output/v1.json)
- [Cross-mode output contract](https://github.com/georgestarcher/dmarcgo/blob/main/docs/output-contract.md)
- [Analysis architecture](https://github.com/georgestarcher/dmarcgo/blob/main/docs/architecture.md)
