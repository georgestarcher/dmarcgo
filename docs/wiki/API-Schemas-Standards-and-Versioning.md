# API, schemas, standards, and versioning

> **Navigation guide, not a versioned contract.** This page tracks `dmarcgo` v2. The repository's Go documentation, schemas, and focused guides are authoritative.

## Who this is for

Developers choosing an API, validating serialized output, evaluating standards
support, or planning an upgrade.

## Question this workflow answers

Where is the stable contract for parsing, analysis, output, schemas, and
standards behavior?

## Inputs

The installed module version, selected analysis/output mode, and any destination
contract that the consuming application must satisfy.

## Activity and side effects

API and schema discovery are offline. Package helpers do not initiate analysis
or network access unless the chosen operation explicitly accepts an I/O
dependency, such as a resolver or enricher.

## Starting APIs

- Import `github.com/georgestarcher/dmarcgo/v2`.
- Use `OutputSchemaVersions`, `OutputSchemaForVersion`,
  `SupportedOutputModes`, `AnalysisOutputDescriptorForMode`, and
  `AnalysisOutputSchema` for contract discovery.
- Use the focused guide linked from the [documentation index](https://github.com/georgestarcher/dmarcgo/blob/main/docs/README.md).

## Outputs

Versioned Go values, embedded schemas, stable mode and finding codes, and
standards-native payloads where documented.

## What this does not prove

Wiki text is not a substitute for the contract shipped with a selected module
version. Vendor exports still require the caller to confirm the current target
instance contract and lifecycle behavior.

## Sensitive data

Schemas describe shape, not recipient authorization. Operational and restricted
values can remain sensitive even when valid. Never put credentials or private
organization data into examples or schema fixtures.

## Safe next steps

Pin a module version, validate serialized output against that release's embedded
schema, review changelog entries before upgrading, and treat major-version
changes as explicit migrations.

## Authoritative references

- [Go package documentation](https://pkg.go.dev/github.com/georgestarcher/dmarcgo/v2)
- [Documentation index](https://github.com/georgestarcher/dmarcgo/blob/main/docs/README.md)
- [Schemas](https://github.com/georgestarcher/dmarcgo/tree/main/schemas)
- [Changelog](https://github.com/georgestarcher/dmarcgo/blob/main/CHANGELOG.md)
- [RFC 9990 aggregate reporting](https://www.rfc-editor.org/rfc/rfc9990.html)
- [RFC 9989 DMARC](https://www.rfc-editor.org/rfc/rfc9989.html)
