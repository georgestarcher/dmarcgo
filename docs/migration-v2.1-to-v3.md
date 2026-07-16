# Migrate from v2.1 to v3

Version 3 publishes the complete organization-analysis feature pack under the
required Go module path `github.com/georgestarcher/dmarcgo/v3`. The new
capabilities are additive, but the finalized Go API contains deliberate source
incompatibilities with v2.1.0, so this is a semantic-major release.

## Application migration

1. Change the module requirement and every import from `/v2` to `/v3`:

   ```shell
   go get github.com/georgestarcher/dmarcgo/v3@v3.0.0
   go mod tidy
   ```

2. Replace the former validation-output call:

   ```go
   result := report.ValidationResult(dmarcgo.ValidationModeCompatibility, generatedAt)
   output, err := dmarcgo.BuildValidationOutput(result, options)
   ```

   `BuildValidationOutput` no longer accepts a report plus findings. Validation
   is completed before serialization, preserving the no-analysis output
   boundary.

3. When constructing common-envelope values directly, use the named string
   types now required by `OutputAction.Code`, `OutputFinding.Code`,
   `OutputFinding.ActionCodes`, `OutputEvidence.Provenance`,
   `OutputEvidence.Sensitivity`, `OutputMessage.Code`, and
   `OutputProvenance.ID`. Their serialized JSON strings are unchanged.

4. Stop comparing `OutputInput` with `==` or using it as a map key. It now owns
   artifact and coverage slices; compare the relevant fields or its serialized
   value instead.

5. Validate newly generated common envelopes against output schema v2.
   `OutputSchema()` returns v2, while `OutputSchemaForVersion("1")` retains the
   exact immutable schema released with v2.1.0.

No compatibility facade is included because there are no known external v2
consumers. The historical v1 and v2 tags remain available and are not rewritten.

## Independent contract versions

The Go module major does not reset every serialized contract. Native analysis,
campaign, report-evidence persistence, scoring-profile, jurisdiction-policy,
STIX-extension, and vendor mapping versions change only when their own contract
changes. Most were introduced after v2.1.0 and are first published unchanged in
v3.0.0.

The common envelope is the exception: its required shape changed after v2.1.0,
so v3 emits envelope schema v2 and continues to expose the released v1 document
for consumers validating stored output.

STIX and MISP deterministic identifiers deliberately retain their original
dmarcgo UUIDv5 namespaces. Changing a Go import path alone must not create new
identifiers for semantically identical evidence or defeat destination-side
deduplication.

## Reproduce the API comparison

The release audit compares v2.1.0 with commit
`d878168b376b3ba9cfba803cba56408830c28c91`, the final pre-migration `/v2`
snapshot. Using that snapshot separates actual API-shape changes from the
required `/v3` import-path change.

```shell
tool=golang.org/x/exp/cmd/apidiff@v0.0.0-20260709172345-9ea1abe57597
audit_dir="$(mktemp -d)"
mkdir -p "${audit_dir}/old" "${audit_dir}/new"
git archive v2.1.0 | tar -x -C "${audit_dir}/old"
git archive d878168b376b3ba9cfba803cba56408830c28c91 | tar -x -C "${audit_dir}/new"
(cd "${audit_dir}/old" && go run "${tool}" -m -w "${audit_dir}/old.export" github.com/georgestarcher/dmarcgo/v2)
(cd "${audit_dir}/new" && go run "${tool}" -m -w "${audit_dir}/new.export" github.com/georgestarcher/dmarcgo/v2)
go run "${tool}" -m -incompatible "${audit_dir}/old.export" "${audit_dir}/new.export"
```

The incompatible result is exactly:

```text
BuildValidationOutput: func(*AggregateReport, []ValidationFinding, OutputOptions) -> func(ReportValidationResult, OutputOptions)
OutputAction.Code: string -> ActionCode
OutputEvidence.Provenance: string -> ProvenanceID
OutputEvidence.Sensitivity: string -> Sensitivity
OutputFinding.ActionCodes: []string -> []ActionCode
OutputFinding.Code: string -> FindingCode
OutputInput: comparable -> not comparable
OutputMessage.Code: string -> DiagnosticCode
OutputProvenance.ID: string -> ProvenanceID
```

The full command without `-incompatible` also enumerates the intentionally
added v3 feature-pack API. It reports no other removals or incompatible changes.
