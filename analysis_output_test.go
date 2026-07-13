package dmarcgo

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type analysisOutputFixture struct {
	mode  AnalysisMode
	write func(io.Writer, AnalysisOutputFormat, AnalysisOutputOptions) error
}

const analysisOutputTestExclusionReason = "SYSTEM: private allowlist rationale"

func TestAnalysisOutputEveryModeAndFormat(t *testing.T) {
	fixtures := analysisOutputFixtures(t)
	if got := SupportedAnalysisOutputModes(); !slices.Equal(got, []AnalysisMode{
		AnalysisModeDNSHealth, AnalysisModeReportEvidence, AnalysisModeDNSReportCorrelation,
		AnalysisModeThreatCandidates, AnalysisModeSourceEnrichment, AnalysisModeJurisdictionContext,
	}) {
		t.Fatalf("unexpected mode discovery: %v", got)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(string(fixture.mode), func(t *testing.T) {
			descriptor, err := AnalysisOutputDescriptorForMode(fixture.mode)
			if err != nil {
				t.Fatal(err)
			}
			if descriptor.SchemaVersion != AnalysisOutputSchemaVersion || len(descriptor.JSONLRecordTypes) < 2 || len(descriptor.CSVColumns) < 10 {
				t.Fatalf("incomplete descriptor: %#v", descriptor)
			}
			for _, format := range descriptor.Formats {
				var first, second bytes.Buffer
				options := AnalysisOutputOptions{Redaction: OutputRedactionRestricted}
				if err := fixture.write(&first, format, options); err != nil {
					t.Fatalf("write %s: %v", format, err)
				}
				if err := fixture.write(&second, format, options); err != nil {
					t.Fatalf("second write %s: %v", format, err)
				}
				if !bytes.Equal(first.Bytes(), second.Bytes()) {
					t.Fatalf("%s output was not deterministic", format)
				}
				validateAnalysisOutputBytes(t, fixture.mode, format, first.Bytes(), descriptor)
			}
		})
	}
}

func TestAnalysisOutputJSONSchemasValidateEveryModeAndRedaction(t *testing.T) {
	for _, fixture := range analysisOutputFixtures(t) {
		schemaData, err := AnalysisOutputSchema(fixture.mode, AnalysisOutputSchemaVersion)
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
		if err != nil {
			t.Fatal(err)
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		schemaID, err := AnalysisOutputSchemaID(fixture.mode, AnalysisOutputSchemaVersion)
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(schemaID, document); err != nil {
			t.Fatal(err)
		}
		validator, err := compiler.Compile(schemaID)
		if err != nil {
			t.Fatal(err)
		}
		lineValidator, err := compiler.Compile(schemaID + "#/$defs/jsonl_record")
		if err != nil {
			t.Fatal(err)
		}
		csvValidator, err := compiler.Compile(schemaID + "#/$defs/csv_record")
		if err != nil {
			t.Fatal(err)
		}
		for _, redaction := range []OutputRedaction{OutputRedactionPublic, OutputRedactionOperational, OutputRedactionRestricted} {
			var output bytes.Buffer
			if err := fixture.write(&output, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: redaction}); err != nil {
				t.Fatal(err)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(output.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(value); err != nil {
				t.Fatalf("mode %s redaction %s: %v", fixture.mode, redaction, err)
			}

			var jsonl bytes.Buffer
			if err := fixture.write(&jsonl, AnalysisOutputJSONL, AnalysisOutputOptions{Redaction: redaction}); err != nil {
				t.Fatal(err)
			}
			for _, line := range bytes.Split(bytes.TrimSpace(jsonl.Bytes()), []byte{'\n'}) {
				value, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
				if err != nil {
					t.Fatal(err)
				}
				if err := lineValidator.Validate(value); err != nil {
					t.Fatalf("mode %s JSONL redaction %s: %v", fixture.mode, redaction, err)
				}
			}

			var csvOutput bytes.Buffer
			if err := fixture.write(&csvOutput, AnalysisOutputCSV, AnalysisOutputOptions{Redaction: redaction}); err != nil {
				t.Fatal(err)
			}
			rows, err := csv.NewReader(bytes.NewReader(csvOutput.Bytes())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows[1:] {
				object := make(map[string]any, len(rows[0]))
				for index, header := range rows[0] {
					object[header] = row[index]
				}
				if err := csvValidator.Validate(object); err != nil {
					t.Fatalf("mode %s CSV redaction %s: %v", fixture.mode, redaction, err)
				}
			}
		}
		copyOfSchema, err := AnalysisOutputSchema(fixture.mode, "")
		if err != nil {
			t.Fatal(err)
		}
		copyOfSchema[0] = 'x'
		fresh, _ := AnalysisOutputSchema(fixture.mode, "")
		if fresh[0] == 'x' {
			t.Fatal("schema accessor did not return a defensive copy")
		}
	}
}

func TestAnalysisOutputContractGolden(t *testing.T) {
	type goldenMode struct {
		Mode             AnalysisMode           `json:"mode"`
		Schema           string                 `json:"schema"`
		SchemaVersion    string                 `json:"schema_version"`
		Formats          []AnalysisOutputFormat `json:"formats"`
		JSONLRecordTypes []string               `json:"jsonl_record_types"`
		CSVColumns       []string               `json:"csv_columns"`
	}
	actual := struct {
		Modes []goldenMode `json:"modes"`
	}{Modes: []goldenMode{}}
	for _, mode := range SupportedAnalysisOutputModes() {
		descriptor, err := AnalysisOutputDescriptorForMode(mode)
		if err != nil {
			t.Fatal(err)
		}
		actual.Modes = append(actual.Modes, goldenMode{mode, descriptor.SchemaIDs[AnalysisOutputJSON], descriptor.SchemaVersion, descriptor.Formats, descriptor.JSONLRecordTypes, descriptor.CSVColumns})
	}
	encoded, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	expected, err := os.ReadFile("testdata/golden/analysis_output_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var expectedValue any
	if err := json.Unmarshal(expected, &expectedValue); err != nil {
		t.Fatal(err)
	}
	var actualValue any
	if err := json.Unmarshal(encoded, &actualValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualValue, expectedValue) {
		t.Fatalf("analysis output contract changed; review and update the golden intentionally\n%s", encoded)
	}
}

func TestAnalysisOutputPrivacyIsStableAndNonMutating(t *testing.T) {
	fixtures := analysisOutputFixtures(t)
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(string(fixture.mode), func(t *testing.T) {
			var restricted, publicA, publicB bytes.Buffer
			if err := fixture.write(&restricted, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
				t.Fatal(err)
			}
			if err := fixture.write(&publicA, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: OutputRedactionPublic}); err != nil {
				t.Fatal(err)
			}
			if err := fixture.write(&publicB, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: OutputRedactionPublic}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(publicA.Bytes(), publicB.Bytes()) {
				t.Fatal("public redaction tokens changed between writes")
			}
			if bytes.Contains(publicA.Bytes(), []byte("198.51.100.20")) || bytes.Contains(publicA.Bytes(), []byte("example.test")) || bytes.Contains(publicA.Bytes(), []byte("receiver-a.example")) {
				t.Fatalf("public output leaked an operational identifier: %s", publicA.Bytes())
			}
			if !bytes.Contains(publicA.Bytes(), []byte("redacted:")) {
				t.Fatal("public output did not report stable redaction tokens")
			}
			var restrictedDocument map[string]any
			if err := json.Unmarshal(restricted.Bytes(), &restrictedDocument); err != nil {
				t.Fatal(err)
			}
			if digest, _ := restrictedDocument["result_digest"].(string); digest != "" && bytes.Contains(publicA.Bytes(), []byte(digest)) {
				t.Fatal("public output leaked the result digest")
			}
			var restrictedAgain bytes.Buffer
			if err := fixture.write(&restrictedAgain, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restricted.Bytes(), restrictedAgain.Bytes()) {
				t.Fatal("redaction mutated the source result")
			}
		})
	}
}

func TestAnalysisOutputJSONLAndCSVPropagateWriterFailures(t *testing.T) {
	for _, fixture := range analysisOutputFixtures(t) {
		for _, format := range []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV} {
			err := fixture.write(&analysisFailWriter{remaining: 80}, format, AnalysisOutputOptions{})
			if !errors.Is(err, errAnalysisOutputWrite) {
				t.Fatalf("mode %s format %s: got %v", fixture.mode, format, err)
			}
		}
	}
}

func TestAnalysisOutputRejectsInvalidRequests(t *testing.T) {
	fixtures := analysisOutputFixtures(t)
	if err := fixtures[0].write(io.Discard, "yaml", AnalysisOutputOptions{}); !errors.Is(err, ErrUnsupportedAnalysisOutput) {
		t.Fatalf("unsupported format error = %v", err)
	}
	if err := fixtures[0].write(io.Discard, AnalysisOutputJSON, AnalysisOutputOptions{SchemaVersion: "99"}); !errors.Is(err, ErrUnsupportedAnalysisOutput) {
		t.Fatalf("unsupported schema error = %v", err)
	}
	if err := fixtures[0].write(io.Discard, AnalysisOutputJSON, AnalysisOutputOptions{Redaction: "secret"}); !errors.Is(err, ErrUnsupportedAnalysisOutput) {
		t.Fatalf("unsupported redaction error = %v", err)
	}
	if err := WriteDNSHealthOutput(io.Discard, DNSHealthResult{}, AnalysisOutputJSON, AnalysisOutputOptions{}); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("zero result error = %v", err)
	}
	if _, err := AnalysisOutputDescriptorForMode(AnalysisMode("unknown")); !errors.Is(err, ErrUnsupportedAnalysisOutput) {
		t.Fatalf("unknown descriptor error = %v", err)
	}
}

func TestAnalysisOutputCSVNeutralizesFormulas(t *testing.T) {
	report := correlationTestReport("=report", "@receiver.example", 100, 200,
		correlationTestRecord("198.51.100.20", "1", "+author.example", "fail", "fail", "-dkim.example", "@selector", "=spf.example"))
	evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteReportEvidenceOutput(&output, evidence, AnalysisOutputCSV, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Fatalf("formula-capable CSV cell was not neutralized: %q", cell)
			}
		}
	}
	if !bytes.Contains(output.Bytes(), []byte("'@receiver.example")) {
		t.Fatalf("expected neutralized synthetic values in CSV: %s", output.Bytes())
	}
}

func TestAnalysisOutputOperationalRemovesRawAndEnrichmentFreeText(t *testing.T) {
	report := correlationTestReport("report", "receiver.example", 100, 200,
		correlationTestRecord("not-an-ip", "not-a-count", "example.test", "unknown", "unknown", "", "", ""))
	evidence, err := AnalyzeReportEvidence([]*AggregateReport{report}, ReportEvidenceOptions{GeneratedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteReportEvidenceOutput(&output, evidence, AnalysisOutputJSON, AnalysisOutputOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("raw_value")) || bytes.Contains(output.Bytes(), []byte("not-a-count")) {
		t.Fatalf("operational output retained raw report text: %s", output.Bytes())
	}

	_, _, _, _, enrichment, _ := analysisOutputTestResults(t)
	output.Reset()
	if err := WriteSourceEnrichmentOutput(&output, enrichment, AnalysisOutputJSON, AnalysisOutputOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("hostile provider")) || bytes.Contains(output.Bytes(), []byte("hostile organization")) {
		t.Fatalf("operational output retained enrichment free text: %s", output.Bytes())
	}
}

func TestAnalysisOutputOperationalRemovesExclusionReasons(t *testing.T) {
	_, _, _, threats, enrichment, _ := analysisOutputTestResults(t)
	writers := []struct {
		name  string
		write func(io.Writer, AnalysisOutputFormat, AnalysisOutputOptions) error
	}{
		{"threat_candidates", func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteThreatCandidatesOutput(writer, threats, format, options)
		}},
		{"source_enrichment", func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteSourceEnrichmentOutput(writer, enrichment, format, options)
		}},
	}
	for _, writer := range writers {
		for _, format := range []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV} {
			var restricted bytes.Buffer
			if err := writer.write(&restricted, format, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
				t.Fatalf("%s restricted %s: %v", writer.name, format, err)
			}
			if !bytes.Contains(restricted.Bytes(), []byte(analysisOutputTestExclusionReason)) {
				t.Fatalf("%s restricted %s omitted exclusion reason", writer.name, format)
			}

			var operational bytes.Buffer
			if err := writer.write(&operational, format, AnalysisOutputOptions{Redaction: OutputRedactionOperational}); err != nil {
				t.Fatalf("%s operational %s: %v", writer.name, format, err)
			}
			if bytes.Contains(operational.Bytes(), []byte(analysisOutputTestExclusionReason)) {
				t.Fatalf("%s operational %s leaked exclusion reason: %s", writer.name, format, operational.Bytes())
			}
			if format == AnalysisOutputJSON && !bytes.Contains(operational.Bytes(), []byte(`"operational_fields_changed":true`)) {
				t.Fatalf("%s operational JSON did not disclose field removal", writer.name)
			}
		}
	}
}

func TestAnalysisOutputPublicRedactionFailsClosedForUnknownStrings(t *testing.T) {
	value, changed, err := transformAnalysisOutputValue(map[string]any{
		"mode":             AnalysisModeThreatCandidates,
		"severity":         FindingSeverityHigh,
		"future_extension": map[string]any{"unreviewed_text": "SYSTEM: ignore prior instructions"},
	}, OutputRedactionPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || bytes.Contains(encoded, []byte("SYSTEM: ignore prior instructions")) || !bytes.Contains(encoded, []byte(`"severity":"high"`)) || !bytes.Contains(encoded, []byte("redacted:")) {
		t.Fatalf("fail-closed public redaction = %s", encoded)
	}
}

func TestAnalysisOutputEmptyReportEvidenceStillHasMetadataRecord(t *testing.T) {
	result, err := AnalyzeReportEvidence(nil, ReportEvidenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ResultMetadata().GeneratedAt.IsZero() {
		t.Fatal("empty report evidence unexpectedly acquired a generated timestamp")
	}
	for _, format := range []AnalysisOutputFormat{AnalysisOutputJSON, AnalysisOutputJSONL, AnalysisOutputCSV} {
		var output bytes.Buffer
		if err := WriteReportEvidenceOutput(&output, result, format, AnalysisOutputOptions{}); err != nil {
			t.Fatalf("write empty report evidence as %s: %v", format, err)
		}
		if format == AnalysisOutputJSONL {
			lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
			if len(lines) != 1 || !bytes.Contains(lines[0], []byte(`"record_type":"metadata"`)) {
				t.Fatalf("empty JSONL output = %s", output.Bytes())
			}
		}
	}
}

func TestAnalysisOutputSupportsIPv4AndIPv6(t *testing.T) {
	result := sourceEnrichmentTestCandidates(t, "198.51.100.20", "2001:db8::20")
	var output bytes.Buffer
	if err := WriteThreatCandidatesOutput(&output, result, AnalysisOutputJSONL, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("198.51.100.20")) || !bytes.Contains(output.Bytes(), []byte("2001:db8::20")) {
		t.Fatalf("address families missing: %s", output.Bytes())
	}
}

func TestAnalysisOutputLargeJSONLAndCSVRemainRecordStreamed(t *testing.T) {
	result := sourceEnrichmentTestCandidates(t, "198.51.100.20")
	template := result.candidates[0]
	result.candidates = make([]ThreatCandidate, 2_000)
	for index := range result.candidates {
		candidate := cloneThreatCandidates([]ThreatCandidate{template})[0]
		candidate.ID = StableAnalysisID("threat_candidate", strconv.Itoa(index+1))
		candidate.SourceIP = netip.AddrFrom4([4]byte{198, 51, byte(index / 250), byte(index%250 + 1)}).String()
		result.candidates[index] = candidate
	}
	result.digest = StableAnalysisID("threat_candidates", "large-stream-fixture")
	for _, format := range []AnalysisOutputFormat{AnalysisOutputJSONL, AnalysisOutputCSV} {
		writer := &analysisCountingWriter{}
		if err := WriteThreatCandidatesOutput(writer, result, format, AnalysisOutputOptions{}); err != nil {
			t.Fatal(err)
		}
		if writer.writes < len(result.candidates) || writer.maximum >= writer.total/2 {
			t.Fatalf("format %s was not record streamed: writes=%d max=%d total=%d", format, writer.writes, writer.maximum, writer.total)
		}
	}
}

func validateAnalysisOutputBytes(t testing.TB, mode AnalysisMode, format AnalysisOutputFormat, data []byte, descriptor AnalysisOutputDescriptor) {
	t.Helper()
	switch format {
	case AnalysisOutputJSON:
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if document["schema_version"] != AnalysisOutputSchemaVersion || document["mode"] != string(mode) || document["profile"] != "native" {
			t.Fatalf("bad JSON contract header: %#v", document)
		}
	case AnalysisOutputJSONL:
		allowed := map[string]bool{}
		seen := map[string]bool{}
		for _, value := range descriptor.JSONLRecordTypes {
			allowed[value] = true
		}
		lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
		for _, line := range lines {
			var record analysisOutputRecord
			if err := json.Unmarshal(line, &record); err != nil {
				t.Fatal(err)
			}
			if record.SchemaVersion != AnalysisOutputSchemaVersion || record.Mode != mode || !allowed[record.RecordType] || record.RecordID == "" {
				t.Fatalf("bad JSONL record: %#v", record)
			}
			key := record.RecordType + "\x00" + record.RecordID
			if seen[key] {
				t.Fatalf("duplicate JSONL record identity %q", key)
			}
			seen[key] = true
			if record.RecordType == "metadata" {
				data, ok := record.Data.(map[string]any)
				if !ok {
					t.Fatalf("metadata record data type = %T", record.Data)
				}
				resultMetadata, ok := data["metadata"].(map[string]any)
				if !ok || resultMetadata["contract_version"] != AnalysisContractVersion {
					t.Fatalf("metadata record omitted result contract: %#v", data)
				}
			}
		}
	case AnalysisOutputCSV:
		rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) < 2 || !slices.Equal(rows[0], descriptor.CSVColumns) {
			t.Fatalf("bad CSV header/rows: %#v", rows)
		}
		for _, row := range rows[1:] {
			if len(row) != len(descriptor.CSVColumns) || row[2] != string(mode) || !json.Valid([]byte(row[len(row)-1])) {
				t.Fatalf("bad CSV record: %#v", row)
			}
		}
	}
}

var errAnalysisOutputWrite = errors.New("synthetic writer failure")

type analysisFailWriter struct{ remaining int }

func (writer *analysisFailWriter) Write(data []byte) (int, error) {
	if writer.remaining <= 0 {
		return 0, errAnalysisOutputWrite
	}
	if len(data) > writer.remaining {
		written := writer.remaining
		writer.remaining = 0
		return written, errAnalysisOutputWrite
	}
	writer.remaining -= len(data)
	return len(data), nil
}

type analysisCountingWriter struct {
	writes  int
	maximum int
	total   int
}

func (writer *analysisCountingWriter) Write(data []byte) (int, error) {
	writer.writes++
	writer.total += len(data)
	writer.maximum = max(writer.maximum, len(data))
	return len(data), nil
}

func analysisOutputFixtures(t testing.TB) []analysisOutputFixture {
	health, evidence, correlation, threats, enrichment, jurisdiction := analysisOutputTestResults(t)
	return []analysisOutputFixture{
		{AnalysisModeDNSHealth, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteDNSHealthOutput(w, health, f, o)
		}},
		{AnalysisModeReportEvidence, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteReportEvidenceOutput(w, evidence, f, o)
		}},
		{AnalysisModeDNSReportCorrelation, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteDNSReportCorrelationOutput(w, correlation, f, o)
		}},
		{AnalysisModeThreatCandidates, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteThreatCandidatesOutput(w, threats, f, o)
		}},
		{AnalysisModeSourceEnrichment, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteSourceEnrichmentOutput(w, enrichment, f, o)
		}},
		{AnalysisModeJurisdictionContext, func(w io.Writer, f AnalysisOutputFormat, o AnalysisOutputOptions) error {
			return WriteJurisdictionContextOutput(w, jurisdiction, f, o)
		}},
	}
}

func analysisOutputTestResults(t testing.TB) (DNSHealthResult, ReportEvidenceResult, DNSReportCorrelationResult, ThreatCandidateResult, SourceEnrichmentResult, JurisdictionContextResult) {
	t.Helper()
	config := correlationTestConfig(AuthenticationPolicyConfig{})
	config.Entities[0].Domains[0].Exclusions = []ScopedExclusionConfig{{
		ID: "private-review", Owner: "mail-team", Reason: analysisOutputTestExclusionReason,
		Scope: ExclusionScopeSource, Target: "192.0.2.0/24", CreatedAt: time.Unix(10, 0).UTC(),
	}}
	portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
	reports := []*AggregateReport{
		correlationTestReport("r1", "receiver-a.example", 100, 1_000, threatTestRecord("198.51.100.20", "70", "example.test", "reject")),
		correlationTestReport("r2", "receiver-b.example", 90_000, 100_000, threatTestRecord("198.51.100.20", "70", "example.test", "quarantine")),
	}
	evidence := correlationTestEvidence(t, reports, time.Unix(100_000, 0))
	correlation, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	threats, err := ScoreThreatCandidates(portfolio, evidence, correlation, ThreatCandidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100_100, 0).UTC()
	expires := now.Add(24 * time.Hour)
	metadata := sourceTestMetadata(64500, "hostile ASN name", netip.MustParsePrefix("198.51.100.0/24").String(), "hostile organization", "IR", "hostile provider", now.Add(-time.Hour), &expires)
	enrichment, err := EnrichThreatCandidates(context.Background(), threats, &sourceFixtureEnricher{metadata: map[string]IPMetadata{"198.51.100.20": metadata}}, SourceEnrichmentOptions{Clock: ClockFunc(func() time.Time { return now })})
	if err != nil {
		t.Fatal(err)
	}
	jurisdiction, err := EvaluateJurisdictionContext(enrichment, BuiltinJurisdictionRiskPolicy(), JurisdictionContextOptions{EnableReviewPriorityAdjustment: true})
	if err != nil {
		t.Fatal(err)
	}
	return health, evidence, correlation, threats, enrichment, jurisdiction
}
