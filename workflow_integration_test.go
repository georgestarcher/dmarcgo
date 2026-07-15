package dmarcgo

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const phase13WorkflowSamplesVersion = "phase13-workflow-samples-v1"

type phase13AnalysisSample struct {
	MetadataRecord analysisOutputRecord `json:"metadata_record"`
	RecordTypes    []string             `json:"record_types"`
}

type phase13ExportSample struct {
	Name                  string       `json:"name"`
	NativeType            string       `json:"native_type"`
	CandidateIDs          []AnalysisID `json:"candidate_ids"`
	ThreatCandidateDigest AnalysisID   `json:"threat_candidate_digest"`
	ReviewOnly            bool         `json:"review_only"`
	SubmissionPerformed   bool         `json:"submission_performed"`
}

type phase13WorkflowSamples struct {
	Version  string                  `json:"version"`
	Analysis []phase13AnalysisSample `json:"analysis_jsonl_metadata_records"`
	Exports  []phase13ExportSample   `json:"exchange_outputs"`
}

func TestPhase13CompletedWorkflowSamples(t *testing.T) {
	health, evidence, correlation, threats, enrichment, jurisdiction := analysisOutputTestResults(t)
	fixtures := phase13AnalysisFixtures(health, evidence, correlation, threats, enrichment, jurisdiction)
	samples := phase13WorkflowSamples{Version: phase13WorkflowSamplesVersion, Analysis: []phase13AnalysisSample{}, Exports: []phase13ExportSample{}}

	for _, fixture := range fixtures {
		descriptor, err := AnalysisOutputDescriptorForMode(fixture.mode)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := fixture.write(&output, AnalysisOutputJSONL, AnalysisOutputOptions{Redaction: OutputRedactionRestricted}); err != nil {
			t.Fatalf("write %s metadata sample: %v", fixture.mode, err)
		}
		lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
		if len(lines) == 0 {
			t.Fatalf("mode %s produced no JSONL records", fixture.mode)
		}
		var record analysisOutputRecord
		if err := json.Unmarshal(lines[0], &record); err != nil {
			t.Fatalf("decode %s metadata sample: %v", fixture.mode, err)
		}
		if record.Mode != fixture.mode || record.RecordType != "metadata" || record.RecordID != "metadata" || record.ResultDigest == "" {
			t.Fatalf("mode %s metadata record = %#v", fixture.mode, record)
		}
		samples.Analysis = append(samples.Analysis, phase13AnalysisSample{
			MetadataRecord: record,
			RecordTypes:    descriptor.JSONLRecordTypes,
		})
	}

	samples.Exports = phase13ExchangeSamples(t, threats, enrichment)
	encoded, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	const goldenPath = "testdata/golden/phase13_workflow_samples.json"
	if os.Getenv("DMARCGO_UPDATE_PHASE13_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("Phase 13 workflow samples changed; review and regenerate with DMARCGO_UPDATE_PHASE13_GOLDEN=1 go test -run '^TestPhase13CompletedWorkflowSamples$' .\n%s", encoded)
	}
}

func TestPhase13OnboardingAndUnknownSourcesStayDistinct(t *testing.T) {
	t.Run("healthy expected sender", func(t *testing.T) {
		config := correlationTestConfig(AuthenticationPolicyConfig{})
		portfolio, health := correlationTestDNSHealth(t, config, correlationHealthyDNSValues())
		report := correlationTestReport("healthy", "receiver.example", 100, 200,
			correlationTestRecord("192.0.2.11", "10", "example.test", "pass", "fail", "example.test", "mk1", "example.test"),
		)
		evidence := correlationTestEvidence(t, []*AggregateReport{report}, time.Unix(200, 0))
		correlation, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assertCorrelationClassification(t, correlation.Findings(), CorrelationExpectedSenderHealthy, "192.0.2.11")
		candidates, err := ScoreThreatCandidates(portfolio, evidence, correlation, ThreatCandidateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(candidates.Candidates()) != 0 {
			t.Fatalf("healthy expected sender became a threat candidate: %+v", candidates.Candidates())
		}
	})

	t.Run("onboarding gap and persistent unknown source", func(t *testing.T) {
		config := correlationTestConfig(AuthenticationPolicyConfig{})
		portfolio, health := correlationTestDNSHealth(t, config, map[string]string{
			"example.test":        "v=spf1 -all",
			"_dmarc.example.test": "v=DMARC1; p=reject; rua=mailto:reports@example.test",
		})
		reports := []*AggregateReport{
			correlationTestReport("r1", "receiver-a.example", 100, 1_000,
				correlationTestRecord("192.0.2.10", "20", "example.test", "fail", "fail", "example.test", "mk1", "example.test"),
				correlationTestRecord("198.51.100.20", "70", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example"),
			),
			correlationTestReport("r2", "receiver-b.example", 90_000, 100_000,
				correlationTestRecord("198.51.100.20", "70", "example.test", "fail", "fail", "unknown.example", "rogue", "unknown.example"),
			),
		}
		evidence := correlationTestEvidence(t, reports, time.Unix(100_000, 0))
		correlation, err := CorrelateReportEvidence(portfolio, health, evidence, DNSReportCorrelationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assertCorrelationClassification(t, correlation.Findings(), CorrelationProbableOnboardingGap, "192.0.2.10")
		assertCorrelationClassification(t, correlation.Findings(), CorrelationUnknownSourceFailure, "198.51.100.20")

		candidates, err := ScoreThreatCandidates(portfolio, evidence, correlation, ThreatCandidateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		values := candidates.Candidates()
		if len(values) != 1 || values[0].SourceIP != "198.51.100.20" || !values[0].ReviewEligible || values[0].PromotionEligible ||
			candidates.Summary().ExpectedSenderSourcesOmitted != 1 || candidates.Summary().ExpectedSenderMessagesOmitted != 20 {
			t.Fatalf("onboarding and unknown-source separation failed: candidates=%+v summary=%+v", values, candidates.Summary())
		}
	})
}

func TestPhase13TruncationPreservesFullFindingEvidence(t *testing.T) {
	review := SourceReview{
		Domain:          "example.test",
		Unauthenticated: []SuspiciousSource{{SourceIP: "198.51.100.20", Messages: 7}, {SourceIP: "192.0.2.10", Messages: 5}},
		Rejected:        []SuspiciousSource{{SourceIP: "198.51.100.20", Messages: 7}, {SourceIP: "192.0.2.10", Messages: 5}},
	}
	output, err := BuildSourceReviewOutput(review, OutputOptions{
		Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionRestricted,
		GeneratedAt: time.Unix(200, 0).UTC(), MaxItems: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Findings) != 1 || output.Findings[0].Code != "report.unauthenticated_sources" {
		t.Fatalf("truncation removed the review finding: %+v", output.Findings)
	}
	evidence, ok := output.Findings[0].Evidence[0].Value.(map[string]int)
	if !ok || evidence["sources"] != 2 || evidence["messages"] != 12 {
		t.Fatalf("finding was recomputed from truncated data: %#v", output.Findings[0].Evidence)
	}
	data, ok := output.Data.(SourceReview)
	if !ok || len(data.Unauthenticated) != 1 || len(data.Rejected) != 1 {
		t.Fatalf("bounded detail was not applied: %#v", output.Data)
	}
}

func TestPhase13PureStagesCannotJumpUpstream(t *testing.T) {
	files := []string{
		"dns_health.go",
		"dns_maturity.go",
		"report_evidence.go",
		"correlation.go",
		"threat_candidates.go",
		"phishing_intelligence.go",
		"jurisdiction_context.go",
		"analysis_output.go",
		"analysis_output_modes.go",
		"stix.go",
		"stix_validate.go",
		"threatconnect.go",
		"misp.go",
		"threatstream.go",
		"campaign_config.go",
		"campaign_evidence.go",
		"campaign_classification.go",
		"campaign_report.go",
		"campaign_output.go",
	}
	forbiddenImports := map[string]bool{
		"net": true, "net/http": true, "os": true, "os/exec": true,
	}
	forbiddenCalls := map[string]bool{
		"LoadFile": true, "LoadBytes": true, "LoadReader": true, "LoadReaderContext": true,
		"ParseBytes": true, "ParseReader": true, "CollectDNSSnapshot": true, "LookupTXT": true,
		"ParseAuthenticationRecords": true, "EvaluateDNSHealth": true, "AnalyzeReportEvidence": true,
		"CorrelateReportEvidence": true, "ScoreThreatCandidates": true, "EnrichThreatCandidates": true,
		"CorrelatePhishingIntelligence": true, "EvaluateJurisdictionContext": true,
	}

	for _, filename := range files {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if forbiddenImports[path] {
				t.Errorf("%s imports forbidden side-effect package %q", filename, path)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if forbiddenCalls[name] {
				t.Errorf("%s calls upstream collection or analysis function %s", filename, name)
			}
			return true
		})
	}
}

func BenchmarkPhase13NativeAnalysisOutputs(b *testing.B) {
	health, evidence, correlation, threats, enrichment, jurisdiction := analysisOutputTestResults(b)
	for _, fixture := range phase13AnalysisFixtures(health, evidence, correlation, threats, enrichment, jurisdiction) {
		b.Run(string(fixture.mode), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := fixture.write(io.Discard, AnalysisOutputJSON, AnalysisOutputOptions{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func phase13AnalysisFixtures(
	health DNSHealthResult,
	evidence ReportEvidenceResult,
	correlation DNSReportCorrelationResult,
	threats ThreatCandidateResult,
	enrichment SourceEnrichmentResult,
	jurisdiction JurisdictionContextResult,
) []analysisOutputFixture {
	return []analysisOutputFixture{
		{AnalysisModeDNSHealth, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteDNSHealthOutput(writer, health, format, options)
		}},
		{AnalysisModeReportEvidence, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteReportEvidenceOutput(writer, evidence, format, options)
		}},
		{AnalysisModeDNSReportCorrelation, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteDNSReportCorrelationOutput(writer, correlation, format, options)
		}},
		{AnalysisModeThreatCandidates, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteThreatCandidatesOutput(writer, threats, format, options)
		}},
		{AnalysisModeSourceEnrichment, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteSourceEnrichmentOutput(writer, enrichment, format, options)
		}},
		{AnalysisModeJurisdictionContext, func(writer io.Writer, format AnalysisOutputFormat, options AnalysisOutputOptions) error {
			return WriteJurisdictionContextOutput(writer, jurisdiction, format, options)
		}},
	}
}

func phase13ExchangeSamples(t testing.TB, threats ThreatCandidateResult, enrichment SourceEnrichmentResult) []phase13ExportSample {
	t.Helper()
	candidates := threats.Candidates()
	if len(candidates) != 1 || !candidates[0].ReviewEligible || candidates[0].PromotionEligible {
		t.Fatalf("unexpected Phase 13 candidate fixture: %+v", candidates)
	}
	candidate := candidates[0]

	bundle, err := BuildSTIXBundle(threats, &enrichment, STIXExportOptions{
		Producer: STIXProducer{Name: "Phase 13 synthetic SOC", CreatedAt: time.Unix(10, 0).UTC()},
		TLP:      STIXTLPAmber,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSTIXBundle(bundle); err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bundleJSON, []byte(candidate.ID)) || bytes.Contains(bundleJSON, []byte(`"type":"indicator"`)) {
		t.Fatalf("STIX output lost candidate evidence or promoted it implicitly: %s", bundleJSON)
	}

	threatConnect, err := BuildThreatConnectIndicatorPayloads(threats, &enrichment, ThreatConnectExportOptions{
		CandidateSelections: []ThreatConnectCandidateSelection{{CandidateID: candidate.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(threatConnect) != 1 || !slices.Equal(threatConnect[0].Source().CandidateIDs, []AnalysisID{candidate.ID}) ||
		threatConnect[0].Source().ThreatCandidateDigest != threats.Digest() {
		t.Fatalf("ThreatConnect source mismatch: %+v", threatConnect)
	}

	mapping := MISPAttributeMapping{Type: MISPAttributeTypeIPSource, Category: "Network activity"}
	misp, err := BuildMISPAttributePayloads(threats, MISPAttributeExportOptions{
		Event: MISPEventReference{Identifier: "42"},
		Capabilities: MISPInstanceCapabilities{
			ContractVersion:   "phase13-synthetic-2.5",
			AttributeMappings: []MISPAttributeMapping{mapping},
		},
		Selections: []MISPAttributeSelection{{CandidateID: candidate.ID, Mapping: mapping}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(misp) != 1 || misp[0].CandidateID() != candidate.ID || misp[0].Source().ThreatCandidateDigest != threats.Digest() {
		t.Fatalf("MISP source mismatch: %+v", misp)
	}

	threatStream, err := BuildThreatStreamPayloads(threats, ThreatStreamExportOptions{
		Capabilities: threatStreamFixtureCapabilities(ThreatStreamReviewedImport),
		Selections:   []ThreatStreamCandidateSelection{{CandidateID: candidate.ID, IType: "review_ip"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(threatStream) != 1 || threatStream[0].CandidateID() != candidate.ID ||
		threatStream[0].Source().ThreatCandidateDigest != threats.Digest() {
		t.Fatalf("ThreatStream source mismatch: %+v", threatStream)
	}

	if !reflect.DeepEqual(candidates, threats.Candidates()) {
		t.Fatal("exchange builders mutated the completed threat candidates")
	}
	return []phase13ExportSample{
		{
			Name: "stix_2_1", NativeType: "observed-data", CandidateIDs: []AnalysisID{candidate.ID},
			ThreatCandidateDigest: threats.Digest(), ReviewOnly: true, SubmissionPerformed: false,
		},
		{
			Name: "threatconnect_v3", NativeType: string(threatConnect[0].Type()), CandidateIDs: threatConnect[0].Source().CandidateIDs,
			ThreatCandidateDigest: threatConnect[0].Source().ThreatCandidateDigest, ReviewOnly: true, SubmissionPerformed: false,
		},
		{
			Name: "misp_attribute", NativeType: string(mapping.Type), CandidateIDs: []AnalysisID{misp[0].CandidateID()},
			ThreatCandidateDigest: misp[0].Source().ThreatCandidateDigest, ReviewOnly: true, SubmissionPerformed: false,
		},
		{
			Name: "anomali_threatstream", NativeType: string(threatStream[0].Variant()), CandidateIDs: []AnalysisID{threatStream[0].CandidateID()},
			ThreatCandidateDigest: threatStream[0].Source().ThreatCandidateDigest, ReviewOnly: true, SubmissionPerformed: false,
		},
	}
}
