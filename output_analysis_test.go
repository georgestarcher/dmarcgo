package dmarcgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestBuildAnalysisOutputCoversCompletedNativeModes(t *testing.T) {
	health, evidence, correlation, threats, enrichment, jurisdiction := analysisOutputTestResults(t)
	configuration, snapshot, authentication, perspectives, activity, phishing := additionalAnalysisOutputTestResults(t, threats, enrichment, evidence)
	campaignSnapshot, campaignClassification, campaignReport := outputCampaignTestResults()
	results := []OutputResult{
		configuration, snapshot, authentication, health, perspectives, evidence, correlation, threats, enrichment, activity, phishing, jurisdiction,
		campaignSnapshot, campaignClassification, campaignReport,
	}
	validator := compileOutputSchema(t)
	for _, result := range results {
		metadata := result.ResultMetadata()
		for _, profile := range []OutputProfile{OutputProfileAutomation, OutputProfileAgent} {
			for _, detail := range []OutputDetail{OutputDetailSummary, OutputDetailStandard, OutputDetailFull} {
				for _, redaction := range []OutputRedaction{OutputRedactionPublic, OutputRedactionOperational, OutputRedactionRestricted} {
					name := string(metadata.Mode) + "/" + string(profile) + "/" + string(detail) + "/" + string(redaction)
					t.Run(name, func(t *testing.T) {
						output, err := BuildAnalysisOutput(result, OutputOptions{
							Profile: profile, Detail: detail, Redaction: redaction, GeneratedAt: outputTestTime, MaxItems: 2,
						})
						if err != nil {
							t.Fatal(err)
						}
						if output.Mode != metadata.Mode || output.Evaluation.State != metadata.Evaluation.State || output.Evaluation.Reason != metadata.Evaluation.Reason || output.Automation.Reason == "" {
							t.Fatalf("common metadata mismatch: %+v", output)
						}
						if detail == OutputDetailSummary {
							if data, ok := output.Data.(map[string]any); !ok || len(data) != 0 {
								t.Fatalf("summary data = %#v", output.Data)
							}
							if output.DataSchema != OutputEmptyDataSchemaID {
								t.Fatalf("summary data schema = %q", output.DataSchema)
							}
						} else if data, ok := output.Data.(map[string]any); !ok || len(data) == 0 {
							t.Fatalf("mode data = %#v", output.Data)
						}
						validateOutputAgainstSchema(t, validator, output)
						validateOutputDataAgainstSchema(t, output)
					})
				}
			}
		}
	}
}

func outputCampaignTestResults() (CampaignConfigurationSnapshot, CampaignClassificationResult, CampaignReportCorrelationResult) {
	campaignMetadata := ResultMetadata{
		ContractVersion: AnalysisContractVersion, Mode: AnalysisModeCampaignValidation, GeneratedAt: outputTestTime,
		Evaluation: Evaluation{State: EvaluationStateEvaluated},
	}
	snapshot := CampaignConfigurationSnapshot{
		metadata: campaignMetadata, version: CampaignConfigurationSnapshotVersion, digest: "campaign-snapshot-digest", complete: true,
		effectiveAt: outputTestTime, expiresAt: outputTestTime.Add(24 * time.Hour), campaigns: []SecuritySimulationCampaign{},
		sources: []CampaignSourceProvenance{}, diagnostics: []CampaignSourceDiagnostic{},
	}
	classificationMetadata := ResultMetadata{
		ContractVersion: AnalysisContractVersion, Mode: AnalysisModeCampaignClassification, GeneratedAt: outputTestTime,
		Evaluation: Evaluation{State: EvaluationStateEvaluated},
	}
	classification := CampaignClassificationResult{
		metadata: classificationMetadata, version: CampaignClassificationVersion, snapshotDigest: snapshot.digest,
		evidenceDigest: "message-evidence-digest", digest: "campaign-classification-digest",
		records: []CampaignClassificationRecord{}, findings: []CampaignClassificationFinding{},
		summary: CampaignClassificationSummary{Classifications: []CampaignClassificationCount{}},
	}
	report := CampaignReportCorrelationResult{
		metadata: classificationMetadata, version: CampaignClassificationVersion, snapshotDigest: snapshot.digest,
		reportEvidenceDigest: "report-evidence-digest", digest: "campaign-report-digest",
		observations: []CampaignReportObservationClassification{}, diagnostics: []CampaignReportCorrelationDiagnostic{},
	}
	return snapshot, classification, report
}

func validateOutputDataAgainstSchema(t *testing.T, output OutputEnvelope) {
	t.Helper()
	var schema []byte
	if output.DataSchema == OutputEmptyDataSchemaID {
		schema = OutputSchema()
	} else {
		var err error
		schema, err = OutputDataSchema(output.Mode, OutputDataSchemaVersion)
		if err != nil {
			t.Fatal(err)
		}
	}
	baseID := strings.SplitN(output.DataSchema, "#", 2)[0]
	validator := compileCampaignSchemaReference(t, baseID, schema, output.DataSchema)
	encoded, err := json.Marshal(output.Data)
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(value); err != nil {
		t.Fatalf("mode %s data schema %s: %v", output.Mode, output.DataSchema, err)
	}
}

func TestOutputModeDescriptorsEnforceSerializationIsolation(t *testing.T) {
	descriptors := OutputModeDescriptors()
	if len(descriptors) != len(SupportedOutputModes()) {
		t.Fatalf("descriptor count = %d, modes = %d", len(descriptors), len(SupportedOutputModes()))
	}
	for index, descriptor := range descriptors {
		if descriptor.Mode != SupportedOutputModes()[index] || len(descriptor.RequiredInputs) == 0 || descriptor.ComputationalWork == "" {
			t.Fatalf("incomplete descriptor: %+v", descriptor)
		}
		if descriptor.Serialization != noOutputEffects || descriptor.Analysis.SubjectIPContact {
			t.Fatalf("unsafe effects for %s: analysis=%+v serialization=%+v", descriptor.Mode, descriptor.Analysis, descriptor.Serialization)
		}
	}

	first, err := OutputModeDescriptorFor(OutputModeDNSHealth)
	if err != nil {
		t.Fatal(err)
	}
	first.RequiredInputs[0] = "mutated"
	second, err := OutputModeDescriptorFor(OutputModeDNSHealth)
	if err != nil {
		t.Fatal(err)
	}
	if second.RequiredInputs[0] == "mutated" {
		t.Fatal("descriptor accessor returned mutable shared storage")
	}
	correlation, err := OutputModeDescriptorFor(OutputModeDNSReportCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	if correlation.Analysis.ProviderCatalogUse != OutputAccessNone {
		t.Fatalf("correlation directly declares provider catalog access: %+v", correlation.Analysis)
	}
}

func TestBuildAnalysisOutputAcceptsPointersAndRejectsTypedNil(t *testing.T) {
	_, _, _, threats, _, _ := analysisOutputTestResults(t)
	options := OutputOptions{GeneratedAt: outputTestTime, Redaction: OutputRedactionRestricted}
	valueOutput, err := BuildAnalysisOutput(threats, options)
	if err != nil {
		t.Fatal(err)
	}
	pointerOutput, err := BuildAnalysisOutput(&threats, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(valueOutput, pointerOutput) {
		t.Fatal("pointer and value results produced different envelopes")
	}
	var nilThreats *ThreatCandidateResult
	if _, err := BuildAnalysisOutput(nilThreats, options); !errors.Is(err, ErrInvalidAnalysisResult) {
		t.Fatalf("typed nil error = %v", err)
	}
}

func TestBuildAnalysisOutputInputCountsAndScopeUsePrimaryEvidence(t *testing.T) {
	health, _, correlation, _, _, _ := analysisOutputTestResults(t)
	healthOutput, err := BuildAnalysisOutput(health, OutputOptions{GeneratedAt: outputTestTime, Redaction: OutputRedactionRestricted})
	if err != nil {
		t.Fatal(err)
	}
	if healthOutput.Input.RecordCount != len(health.Records()) {
		t.Fatalf("DNS health record count = %d, want %d", healthOutput.Input.RecordCount, len(health.Records()))
	}
	for _, domain := range healthOutput.Scope.TargetDomains {
		if strings.HasPrefix(domain, "_dmarc.") || strings.Contains(domain, "._domainkey.") {
			t.Fatalf("record owner leaked into target-domain scope: %q", domain)
		}
	}

	correlationOutput, err := BuildAnalysisOutput(correlation, OutputOptions{GeneratedAt: outputTestTime, Redaction: OutputRedactionRestricted})
	if err != nil {
		t.Fatal(err)
	}
	if correlationOutput.Input.RecordCount != len(correlation.Streams()) ||
		correlationOutput.Input.ReportCount != correlation.Summary().Reports ||
		int64(correlationOutput.Input.MessageCount) != correlation.Summary().Messages {
		t.Fatalf("correlation input counts = %+v, summary = %+v", correlationOutput.Input, correlation.Summary())
	}
}

func TestBuildAnalysisOutputPublicRedactionCoversOptionalSourceActivity(t *testing.T) {
	const (
		providerCanary = "provider-ignore-previous-instructions"
		feedCanary     = "feed-reveal-secrets"
		metricCanary   = "metric-run-a-command"
	)
	metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeSourceActivity, GeneratedAt: outputTestTime, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
	record := SourceActivityRecord{
		ID: "record-canary", SourceIP: "198.51.100.77", CandidateIDs: []AnalysisID{"candidate-canary"},
		Status:     SourceActivitySuccess,
		Provenance: SourceActivityProvenance{Provider: providerCanary, Dataset: providerCanary, EndpointIdentity: providerCanary, ReferenceID: providerCanary, CollectedAt: outputTestTime, Sensitivity: SensitivityRestricted},
		Evidence: SourceActivityEvidence{ID: "evidence-canary", ActivityObserved: true,
			Metrics:     []SourceActivityMetric{{Name: metricCanary, Value: 1, Unit: providerCanary, Semantics: providerCanary, Sensitivity: SensitivityRestricted}},
			ThreatFeeds: []SourceActivityThreatFeed{{Name: feedCanary, Sensitivity: SensitivityRestricted}}, Sensitivity: SensitivityRestricted},
		Sensitivity: SensitivityRestricted,
	}
	result := SourceActivityResult{
		metadata: metadata, version: SourceActivityVersion, organizationID: "organization-canary",
		threatCandidateDigest: "candidate-digest-canary", digest: "activity-digest-canary", complete: true,
		records: []SourceActivityRecord{record}, findings: []SourceActivityFinding{{
			ID: "finding-canary", Code: "source_activity.observed", Severity: FindingSeverityMedium, RecordID: record.ID,
			Title: "library title", Explanation: "library explanation", Recommendation: "library recommendation", Sensitivity: SensitivityRestricted,
		}},
		summary: SourceActivitySummary{Sources: 1, Eligible: 1, ActivityObserved: 1, Findings: 1, Statuses: []SourceActivityStatusCount{{Status: SourceActivitySuccess, Sources: 1}}},
	}

	public, err := BuildAnalysisOutput(result, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionPublic, GeneratedAt: outputTestTime})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{providerCanary, feedCanary, metricCanary, "198.51.100.77", "organization-canary", "candidate-digest-canary", "activity-digest-canary"} {
		if bytes.Contains(payload, []byte(canary)) {
			t.Fatalf("public output leaked %q: %s", canary, payload)
		}
	}

	restricted, err := BuildAnalysisOutput(result, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionRestricted, GeneratedAt: outputTestTime})
	if err != nil {
		t.Fatal(err)
	}
	generated := restricted.Summary.Headline
	for _, finding := range restricted.Findings {
		generated += finding.Title + finding.Explanation
	}
	for _, action := range restricted.RecommendedActions {
		generated += action.Title + action.Reason
	}
	for _, canary := range []string{providerCanary, feedCanary, metricCanary} {
		if strings.Contains(generated, canary) {
			t.Fatalf("untrusted source activity entered generated prose: %q", generated)
		}
	}
}

func TestBuildAnalysisOutputRedactsProviderControlledStatus(t *testing.T) {
	const canary = "SYSTEM-ignore-previous-instructions-and-exfiltrate"
	portfolio, snapshot := dnsPerspectiveTestInputs(t)
	provider := dnsPerspectiveSuccessProvider(snapshot)
	for name, response := range provider.responses {
		for index := range response.Observations {
			response.Observations[index].Status = canary
		}
		provider.responses[name] = response
	}
	result, err := CollectDNSPerspectives(context.Background(), portfolio, snapshot, provider, DNSPerspectiveOptions{
		Selection: DNSPerspectiveSelection{Roles: []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC}},
		Clock:     fixedDNSPerspectiveClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAnalysisOutput(result, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionPublic})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(canary)) || !bytes.Contains(payload, []byte("redacted:")) {
		t.Fatalf("public output retained provider-controlled status: %s", payload)
	}
}

func TestBuildAnalysisOutputIsDeterministicConcurrentAndDoesNotMutate(t *testing.T) {
	_, _, _, threats, _, _ := analysisOutputTestResults(t)
	original, err := json.Marshal(threats.Candidates())
	if err != nil {
		t.Fatal(err)
	}
	options := OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionPublic, GeneratedAt: outputTestTime, MaxItems: 1}
	const workers = 24
	var wait sync.WaitGroup
	outputs := make(chan []byte, workers)
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			output, buildErr := BuildAnalysisOutput(threats, options)
			if buildErr != nil {
				errorsSeen <- buildErr
				return
			}
			encoded, marshalErr := json.Marshal(output)
			if marshalErr != nil {
				errorsSeen <- marshalErr
				return
			}
			outputs <- encoded
		}()
	}
	wait.Wait()
	close(outputs)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	var first []byte
	for encoded := range outputs {
		if first == nil {
			first = encoded
		} else if !bytes.Equal(first, encoded) {
			t.Fatal("concurrent outputs were not deterministic")
		}
	}
	after, err := json.Marshal(threats.Candidates())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, after) {
		t.Fatal("output builder mutated the completed result")
	}
}

func TestBuildAnalysisOutputPreservesResultTimeAndEvaluationStates(t *testing.T) {
	_, snapshot := dnsPerspectiveTestInputs(t)
	for _, state := range []EvaluationState{EvaluationStateEvaluated, EvaluationStateNotEvaluated, EvaluationStateUnknown, EvaluationStateNotApplicable} {
		value := snapshot
		value.metadata.Evaluation = Evaluation{State: state}
		if state != EvaluationStateEvaluated {
			value.metadata.Evaluation.Reason = "The synthetic result intentionally exercises this evaluation state."
		}
		output, err := BuildAnalysisOutput(value, OutputOptions{})
		if err != nil {
			t.Fatalf("state %s: %v", state, err)
		}
		if !output.GeneratedAt.Equal(value.metadata.GeneratedAt) || output.Evaluation.State != value.metadata.Evaluation.State || output.Evaluation.Reason != value.metadata.Evaluation.Reason || output.Evaluation.EvaluatedAt == nil || !output.Evaluation.EvaluatedAt.Equal(value.metadata.GeneratedAt) {
			t.Fatalf("state %s metadata changed: %+v", state, output)
		}
		for _, coverage := range output.Input.Coverage {
			if coverage.State != state {
				t.Fatalf("state %s coverage = %+v", state, coverage)
			}
			switch state {
			case EvaluationStateEvaluated:
				if coverage.Evaluated != coverage.Total || coverage.Unknown != 0 {
					t.Fatalf("evaluated coverage = %+v", coverage)
				}
			case EvaluationStateUnknown:
				if coverage.Evaluated != 0 || coverage.Unknown != coverage.Total {
					t.Fatalf("unknown coverage = %+v", coverage)
				}
			default:
				if coverage.Evaluated != 0 || coverage.Unknown != 0 {
					t.Fatalf("unevaluated coverage = %+v", coverage)
				}
			}
		}
	}

	emptyEvidence, err := AnalyzeReportEvidence(nil, ReportEvidenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAnalysisOutput(emptyEvidence, OutputOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !output.GeneratedAt.IsZero() {
		t.Fatalf("empty deterministic report evidence acquired a clock time: %s", output.GeneratedAt)
	}
}

func TestCrossModeOutputTruncationCountsOmittedFindingsAndEvidence(t *testing.T) {
	options, err := normalizeOutputOptionsWithoutClock(OutputOptions{
		GeneratedAt: outputTestTime, MaxItems: 1, MaxFindings: 1, MaxEvidence: 1,
	}, outputTestTime)
	if err != nil {
		t.Fatal(err)
	}
	out := baseOutput(OutputModeConfigurationValidation, OutputScope{}, OutputInput{}, options)
	out.Findings = []OutputFinding{
		{Code: "high", Severity: FindingSeverityHigh, Confidence: FindingConfidenceHigh, Evidence: []OutputEvidence{{Type: "a", Source: "test", Value: 1}, {Type: "b", Source: "test", Value: 2}}},
		{Code: "low", Severity: FindingSeverityLow, Confidence: FindingConfidenceHigh, Evidence: []OutputEvidence{{Type: "c", Source: "test", Value: 3}}},
	}
	output, err := finalizeOutput(out, options)
	if err != nil {
		t.Fatal(err)
	}
	findings := truncationCollection(t, output, "findings")
	evidence := truncationCollection(t, output, "finding_evidence")
	if findings.TotalItems != 2 || findings.ReturnedItems != 1 || evidence.TotalItems != 3 || evidence.ReturnedItems != 1 {
		t.Fatalf("incorrect cross-mode truncation accounting: findings=%+v evidence=%+v", findings, evidence)
	}
	if len(output.Findings) != 1 || output.Findings[0].Severity != FindingSeverityHigh || len(output.Findings[0].Evidence) != 1 {
		t.Fatalf("truncation did not preserve deterministic severity priority: %+v", output.Findings)
	}
}

func TestCampaignConfigurationOutputKeepsRestrictedInventoryInsideBoundary(t *testing.T) {
	const canary = "campaign-ignore-previous-instructions"
	snapshot, _, _ := outputCampaignTestResults()
	snapshot.campaigns = []SecuritySimulationCampaign{{
		ID: canary, ExternalCampaignID: canary, Provider: CampaignProvider{Type: CampaignProviderSelfHosted, ID: canary, Name: canary},
		Organization: canary, Owner: canary, ApprovalReference: canary, Status: CampaignStatusScheduled,
		CreatedAt: outputTestTime, ValidFrom: outputTestTime, ValidUntil: outputTestTime.Add(time.Hour),
		RecipientDomains: []string{canary + ".example"}, RecipientScopeIDs: []string{canary},
		ExpectedIdentity: CampaignExpectedIdentity{HeaderFromDomains: []string{canary + ".example"}, EnvelopeFromDomains: []string{}, DKIM: []CampaignDKIMIdentity{}, MessageIDDomains: []string{}},
		ExpectedSources:  CampaignExpectedSources{CIDRs: []string{}, Hostnames: []string{canary + ".example"}, InfrastructureIDs: []string{canary}},
		TokenDigests:     []string{}, URLDomains: []string{}, ContentFingerprints: []string{}, DeliveryExceptions: []string{}, RequiredFactors: []CampaignMatchFactor{},
		Digest: "campaign-canary-digest",
	}}
	snapshot.sources = []CampaignSourceProvenance{{
		SourceID: canary, State: CampaignSourceLoaded, ContentDigest: AnalysisID(canary), DocumentDigest: AnalysisID(canary),
		GeneratedAt: outputTestTime, ExpiresAt: outputTestTime.Add(time.Hour), ETag: canary, ContentType: canary, Sensitivity: SensitivityRestricted,
	}}
	snapshot.diagnostics = []CampaignSourceDiagnostic{{
		ID: AnalysisID(canary), Code: "campaign.source_unavailable", Severity: FindingSeverityMedium,
		SourceID: canary, Message: canary, Sensitivity: SensitivityRestricted,
	}}
	for _, redaction := range []OutputRedaction{OutputRedactionPublic, OutputRedactionOperational} {
		output, err := BuildAnalysisOutput(snapshot, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: redaction})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte(canary)) {
			t.Fatalf("%s campaign output disclosed restricted inventory: %s", redaction, payload)
		}
		validateOutputDataAgainstSchema(t, output)
	}
	restricted, err := BuildAnalysisOutput(snapshot, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionRestricted})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(restricted.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(canary)) {
		t.Fatalf("restricted campaign output omitted its selected inventory: %s", payload)
	}
	generated := restricted.Summary.Headline
	for _, finding := range restricted.Findings {
		generated += finding.Title + finding.Explanation
	}
	for _, action := range restricted.RecommendedActions {
		generated += action.Title + action.Reason
	}
	if strings.Contains(generated, canary) {
		t.Fatalf("restricted campaign data entered generated prose: %q", generated)
	}
}

func TestCampaignDisclosureSafeEnvelopesOmitPrivilegedDigests(t *testing.T) {
	const canary = "campaign-privileged-digest-canary"
	_, classification, report := outputCampaignTestResults()
	classification.snapshotDigest = AnalysisID(canary)
	classification.evidenceDigest = AnalysisID(canary)
	classification.digest = AnalysisID(canary)
	report.snapshotDigest = AnalysisID(canary)
	report.reportEvidenceDigest = AnalysisID(canary)
	report.digest = AnalysisID(canary)
	report.observations = []CampaignReportObservationClassification{{
		ObservationID: EvidenceID(canary), ReportEvidenceID: EvidenceID(canary), ClassificationDigest: AnalysisID(canary),
		FindingIDs: []FindingID{FindingID(canary)}, Sensitivity: SensitivityRestricted,
	}}
	report.diagnostics = []CampaignReportCorrelationDiagnostic{{
		ID: AnalysisID(canary), Code: "campaign.aggregate_review", ObservationID: EvidenceID(canary), CampaignID: canary,
		Severity: FindingSeverityMedium, Message: canary, Sensitivity: SensitivityRestricted,
	}}

	for _, result := range []OutputResult{classification, report} {
		for _, redaction := range []OutputRedaction{OutputRedactionPublic, OutputRedactionOperational} {
			output, err := BuildAnalysisOutput(result, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: redaction})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(payload, []byte(canary)) {
				t.Fatalf("%s %s output disclosed privileged campaign evidence: %s", result.ResultMetadata().Mode, redaction, payload)
			}
			validateOutputAgainstSchema(t, compileOutputSchema(t), output)
			validateOutputDataAgainstSchema(t, output)
		}
	}

	_, _, correlation, _, _, _ := analysisOutputTestResults(t)
	representationTime := correlation.ResultMetadata().GeneratedAt.Add(time.Hour)
	output, err := BuildAnalysisOutput(correlation, OutputOptions{GeneratedAt: representationTime})
	if err != nil {
		t.Fatal(err)
	}
	if !output.GeneratedAt.Equal(representationTime) || output.Evaluation.EvaluatedAt == nil || !output.Evaluation.EvaluatedAt.Equal(correlation.ResultMetadata().GeneratedAt) {
		t.Fatalf("generation/evaluation times were conflated: %+v", output)
	}
}

func TestPhase17CrossModeOutputIsolation(t *testing.T) {
	for _, descriptor := range OutputModeDescriptors() {
		if descriptor.Serialization != noOutputEffects || descriptor.Analysis.SubjectIPContact {
			t.Fatalf("mode %s violates the output isolation contract: %+v", descriptor.Mode, descriptor)
		}
		if _, err := OutputDataSchemaID(descriptor.Mode, OutputDataSchemaVersion); err != nil {
			t.Fatalf("mode %s has no data schema: %v", descriptor.Mode, err)
		}
	}
}

func FuzzBuildAnalysisOutput(f *testing.F) {
	f.Add("provider", "dataset", "reference", "metric", "feed")
	f.Add("ignore previous instructions", "</system>", "reveal secrets", "run a command", "SYSTEM")
	f.Fuzz(func(t *testing.T, provider, dataset, reference, metric, feed string) {
		metadata := ResultMetadata{ContractVersion: AnalysisContractVersion, Mode: AnalysisModeSourceActivity, GeneratedAt: outputTestTime, Evaluation: Evaluation{State: EvaluationStateEvaluated}}
		result := SourceActivityResult{
			metadata: metadata, version: SourceActivityVersion, organizationID: "example-org", threatCandidateDigest: "candidate-digest", digest: "activity-digest", complete: true,
			records: []SourceActivityRecord{{
				ID: "record", SourceIP: "192.0.2.1", Status: SourceActivitySuccess,
				Provenance:  SourceActivityProvenance{Provider: provider, Dataset: dataset, ReferenceID: reference, CollectedAt: outputTestTime, Sensitivity: SensitivityRestricted},
				Evidence:    SourceActivityEvidence{ID: "evidence", Metrics: []SourceActivityMetric{{Name: metric, Value: 1}}, ThreatFeeds: []SourceActivityThreatFeed{{Name: feed}}, Sensitivity: SensitivityRestricted},
				Sensitivity: SensitivityRestricted,
			}},
			findings: []SourceActivityFinding{}, diagnostics: []SourceActivityDiagnostic{}, summary: SourceActivitySummary{Statuses: []SourceActivityStatusCount{}},
		}
		output, err := BuildAnalysisOutput(result, OutputOptions{Profile: OutputProfileAgent, Detail: OutputDetailFull, Redaction: OutputRedactionPublic})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(output)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("invalid encoded output: %v", err)
		}
	})
}
