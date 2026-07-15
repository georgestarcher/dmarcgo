package dmarcgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

type analysisEnvelopeSpec struct {
	mode        OutputMode
	metadata    ResultMetadata
	digest      AnalysisID
	dataSchema  string
	data        any
	findings    []any
	diagnostics []any
	input       OutputInput
	scope       OutputScope
	limitations []string
	automation  AutomationPolicy
}

type campaignConfigurationPrivilegedData struct {
	View                   CampaignOutputView           `json:"view"`
	Version                string                       `json:"version"`
	PreviousDigest         AnalysisID                   `json:"previous_digest,omitempty"`
	Complete               bool                         `json:"complete"`
	AuthorizationAvailable bool                         `json:"authorization_available"`
	EffectiveAt            time.Time                    `json:"effective_at"`
	ExpiresAt              time.Time                    `json:"expires_at"`
	Campaigns              []SecuritySimulationCampaign `json:"campaigns"`
	Sources                []CampaignSourceProvenance   `json:"sources"`
	Diagnostics            []CampaignSourceDiagnostic   `json:"diagnostics"`
}

type campaignConfigurationDisclosureData struct {
	View                   CampaignOutputView `json:"view"`
	Version                string             `json:"version"`
	Complete               bool               `json:"complete"`
	AuthorizationAvailable bool               `json:"authorization_available"`
	CampaignCount          int                `json:"campaign_count"`
	SourceCount            int                `json:"source_count"`
	DiagnosticCount        int                `json:"diagnostic_count"`
}

type campaignClassificationPrivilegedData struct {
	View           CampaignOutputView              `json:"view"`
	Version        string                          `json:"version"`
	SnapshotDigest AnalysisID                      `json:"campaign_snapshot_digest"`
	EvidenceDigest AnalysisID                      `json:"message_evidence_digest"`
	Records        []CampaignClassificationRecord  `json:"records"`
	Findings       []CampaignClassificationFinding `json:"findings"`
	Summary        CampaignClassificationSummary   `json:"summary"`
}

type campaignClassificationDisclosureData struct {
	View     CampaignOutputView              `json:"view"`
	Version  string                          `json:"version"`
	Records  []CampaignDisclosureSafeRecord  `json:"records"`
	Findings []CampaignDisclosureSafeFinding `json:"findings"`
	Summary  CampaignDisclosureSafeSummary   `json:"summary"`
}

type campaignReportPrivilegedData struct {
	View                 CampaignOutputView                        `json:"view"`
	EvidenceKind         string                                    `json:"evidence_kind"`
	Version              string                                    `json:"version"`
	SnapshotDigest       AnalysisID                                `json:"campaign_snapshot_digest"`
	ReportEvidenceDigest AnalysisID                                `json:"report_evidence_digest"`
	Observations         []CampaignReportObservationClassification `json:"observations"`
	Diagnostics          []CampaignReportCorrelationDiagnostic     `json:"diagnostics"`
	Summary              CampaignReportCorrelationSummary          `json:"summary"`
}

type campaignReportDisclosureData struct {
	View                  CampaignOutputView `json:"view"`
	EvidenceKind          string             `json:"evidence_kind"`
	Version               string             `json:"version"`
	ObservationCount      int                `json:"observation_count"`
	DiagnosticCount       int                `json:"diagnostic_count"`
	AggregateEvidenceOnly bool               `json:"aggregate_evidence_only"`
}

// OutputResult is a completed result supported by BuildAnalysisOutput. The
// unexported marker keeps the accepted result set compile-time bounded while
// allowing every supported dmarcgo result to share one serialization entrypoint.
type OutputResult interface {
	Result
	outputResult()
}

func (ConfigurationValidationResult) outputResult()   {}
func (DNSSnapshot) outputResult()                     {}
func (DNSAuthenticationResult) outputResult()         {}
func (DNSPerspectiveResult) outputResult()            {}
func (DNSHealthResult) outputResult()                 {}
func (ReportEvidenceResult) outputResult()            {}
func (DNSReportCorrelationResult) outputResult()      {}
func (ThreatCandidateResult) outputResult()           {}
func (SourceEnrichmentResult) outputResult()          {}
func (SourceActivityResult) outputResult()            {}
func (PhishingIntelligenceResult) outputResult()      {}
func (JurisdictionContextResult) outputResult()       {}
func (CampaignConfigurationSnapshot) outputResult()   {}
func (CampaignClassificationResult) outputResult()    {}
func (CampaignReportCorrelationResult) outputResult() {}

// BuildAnalysisOutput creates the common automation/agent envelope for an
// already completed v2 analysis result. It performs no analysis, collection,
// lookup, file access, enrichment, campaign retrieval, or clock lookup beyond
// the representation timestamp selected through OutputOptions.
func BuildAnalysisOutput(result OutputResult, options OutputOptions) (OutputEnvelope, error) {
	result, err := normalizeOutputResult(result)
	if err != nil {
		return OutputEnvelope{}, err
	}
	options, err = normalizeOutputOptionsWithoutClock(options, result.ResultMetadata().GeneratedAt)
	if err != nil {
		return OutputEnvelope{}, err
	}
	spec, err := analysisEnvelopeSpecFor(result, options.Redaction)
	if err != nil {
		return OutputEnvelope{}, err
	}
	if err := validateAnalysisEnvelopeSpec(spec); err != nil {
		return OutputEnvelope{}, err
	}

	data, err := outputDataObject(spec.data)
	if err != nil {
		return OutputEnvelope{}, err
	}
	dataChanged := false
	if options.Detail == OutputDetailStandard {
		value, changed, transformErr := transformAnalysisOutputValue(data, OutputRedactionOperational)
		if transformErr != nil {
			return OutputEnvelope{}, transformErr
		}
		data = value.(map[string]any)
		dataChanged = changed
	}
	setAnalysisDocumentRedaction(data, options.Redaction, dataChanged)

	out := baseOutput(spec.mode, spec.scope, spec.input, options)
	out.DataSchema = spec.dataSchema
	out.Evaluation = outputEvaluationFromMetadata(spec.metadata)
	out.Data = data
	out.Limitations = append([]string(nil), spec.limitations...)
	if spec.automation.Reason != "" {
		out.Automation = spec.automation
	}
	out.Input.Artifacts = outputArtifactsForSpec(spec, data)
	out.Provenance = outputProvenanceForSpec(spec, out.Input.Artifacts)
	out.Input.Coverage = outputCoverageForSpec(spec, data)
	out.Findings = outputFindingsForSpec(spec)
	out.Warnings = outputDiagnosticsForSpec(spec)
	out.Summary = outputSummaryForSpec(spec, out.Findings)
	if len(out.Findings) > 0 {
		code := ActionCode("review_" + strings.ReplaceAll(string(spec.mode), ".", "_"))
		out.RecommendedActions = []OutputAction{{
			Code: code, Priority: 1, Title: "Review the completed analysis findings",
			Reason: "Confirm the structured evidence, contradictions, unknowns, and organizational context before taking action.",
			Target: map[string]string{}, Automation: AutomationPolicy{Eligible: false, Reason: "The library does not execute or authorize external action."},
			Sensitivity: SensitivityOperational,
		}}
		for index := range out.Findings {
			out.Findings[index].ActionCodes = []ActionCode{code}
		}
	}
	limitOutputDataCollections(&out, options.MaxItems)
	return finalizeOutput(out, options)
}

func outputEvaluationFromMetadata(metadata ResultMetadata) OutputEvaluation {
	result := OutputEvaluation{State: metadata.Evaluation.State, Reason: metadata.Evaluation.Reason}
	if !metadata.GeneratedAt.IsZero() {
		evaluatedAt := metadata.GeneratedAt.UTC()
		result.EvaluatedAt = &evaluatedAt
	}
	return result
}

func normalizeOutputResult(result OutputResult) (OutputResult, error) {
	if result == nil {
		return nil, fmt.Errorf("%w: nil analysis result", ErrInvalidAnalysisResult)
	}
	value := reflect.ValueOf(result)
	if value.Kind() != reflect.Pointer {
		return result, nil
	}
	if value.IsNil() {
		return nil, fmt.Errorf("%w: nil analysis result", ErrInvalidAnalysisResult)
	}
	normalized, ok := value.Elem().Interface().(OutputResult)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported result type %T", ErrInvalidAnalysisResult, result)
	}
	return normalized, nil
}

func analysisEnvelopeSpecFor(result OutputResult, redaction OutputRedaction) (analysisEnvelopeSpec, error) {
	switch value := result.(type) {
	case ConfigurationValidationResult:
		spec, err := analysisEnvelopeSpecFromNative(configurationValidationOutputSpec(value))
		if err == nil {
			spec.findings = anySlice(value.Diagnostics)
			spec.diagnostics = []any{}
		}
		return spec, err
	case DNSSnapshot:
		return analysisEnvelopeSpecFromNative(dnsSnapshotOutputSpec(value))
	case DNSAuthenticationResult:
		spec, err := analysisEnvelopeSpecFromNative(dnsAuthenticationOutputSpec(value))
		if err == nil {
			spec.findings = anySlice(value.Diagnostics())
			spec.diagnostics = []any{}
		}
		return spec, err
	case DNSPerspectiveResult:
		return analysisEnvelopeSpecFromNative(dnsPerspectivesOutputSpec(value))
	case DNSHealthResult:
		return analysisEnvelopeSpecFromNative(dnsHealthOutputSpec(value))
	case ReportEvidenceResult:
		return analysisEnvelopeSpecFromNative(reportEvidenceOutputSpec(value))
	case DNSReportCorrelationResult:
		return analysisEnvelopeSpecFromNative(correlationOutputSpec(value))
	case ThreatCandidateResult:
		spec, err := analysisEnvelopeSpecFromNative(threatCandidateOutputSpec(value))
		if err == nil {
			spec.findings = anySlice(value.Candidates())
		}
		return spec, err
	case SourceEnrichmentResult:
		return analysisEnvelopeSpecFromNative(sourceEnrichmentOutputSpec(value))
	case SourceActivityResult:
		return analysisEnvelopeSpecFromNative(sourceActivityOutputSpec(value))
	case PhishingIntelligenceResult:
		return analysisEnvelopeSpecFromNative(phishingIntelligenceOutputSpec(value))
	case JurisdictionContextResult:
		return analysisEnvelopeSpecFromNative(jurisdictionContextOutputSpec(value))
	case CampaignConfigurationSnapshot:
		return campaignConfigurationEnvelopeSpec(value, redaction)
	case CampaignClassificationResult:
		return campaignClassificationEnvelopeSpec(value, redaction)
	case CampaignReportCorrelationResult:
		return campaignReportEnvelopeSpec(value, redaction)
	default:
		return analysisEnvelopeSpec{}, fmt.Errorf("%w: unsupported result type %T", ErrInvalidAnalysisResult, result)
	}
}

func analysisEnvelopeSpecFromNative(native analysisOutputSpec) (analysisEnvelopeSpec, error) {
	data, err := outputDataObject(native.document)
	if err != nil {
		return analysisEnvelopeSpec{}, err
	}
	findings := []any{}
	diagnostics := []any{}
	if err := native.walk(func(recordType, _ string, value any) error {
		switch recordType {
		case "finding":
			findings = append(findings, value)
		case "diagnostic":
			diagnostics = append(diagnostics, value)
		}
		return nil
	}); err != nil {
		return analysisEnvelopeSpec{}, err
	}
	for _, key := range []string{"schema", "schema_version", "mode", "profile", "metadata", "result_digest", "redaction"} {
		delete(data, key)
	}
	input := outputInputFromData(native.mode, data)
	scope := outputScopeFromData(data)
	dataSchema, _ := AnalysisOutputSchemaID(native.mode, AnalysisOutputSchemaVersion)
	return analysisEnvelopeSpec{
		mode: native.mode, metadata: native.metadata, digest: native.digest, dataSchema: dataSchema + "#/$defs/envelope_data", data: data,
		findings: findings, diagnostics: diagnostics, input: input, scope: scope,
		limitations: outputModeLimitations(native.mode),
	}, nil
}

func campaignConfigurationEnvelopeSpec(snapshot CampaignConfigurationSnapshot, redaction OutputRedaction) (analysisEnvelopeSpec, error) {
	metadata := snapshot.ResultMetadata()
	campaigns, sources, diagnostics := snapshot.Campaigns(), snapshot.Sources(), snapshot.Diagnostics()
	var data any
	digest := snapshot.Digest()
	findings := anySlice(diagnostics)
	artifacts := make([]OutputInputArtifact, 0, len(sources))
	if redaction == OutputRedactionRestricted {
		data = campaignConfigurationPrivilegedData{
			View: CampaignOutputPrivileged, Version: snapshot.Version(), PreviousDigest: snapshot.PreviousDigest(), Complete: snapshot.Complete(),
			AuthorizationAvailable: snapshot.AuthorizationAvailable(), EffectiveAt: snapshot.EffectiveAt(), ExpiresAt: snapshot.ExpiresAt(),
			Campaigns: campaigns, Sources: sources, Diagnostics: diagnostics,
		}
		for _, source := range sources {
			sourceDigest := source.DocumentDigest
			if sourceDigest == "" {
				sourceDigest = source.ContentDigest
			}
			artifacts = append(artifacts, OutputInputArtifact{Type: "campaign_source", Digest: sourceDigest, State: metadata.Evaluation.State, Sensitivity: SensitivityRestricted})
		}
	} else {
		data = campaignConfigurationDisclosureData{
			View: CampaignOutputDisclosureSafe, Version: snapshot.Version(), Complete: snapshot.Complete(), AuthorizationAvailable: snapshot.AuthorizationAvailable(),
			CampaignCount: len(campaigns), SourceCount: len(sources), DiagnosticCount: len(diagnostics),
		}
		findings = campaignConfigurationDisclosureFindings(diagnostics)
		digest = StableAnalysisID("campaign_configuration_disclosure_safe_result", canonicalSortKey(struct {
			Metadata ResultMetadata                      `json:"metadata"`
			Data     campaignConfigurationDisclosureData `json:"data"`
			Findings []any                               `json:"findings"`
		}{metadata, data.(campaignConfigurationDisclosureData), findings}))
	}
	return analysisEnvelopeSpec{
		mode: metadata.Mode, metadata: metadata, digest: digest, dataSchema: campaignConfigurationOutputDataSchemaID, data: data,
		findings: findings, input: OutputInput{RecordCount: len(campaigns), Artifacts: artifacts},
		limitations: []string{"Campaign inventory is restricted operational data; disclosure-safe output omits campaign identities, timing, infrastructure, and source details."},
	}, nil
}

func campaignConfigurationDisclosureFindings(diagnostics []CampaignSourceDiagnostic) []any {
	result := make([]any, 0, len(diagnostics))
	for index, diagnostic := range diagnostics {
		result = append(result, struct {
			ID          AnalysisID      `json:"id"`
			Code        DiagnosticCode  `json:"code"`
			Severity    FindingSeverity `json:"severity"`
			Sensitivity Sensitivity     `json:"sensitivity"`
		}{
			ID:   StableAnalysisID("campaign_configuration_disclosure_safe_finding", fmt.Sprint(index), string(diagnostic.Code), string(diagnostic.Severity)),
			Code: diagnostic.Code, Severity: diagnostic.Severity, Sensitivity: SensitivityOperational,
		})
	}
	return result
}

func campaignClassificationEnvelopeSpec(result CampaignClassificationResult, redaction OutputRedaction) (analysisEnvelopeSpec, error) {
	metadata := result.ResultMetadata()
	if redaction != OutputRedactionRestricted {
		safe, err := result.DisclosureSafe()
		if err != nil {
			return analysisEnvelopeSpec{}, err
		}
		automation := AutomationPolicy{Eligible: false, Reason: "Disclosure-safe campaign output does not itself authorize disposition."}
		if safe.Summary.AutomaticDispositionReady == 1 {
			automation = AutomationPolicy{Eligible: true, Reason: "Exactly one completed classification met the caller-enabled campaign disposition policy; the application still owns execution and audit."}
		}
		return analysisEnvelopeSpec{
			mode: metadata.Mode, metadata: metadata, digest: safe.ResultDigest,
			dataSchema: campaignClassificationOutputDataSchemaID,
			data:       campaignClassificationDisclosureData{View: CampaignOutputDisclosureSafe, Version: safe.Version, Records: safe.Records, Findings: safe.Findings, Summary: safe.Summary},
			findings:   anySlice(safe.Findings), input: OutputInput{RecordCount: len(safe.Records)}, automation: automation,
			limitations: []string{"Disclosure-safe campaign output supports neutral routing and never proves an individual message belongs to a campaign from aggregate evidence alone."},
		}, nil
	}
	records, findings := result.Records(), result.Findings()
	automation := AutomationPolicy{Eligible: false, Reason: "The completed campaign classification did not uniquely meet the caller-enabled disposition policy."}
	ready := 0
	for _, record := range records {
		if record.AutomaticDispositionEligible {
			ready++
		}
	}
	if ready == 1 {
		automation = AutomationPolicy{Eligible: true, Reason: "Exactly one completed classification met the caller-enabled campaign disposition policy; the application still owns execution and audit."}
	}
	return analysisEnvelopeSpec{
		mode: metadata.Mode, metadata: metadata, digest: result.Digest(),
		dataSchema: campaignClassificationOutputDataSchemaID,
		data: campaignClassificationPrivilegedData{
			View: CampaignOutputPrivileged, Version: result.Version(), SnapshotDigest: result.SnapshotDigest(), EvidenceDigest: result.EvidenceDigest(),
			Records: records, Findings: findings, Summary: result.Summary(),
		},
		findings: anySlice(findings), input: OutputInput{RecordCount: len(records), Artifacts: []OutputInputArtifact{
			{Type: "campaign_snapshot", Digest: result.SnapshotDigest(), State: EvaluationStateEvaluated, Sensitivity: SensitivityRestricted},
			{Type: "reported_message_evidence", Digest: result.EvidenceDigest(), State: EvaluationStateEvaluated, Sensitivity: SensitivityRestricted},
		}}, automation: automation,
		limitations: []string{"Privileged campaign output is restricted and never executes a disposition or sends an employee response."},
	}, nil
}

func campaignReportEnvelopeSpec(result CampaignReportCorrelationResult, redaction OutputRedaction) (analysisEnvelopeSpec, error) {
	metadata := result.ResultMetadata()
	observations, diagnostics := result.Observations(), result.Diagnostics()
	var data any
	digest := result.Digest()
	findings := anySlice(observations)
	artifacts := []OutputInputArtifact{}
	if redaction == OutputRedactionRestricted {
		data = campaignReportPrivilegedData{
			View: CampaignOutputPrivileged, EvidenceKind: "aggregate_report", Version: result.Version(), SnapshotDigest: result.SnapshotDigest(),
			ReportEvidenceDigest: result.ReportEvidenceDigest(), Observations: observations, Diagnostics: diagnostics, Summary: result.Summary(),
		}
		artifacts = []OutputInputArtifact{
			{Type: "campaign_snapshot", Digest: result.SnapshotDigest(), State: EvaluationStateEvaluated, Sensitivity: SensitivityRestricted},
			{Type: "report_evidence", Digest: result.ReportEvidenceDigest(), State: EvaluationStateEvaluated, Sensitivity: SensitivityOperational},
		}
	} else {
		disclosure := campaignReportDisclosureData{
			View: CampaignOutputDisclosureSafe, EvidenceKind: "aggregate_report", Version: result.Version(), ObservationCount: len(observations),
			DiagnosticCount: len(diagnostics), AggregateEvidenceOnly: true,
		}
		data = disclosure
		findings = campaignReportDisclosureFindings(observations)
		digest = StableAnalysisID("campaign_report_disclosure_safe_result", canonicalSortKey(struct {
			Metadata ResultMetadata               `json:"metadata"`
			Data     campaignReportDisclosureData `json:"data"`
			Findings []any                        `json:"findings"`
		}{metadata, disclosure, findings}))
	}
	return analysisEnvelopeSpec{
		mode: metadata.Mode, metadata: metadata, digest: digest, dataSchema: campaignClassificationOutputDataSchemaID, data: data,
		findings: findings, diagnostics: anySlice(diagnostics), input: OutputInput{RecordCount: len(observations), Artifacts: artifacts},
		limitations: []string{"Aggregate report periods are not exact message times and cannot prove that an individual message belonged to a campaign."},
	}, nil
}

func campaignReportDisclosureFindings(observations []CampaignReportObservationClassification) []any {
	result := []any{}
	for observationIndex, observation := range observations {
		for findingIndex := range observation.FindingIDs {
			result = append(result, struct {
				ID          FindingID         `json:"id"`
				Code        FindingCode       `json:"code"`
				Severity    FindingSeverity   `json:"severity"`
				Confidence  FindingConfidence `json:"confidence"`
				Sensitivity Sensitivity       `json:"sensitivity"`
			}{
				ID:   FindingID(StableAnalysisID("campaign_report_disclosure_safe_finding", fmt.Sprint(observationIndex), fmt.Sprint(findingIndex))),
				Code: "campaign.aggregate_evidence_review", Severity: FindingSeverityMedium, Confidence: FindingConfidenceLow, Sensitivity: SensitivityOperational,
			})
		}
	}
	return result
}

func validateAnalysisEnvelopeSpec(spec analysisEnvelopeSpec) error {
	if spec.metadata.ContractVersion != AnalysisContractVersion || spec.metadata.Mode != spec.mode || spec.digest == "" {
		return fmt.Errorf("%w: incomplete result for mode %q", ErrInvalidAnalysisResult, spec.mode)
	}
	if spec.metadata.GeneratedAt.IsZero() && spec.mode != AnalysisModeReportEvidence {
		return fmt.Errorf("%w: missing result timestamp for mode %q", ErrInvalidAnalysisResult, spec.mode)
	}
	if _, err := OutputModeDescriptorFor(spec.mode); err != nil {
		return err
	}
	switch spec.metadata.Evaluation.State {
	case EvaluationStateEvaluated:
		if spec.metadata.Evaluation.Reason != "" {
			return fmt.Errorf("%w: evaluated result has a reason", ErrInvalidAnalysisResult)
		}
	case EvaluationStateNotEvaluated, EvaluationStateUnknown, EvaluationStateNotApplicable:
		if spec.metadata.Evaluation.Reason == "" {
			return fmt.Errorf("%w: unevaluated result lacks a reason", ErrInvalidAnalysisResult)
		}
	default:
		return fmt.Errorf("%w: invalid evaluation state %q", ErrInvalidAnalysisResult, spec.metadata.Evaluation.State)
	}
	return nil
}

func outputDataObject(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.Join(ErrOutputSerialization, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.Join(ErrOutputSerialization, err)
	}
	if result == nil {
		return nil, fmt.Errorf("%w: mode data must be an object", ErrOutputSerialization)
	}
	return result, nil
}

func anySlice[T any](values []T) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}

func outputFindingsForSpec(spec analysisEnvelopeSpec) []OutputFinding {
	result := make([]OutputFinding, 0, len(spec.findings))
	for index, value := range spec.findings {
		object, err := outputDataObject(value)
		if err != nil {
			continue
		}
		if !outputRecordProducesFinding(spec.mode, object) {
			continue
		}
		code := FindingCode(outputString(object["code"]))
		if code == "" {
			code = outputDefaultFindingCode(spec.mode)
		}
		severity := outputFindingSeverity(object["severity"])
		confidence := FindingConfidence(outputString(object["confidence"]))
		if !validOutputConfidence(confidence) {
			confidence = FindingConfidenceMedium
		}
		sensitivity := Sensitivity(outputString(object["sensitivity"]))
		if !validOutputSensitivity(sensitivity) {
			sensitivity = SensitivityOperational
		}
		id := FindingID(outputString(object["id"]))
		if id == "" {
			id = FindingID(StableAnalysisID("output_mode_finding", string(spec.mode), string(code), fmt.Sprint(index), canonicalSortKey(object)))
		}
		finding := OutputFinding{
			ID: id, Code: code, Category: outputFindingCategory(code), Severity: severity, Confidence: confidence,
			Title: outputModeFindingTitle(spec.mode), Explanation: outputModeFindingExplanation(spec.mode),
			Subject: outputFindingSubject(object), Evidence: []OutputEvidence{}, ContradictoryEvidence: []OutputEvidence{},
			MissingEvidence: []OutputEvidence{}, UnverifiableEvidence: []OutputEvidence{}, Limitations: outputModeLimitations(spec.mode),
			ActionCodes: []ActionCode{}, Automation: AutomationPolicy{Eligible: false, Reason: "A finding requires caller policy and human authorization."},
			Sensitivity: sensitivity, Documentation: outputModeDocumentation(spec.mode), Provenance: []ProvenanceID{ProvenanceID(spec.digest)},
		}
		finding.Evidence = outputEvidenceFields(spec, id, object, []string{
			"evidence", "matched", "matched_evidence", "reasons", "evidence_ids", "observation_ids", "report_evidence_ids", "stream_ids",
			"record_ids", "match_ids", "assertion_ids", "policy_entry_ids", "dns_finding_ids", "correlation_finding_ids", "provider_context_ids",
		})
		finding.ContradictoryEvidence = outputEvidenceFields(spec, id, object, []string{"contradictory_evidence", "mismatched", "counter_evidence", "conflict_fields"})
		finding.MissingEvidence = outputEvidenceFields(spec, id, object, []string{"missing", "missing_evidence"})
		finding.UnverifiableEvidence = outputEvidenceFields(spec, id, object, []string{"unverifiable", "unverifiable_evidence", "unknown"})
		if len(finding.Evidence)+len(finding.ContradictoryEvidence)+len(finding.MissingEvidence)+len(finding.UnverifiableEvidence) == 0 {
			finding.Evidence = []OutputEvidence{{
				Type: "analysis_record", Source: string(spec.mode), Value: map[string]any{"record_id": string(id)}, State: spec.metadata.Evaluation.State,
				Provenance: ProvenanceID(spec.digest), Sensitivity: sensitivity,
			}}
		}
		result = append(result, finding)
	}
	return result
}

func outputRecordProducesFinding(mode OutputMode, object map[string]any) bool {
	switch mode {
	case OutputModeThreatCandidates:
		eligible, _ := object["review_eligible"].(bool)
		excluded, _ := object["excluded"].(bool)
		return eligible && !excluded
	case OutputModeCampaignClassification:
		if _, aggregate := object["observation_id"]; aggregate {
			ids, _ := object["finding_ids"].([]any)
			return len(ids) > 0
		}
	}
	return true
}

func outputDefaultFindingCode(mode OutputMode) FindingCode {
	switch mode {
	case OutputModeThreatCandidates:
		return "threat_candidate.review"
	case OutputModeCampaignClassification:
		return "campaign.aggregate_evidence_review"
	default:
		return FindingCode(string(mode) + ".review")
	}
}

func outputFindingSeverity(value any) FindingSeverity {
	severity := FindingSeverity(outputString(value))
	if validOutputSeverity(severity) {
		return severity
	}
	switch ValidationSeverity(outputString(value)) {
	case ValidationError:
		return FindingSeverityMedium
	case ValidationWarning:
		return FindingSeverityLow
	default:
		return FindingSeverityMedium
	}
}

func outputEvidenceFields(spec analysisEnvelopeSpec, findingID FindingID, object map[string]any, fields []string) []OutputEvidence {
	result := []OutputEvidence{}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || value == nil {
			continue
		}
		result = append(result, OutputEvidence{
			ID:   EvidenceID(StableAnalysisID("output_mode_evidence", string(findingID), field, canonicalSortKey(value))),
			Type: field, Source: string(spec.mode), Path: field, Value: value, State: spec.metadata.Evaluation.State,
			Provenance: ProvenanceID(spec.digest), Sensitivity: SensitivityOperational,
		})
	}
	return result
}

func outputDiagnosticsForSpec(spec analysisEnvelopeSpec) []OutputMessage {
	result := make([]OutputMessage, 0, len(spec.diagnostics))
	for _, value := range spec.diagnostics {
		object, err := outputDataObject(value)
		if err != nil {
			continue
		}
		code := DiagnosticCode(outputString(object["code"]))
		if code == "" {
			code = DiagnosticCode(string(spec.mode) + ".diagnostic")
		}
		result = append(result, OutputMessage{
			Code: code, Category: outputFindingCategory(FindingCode(code)),
			Message: "The completed analysis retained a structured diagnostic for caller review.", Retryable: false,
		})
	}
	return result
}

func outputSummaryForSpec(spec analysisEnvelopeSpec, findings []OutputFinding) OutputSummary {
	severity := highestSeverity(findings)
	confidence := FindingConfidenceHigh
	if spec.metadata.Evaluation.State != EvaluationStateEvaluated {
		severity = FindingSeverityInfo
		confidence = FindingConfidenceLow
		return OutputSummary{Headline: "The requested analysis was not fully evaluated; inspect the structured evaluation state and limitations.", Severity: severity, Confidence: confidence}
	}
	if len(findings) == 0 {
		return OutputSummary{Headline: "The completed analysis produced no structured review findings.", Severity: FindingSeverityInfo, Confidence: confidence}
	}
	return OutputSummary{Headline: "The completed analysis produced structured findings that require contextual review.", Severity: severity, Confidence: confidence}
}

func outputProvenanceForSpec(spec analysisEnvelopeSpec, artifacts []OutputInputArtifact) []OutputProvenance {
	result := []OutputProvenance{{ID: ProvenanceID(spec.digest), Type: "analysis_result", Sensitivity: SensitivityOperational}}
	seen := map[ProvenanceID]struct{}{ProvenanceID(spec.digest): {}}
	for _, artifact := range artifacts {
		id := ProvenanceID(artifact.Digest)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, OutputProvenance{ID: id, Type: artifact.Type, Sensitivity: artifact.Sensitivity})
	}
	return result
}

func outputArtifactsForSpec(spec analysisEnvelopeSpec, data map[string]any) []OutputInputArtifact {
	artifacts := []OutputInputArtifact{{Type: "analysis_result", Digest: spec.digest, State: spec.metadata.Evaluation.State, Sensitivity: SensitivityOperational}}
	artifacts = append(artifacts, spec.input.Artifacts...)
	keys := make([]string, 0, len(data))
	for key := range data {
		if key != "result_digest" && (strings.HasSuffix(key, "_digest") || strings.HasSuffix(key, "_digests")) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch value := data[key].(type) {
		case string:
			if value != "" {
				artifacts = append(artifacts, OutputInputArtifact{Type: key, Digest: AnalysisID(value), State: spec.metadata.Evaluation.State, Sensitivity: SensitivityOperational})
			}
		case []any:
			for _, item := range value {
				if digest, ok := item.(string); ok && digest != "" {
					artifacts = append(artifacts, OutputInputArtifact{Type: key, Digest: AnalysisID(digest), State: spec.metadata.Evaluation.State, Sensitivity: SensitivityOperational})
				}
			}
		}
	}
	sort.SliceStable(artifacts, func(i, j int) bool { return canonicalSortKey(artifacts[i]) < canonicalSortKey(artifacts[j]) })
	result := artifacts[:0]
	seen := map[string]struct{}{}
	for _, artifact := range artifacts {
		key := canonicalSortKey(artifact)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, artifact)
	}
	return result
}

func outputCoverageForSpec(spec analysisEnvelopeSpec, data map[string]any) []OutputCoverage {
	coverage := []OutputCoverage{}
	keys := make([]string, 0, len(data))
	for key, value := range data {
		if _, ok := value.([]any); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		total := len(data[key].([]any))
		value := OutputCoverage{Name: key, State: spec.metadata.Evaluation.State, Total: total}
		switch spec.metadata.Evaluation.State {
		case EvaluationStateEvaluated:
			value.Evaluated = total
		case EvaluationStateUnknown:
			value.Unknown = total
		}
		coverage = append(coverage, value)
	}
	return coverage
}

func outputInputFromData(mode OutputMode, data map[string]any) OutputInput {
	input := OutputInput{}
	primaryCollections := map[OutputMode]string{
		OutputModeConfigurationValidation: "diagnostics",
		OutputModeDNSSnapshot:             "observations",
		OutputModeDNSAuthentication:       "record_sets",
		OutputModeDNSHealth:               "records",
		OutputModeDNSPerspectives:         "queries",
		OutputModeReportEvidence:          "observations",
		OutputModeDNSReportCorrelation:    "streams",
		OutputModeThreatCandidates:        "candidates",
		OutputModeSourceEnrichment:        "candidates",
		OutputModeSourceActivity:          "records",
		OutputModePhishingIntelligence:    "candidates",
		OutputModeJurisdictionContext:     "candidates",
	}
	if key := primaryCollections[mode]; key != "" {
		if values, ok := data[key].([]any); ok {
			input.RecordCount = len(values)
		}
	}
	if reports, ok := data["reports"].([]any); ok {
		input.ReportCount = len(reports)
	}
	if summary, ok := data["summary"].(map[string]any); ok {
		if value, ok := outputInt(summary["reports"]); ok {
			input.ReportCount = value
		}
		if value, ok := outputInt(summary["records"]); ok {
			input.RecordCount = value
		}
		for _, key := range []string{"messages", "total_messages"} {
			if value, ok := outputInt(summary[key]); ok {
				input.MessageCount = value
				break
			}
		}
	}
	return input
}

func outputScopeFromData(data map[string]any) OutputScope {
	scope := OutputScope{EntityIDs: []string{}, BusinessUnits: []string{}, TargetDomains: []string{}}
	if organization := outputString(data["organization_id"]); organization != "" {
		scope.OrganizationID = organization
	}
	collectOutputScope(data, &scope, 0)
	scope.EntityIDs = compactSortedStrings(scope.EntityIDs)
	scope.BusinessUnits = compactSortedStrings(scope.BusinessUnits)
	scope.TargetDomains = compactSortedStrings(scope.TargetDomains)
	return scope
}

func collectOutputScope(value any, scope *OutputScope, depth int) {
	if depth > 4 || len(scope.TargetDomains)+len(scope.EntityIDs)+len(scope.BusinessUnits) > 10000 {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			switch key {
			case "domain", "target_domain", "author_domain", "policy_domain", "portfolio_domain":
				if text := outputString(item); text != "" {
					scope.TargetDomains = append(scope.TargetDomains, text)
				}
			case "entity_id":
				if text := outputString(item); text != "" {
					scope.EntityIDs = append(scope.EntityIDs, text)
				}
			case "business_unit":
				if text := outputString(item); text != "" {
					scope.BusinessUnits = append(scope.BusinessUnits, text)
				}
			}
			collectOutputScope(item, scope, depth+1)
		}
	case []any:
		for _, item := range typed {
			collectOutputScope(item, scope, depth+1)
		}
	}
}

func limitOutputDataCollections(out *OutputEnvelope, maxItems int) {
	data, ok := out.Data.(map[string]any)
	if !ok {
		return
	}
	keys := make([]string, 0, len(data))
	for key, value := range data {
		if _, ok := value.([]any); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := data[key].([]any)
		total := len(values)
		if total > maxItems {
			data[key] = append([]any(nil), values[:maxItems]...)
		}
		addTruncation(out, "data."+key, total, len(data[key].([]any)))
	}
}

func outputFindingSubject(object map[string]any) map[string]string {
	result := map[string]string{}
	for _, key := range []string{"organization_id", "entity_id", "business_unit", "domain", "target_domain", "author_domain", "record_name", "source_ip", "candidate_id", "campaign_id"} {
		if value := outputString(object[key]); value != "" {
			result[key] = value
		}
	}
	for _, nestedKey := range []string{"candidate", "subject", "record"} {
		if nested, ok := object[nestedKey].(map[string]any); ok {
			for key, value := range outputFindingSubject(nested) {
				result[key] = value
			}
		}
	}
	return result
}

func outputFindingCategory(code FindingCode) string {
	value := string(code)
	if index := strings.IndexByte(value, '.'); index > 0 {
		return value[:index]
	}
	return "analysis"
}

func outputModeFindingTitle(mode OutputMode) string {
	switch mode {
	case OutputModeDNSHealth, OutputModeDNSAuthentication, OutputModeDNSSnapshot, OutputModeDNSPerspectives:
		return "DNS authentication evidence requires review"
	case OutputModeReportEvidence, OutputModeDNSReportCorrelation:
		return "DMARC report evidence requires review"
	case OutputModeThreatCandidates, OutputModeSourceEnrichment, OutputModeSourceActivity, OutputModePhishingIntelligence, OutputModeJurisdictionContext:
		return "Suspicious-source context requires review"
	case OutputModeCampaignValidation, OutputModeCampaignClassification:
		return "Campaign workflow evidence requires restricted review"
	case OutputModeConfigurationValidation:
		return "Organization configuration requires review"
	default:
		return "Analysis evidence requires review"
	}
}

func outputModeFindingExplanation(mode OutputMode) string {
	switch mode {
	case OutputModeDNSHealth, OutputModeDNSAuthentication, OutputModeDNSSnapshot, OutputModeDNSPerspectives:
		return "The completed DNS workflow produced the structured finding identified by this stable code."
	case OutputModeReportEvidence, OutputModeDNSReportCorrelation:
		return "The completed report workflow produced the structured finding identified by this stable code."
	case OutputModeThreatCandidates, OutputModeSourceEnrichment, OutputModeSourceActivity, OutputModePhishingIntelligence, OutputModeJurisdictionContext:
		return "The completed source-review workflow produced the structured finding identified by this stable code without making a malicious attribution."
	case OutputModeCampaignValidation, OutputModeCampaignClassification:
		return "The completed campaign workflow produced the structured finding identified by this stable code; disclosure and disposition remain caller-controlled."
	case OutputModeConfigurationValidation:
		return "The completed configuration workflow produced the structured finding identified by this stable code."
	default:
		return "The completed analysis produced the structured finding identified by this stable code."
	}
}

func outputModeLimitations(mode OutputMode) []string {
	switch mode {
	case OutputModeDNSHealth:
		return []string{"DNS health describes the supplied snapshot and does not prove that every sending system is configured correctly."}
	case OutputModeReportEvidence:
		return []string{"Aggregate report periods are not exact per-message timestamps and failed authentication does not prove malicious intent."}
	case OutputModeDNSReportCorrelation:
		return []string{"Current DNS observation time and historical report periods remain separate; correlation does not establish causation."}
	case OutputModeThreatCandidates:
		return []string{"Candidate scoring is review prioritization only and never authorizes blocking or malicious attribution."}
	case OutputModeSourceEnrichment:
		return []string{"Third-party enrichment may be stale, conflicting, or incomplete and never changes the underlying threat score."}
	case OutputModeJurisdictionContext:
		return []string{"Country assertions describe coarse infrastructure geography and are not legal, nationality, sanctions, or malicious determinations."}
	default:
		return []string{"The output represents only the explicitly completed mode and does not imply that adjacent workflows were evaluated."}
	}
}

func outputModeDocumentation(mode OutputMode) string {
	switch mode {
	case OutputModeDNSHealth:
		return "docs/dns-health.md"
	case OutputModeDNSPerspectives:
		return "docs/dns-perspectives.md"
	case OutputModeReportEvidence:
		return "docs/report-evidence.md"
	case OutputModeDNSReportCorrelation:
		return "docs/dns-report-correlation.md"
	case OutputModeThreatCandidates:
		return "docs/threat-candidates.md"
	case OutputModeSourceEnrichment:
		return "docs/source-enrichment.md"
	case OutputModeSourceActivity:
		return "docs/source-activity.md"
	case OutputModePhishingIntelligence:
		return "docs/phishing-intelligence.md"
	case OutputModeJurisdictionContext:
		return "docs/jurisdiction-context.md"
	case OutputModeCampaignValidation, OutputModeCampaignClassification:
		return "docs/campaign-correlation.md"
	case OutputModeConfigurationValidation:
		return "docs/portfolio-configuration.md"
	default:
		return "docs/wiki/Automation-Outputs-and-AI-Safety.md"
	}
}

func outputString(value any) string {
	text, _ := value.(string)
	return text
}

func outputInt(value any) (int, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil && parsed >= 0 && int64(int(parsed)) == parsed {
			return int(parsed), true
		}
	case float64:
		if typed >= 0 && float64(int(typed)) == typed {
			return int(typed), true
		}
	case int:
		return typed, typed >= 0
	}
	return 0, false
}

func validOutputSeverity(value FindingSeverity) bool {
	switch value {
	case FindingSeverityInfo, FindingSeverityLow, FindingSeverityMedium, FindingSeverityHigh, FindingSeverityCritical:
		return true
	default:
		return false
	}
}

func validOutputConfidence(value FindingConfidence) bool {
	switch value {
	case FindingConfidenceLow, FindingConfidenceMedium, FindingConfidenceHigh:
		return true
	default:
		return false
	}
}

func validOutputSensitivity(value Sensitivity) bool {
	switch value {
	case SensitivityPublic, SensitivityOperational, SensitivityRestricted:
		return true
	default:
		return false
	}
}
