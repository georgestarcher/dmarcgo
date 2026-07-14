package dmarcgo

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// CampaignOutputSchemaVersion is independent of the in-memory analysis and
// campaign-configuration schema versions.
const CampaignOutputSchemaVersion = "1"

// CampaignOutputSchemaID is the published classification output schema.
const CampaignOutputSchemaID = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/campaign/classification/v1.json"

//go:embed schemas/campaign/classification/v1.json
var campaignOutputSchemaFS embed.FS

// CampaignOutputFormat selects a deterministic campaign representation.
type CampaignOutputFormat string

const (
	CampaignOutputJSON  CampaignOutputFormat = "json"
	CampaignOutputJSONL CampaignOutputFormat = "jsonl"
)

// CampaignOutputView selects restricted analyst detail or a disclosure-safe
// workflow view. It changes representation only and never reruns matching.
type CampaignOutputView string

const (
	CampaignOutputPrivileged     CampaignOutputView = "privileged"
	CampaignOutputDisclosureSafe CampaignOutputView = "disclosure_safe"
)

// CampaignOutputOptions controls representation only.
type CampaignOutputOptions struct {
	SchemaVersion string
	View          CampaignOutputView
}

// CampaignDisclosureRouting is safe routing metadata for a consuming SOC
// application. It is not employee-facing response text.
type CampaignDisclosureRouting string

const (
	CampaignRouteRestrictedPolicy CampaignDisclosureRouting = "restricted_policy_review"
	CampaignRouteSecurityReview   CampaignDisclosureRouting = "security_review"
	CampaignRouteOrdinaryReview   CampaignDisclosureRouting = "ordinary_report_review"
)

// CampaignDisclosureSafeRecord omits campaign identifiers, source details,
// dates, infrastructure, factor names, tokens, fingerprints, and privileged
// workflow IDs.
type CampaignDisclosureSafeRecord struct {
	ID                           AnalysisID                `json:"id"`
	Routing                      CampaignDisclosureRouting `json:"routing"`
	Confidence                   FindingConfidence         `json:"confidence"`
	NeutralEmployeeTemplateID    string                    `json:"neutral_employee_template_id"`
	MatchedFactorCount           int                       `json:"matched_factor_count"`
	ContradictoryFactorCount     int                       `json:"contradictory_factor_count"`
	MissingFactorCount           int                       `json:"missing_factor_count"`
	UnverifiableFactorCount      int                       `json:"unverifiable_factor_count"`
	AutomaticDispositionEligible bool                      `json:"automatic_disposition_eligible"`
	AggregateEvidenceOnly        bool                      `json:"aggregate_evidence_only"`
	Sensitivity                  Sensitivity               `json:"sensitivity"`
}

// CampaignDisclosureSafeFinding contains only library-controlled neutral text.
type CampaignDisclosureSafeFinding struct {
	ID              FindingID                 `json:"id"`
	Code            FindingCode               `json:"code"`
	Severity        FindingSeverity           `json:"severity"`
	Confidence      FindingConfidence         `json:"confidence"`
	Routing         CampaignDisclosureRouting `json:"routing"`
	Summary         string                    `json:"summary"`
	Recommendation  string                    `json:"recommendation"`
	AutomaticAction bool                      `json:"automatic_action"`
	Sensitivity     Sensitivity               `json:"sensitivity"`
}

// CampaignDisclosureRoutingCount summarizes only neutral workflow routes. It
// does not reveal whether a route was selected because of campaign identity,
// dates, infrastructure, or authorization state.
type CampaignDisclosureRoutingCount struct {
	Routing CampaignDisclosureRouting `json:"routing"`
	Records int                       `json:"records"`
}

// CampaignDisclosureSafeSummary omits campaign inventory and classification
// counts that could disclose a live exercise.
type CampaignDisclosureSafeSummary struct {
	RelevantRecords           int                              `json:"relevant_records"`
	AutomaticDispositionReady int                              `json:"automatic_disposition_ready"`
	AggregateEvidenceOnly     bool                             `json:"aggregate_evidence_only"`
	Routes                    []CampaignDisclosureRoutingCount `json:"routes"`
}

// CampaignDisclosureSafeResult is safe to pass outside the restricted
// campaign-operations boundary. Its neutral template ID may be sent to a
// response system; its routing metadata must not be copied into employee text.
type CampaignDisclosureSafeResult struct {
	Metadata     ResultMetadata                  `json:"metadata"`
	Version      string                          `json:"version"`
	ResultDigest AnalysisID                      `json:"result_digest"`
	Records      []CampaignDisclosureSafeRecord  `json:"records"`
	Findings     []CampaignDisclosureSafeFinding `json:"findings"`
	Summary      CampaignDisclosureSafeSummary   `json:"summary"`
}

type campaignPrivilegedDocument struct {
	Schema         string                          `json:"schema"`
	SchemaVersion  string                          `json:"schema_version"`
	View           CampaignOutputView              `json:"view"`
	Metadata       ResultMetadata                  `json:"metadata"`
	Version        string                          `json:"version"`
	SnapshotDigest AnalysisID                      `json:"campaign_snapshot_digest"`
	EvidenceDigest AnalysisID                      `json:"message_evidence_digest"`
	ResultDigest   AnalysisID                      `json:"result_digest"`
	Records        []CampaignClassificationRecord  `json:"records"`
	Findings       []CampaignClassificationFinding `json:"findings"`
	Summary        CampaignClassificationSummary   `json:"summary"`
}

type campaignDisclosureDocument struct {
	Schema        string             `json:"schema"`
	SchemaVersion string             `json:"schema_version"`
	View          CampaignOutputView `json:"view"`
	CampaignDisclosureSafeResult
}

type campaignOutputRecord struct {
	Schema        string             `json:"schema"`
	SchemaVersion string             `json:"schema_version"`
	View          CampaignOutputView `json:"view"`
	Mode          AnalysisMode       `json:"mode"`
	ResultDigest  AnalysisID         `json:"result_digest"`
	RecordType    string             `json:"record_type"`
	RecordID      string             `json:"record_id"`
	Data          any                `json:"data"`
}

// CampaignClassificationOutputSchema returns a defensive copy of the embedded
// schema.
func CampaignClassificationOutputSchema(version string) ([]byte, error) {
	if version == "" {
		version = CampaignOutputSchemaVersion
	}
	if version != CampaignOutputSchemaVersion {
		return nil, ErrUnsupportedAnalysisOutput
	}
	data, err := campaignOutputSchemaFS.ReadFile("schemas/campaign/classification/v1.json")
	if err != nil {
		return nil, errors.Join(ErrUnsupportedAnalysisOutput, err)
	}
	return append([]byte(nil), data...), nil
}

// DisclosureSafe derives a disclosure-safe result without rerunning matching.
func (result CampaignClassificationResult) DisclosureSafe() (CampaignDisclosureSafeResult, error) {
	if err := validateCampaignClassificationResult(result); err != nil {
		return CampaignDisclosureSafeResult{}, err
	}
	safe := CampaignDisclosureSafeResult{
		Metadata: result.metadata, Version: result.version,
		Records: []CampaignDisclosureSafeRecord{}, Findings: []CampaignDisclosureSafeFinding{},
	}
	for index, record := range result.records {
		routing := disclosureRouting(record.Classification)
		value := CampaignDisclosureSafeRecord{
			Routing: routing, Confidence: record.Confidence, NeutralEmployeeTemplateID: "suspicious-message-received",
			MatchedFactorCount: len(record.Matched), ContradictoryFactorCount: len(record.Mismatched),
			MissingFactorCount: len(record.Missing), UnverifiableFactorCount: len(record.Unverifiable),
			AutomaticDispositionEligible: record.AutomaticDispositionEligible, AggregateEvidenceOnly: record.AggregateEvidenceOnly,
			Sensitivity: SensitivityOperational,
		}
		value.ID = StableAnalysisID("campaign_disclosure_safe_record", fmt.Sprint(index), string(value.Routing), string(value.Confidence), fmt.Sprint(value.MatchedFactorCount), fmt.Sprint(value.ContradictoryFactorCount), fmt.Sprint(value.MissingFactorCount), fmt.Sprint(value.UnverifiableFactorCount), fmt.Sprint(value.AutomaticDispositionEligible), fmt.Sprint(value.AggregateEvidenceOnly))
		safe.Records = append(safe.Records, value)
	}
	for index, finding := range result.findings {
		routing := disclosureRouting(finding.Classification)
		code, summary, recommendation := disclosureSafeFindingText(routing)
		value := CampaignDisclosureSafeFinding{
			Code: code, Severity: finding.Severity, Confidence: finding.Confidence, Routing: routing,
			Summary: summary, Recommendation: recommendation, AutomaticAction: false, Sensitivity: SensitivityOperational,
		}
		value.ID = FindingID(StableAnalysisID("campaign_disclosure_safe_finding", fmt.Sprint(index), string(value.Code), string(value.Severity), string(value.Confidence), string(value.Routing)))
		safe.Findings = append(safe.Findings, value)
	}
	sort.Slice(safe.Records, func(i, j int) bool { return safe.Records[i].ID < safe.Records[j].ID })
	sort.Slice(safe.Findings, func(i, j int) bool { return safe.Findings[i].ID < safe.Findings[j].ID })
	safe.Summary = summarizeCampaignDisclosureSafe(safe.Records)
	canonical, err := json.Marshal(struct {
		Metadata ResultMetadata                  `json:"metadata"`
		Version  string                          `json:"version"`
		Records  []CampaignDisclosureSafeRecord  `json:"records"`
		Findings []CampaignDisclosureSafeFinding `json:"findings"`
		Summary  CampaignDisclosureSafeSummary   `json:"summary"`
	}{safe.Metadata, safe.Version, safe.Records, safe.Findings, safe.Summary})
	if err != nil {
		return CampaignDisclosureSafeResult{}, errors.Join(ErrOutputSerialization, err)
	}
	safe.ResultDigest = StableAnalysisID("campaign_disclosure_safe_result", string(canonical))
	return safe, nil
}

// WriteCampaignClassificationOutput serializes an already computed immutable
// result. It performs no source retrieval, matching, DNS, report, enrichment,
// filesystem, environment, or clock access.
func WriteCampaignClassificationOutput(writer io.Writer, result CampaignClassificationResult, format CampaignOutputFormat, options CampaignOutputOptions) error {
	if writer == nil {
		return fmt.Errorf("%w: nil writer", ErrUnsupportedAnalysisOutput)
	}
	if options.SchemaVersion == "" {
		options.SchemaVersion = CampaignOutputSchemaVersion
	}
	if options.View == "" {
		options.View = CampaignOutputDisclosureSafe
	}
	if options.SchemaVersion != CampaignOutputSchemaVersion || options.View != CampaignOutputPrivileged && options.View != CampaignOutputDisclosureSafe {
		return ErrUnsupportedAnalysisOutput
	}
	if err := validateCampaignClassificationResult(result); err != nil {
		return err
	}
	var document any
	var records []campaignOutputRecord
	if options.View == CampaignOutputPrivileged {
		document = campaignPrivilegedDocument{
			Schema: CampaignOutputSchemaID, SchemaVersion: options.SchemaVersion, View: options.View,
			Metadata: result.metadata, Version: result.version, SnapshotDigest: result.snapshotDigest,
			EvidenceDigest: result.evidenceDigest, ResultDigest: result.digest, Records: result.Records(), Findings: result.Findings(), Summary: result.Summary(),
		}
		records = campaignPrivilegedRecords(result, options)
	} else {
		safe, err := result.DisclosureSafe()
		if err != nil {
			return err
		}
		document = campaignDisclosureDocument{Schema: CampaignOutputSchemaID, SchemaVersion: options.SchemaVersion, View: options.View, CampaignDisclosureSafeResult: safe}
		records = campaignDisclosureRecords(safe, options)
	}
	switch format {
	case CampaignOutputJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(document); err != nil {
			return errors.Join(ErrOutputSerialization, err)
		}
		return nil
	case CampaignOutputJSONL:
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		for _, record := range records {
			if err := encoder.Encode(record); err != nil {
				return errors.Join(ErrOutputSerialization, err)
			}
		}
		return nil
	default:
		return ErrUnsupportedAnalysisOutput
	}
}

func campaignPrivilegedRecords(result CampaignClassificationResult, options CampaignOutputOptions) []campaignOutputRecord {
	base := func(recordType, id string, data any) campaignOutputRecord {
		return campaignOutputRecord{Schema: CampaignOutputSchemaID + "#/$defs/jsonl_record", SchemaVersion: options.SchemaVersion, View: options.View, Mode: AnalysisModeCampaignClassification, ResultDigest: result.digest, RecordType: recordType, RecordID: id, Data: data}
	}
	records := []campaignOutputRecord{base("metadata", "metadata", struct {
		Metadata       ResultMetadata                `json:"metadata"`
		Version        string                        `json:"version"`
		SnapshotDigest AnalysisID                    `json:"campaign_snapshot_digest"`
		EvidenceDigest AnalysisID                    `json:"message_evidence_digest"`
		Summary        CampaignClassificationSummary `json:"summary"`
	}{result.metadata, result.version, result.snapshotDigest, result.evidenceDigest, result.Summary()})}
	for _, value := range result.Records() {
		records = append(records, base("classification", string(value.ID), value))
	}
	for _, value := range result.Findings() {
		records = append(records, base("finding", string(value.ID), value))
	}
	return records
}

func campaignDisclosureRecords(result CampaignDisclosureSafeResult, options CampaignOutputOptions) []campaignOutputRecord {
	base := func(recordType, id string, data any) campaignOutputRecord {
		return campaignOutputRecord{Schema: CampaignOutputSchemaID + "#/$defs/jsonl_record", SchemaVersion: options.SchemaVersion, View: options.View, Mode: AnalysisModeCampaignClassification, ResultDigest: result.ResultDigest, RecordType: recordType, RecordID: id, Data: data}
	}
	records := []campaignOutputRecord{base("metadata", "metadata", struct {
		Metadata ResultMetadata                `json:"metadata"`
		Version  string                        `json:"version"`
		Summary  CampaignDisclosureSafeSummary `json:"summary"`
	}{result.Metadata, result.Version, result.Summary})}
	for _, value := range result.Records {
		records = append(records, base("classification", string(value.ID), value))
	}
	for _, value := range result.Findings {
		records = append(records, base("finding", string(value.ID), value))
	}
	return records
}

func validateCampaignClassificationResult(result CampaignClassificationResult) error {
	if result.digest == "" || result.version != CampaignClassificationVersion || result.metadata.ContractVersion != AnalysisContractVersion ||
		result.metadata.Mode != AnalysisModeCampaignClassification || result.snapshotDigest == "" || result.evidenceDigest == "" || result.metadata.GeneratedAt.IsZero() {
		return ErrInvalidAnalysisResult
	}
	return nil
}

func disclosureRouting(classification CampaignClassification) CampaignDisclosureRouting {
	switch classification {
	case CampaignAuthorizedHighConfidence:
		return CampaignRouteRestrictedPolicy
	case CampaignPossibleAuthorized, CampaignConfigurationMismatch, CampaignOutsideWindow, CampaignAuthorizationExpired, CampaignAuthorizationUnavailable:
		return CampaignRouteSecurityReview
	default:
		return CampaignRouteOrdinaryReview
	}
}

func disclosureSafeFindingText(routing CampaignDisclosureRouting) (FindingCode, string, string) {
	switch routing {
	case CampaignRouteRestrictedPolicy:
		return "reported_message.restricted_policy_review", "The message matched a restricted internal handling policy.", "Use the restricted review route and send only the neutral acknowledgment template."
	case CampaignRouteSecurityReview:
		return "reported_message.security_review", "The message requires security review.", "Retain the supplied security evidence and use the neutral acknowledgment template."
	default:
		return "reported_message.ordinary_review", "The message remains in the ordinary reported-message workflow.", "Continue the normal security review process."
	}
}

func summarizeCampaignDisclosureSafe(records []CampaignDisclosureSafeRecord) CampaignDisclosureSafeSummary {
	counts := map[CampaignDisclosureRouting]int{}
	summary := CampaignDisclosureSafeSummary{RelevantRecords: len(records), Routes: []CampaignDisclosureRoutingCount{}}
	for _, record := range records {
		counts[record.Routing]++
		if record.AutomaticDispositionEligible {
			summary.AutomaticDispositionReady++
		}
		summary.AggregateEvidenceOnly = summary.AggregateEvidenceOnly || record.AggregateEvidenceOnly
	}
	for routing, count := range counts {
		summary.Routes = append(summary.Routes, CampaignDisclosureRoutingCount{Routing: routing, Records: count})
	}
	sort.Slice(summary.Routes, func(i, j int) bool { return summary.Routes[i].Routing < summary.Routes[j].Routing })
	return summary
}
