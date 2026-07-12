package dmarcgo

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/georgestarcher/dmarcgo/v2/utilities"
)

// OutputSchemaVersion is the current automation-envelope schema version.
const OutputSchemaVersion = "1"

// OutputSchemaID identifies the JSON Schema for the current envelope.
const OutputSchemaID = "https://raw.githubusercontent.com/georgestarcher/dmarcgo/main/schemas/output/v1.json"

//go:embed schemas/output/v1.json
var outputSchemaV1 []byte

// ErrInvalidOutputOptions identifies an unsupported output option.
var ErrInvalidOutputOptions = errors.New("invalid output options")

// ErrUnsupportedOutputSchema identifies an unavailable output schema version.
var ErrUnsupportedOutputSchema = errors.New("unsupported output schema version")

// ErrOutputRedaction identifies a failed output-redaction transformation.
var ErrOutputRedaction = errors.New("output redaction failed")

// ErrOutputSerialization identifies an output value that JSON cannot encode.
var ErrOutputSerialization = errors.New("output serialization failed")

// OutputMode identifies the analysis result carried by an OutputEnvelope.
// It aliases AnalysisMode so completed analysis values and encoders share one
// canonical mode vocabulary.
type OutputMode = AnalysisMode

const (
	OutputModeReportValidation = AnalysisModeReportValidation
	OutputModeReportSummary    = AnalysisModeReportSummary
	OutputModeAggregateSummary = AnalysisModeAggregateSummary
	OutputModeReportRows       = AnalysisModeReportRows
	OutputModeSourceReview     = AnalysisModeSourceReview
)

// OutputProfile controls representation. It never triggers analysis or I/O.
type OutputProfile string

const (
	OutputProfileAutomation OutputProfile = "automation"
	OutputProfileAgent      OutputProfile = "agent"
)

// OutputDetail controls the amount of result data returned.
type OutputDetail string

const (
	OutputDetailSummary  OutputDetail = "summary"
	OutputDetailStandard OutputDetail = "standard"
	OutputDetailFull     OutputDetail = "full"
)

// OutputRedaction controls operational identifier disclosure.
type OutputRedaction string

const (
	OutputRedactionPublic      OutputRedaction = "public"
	OutputRedactionOperational OutputRedaction = "operational"
	OutputRedactionRestricted  OutputRedaction = "restricted"
)

// OutputStatus describes whether processing completed and produced findings.
type OutputStatus string

const (
	OutputStatusCompleted             OutputStatus = "completed"
	OutputStatusCompletedWithFindings OutputStatus = "completed_with_findings"
	OutputStatusFailed                OutputStatus = "failed"
)

// OutputEvaluationState aliases the shared EvaluationState contract.
type OutputEvaluationState = EvaluationState

const (
	OutputEvaluationEvaluated     = EvaluationStateEvaluated
	OutputEvaluationNotEvaluated  = EvaluationStateNotEvaluated
	OutputEvaluationUnknown       = EvaluationStateUnknown
	OutputEvaluationNotApplicable = EvaluationStateNotApplicable
)

// OutputOptions controls envelope representation without rerunning analysis.
type OutputOptions struct {
	Profile       OutputProfile
	Detail        OutputDetail
	Redaction     OutputRedaction
	GeneratedAt   time.Time
	ModuleVersion string
	MaxItems      int
}

// OutputEnvelope is the common versioned contract for automation and AI consumers.
type OutputEnvelope struct {
	Schema             string             `json:"schema"`
	SchemaVersion      string             `json:"schema_version"`
	ModuleVersion      string             `json:"module_version,omitempty"`
	Mode               OutputMode         `json:"mode"`
	Profile            OutputProfile      `json:"profile"`
	Detail             OutputDetail       `json:"detail"`
	GeneratedAt        time.Time          `json:"generated_at"`
	Status             OutputStatus       `json:"status"`
	Evaluation         OutputEvaluation   `json:"evaluation"`
	Scope              OutputScope        `json:"scope"`
	Input              OutputInput        `json:"input"`
	Summary            OutputSummary      `json:"summary"`
	Findings           []OutputFinding    `json:"findings"`
	Data               any                `json:"data"`
	RecommendedActions []OutputAction     `json:"recommended_actions"`
	Warnings           []OutputMessage    `json:"warnings"`
	Errors             []OutputMessage    `json:"errors"`
	Limitations        []string           `json:"limitations"`
	Provenance         []OutputProvenance `json:"provenance"`
	Redaction          RedactionMetadata  `json:"redaction"`
	Truncation         TruncationMetadata `json:"truncation"`
}

// OutputEvaluation records whether analysis was performed and why it was not
// performed when the state is not evaluated.
type OutputEvaluation = Evaluation

type OutputScope struct {
	TargetDomains []string `json:"target_domains"`
}

type OutputInput struct {
	ReportCount  int `json:"report_count"`
	RecordCount  int `json:"record_count"`
	MessageCount int `json:"message_count"`
}

type OutputSummary struct {
	Headline   string            `json:"headline"`
	Severity   FindingSeverity   `json:"severity"`
	Confidence FindingConfidence `json:"confidence"`
}

type OutputFinding struct {
	Code        FindingCode       `json:"code"`
	Category    string            `json:"category"`
	Severity    FindingSeverity   `json:"severity"`
	Confidence  FindingConfidence `json:"confidence"`
	Title       string            `json:"title"`
	Explanation string            `json:"explanation"`
	Subject     map[string]string `json:"subject"`
	Evidence    []OutputEvidence  `json:"evidence"`
	Limitations []string          `json:"limitations"`
	ActionCodes []ActionCode      `json:"action_codes"`
}

type OutputEvidence struct {
	Type        string                `json:"type"`
	Source      string                `json:"source"`
	Path        string                `json:"path,omitempty"`
	Value       any                   `json:"value"`
	State       OutputEvaluationState `json:"state"`
	Provenance  ProvenanceID          `json:"provenance,omitempty"`
	Sensitivity Sensitivity           `json:"sensitivity"`
}

type OutputAction struct {
	Code       ActionCode        `json:"code"`
	Priority   int               `json:"priority"`
	Title      string            `json:"title"`
	Reason     string            `json:"reason"`
	Target     map[string]string `json:"target"`
	Automation AutomationPolicy  `json:"automation"`
}

type AutomationPolicy struct {
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason"`
}

type OutputMessage struct {
	Code      DiagnosticCode `json:"code"`
	Category  string         `json:"category"`
	Message   string         `json:"message"`
	Path      string         `json:"path,omitempty"`
	Retryable bool           `json:"retryable"`
}

const (
	OutputErrorCodeMalformedXML      = "report.malformed_xml"
	OutputErrorCodeUnsupportedFormat = "report.unsupported_format"
	OutputErrorCodePayloadTooLarge   = "report.payload_too_large"
	OutputErrorCodeMissingPath       = "report.missing_path"
	OutputErrorCodeCancelled         = "report.cancelled"
	OutputErrorCodeProcessingFailed  = "report.processing_failed"
)

type OutputProvenance struct {
	ID   ProvenanceID `json:"id"`
	Type string       `json:"type"`
	Key  string       `json:"key,omitempty"`
}

// ResultMetadata returns shared metadata without performing analysis or I/O.
func (output OutputEnvelope) ResultMetadata() ResultMetadata {
	return ResultMetadata{
		ContractVersion: AnalysisContractVersion,
		Mode:            output.Mode,
		GeneratedAt:     output.GeneratedAt,
		Evaluation:      output.Evaluation,
	}
}

type RedactionMetadata struct {
	Profile                  OutputRedaction `json:"profile"`
	OperationalFieldsChanged bool            `json:"operational_fields_changed"`
}

type TruncationMetadata struct {
	Truncated   bool                         `json:"truncated"`
	Collections []OutputCollectionTruncation `json:"collections"`
}

// OutputCollectionTruncation describes one independently bounded collection.
type OutputCollectionTruncation struct {
	Name          string `json:"name"`
	TotalItems    int    `json:"total_items"`
	ReturnedItems int    `json:"returned_items"`
}

// SourceReview groups the current source-review helper results for serialization.
type SourceReview struct {
	Domain          string             `json:"domain"`
	Unauthenticated []SuspiciousSource `json:"unauthenticated"`
	Rejected        []SuspiciousSource `json:"rejected_unauthenticated"`
	Passing         []SourceSummary    `json:"passing"`
}

// OutputSchema returns a copy of the embedded JSON Schema for version 1.
func OutputSchema() []byte { return append([]byte(nil), outputSchemaV1...) }

// OutputSchemaForVersion returns a copy of a supported embedded JSON Schema.
func OutputSchemaForVersion(version string) ([]byte, error) {
	switch version {
	case OutputSchemaVersion:
		return OutputSchema(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedOutputSchema, version)
	}
}

// OutputSchemaVersions returns supported schema versions in ascending order.
func OutputSchemaVersions() []string { return []string{OutputSchemaVersion} }

// SupportedOutputModes returns the modes supported by the current schema.
func SupportedOutputModes() []OutputMode {
	return []OutputMode{
		OutputModeReportValidation,
		OutputModeReportSummary,
		OutputModeAggregateSummary,
		OutputModeReportRows,
		OutputModeSourceReview,
	}
}

// OutputMessageForError classifies a report-processing error without copying
// path context, raw payloads, or other potentially sensitive error text.
func OutputMessageForError(err error) OutputMessage {
	switch {
	case errors.Is(err, utilities.ErrPayloadTooLarge):
		return OutputMessage{Code: OutputErrorCodePayloadTooLarge, Category: "payload_too_large", Message: "The report payload exceeded the configured decompressed-size limit."}
	case errors.Is(err, ErrMalformedXML):
		return OutputMessage{Code: OutputErrorCodeMalformedXML, Category: "malformed_xml", Message: "The report payload could not be parsed as valid DMARC aggregate XML."}
	case errors.Is(err, ErrUnsupportedReportFormat):
		return OutputMessage{Code: OutputErrorCodeUnsupportedFormat, Category: "unsupported_format", Message: "The report payload format is not supported."}
	case errors.Is(err, ErrNoFilePath):
		return OutputMessage{Code: OutputErrorCodeMissingPath, Category: "missing_path", Message: "No report file path was supplied."}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return OutputMessage{Code: OutputErrorCodeCancelled, Category: "cancelled", Message: "Report processing was cancelled before evaluation completed.", Retryable: true}
	default:
		return OutputMessage{Code: OutputErrorCodeProcessingFailed, Category: "processing_failed", Message: "Report processing failed before evaluation completed."}
	}
}

// BuildValidationOutput creates an envelope from an already computed report
// validation result.
func BuildValidationOutput(result ReportValidationResult, options OutputOptions) (OutputEnvelope, error) {
	metadata := result.ResultMetadata()
	if metadata.ContractVersion != AnalysisContractVersion {
		return OutputEnvelope{}, fmt.Errorf("%w: unsupported contract version %q", ErrInvalidAnalysisResult, metadata.ContractVersion)
	}
	if metadata.Mode != AnalysisModeReportValidation {
		return OutputEnvelope{}, fmt.Errorf("%w: validation result has mode %q", ErrInvalidAnalysisResult, metadata.Mode)
	}
	if metadata.GeneratedAt.IsZero() {
		return OutputEnvelope{}, fmt.Errorf("%w: validation result requires generated time", ErrInvalidAnalysisResult)
	}
	if metadata.Evaluation.State != EvaluationStateEvaluated {
		return OutputEnvelope{}, fmt.Errorf("%w: validation result state is %q; use BuildFailureOutput", ErrInvalidAnalysisResult, metadata.Evaluation.State)
	}
	options.GeneratedAt = metadata.GeneratedAt
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	out := baseOutput(
		OutputModeReportValidation,
		OutputScope{TargetDomains: compactSortedStrings([]string{result.TargetDomain})},
		OutputInput{ReportCount: result.ReportCount, RecordCount: result.RecordCount, MessageCount: result.MessageCount},
		options,
	)
	data := append([]ValidationFinding{}, result.Findings...)
	sort.SliceStable(data, func(i, j int) bool {
		if validationSeverityRank(data[i].Severity) != validationSeverityRank(data[j].Severity) {
			return validationSeverityRank(data[i].Severity) > validationSeverityRank(data[j].Severity)
		}
		if data[i].Path != data[j].Path {
			return data[i].Path < data[j].Path
		}
		return data[i].Message < data[j].Message
	})
	totalFindings := len(data)
	data = limitSlice(data, options.MaxItems)
	addTruncation(&out, "validation_findings", totalFindings, len(data))
	out.Data = data
	for _, finding := range data {
		severity := FindingSeverityLow
		if string(finding.Severity) == "error" {
			severity = FindingSeverityMedium
		}
		out.Findings = append(out.Findings, OutputFinding{
			Code: "report.validation", Category: "data_quality", Severity: severity, Confidence: FindingConfidenceHigh,
			Title: "Report validation finding", Explanation: "The report field did not satisfy the selected validation rules.",
			Subject:     map[string]string{"path": finding.Path},
			Evidence:    []OutputEvidence{{Type: "validation_result", Source: "dmarcgo", Path: finding.Path, Value: finding.Message, State: OutputEvaluationEvaluated, Sensitivity: SensitivityOperational}},
			Limitations: []string{}, ActionCodes: []ActionCode{"review_report_data"},
		})
	}
	if len(data) == 0 {
		out.Summary = OutputSummary{Headline: "The report passed the selected validation checks.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "The report has validation findings that may affect downstream analysis.", Severity: highestSeverity(out.Findings), Confidence: FindingConfidenceHigh}
		out.RecommendedActions = []OutputAction{reviewAction("review_report_data", "Review report validation findings", "Resolve or account for malformed and nonconforming report fields.")}
	}
	return finalizeOutput(out, options)
}

// BuildReportSummaryOutput creates an envelope from an already computed report summary.
func BuildReportSummaryOutput(summary ReportSummary, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	out := baseOutput(OutputModeReportSummary, OutputScope{TargetDomains: compactSortedStrings([]string{summary.TargetDomain})}, OutputInput{ReportCount: 1, RecordCount: summary.TotalRecords, MessageCount: summary.TotalMessages}, options)
	summary = cloneReportSummary(summary)
	applyReportSummaryDetail(&summary, options.Detail)
	limitReportSummary(&out, &summary, options.MaxItems)
	out.Data = summary
	addAuthenticationFindings(&out, summary.FailedMessages, summary.InvalidRecords, summary.TargetDomain)
	out.Provenance = []OutputProvenance{{ID: "report-1", Type: "aggregate_report", Key: summary.ReportID}}
	return finalizeOutput(out, options)
}

// BuildAggregateSummaryOutput creates an envelope from an already computed multi-report summary.
func BuildAggregateSummaryOutput(summary AggregateSummary, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	domains := make([]string, 0, len(summary.ByTargetDomain))
	for domain := range summary.ByTargetDomain {
		domains = append(domains, domain)
	}
	out := baseOutput(OutputModeAggregateSummary, OutputScope{TargetDomains: compactSortedStrings(domains)}, OutputInput{ReportCount: summary.Reports, RecordCount: summary.TotalRecords, MessageCount: summary.TotalMessages}, options)
	summary = cloneAggregateSummary(summary)
	applyAggregateSummaryDetail(&summary, options.Detail)
	limitAggregateSummary(&out, &summary, options.MaxItems)
	out.Data = summary
	addAuthenticationFindings(&out, summary.FailedMessages, summary.InvalidRecords, "")
	return finalizeOutput(out, options)
}

// BuildReportRowsOutput creates an envelope from already flattened report rows.
func BuildReportRowsOutput(rows []FeatureRow, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	rows = cloneFeatureRows(rows)
	sort.SliceStable(rows, func(i, j int) bool { return featureRowSortKey(rows[i]) < featureRowSortKey(rows[j]) })
	applyFeatureRowDetail(rows, options.Detail)
	domains := make([]string, 0, len(rows))
	reportIDs := map[string]struct{}{}
	messages := 0
	for _, row := range rows {
		domains = append(domains, row.TargetDomain)
		if row.ReportID != "" {
			reportIDs[row.ReportID] = struct{}{}
		}
		if row.MailCount > 0 {
			messages += row.MailCount
		}
	}
	out := baseOutput(OutputModeReportRows, OutputScope{TargetDomains: compactSortedStrings(domains)}, OutputInput{ReportCount: len(reportIDs), RecordCount: len(rows), MessageCount: messages}, options)
	total := len(rows)
	rows = limitSlice(rows, options.MaxItems)
	out.Data = rows
	addTruncation(&out, "report_rows", total, len(rows))
	out.Summary = OutputSummary{Headline: "Flattened DMARC report rows are ready for downstream processing.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	return finalizeOutput(out, options)
}

// BuildSourceReviewOutput creates an envelope from already computed source-review results.
func BuildSourceReviewOutput(review SourceReview, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	review = cloneSourceReview(review)
	applySourceReviewDetail(&review, options.Detail)
	sortSuspiciousSources(review.Unauthenticated)
	sortSuspiciousSources(review.Rejected)
	sortSourceSummaries(review.Passing)
	records, messages := sourceReviewCounts(review)
	out := baseOutput(OutputModeSourceReview, OutputScope{TargetDomains: compactSortedStrings([]string{review.Domain})}, OutputInput{RecordCount: records, MessageCount: messages}, options)
	totalUnauthenticated := len(review.Unauthenticated)
	totalRejected := len(review.Rejected)
	totalPassing := len(review.Passing)
	if len(review.Unauthenticated) > 0 {
		messages := 0
		for _, source := range review.Unauthenticated {
			messages += source.Messages
		}
		out.Findings = []OutputFinding{{
			Code: "report.unauthenticated_sources", Category: "source_review", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh,
			Title: "Unauthenticated sources observed", Explanation: "These sources used the target Header From domain while both policy-evaluated DKIM and SPF failed.",
			Subject: map[string]string{"domain": review.Domain}, Evidence: []OutputEvidence{{Type: "source_summary", Source: "aggregate_report", Value: map[string]int{"sources": totalUnauthenticated, "messages": messages}, State: OutputEvaluationEvaluated, Sensitivity: SensitivityOperational}},
			Limitations: []string{"DMARC aggregate evidence does not establish malicious intent."}, ActionCodes: []ActionCode{"review_unauthenticated_sources"},
		}}
		out.RecommendedActions = []OutputAction{reviewAction("review_unauthenticated_sources", "Review unauthenticated sending sources", "Confirm whether the sources are expected before taking defensive action.")}
		out.Summary = OutputSummary{Headline: "Unauthenticated sources require review; the report alone does not establish malicious intent.", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "No unauthenticated sources were present in the supplied source-review result.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	}
	review.Unauthenticated = limitSlice(review.Unauthenticated, options.MaxItems)
	review.Rejected = limitSlice(review.Rejected, options.MaxItems)
	review.Passing = limitSlice(review.Passing, options.MaxItems)
	addTruncation(&out, "unauthenticated_sources", totalUnauthenticated, len(review.Unauthenticated))
	addTruncation(&out, "rejected_unauthenticated_sources", totalRejected, len(review.Rejected))
	addTruncation(&out, "passing_sources", totalPassing, len(review.Passing))
	out.Data = review
	return finalizeOutput(out, options)
}

// BuildFailureOutput creates a failed envelope from already classified errors.
func BuildFailureOutput(mode OutputMode, scope OutputScope, input OutputInput, outputErrors []OutputMessage, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	if !isSupportedOutputMode(mode) {
		return OutputEnvelope{}, fmt.Errorf("%w: unsupported mode %q", ErrInvalidOutputOptions, mode)
	}
	if len(outputErrors) == 0 {
		return OutputEnvelope{}, fmt.Errorf("%w: failed output requires at least one error", ErrInvalidOutputOptions)
	}
	for _, outputError := range outputErrors {
		if outputError.Code == "" || outputError.Category == "" {
			return OutputEnvelope{}, fmt.Errorf("%w: failed output errors require code and category", ErrInvalidOutputOptions)
		}
	}
	out := baseOutput(mode, OutputScope{TargetDomains: compactSortedStrings(scope.TargetDomains)}, input, options)
	out.Status = OutputStatusFailed
	out.Evaluation = OutputEvaluation{State: OutputEvaluationNotEvaluated, Reason: "The requested analysis did not complete."}
	out.Summary = OutputSummary{Headline: "The requested analysis did not complete.", Severity: FindingSeverityHigh, Confidence: FindingConfidenceHigh}
	out.Errors = append([]OutputMessage(nil), outputErrors...)
	sortOutputMessages(out.Errors)
	return finalizeOutput(out, options)
}

// WriteOutputJSON writes one envelope as JSON followed by a newline.
func WriteOutputJSON(writer io.Writer, output OutputEnvelope) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(output)
}

// WriteOutputJSONL writes each envelope as one self-describing JSON line.
func WriteOutputJSONL(writer io.Writer, outputs []OutputEnvelope) error {
	for _, output := range outputs {
		if err := WriteOutputJSON(writer, output); err != nil {
			return err
		}
	}
	return nil
}

func normalizeOutputOptions(options OutputOptions) (OutputOptions, error) {
	if options.Profile == "" {
		options.Profile = OutputProfileAutomation
	}
	if options.Detail == "" {
		options.Detail = OutputDetailStandard
	}
	if options.Redaction == "" {
		options.Redaction = OutputRedactionOperational
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = time.Now().UTC()
	} else {
		options.GeneratedAt = options.GeneratedAt.UTC()
	}
	if options.MaxItems < 0 {
		return options, fmt.Errorf("%w: max items must not be negative", ErrInvalidOutputOptions)
	}
	if options.Profile != OutputProfileAutomation && options.Profile != OutputProfileAgent {
		return options, fmt.Errorf("%w: unsupported profile %q", ErrInvalidOutputOptions, options.Profile)
	}
	if options.Detail != OutputDetailSummary && options.Detail != OutputDetailStandard && options.Detail != OutputDetailFull {
		return options, fmt.Errorf("%w: unsupported detail %q", ErrInvalidOutputOptions, options.Detail)
	}
	if options.Redaction != OutputRedactionPublic && options.Redaction != OutputRedactionOperational && options.Redaction != OutputRedactionRestricted {
		return options, fmt.Errorf("%w: unsupported redaction %q", ErrInvalidOutputOptions, options.Redaction)
	}
	return options, nil
}

func baseOutput(mode OutputMode, scope OutputScope, input OutputInput, options OutputOptions) OutputEnvelope {
	scope.TargetDomains = compactSortedStrings(scope.TargetDomains)
	return OutputEnvelope{
		Schema: OutputSchemaID, SchemaVersion: OutputSchemaVersion, ModuleVersion: options.ModuleVersion,
		Mode: mode, Profile: options.Profile, Detail: options.Detail, GeneratedAt: options.GeneratedAt, Status: OutputStatusCompleted,
		Evaluation: OutputEvaluation{State: OutputEvaluationEvaluated},
		Scope:      scope, Input: input, Summary: OutputSummary{Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh},
		Findings: []OutputFinding{}, Data: map[string]any{}, RecommendedActions: []OutputAction{}, Warnings: []OutputMessage{}, Errors: []OutputMessage{}, Limitations: []string{}, Provenance: []OutputProvenance{},
		Redaction: RedactionMetadata{Profile: options.Redaction}, Truncation: TruncationMetadata{Collections: []OutputCollectionTruncation{}},
	}
}

func addAuthenticationFindings(out *OutputEnvelope, failed, invalid int, domain string) {
	if failed > 0 {
		out.Findings = append(out.Findings, OutputFinding{
			Code: "report.authentication_failures", Category: "authentication", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh,
			Title: "DMARC authentication failures observed", Explanation: "Messages failed both policy-evaluated DKIM and SPF alignment.",
			Subject: map[string]string{"domain": domain}, Evidence: []OutputEvidence{{Type: "authentication_result", Source: "aggregate_report", Value: map[string]int{"failed_messages": failed}, State: OutputEvaluationEvaluated, Sensitivity: SensitivityOperational}},
			Limitations: []string{"Authentication failure does not by itself prove spoofing or malicious intent."}, ActionCodes: []ActionCode{"review_authentication_failures"},
		})
		out.RecommendedActions = append(out.RecommendedActions, reviewAction("review_authentication_failures", "Review authentication failures", "Determine whether failed traffic is an expected sender configuration issue or unauthorized use."))
	}
	if invalid > 0 {
		out.Findings = append(out.Findings, OutputFinding{
			Code: "report.invalid_records", Category: "data_quality", Severity: FindingSeverityLow, Confidence: FindingConfidenceHigh,
			Title: "Invalid report records excluded from message totals", Explanation: "One or more records had invalid counts and were excluded from message totals.",
			Subject: map[string]string{}, Evidence: []OutputEvidence{{Type: "validation_result", Source: "aggregate_report", Value: map[string]int{"invalid_records": invalid}, State: OutputEvaluationEvaluated, Sensitivity: SensitivityOperational}},
			Limitations: []string{}, ActionCodes: []ActionCode{"review_report_data"},
		})
	}
	if len(out.Findings) == 0 {
		out.Summary = OutputSummary{Headline: "No authentication failures or invalid records were present in the supplied summary.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "The supplied summary contains findings that require contextual review.", Severity: highestSeverity(out.Findings), Confidence: FindingConfidenceHigh}
	}
}

func finalizeOutput(out OutputEnvelope, options OutputOptions) (OutputEnvelope, error) {
	if len(out.Findings) > 0 {
		out.Status = OutputStatusCompletedWithFindings
	}
	if len(out.Errors) > 0 {
		out.Status = OutputStatusFailed
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		if severityRank(out.Findings[i].Severity) != severityRank(out.Findings[j].Severity) {
			return severityRank(out.Findings[i].Severity) > severityRank(out.Findings[j].Severity)
		}
		if out.Findings[i].Code != out.Findings[j].Code {
			return out.Findings[i].Code < out.Findings[j].Code
		}
		return canonicalSortKey(out.Findings[i]) < canonicalSortKey(out.Findings[j])
	})
	sort.SliceStable(out.RecommendedActions, func(i, j int) bool {
		if out.RecommendedActions[i].Priority != out.RecommendedActions[j].Priority {
			return out.RecommendedActions[i].Priority < out.RecommendedActions[j].Priority
		}
		return out.RecommendedActions[i].Code < out.RecommendedActions[j].Code
	})
	sortOutputMessages(out.Warnings)
	sortOutputMessages(out.Errors)
	sort.SliceStable(out.Provenance, func(i, j int) bool { return canonicalSortKey(out.Provenance[i]) < canonicalSortKey(out.Provenance[j]) })
	if options.Detail == OutputDetailSummary {
		out.Data = map[string]any{}
		omitModeDataCollections(&out)
	}
	if options.Profile == OutputProfileAutomation {
		out.Summary.Headline = ""
		for i := range out.Findings {
			out.Findings[i].Explanation = ""
		}
	}
	if options.Redaction == OutputRedactionPublic {
		before, err := json.Marshal(out)
		if err != nil {
			return OutputEnvelope{}, fmt.Errorf("%w: %w: %v", ErrOutputRedaction, ErrOutputSerialization, err)
		}
		out, err = redactOutput(out)
		if err != nil {
			return OutputEnvelope{}, err
		}
		after, err := json.Marshal(out)
		if err != nil {
			return OutputEnvelope{}, fmt.Errorf("%w: %w: %v", ErrOutputRedaction, ErrOutputSerialization, err)
		}
		out.Redaction.OperationalFieldsChanged = !bytes.Equal(before, after)
	} else if options.Redaction == OutputRedactionOperational {
		out, out.Redaction.OperationalFieldsChanged = removeRestrictedReportText(out)
	}
	if _, err := json.Marshal(out); err != nil {
		if options.Redaction == OutputRedactionPublic {
			return OutputEnvelope{}, fmt.Errorf("%w: %w: %v", ErrOutputRedaction, ErrOutputSerialization, err)
		}
		return OutputEnvelope{}, fmt.Errorf("%w: %v", ErrOutputSerialization, err)
	}
	return out, nil
}

func redactOutput(out OutputEnvelope) (OutputEnvelope, error) {
	for i, domain := range out.Scope.TargetDomains {
		out.Scope.TargetDomains[i] = redactionToken("target_domain", domain)
	}
	for i := range out.Findings {
		out.Findings[i].Subject = redactStringMap(out.Findings[i].Subject, "finding_subject")
		for j := range out.Findings[i].Evidence {
			value, err := redactArbitraryValue(out.Findings[i].Evidence[j].Value, "evidence")
			if err != nil {
				return OutputEnvelope{}, err
			}
			out.Findings[i].Evidence[j].Value = value
			out.Findings[i].Evidence[j].Path = redactOptionalText("evidence_path", out.Findings[i].Evidence[j].Path)
			out.Findings[i].Evidence[j].Provenance = ProvenanceID(redactOptionalText("provenance", string(out.Findings[i].Evidence[j].Provenance)))
		}
	}
	for i := range out.RecommendedActions {
		out.RecommendedActions[i].Target = redactStringMap(out.RecommendedActions[i].Target, "action_target")
	}
	for i := range out.Warnings {
		redactOutputMessage(&out.Warnings[i])
	}
	for i := range out.Errors {
		redactOutputMessage(&out.Errors[i])
	}
	for i := range out.Provenance {
		out.Provenance[i].Key = redactOptionalText("provenance_key", out.Provenance[i].Key)
	}

	switch data := out.Data.(type) {
	case map[string]any:
		if len(data) != 0 {
			return OutputEnvelope{}, fmt.Errorf("%w: unsupported untyped data object", ErrOutputRedaction)
		}
	case []ValidationFinding:
		for i := range data {
			data[i].Message = redactOptionalText("validation_message", data[i].Message)
			data[i].Path = redactOptionalText("validation_path", data[i].Path)
		}
		out.Data = data
	case ReportSummary:
		out.Data = redactReportSummary(data)
	case AggregateSummary:
		out.Data = redactAggregateSummary(data)
	case []FeatureRow:
		out.Data = redactFeatureRows(data)
	case SourceReview:
		out.Data = redactSourceReview(data)
	default:
		return OutputEnvelope{}, fmt.Errorf("%w: unsupported data type %T", ErrOutputRedaction, out.Data)
	}
	return out, nil
}

func redactionToken(kind, value string) string {
	value = canonicalRedactionValue(kind, value)
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	return "redacted:" + hex.EncodeToString(sum[:16])
}

func canonicalRedactionValue(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "target_domain", "header_from", "dkim_domain", "spf_domain":
		return strings.ToLower(value)
	default:
		return value
	}
}

func redactOptionalText(kind, value string) string {
	if value == "" {
		return ""
	}
	return redactionToken(kind, value)
}

func redactStringMap(values map[string]string, kind string) map[string]string {
	if values == nil {
		return nil
	}
	keys := sortedMapKeys(values)
	out := make(map[string]string, len(values))
	for _, key := range keys {
		out[key] = redactOptionalText(redactionKindForField(key, kind), values[key])
	}
	return out
}

func redactionKindForField(field, fallback string) string {
	switch field {
	case "domain", "target_domain":
		return "target_domain"
	case "reporter", "reporting_org":
		return "reporting_org"
	case "source_ip", "report_id", "header_from", "envelope_from", "envelope_to", "dkim_domain", "dkim_selector", "spf_domain":
		return field
	default:
		return fallback + "." + field
	}
}

func redactCountMap(values map[string]int, kind string) map[string]int {
	if values == nil {
		return nil
	}
	keys := sortedMapKeys(values)
	out := make(map[string]int, len(values))
	used := map[string]string{}
	for _, key := range keys {
		canonical := canonicalRedactionValue(kind, key)
		token := uniqueRedactionToken(kind, canonical, used)
		out[token] += values[key]
		used[token] = canonical
	}
	return out
}

func uniqueRedactionToken(kind, value string, used map[string]string) string {
	for attempt := 0; ; attempt++ {
		tokenKind := kind
		if attempt > 0 {
			tokenKind = fmt.Sprintf("%s#%d", kind, attempt)
		}
		token := redactionToken(tokenKind, value)
		if original, exists := used[token]; !exists || original == value {
			return token
		}
	}
}

func redactOutputMessage(message *OutputMessage) {
	message.Message = redactOptionalText("output_message", message.Message)
	message.Path = redactOptionalText("output_message_path", message.Path)
}

func redactArbitraryValue(value any, kind string) (any, error) {
	switch typed := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return value, nil
	case string:
		return redactOptionalText(kind, typed), nil
	case map[string]int:
		out := make(map[string]int, len(typed))
		used := map[string]string{}
		for _, key := range sortedMapKeys(typed) {
			redactedKey := key
			if !isPublicMetricKey(key) {
				redactedKey = uniqueRedactionToken(kind+".key", key, used)
				used[redactedKey] = key
			}
			out[redactedKey] = typed[key]
		}
		return out, nil
	case map[string]string:
		return redactStringMap(typed, kind), nil
	case []string:
		out := make([]string, len(typed))
		for i := range typed {
			out[i] = redactOptionalText(kind, typed[i])
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			redacted, err := redactArbitraryValue(typed[i], kind)
			if err != nil {
				return nil, err
			}
			out[i] = redacted
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		used := map[string]string{}
		for _, key := range sortedMapKeys(typed) {
			redactedKey := uniqueRedactionToken(kind+".key", key, used)
			used[redactedKey] = key
			redacted, err := redactArbitraryValue(typed[key], kind+".value")
			if err != nil {
				return nil, err
			}
			out[redactedKey] = redacted
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unsupported value type %T", ErrOutputRedaction, value)
	}
}

func isPublicMetricKey(key string) bool {
	switch key {
	case "failed_messages", "invalid_records", "messages", "sources":
		return true
	default:
		return false
	}
}

func redactReportSummary(summary ReportSummary) ReportSummary {
	summary.ReportID = redactOptionalText("report_id", summary.ReportID)
	summary.ReportingOrg = redactOptionalText("reporting_org", summary.ReportingOrg)
	summary.TargetDomain = redactOptionalText("target_domain", summary.TargetDomain)
	summary.ByHeaderFrom = redactCountMap(summary.ByHeaderFrom, "header_from")
	for i := range summary.BySourceIP {
		summary.BySourceIP[i] = redactSourceSummary(summary.BySourceIP[i])
	}
	return summary
}

func redactAggregateSummary(summary AggregateSummary) AggregateSummary {
	summary.ByReporter = redactCountMap(summary.ByReporter, "reporting_org")
	summary.ByTargetDomain = redactCountMap(summary.ByTargetDomain, "target_domain")
	summary.ByHeaderFrom = redactCountMap(summary.ByHeaderFrom, "header_from")
	for i := range summary.BySourceIP {
		summary.BySourceIP[i] = redactSourceSummary(summary.BySourceIP[i])
	}
	return summary
}

func redactSourceSummary(source SourceSummary) SourceSummary {
	source.SourceIP = redactOptionalText("source_ip", source.SourceIP)
	source.HeaderFrom = redactCountMap(source.HeaderFrom, "header_from")
	source.DKIMDomains = redactCountMap(source.DKIMDomains, "dkim_domain")
	source.SPFDomains = redactCountMap(source.SPFDomains, "spf_domain")
	source.Reporters = redactCountMap(source.Reporters, "reporting_org")
	return source
}

func redactSuspiciousSource(source SuspiciousSource) SuspiciousSource {
	source.SourceIP = redactOptionalText("source_ip", source.SourceIP)
	source.HeaderFrom = redactCountMap(source.HeaderFrom, "header_from")
	source.DKIMDomains = redactCountMap(source.DKIMDomains, "dkim_domain")
	source.SPFDomains = redactCountMap(source.SPFDomains, "spf_domain")
	return source
}

func redactSourceReview(review SourceReview) SourceReview {
	review.Domain = redactOptionalText("target_domain", review.Domain)
	for i := range review.Unauthenticated {
		review.Unauthenticated[i] = redactSuspiciousSource(review.Unauthenticated[i])
	}
	for i := range review.Rejected {
		review.Rejected[i] = redactSuspiciousSource(review.Rejected[i])
	}
	for i := range review.Passing {
		review.Passing[i] = redactSourceSummary(review.Passing[i])
	}
	return review
}

func redactFeatureRows(rows []FeatureRow) []FeatureRow {
	out := cloneFeatureRows(rows)
	for i := range out {
		row := &out[i]
		row.ReportingOrg = redactOptionalText("reporting_org", row.ReportingOrg)
		row.ReportingEmail = redactOptionalText("reporting_addr", row.ReportingEmail)
		row.ReportID = redactOptionalText("report_id", row.ReportID)
		row.ReportGenerator = redactOptionalText("report_generator", row.ReportGenerator)
		row.TargetDomain = redactOptionalText("target_domain", row.TargetDomain)
		row.SourceIP = redactOptionalText("source_ip", row.SourceIP)
		row.HeaderFrom = redactOptionalText("header_from", row.HeaderFrom)
		row.EnvelopeFrom = redactOptionalText("envelope_from", row.EnvelopeFrom)
		row.EnvelopeTo = redactOptionalText("envelope_to", row.EnvelopeTo)
		row.DKIMDomain = redactOptionalText("dkim_domain", row.DKIMDomain)
		row.DKIMSelector = redactOptionalText("dkim_selector", row.DKIMSelector)
		row.SPFDomain = redactOptionalText("spf_domain", row.SPFDomain)
		clearRestrictedFeatureText(row)
		for j := range row.DKIMAuthResults {
			row.DKIMAuthResults[j].Domain = redactOptionalText("dkim_domain", row.DKIMAuthResults[j].Domain)
			row.DKIMAuthResults[j].Selector = redactOptionalText("dkim_selector", row.DKIMAuthResults[j].Selector)
		}
		if row.SPFAuthResult != nil {
			copyResult := *row.SPFAuthResult
			copyResult.Domain = redactOptionalText("spf_domain", copyResult.Domain)
			row.SPFAuthResult = &copyResult
		}
	}
	return out
}

func removeRestrictedReportText(out OutputEnvelope) (OutputEnvelope, bool) {
	rows, ok := out.Data.([]FeatureRow)
	if !ok {
		return out, false
	}
	rows = cloneFeatureRows(rows)
	changed := false
	for i := range rows {
		changed = changed || featureRowHasRestrictedText(rows[i])
		clearRestrictedFeatureText(&rows[i])
	}
	out.Data = rows
	return out, changed
}

func featureRowHasRestrictedText(row FeatureRow) bool {
	if row.ExtraContactInfo != "" || row.ExtraContactInfoLang != "" || row.ReportError != "" || row.ReportErrorLang != "" || row.Comment != "" || row.DKIMHumanResult != "" || row.SPFHumanResult != "" {
		return true
	}
	for _, result := range row.DKIMAuthResults {
		if result.HumanResult != (LangString{}) {
			return true
		}
	}
	if row.SPFAuthResult != nil && row.SPFAuthResult.HumanResult != (LangString{}) {
		return true
	}
	for _, reason := range row.PolicyOverrideReasons {
		if reason.Comment != (LangString{}) {
			return true
		}
	}
	return false
}

func clearRestrictedFeatureText(row *FeatureRow) {
	row.ExtraContactInfo = ""
	row.ExtraContactInfoLang = ""
	row.ReportError = ""
	row.ReportErrorLang = ""
	row.Comment = ""
	row.DKIMHumanResult = ""
	row.SPFHumanResult = ""
	for i := range row.DKIMAuthResults {
		row.DKIMAuthResults[i].HumanResult = LangString{}
	}
	if row.SPFAuthResult != nil {
		copyResult := *row.SPFAuthResult
		copyResult.HumanResult = LangString{}
		row.SPFAuthResult = &copyResult
	}
	for i := range row.PolicyOverrideReasons {
		row.PolicyOverrideReasons[i].Comment = LangString{}
	}
}

func reviewAction(code, title, reason string) OutputAction {
	return OutputAction{Code: ActionCode(code), Priority: 1, Title: title, Reason: reason, Target: map[string]string{}, Automation: AutomationPolicy{Eligible: false, Reason: "DMARC aggregate evidence requires organizational context and human authorization."}}
}

func highestSeverity(findings []OutputFinding) FindingSeverity {
	result := FindingSeverityInfo
	for _, finding := range findings {
		if severityRank(finding.Severity) > severityRank(result) {
			result = finding.Severity
		}
	}
	return result
}

func severityRank(severity FindingSeverity) int {
	switch severity {
	case FindingSeverityCritical:
		return 5
	case FindingSeverityHigh:
		return 4
	case FindingSeverityMedium:
		return 3
	case FindingSeverityLow:
		return 2
	default:
		return 1
	}
}

func compactSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortSuspiciousSources(sources []SuspiciousSource) {
	sort.SliceStable(sources, func(i, j int) bool { return canonicalSortKey(sources[i]) < canonicalSortKey(sources[j]) })
}

func sortSourceSummaries(sources []SourceSummary) {
	sort.SliceStable(sources, func(i, j int) bool { return canonicalSortKey(sources[i]) < canonicalSortKey(sources[j]) })
}

func sortOutputMessages(messages []OutputMessage) {
	sort.SliceStable(messages, func(i, j int) bool { return canonicalSortKey(messages[i]) < canonicalSortKey(messages[j]) })
}

func featureRowSortKey(row FeatureRow) string { return canonicalSortKey(row) }

func canonicalSortKey(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%T:%v", value, value)
	}
	return string(payload)
}

func validationSeverityRank(severity ValidationSeverity) int {
	if severity == ValidationError {
		return 2
	}
	return 1
}

func isSupportedOutputMode(mode OutputMode) bool {
	for _, supported := range SupportedOutputModes() {
		if mode == supported {
			return true
		}
	}
	return false
}

func addTruncation(out *OutputEnvelope, name string, total, returned int) {
	out.Truncation.Collections = append(out.Truncation.Collections, OutputCollectionTruncation{Name: name, TotalItems: total, ReturnedItems: returned})
	if returned < total {
		out.Truncation.Truncated = true
	}
}

func omitModeDataCollections(out *OutputEnvelope) {
	out.Truncation.Truncated = false
	for i := range out.Truncation.Collections {
		if out.Truncation.Collections[i].Name != "validation_findings" {
			out.Truncation.Collections[i].ReturnedItems = 0
		}
		if out.Truncation.Collections[i].ReturnedItems < out.Truncation.Collections[i].TotalItems {
			out.Truncation.Truncated = true
		}
	}
}

func cloneReportSummary(summary ReportSummary) ReportSummary {
	summary.ByDisposition = cloneCountMap(summary.ByDisposition)
	summary.ByHeaderFrom = cloneCountMap(summary.ByHeaderFrom)
	summary.BySourceIP = cloneSourceSummaries(summary.BySourceIP)
	return summary
}

func cloneAggregateSummary(summary AggregateSummary) AggregateSummary {
	summary.ByReporter = cloneCountMap(summary.ByReporter)
	summary.ByTargetDomain = cloneCountMap(summary.ByTargetDomain)
	summary.ByDisposition = cloneCountMap(summary.ByDisposition)
	summary.ByHeaderFrom = cloneCountMap(summary.ByHeaderFrom)
	summary.BySourceIP = cloneSourceSummaries(summary.BySourceIP)
	return summary
}

func cloneSourceReview(review SourceReview) SourceReview {
	review.Unauthenticated = cloneSuspiciousSources(review.Unauthenticated)
	review.Rejected = cloneSuspiciousSources(review.Rejected)
	review.Passing = cloneSourceSummaries(review.Passing)
	return review
}

func cloneFeatureRows(rows []FeatureRow) []FeatureRow {
	out := append([]FeatureRow{}, rows...)
	for i := range out {
		out[i].DKIMAuthResults = append([]DKIMAuthResult(nil), out[i].DKIMAuthResults...)
		out[i].PolicyOverrideReasons = append([]PolicyOverrideReason(nil), out[i].PolicyOverrideReasons...)
		if out[i].SPFAuthResult != nil {
			copyResult := *out[i].SPFAuthResult
			out[i].SPFAuthResult = &copyResult
		}
	}
	return out
}

func cloneSourceSummaries(sources []SourceSummary) []SourceSummary {
	out := append([]SourceSummary{}, sources...)
	for i := range out {
		out[i].HeaderFrom = cloneCountMap(out[i].HeaderFrom)
		out[i].DKIMDomains = cloneCountMap(out[i].DKIMDomains)
		out[i].SPFDomains = cloneCountMap(out[i].SPFDomains)
		out[i].Reporters = cloneCountMap(out[i].Reporters)
	}
	return out
}

func cloneSuspiciousSources(sources []SuspiciousSource) []SuspiciousSource {
	out := append([]SuspiciousSource{}, sources...)
	for i := range out {
		out[i].HeaderFrom = cloneCountMap(out[i].HeaderFrom)
		out[i].DKIMDomains = cloneCountMap(out[i].DKIMDomains)
		out[i].SPFDomains = cloneCountMap(out[i].SPFDomains)
	}
	return out
}

func cloneCountMap(values map[string]int) map[string]int {
	if values == nil {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func applyReportSummaryDetail(summary *ReportSummary, detail OutputDetail) {
	if detail == OutputDetailStandard {
		summary.BySourceIP = nil
	}
}

func applyAggregateSummaryDetail(summary *AggregateSummary, detail OutputDetail) {
	if detail == OutputDetailStandard {
		summary.BySourceIP = nil
	}
}

func applyFeatureRowDetail(rows []FeatureRow, detail OutputDetail) {
	if detail != OutputDetailStandard {
		return
	}
	for i := range rows {
		rows[i].DKIMAuthResults = nil
		rows[i].SPFAuthResult = nil
		rows[i].PolicyOverrideReasons = nil
	}
}

func applySourceReviewDetail(review *SourceReview, detail OutputDetail) {
	if detail != OutputDetailStandard {
		return
	}
	for i := range review.Unauthenticated {
		review.Unauthenticated[i].HeaderFrom = nil
		review.Unauthenticated[i].DKIMDomains = nil
		review.Unauthenticated[i].SPFDomains = nil
	}
	for i := range review.Rejected {
		review.Rejected[i].HeaderFrom = nil
		review.Rejected[i].DKIMDomains = nil
		review.Rejected[i].SPFDomains = nil
	}
	for i := range review.Passing {
		review.Passing[i].HeaderFrom = nil
		review.Passing[i].DKIMDomains = nil
		review.Passing[i].SPFDomains = nil
		review.Passing[i].Reporters = nil
	}
}

func limitReportSummary(out *OutputEnvelope, summary *ReportSummary, max int) {
	sortSourceSummariesForLimit(summary.BySourceIP)
	totalSources := len(summary.BySourceIP)
	summary.BySourceIP = limitSlice(summary.BySourceIP, max)
	addTruncation(out, "data.by_source_ip", totalSources, len(summary.BySourceIP))
	summary.ByDisposition = limitCountMap(out, "data.by_disposition", summary.ByDisposition, max)
	summary.ByHeaderFrom = limitCountMap(out, "data.by_header_from", summary.ByHeaderFrom, max)
}

func limitAggregateSummary(out *OutputEnvelope, summary *AggregateSummary, max int) {
	sortSourceSummariesForLimit(summary.BySourceIP)
	totalSources := len(summary.BySourceIP)
	summary.BySourceIP = limitSlice(summary.BySourceIP, max)
	addTruncation(out, "data.by_source_ip", totalSources, len(summary.BySourceIP))
	summary.ByReporter = limitCountMap(out, "data.by_reporter", summary.ByReporter, max)
	summary.ByTargetDomain = limitCountMap(out, "data.by_target_domain", summary.ByTargetDomain, max)
	summary.ByDisposition = limitCountMap(out, "data.by_disposition", summary.ByDisposition, max)
	summary.ByHeaderFrom = limitCountMap(out, "data.by_header_from", summary.ByHeaderFrom, max)
}

func sortSourceSummariesForLimit(sources []SourceSummary) {
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Messages != sources[j].Messages {
			return sources[i].Messages > sources[j].Messages
		}
		if sources[i].SourceIP != sources[j].SourceIP {
			return sources[i].SourceIP < sources[j].SourceIP
		}
		return canonicalSortKey(sources[i]) < canonicalSortKey(sources[j])
	})
}

func limitCountMap(out *OutputEnvelope, name string, values map[string]int, max int) map[string]int {
	values = canonicalizeCountMapForOutput(out, name, values)
	total := len(values)
	if max <= 0 || total <= max {
		addTruncation(out, name, total, total)
		return values
	}
	type entry struct {
		key   string
		value int
	}
	entries := make([]entry, 0, len(values))
	for key, value := range values {
		entries = append(entries, entry{key: key, value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].value != entries[j].value {
			return entries[i].value > entries[j].value
		}
		return entries[i].key < entries[j].key
	})
	limited := make(map[string]int, max)
	for _, item := range entries[:max] {
		limited[item.key] = item.value
	}
	addTruncation(out, name, total, len(limited))
	return limited
}

func canonicalizeCountMapForOutput(out *OutputEnvelope, name string, values map[string]int) map[string]int {
	if out.Redaction.Profile != OutputRedactionPublic {
		return values
	}
	var kind string
	switch name {
	case "data.by_target_domain":
		kind = "target_domain"
	case "data.by_header_from":
		kind = "header_from"
	default:
		return values
	}
	canonical := make(map[string]int, len(values))
	for key, count := range values {
		canonical[canonicalRedactionValue(kind, key)] += count
	}
	return canonical
}

func sourceReviewCounts(review SourceReview) (records, messages int) {
	for _, source := range review.Unauthenticated {
		records += source.Records
		messages += source.Messages
	}
	for _, source := range review.Passing {
		records += source.Records
		messages += source.Messages
	}
	return records, messages
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func limitSlice[T any](values []T, max int) []T {
	if max > 0 && len(values) > max {
		return values[:max]
	}
	return values
}
