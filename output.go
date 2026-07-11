package dmarcgo

import (
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
)

// OutputSchemaVersion is the current automation-envelope schema version.
const OutputSchemaVersion = "1"

// OutputSchemaID identifies the JSON Schema for the current envelope.
const OutputSchemaID = "https://github.com/georgestarcher/dmarcgo/schemas/output/v1.json"

//go:embed schemas/output/v1.json
var outputSchemaV1 []byte

// ErrInvalidOutputOptions identifies an unsupported output option.
var ErrInvalidOutputOptions = errors.New("invalid output options")

// OutputMode identifies the analysis result carried by an OutputEnvelope.
type OutputMode string

const (
	OutputModeReportValidation OutputMode = "report_validation"
	OutputModeReportSummary    OutputMode = "report_summary"
	OutputModeAggregateSummary OutputMode = "aggregate_summary"
	OutputModeReportRows       OutputMode = "report_rows"
	OutputModeSourceReview     OutputMode = "source_review"
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

// FindingSeverity is the operational importance of a finding.
type FindingSeverity string

const (
	FindingSeverityInfo     FindingSeverity = "info"
	FindingSeverityLow      FindingSeverity = "low"
	FindingSeverityMedium   FindingSeverity = "medium"
	FindingSeverityHigh     FindingSeverity = "high"
	FindingSeverityCritical FindingSeverity = "critical"
)

// FindingConfidence describes how strongly the supplied evidence supports a finding.
type FindingConfidence string

const (
	FindingConfidenceLow    FindingConfidence = "low"
	FindingConfidenceMedium FindingConfidence = "medium"
	FindingConfidenceHigh   FindingConfidence = "high"
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
	GeneratedAt        time.Time          `json:"generated_at"`
	Status             OutputStatus       `json:"status"`
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
	Code        string            `json:"code"`
	Category    string            `json:"category"`
	Severity    FindingSeverity   `json:"severity"`
	Confidence  FindingConfidence `json:"confidence"`
	Title       string            `json:"title"`
	Explanation string            `json:"explanation"`
	Subject     map[string]string `json:"subject"`
	Evidence    []OutputEvidence  `json:"evidence"`
	Limitations []string          `json:"limitations"`
	ActionCodes []string          `json:"action_codes"`
}

type OutputEvidence struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Path        string `json:"path,omitempty"`
	Value       any    `json:"value"`
	Provenance  string `json:"provenance,omitempty"`
	Sensitivity string `json:"sensitivity"`
}

type OutputAction struct {
	Code       string            `json:"code"`
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
	Code      string `json:"code"`
	Message   string `json:"message"`
	Path      string `json:"path,omitempty"`
	Retryable bool   `json:"retryable"`
}

type OutputProvenance struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Key  string `json:"key,omitempty"`
}

type RedactionMetadata struct {
	Profile                  OutputRedaction `json:"profile"`
	OperationalFieldsChanged bool            `json:"operational_fields_changed"`
}

type TruncationMetadata struct {
	Truncated     bool `json:"truncated"`
	TotalItems    int  `json:"total_items"`
	ReturnedItems int  `json:"returned_items"`
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

// BuildValidationOutput creates an envelope from already computed validation findings.
func BuildValidationOutput(report *AggregateReport, findings []ValidationFinding, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	scope := OutputScope{}
	input := OutputInput{}
	if report != nil {
		scope.TargetDomains = compactSortedStrings([]string{report.PolicyPublished.Domain})
		input = OutputInput{ReportCount: 1, RecordCount: len(report.Record), MessageCount: report.Summary().TotalMessages}
	}
	out := baseOutput(OutputModeReportValidation, scope, input, options)
	data := append([]ValidationFinding(nil), findings...)
	sort.SliceStable(data, func(i, j int) bool {
		if data[i].Path != data[j].Path {
			return data[i].Path < data[j].Path
		}
		if data[i].Severity != data[j].Severity {
			return data[i].Severity < data[j].Severity
		}
		return data[i].Message < data[j].Message
	})
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
			Evidence:    []OutputEvidence{{Type: "validation_result", Source: "dmarcgo", Path: finding.Path, Value: finding.Message, Sensitivity: "operational"}},
			Limitations: []string{}, ActionCodes: []string{"review_report_data"},
		})
	}
	if len(data) == 0 {
		out.Summary = OutputSummary{Headline: "The report passed the selected validation checks.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "The report has validation findings that may affect downstream analysis.", Severity: highestSeverity(out.Findings), Confidence: FindingConfidenceHigh}
		out.RecommendedActions = []OutputAction{reviewAction("review_report_data", "Review report validation findings", "Resolve or account for malformed and nonconforming report fields.")}
	}
	return finalizeOutput(out, options), nil
}

// BuildReportSummaryOutput creates an envelope from an already computed report summary.
func BuildReportSummaryOutput(summary ReportSummary, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	out := baseOutput(OutputModeReportSummary, OutputScope{TargetDomains: compactSortedStrings([]string{summary.TargetDomain})}, OutputInput{ReportCount: 1, RecordCount: summary.TotalRecords, MessageCount: summary.TotalMessages}, options)
	out.Data = summary
	addAuthenticationFindings(&out, summary.FailedMessages, summary.InvalidRecords, summary.TargetDomain)
	out.Provenance = []OutputProvenance{{ID: "report-1", Type: "aggregate_report", Key: summary.ReportID}}
	return finalizeOutput(out, options), nil
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
	out.Data = summary
	addAuthenticationFindings(&out, summary.FailedMessages, summary.InvalidRecords, "")
	return finalizeOutput(out, options), nil
}

// BuildReportRowsOutput creates an envelope from already flattened report rows.
func BuildReportRowsOutput(rows []FeatureRow, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	rows = append([]FeatureRow(nil), rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ReportID != rows[j].ReportID {
			return rows[i].ReportID < rows[j].ReportID
		}
		if rows[i].SourceIP != rows[j].SourceIP {
			return rows[i].SourceIP < rows[j].SourceIP
		}
		return rows[i].HeaderFrom < rows[j].HeaderFrom
	})
	domains := make([]string, 0, len(rows))
	messages := 0
	for _, row := range rows {
		domains = append(domains, row.TargetDomain)
		if row.MailCount > 0 {
			messages += row.MailCount
		}
	}
	out := baseOutput(OutputModeReportRows, OutputScope{TargetDomains: compactSortedStrings(domains)}, OutputInput{RecordCount: len(rows), MessageCount: messages}, options)
	total := len(rows)
	if options.MaxItems > 0 && len(rows) > options.MaxItems {
		rows = rows[:options.MaxItems]
	}
	out.Data = rows
	out.Truncation = TruncationMetadata{Truncated: len(rows) < total, TotalItems: total, ReturnedItems: len(rows)}
	out.Summary = OutputSummary{Headline: "Flattened DMARC report rows are ready for downstream processing.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	return finalizeOutput(out, options), nil
}

// BuildSourceReviewOutput creates an envelope from already computed source-review results.
func BuildSourceReviewOutput(review SourceReview, options OutputOptions) (OutputEnvelope, error) {
	options, err := normalizeOutputOptions(options)
	if err != nil {
		return OutputEnvelope{}, err
	}
	sortSuspiciousSources(review.Unauthenticated)
	sortSuspiciousSources(review.Rejected)
	sort.SliceStable(review.Passing, func(i, j int) bool { return review.Passing[i].SourceIP < review.Passing[j].SourceIP })
	out := baseOutput(OutputModeSourceReview, OutputScope{TargetDomains: compactSortedStrings([]string{review.Domain})}, OutputInput{}, options)
	total := len(review.Unauthenticated) + len(review.Passing)
	if options.MaxItems > 0 {
		review.Unauthenticated = limitSlice(review.Unauthenticated, options.MaxItems)
		review.Rejected = limitSlice(review.Rejected, options.MaxItems)
		review.Passing = limitSlice(review.Passing, options.MaxItems)
	}
	out.Data = review
	out.Truncation = TruncationMetadata{Truncated: total > len(review.Unauthenticated)+len(review.Passing), TotalItems: total, ReturnedItems: len(review.Unauthenticated) + len(review.Passing)}
	if len(review.Unauthenticated) > 0 {
		messages := 0
		for _, source := range review.Unauthenticated {
			messages += source.Messages
		}
		out.Findings = []OutputFinding{{
			Code: "report.unauthenticated_sources", Category: "source_review", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh,
			Title: "Unauthenticated sources observed", Explanation: "These sources used the target Header From domain while both policy-evaluated DKIM and SPF failed.",
			Subject: map[string]string{"domain": review.Domain}, Evidence: []OutputEvidence{{Type: "source_summary", Source: "aggregate_report", Value: map[string]int{"sources": len(review.Unauthenticated), "messages": messages}, Sensitivity: "operational"}},
			Limitations: []string{"DMARC aggregate evidence does not establish malicious intent."}, ActionCodes: []string{"review_unauthenticated_sources"},
		}}
		out.RecommendedActions = []OutputAction{reviewAction("review_unauthenticated_sources", "Review unauthenticated sending sources", "Confirm whether the sources are expected before taking defensive action.")}
		out.Summary = OutputSummary{Headline: "Unauthenticated sources require review; the report alone does not establish malicious intent.", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "No unauthenticated sources were present in the supplied source-review result.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	}
	return finalizeOutput(out, options), nil
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
	return OutputEnvelope{
		Schema: OutputSchemaID, SchemaVersion: OutputSchemaVersion, ModuleVersion: options.ModuleVersion,
		Mode: mode, Profile: options.Profile, GeneratedAt: options.GeneratedAt, Status: OutputStatusCompleted,
		Scope: scope, Input: input, Summary: OutputSummary{Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh},
		Findings: []OutputFinding{}, Data: map[string]any{}, RecommendedActions: []OutputAction{}, Warnings: []OutputMessage{}, Errors: []OutputMessage{}, Limitations: []string{}, Provenance: []OutputProvenance{},
		Redaction: RedactionMetadata{Profile: options.Redaction}, Truncation: TruncationMetadata{},
	}
}

func addAuthenticationFindings(out *OutputEnvelope, failed, invalid int, domain string) {
	if failed > 0 {
		out.Findings = append(out.Findings, OutputFinding{
			Code: "report.authentication_failures", Category: "authentication", Severity: FindingSeverityMedium, Confidence: FindingConfidenceHigh,
			Title: "DMARC authentication failures observed", Explanation: "Messages failed both policy-evaluated DKIM and SPF alignment.",
			Subject: map[string]string{"domain": domain}, Evidence: []OutputEvidence{{Type: "authentication_result", Source: "aggregate_report", Value: map[string]int{"failed_messages": failed}, Sensitivity: "operational"}},
			Limitations: []string{"Authentication failure does not by itself prove spoofing or malicious intent."}, ActionCodes: []string{"review_authentication_failures"},
		})
		out.RecommendedActions = append(out.RecommendedActions, reviewAction("review_authentication_failures", "Review authentication failures", "Determine whether failed traffic is an expected sender configuration issue or unauthorized use."))
	}
	if invalid > 0 {
		out.Findings = append(out.Findings, OutputFinding{
			Code: "report.invalid_records", Category: "data_quality", Severity: FindingSeverityLow, Confidence: FindingConfidenceHigh,
			Title: "Invalid report records excluded from message totals", Explanation: "One or more records had invalid counts and were excluded from message totals.",
			Subject: map[string]string{}, Evidence: []OutputEvidence{{Type: "validation_result", Source: "aggregate_report", Value: map[string]int{"invalid_records": invalid}, Sensitivity: "operational"}},
			Limitations: []string{}, ActionCodes: []string{"review_report_data"},
		})
	}
	if len(out.Findings) == 0 {
		out.Summary = OutputSummary{Headline: "No authentication failures or invalid records were present in the supplied summary.", Severity: FindingSeverityInfo, Confidence: FindingConfidenceHigh}
	} else {
		out.Summary = OutputSummary{Headline: "The supplied summary contains findings that require contextual review.", Severity: highestSeverity(out.Findings), Confidence: FindingConfidenceHigh}
	}
}

func finalizeOutput(out OutputEnvelope, options OutputOptions) OutputEnvelope {
	if len(out.Findings) > 0 {
		out.Status = OutputStatusCompletedWithFindings
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		if severityRank(out.Findings[i].Severity) != severityRank(out.Findings[j].Severity) {
			return severityRank(out.Findings[i].Severity) > severityRank(out.Findings[j].Severity)
		}
		return out.Findings[i].Code < out.Findings[j].Code
	})
	sort.SliceStable(out.RecommendedActions, func(i, j int) bool {
		if out.RecommendedActions[i].Priority != out.RecommendedActions[j].Priority {
			return out.RecommendedActions[i].Priority < out.RecommendedActions[j].Priority
		}
		return out.RecommendedActions[i].Code < out.RecommendedActions[j].Code
	})
	if options.Detail == OutputDetailSummary {
		out.Data = map[string]any{}
	}
	if options.Profile == OutputProfileAutomation {
		out.Summary.Headline = ""
		for i := range out.Findings {
			out.Findings[i].Explanation = ""
		}
	}
	if options.Redaction == OutputRedactionPublic {
		out = redactOutput(out)
		out.Redaction.OperationalFieldsChanged = true
	}
	return out
}

func redactOutput(out OutputEnvelope) OutputEnvelope {
	payload, err := json.Marshal(out)
	if err != nil {
		return out
	}
	var value any
	if json.Unmarshal(payload, &value) != nil {
		return out
	}
	redactValue(value, "")
	redacted, err := json.Marshal(value)
	if err != nil {
		return out
	}
	var result OutputEnvelope
	if json.Unmarshal(redacted, &result) != nil {
		return out
	}
	return result
}

func redactValue(value any, key string) {
	switch typed := value.(type) {
	case map[string]any:
		if shouldRedactMapKeys(key) {
			for childKey, child := range typed {
				delete(typed, childKey)
				typed[redactionToken(key, childKey)] = child
			}
		}
		for childKey, child := range typed {
			if text, ok := child.(string); ok && shouldRedactKey(childKey) && text != "" {
				typed[childKey] = redactionToken(childKey, text)
				continue
			}
			redactValue(child, childKey)
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok && shouldRedactStringList(key) && text != "" {
				typed[index] = redactionToken(key, text)
				continue
			}
			redactValue(child, key)
		}
	}
}

func shouldRedactMapKeys(key string) bool {
	switch key {
	case "by_header_from", "by_reporter", "by_target_domain", "dkim_domains", "header_from", "reporters", "spf_domains":
		return true
	default:
		return false
	}
}

func shouldRedactStringList(key string) bool {
	return key == "target_domains"
}

func shouldRedactKey(key string) bool {
	switch key {
	case "source_ip", "report_id", "reporting_org", "reporting_addr", "target_domain", "domain", "header_from", "envelope_from", "envelope_to", "dkim_domain", "spf_domain", "key":
		return true
	default:
		return false
	}
}

func redactionToken(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + strings.ToLower(value)))
	return "redacted:" + hex.EncodeToString(sum[:6])
}

func reviewAction(code, title, reason string) OutputAction {
	return OutputAction{Code: code, Priority: 1, Title: title, Reason: reason, Target: map[string]string{}, Automation: AutomationPolicy{Eligible: false, Reason: "DMARC aggregate evidence requires organizational context and human authorization."}}
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
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].SourceIP < sources[j].SourceIP })
}

func limitSlice[T any](values []T, max int) []T {
	if max > 0 && len(values) > max {
		return values[:max]
	}
	return values
}
