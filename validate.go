package dmarcgo

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ValidationSeverity classifies report validation findings.
type ValidationSeverity string

const (
	ValidationError   ValidationSeverity = "error"
	ValidationWarning ValidationSeverity = "warning"
)

// ValidationMode controls how strictly ValidateWithMode checks a report.
type ValidationMode int

const (
	// ValidationModeCompatibility accepts common legacy aggregate-report shapes.
	ValidationModeCompatibility ValidationMode = iota
	// ValidationModeStrictRFC9990 adds checks for the current RFC 9990 shape.
	ValidationModeStrictRFC9990
)

// ValidationFinding describes a non-fatal standards or data-quality issue.
type ValidationFinding struct {
	Severity ValidationSeverity `json:"severity"`
	Path     string             `json:"path"`
	Message  string             `json:"message"`
}

// ReportValidationResult is a completed report-validation result suitable for
// inspection, persistence, or output serialization without rerunning report
// analysis.
type ReportValidationResult struct {
	Metadata     ResultMetadata      `json:"metadata"`
	TargetDomain string              `json:"target_domain"`
	ReportCount  int                 `json:"report_count"`
	RecordCount  int                 `json:"record_count"`
	MessageCount int                 `json:"message_count"`
	Findings     []ValidationFinding `json:"findings"`
}

// ResultMetadata returns the completed validation metadata without performing
// analysis or I/O.
func (result ReportValidationResult) ResultMetadata() ResultMetadata {
	return result.Metadata
}

// ValidationResult validates the report in mode and captures the counts needed
// by downstream output builders. A nil report produces a not-evaluated result
// that output builders reject; use BuildFailureOutput for prerequisite errors.
func (r *AggregateReport) ValidationResult(mode ValidationMode, generatedAt time.Time) ReportValidationResult {
	metadata := ResultMetadata{
		ContractVersion: AnalysisContractVersion,
		Mode:            AnalysisModeReportValidation,
		GeneratedAt:     generatedAt.UTC(),
		Evaluation:      Evaluation{State: EvaluationStateEvaluated},
	}
	if r == nil {
		metadata.Evaluation = Evaluation{State: EvaluationStateNotEvaluated, Reason: "No report was supplied for validation."}
		return ReportValidationResult{Metadata: metadata, Findings: []ValidationFinding{}}
	}
	summary := r.Summary()
	findings := r.ValidateWithMode(mode)
	if findings == nil {
		findings = []ValidationFinding{}
	}
	return ReportValidationResult{
		Metadata:     metadata,
		TargetDomain: r.PolicyPublished.Domain,
		ReportCount:  1,
		RecordCount:  summary.TotalRecords,
		MessageCount: summary.TotalMessages,
		Findings:     findings,
	}
}

// Validate checks required aggregate-report fields and common value constraints
// using compatibility mode. It is intentionally non-mutating and tolerant of
// real-world legacy reports.
func (r AggregateReport) Validate() []ValidationFinding {
	return r.ValidateWithMode(ValidationModeCompatibility)
}

// ValidateCompatibility checks required fields and common value constraints while
// accepting common legacy aggregate-report shapes.
func (r AggregateReport) ValidateCompatibility() []ValidationFinding {
	return r.ValidateWithMode(ValidationModeCompatibility)
}

// ValidateStrict checks compatibility findings plus stricter RFC 9990
// expectations such as namespace, version, DKIM selectors, and current policy
// fields. It is best used for synthetic fixtures or producers claiming RFC 9990.
func (r AggregateReport) ValidateStrict() []ValidationFinding {
	return r.ValidateWithMode(ValidationModeStrictRFC9990)
}

// ValidateStrictRFC9990 checks compatibility findings plus stricter RFC 9990
// expectations.
//
// Deprecated: use ValidateStrict.
func (r AggregateReport) ValidateStrictRFC9990() []ValidationFinding {
	return r.ValidateStrict()
}

// ValidateWithMode checks required aggregate-report fields and common value constraints.
func (r AggregateReport) ValidateWithMode(mode ValidationMode) []ValidationFinding {
	var findings []ValidationFinding
	add := func(severity ValidationSeverity, path, message string) {
		findings = append(findings, ValidationFinding{Severity: severity, Path: path, Message: message})
	}

	if mode == ValidationModeStrictRFC9990 {
		if r.XMLName.Space != RFC9990Namespace {
			add(ValidationError, "feedback.xmlns", "strict RFC 9990 reports must use the RFC 9990 DMARC namespace")
		}
		if strings.TrimSpace(r.Version) != "" && strings.TrimSpace(r.Version) != "1.0" {
			add(ValidationError, "version", "version must be 1.0 when present")
		}
		if r.PolicyPublished.Pct != "" {
			add(ValidationWarning, "policy_published.pct", "pct is legacy aggregate-report data and is not part of RFC 9990")
		}
	}

	if strings.TrimSpace(r.ReportMetadata.OrgName) == "" {
		add(ValidationError, "report_metadata.org_name", "missing reporting organization")
	}
	if strings.TrimSpace(r.ReportMetadata.Email) == "" {
		add(ValidationError, "report_metadata.email", "missing reporting contact email")
	}
	if strings.TrimSpace(r.ReportMetadata.ReportID) == "" {
		add(ValidationError, "report_metadata.report_id", "missing report id")
	}
	if _, err := r.ReportMetadata.DateRange.BeginTime(); err != nil {
		add(ValidationError, "report_metadata.date_range.begin", "begin must be Unix epoch seconds")
	}
	if _, err := r.ReportMetadata.DateRange.EndTime(); err != nil {
		add(ValidationError, "report_metadata.date_range.end", "end must be Unix epoch seconds")
	}
	if begin, beginErr := r.ReportMetadata.DateRange.BeginTime(); beginErr == nil {
		if end, endErr := r.ReportMetadata.DateRange.EndTime(); endErr == nil && end.Before(begin) {
			add(ValidationError, "report_metadata.date_range", "end must be greater than or equal to begin")
		}
	}
	if strings.TrimSpace(r.PolicyPublished.Domain) == "" {
		add(ValidationError, "policy_published.domain", "missing policy domain")
	}
	validateEnum(&findings, "policy_published.p", r.PolicyPublished.P, []string{"none", "quarantine", "reject"}, true)
	validateEnum(&findings, "policy_published.sp", r.PolicyPublished.Sp, []string{"none", "quarantine", "reject"}, false)
	validateEnum(&findings, "policy_published.np", r.PolicyPublished.Np, []string{"none", "quarantine", "reject"}, false)
	validateEnum(&findings, "policy_published.adkim", r.PolicyPublished.ADKIM, []string{"r", "s"}, false)
	validateEnum(&findings, "policy_published.aspf", r.PolicyPublished.ASPF, []string{"r", "s"}, false)
	validateEnum(&findings, "policy_published.discovery_method", r.PolicyPublished.DiscoveryMethod, []string{"psl", "treewalk"}, false)
	validateEnum(&findings, "policy_published.testing", r.PolicyPublished.Testing, []string{"n", "y"}, false)
	if r.PolicyPublished.Pct != "" {
		pct, err := strconv.Atoi(strings.TrimSpace(r.PolicyPublished.Pct))
		if err != nil || pct < 0 || pct > 100 {
			add(ValidationWarning, "policy_published.pct", "pct should be an integer from 0 through 100")
		}
	}
	if len(r.Record) == 0 {
		add(ValidationError, "record", "report must contain at least one record")
	}

	for i, record := range r.Record {
		prefix := fmt.Sprintf("record[%d]", i)
		if strings.TrimSpace(record.Row.SourceIP) == "" {
			add(ValidationError, prefix+".row.source_ip", "missing source IP")
		} else if _, err := netip.ParseAddr(strings.TrimSpace(record.Row.SourceIP)); err != nil {
			add(ValidationWarning, prefix+".row.source_ip", "source IP is not a valid IPv4 or IPv6 address")
		}
		count, err := strconv.Atoi(strings.TrimSpace(record.Row.Count))
		if err != nil || count < 0 {
			add(ValidationError, prefix+".row.count", "count must be a non-negative integer")
		}
		validateEnum(&findings, prefix+".row.policy_evaluated.disposition", record.Row.PolicyEvaluated.Disposition, []string{"none", "pass", "quarantine", "reject"}, true)
		validateEnum(&findings, prefix+".row.policy_evaluated.dkim", record.Row.PolicyEvaluated.DKIM, []string{"pass", "fail"}, true)
		validateEnum(&findings, prefix+".row.policy_evaluated.spf", record.Row.PolicyEvaluated.SPF, []string{"pass", "fail"}, true)
		if strings.TrimSpace(record.Identifiers.HeaderFrom) == "" {
			add(ValidationError, prefix+".identifiers.header_from", "missing header_from domain")
		}
		for reasonIndex, reason := range record.Row.PolicyEvaluated.Reasons {
			validateEnum(&findings, fmt.Sprintf("%s.row.policy_evaluated.reason[%d].type", prefix, reasonIndex), reason.Type, []string{"local_policy", "mailing_list", "other", "policy_test_mode", "trusted_forwarder"}, true)
		}
		for dkimIndex, dkim := range record.AuthResults.DKIM {
			dkimPrefix := fmt.Sprintf("%s.auth_results.dkim[%d]", prefix, dkimIndex)
			if strings.TrimSpace(dkim.Domain) == "" {
				add(ValidationError, dkimPrefix+".domain", "missing DKIM domain")
			}
			if mode == ValidationModeStrictRFC9990 && strings.TrimSpace(dkim.Selector) == "" {
				add(ValidationError, dkimPrefix+".selector", "strict RFC 9990 DKIM auth results must include selector")
			}
			validateEnum(&findings, dkimPrefix+".result", dkim.Result, []string{"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"}, true)
		}
		if record.AuthResults.SPF != nil {
			if strings.TrimSpace(record.AuthResults.SPF.Domain) == "" {
				add(ValidationError, prefix+".auth_results.spf.domain", "missing SPF domain")
			}
			validateEnum(&findings, prefix+".auth_results.spf.scope", record.AuthResults.SPF.Scope, []string{"mfrom"}, false)
			validateEnum(&findings, prefix+".auth_results.spf.result", record.AuthResults.SPF.Result, []string{"none", "pass", "fail", "softfail", "policy", "neutral", "temperror", "permerror"}, true)
		}
	}
	return findings
}

func validateEnum(findings *[]ValidationFinding, path, value string, allowed []string, required bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			*findings = append(*findings, ValidationFinding{Severity: ValidationError, Path: path, Message: "missing required value"})
		}
		return
	}
	for _, candidate := range allowed {
		if value == candidate {
			return
		}
	}
	*findings = append(*findings, ValidationFinding{Severity: ValidationWarning, Path: path, Message: fmt.Sprintf("unexpected value %q", value)})
}
