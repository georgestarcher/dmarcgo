package dmarcgo

import "strings"

// ValidateReportFilename validates parsed DMARC aggregate report attachment
// filename metadata. Compatibility mode accepts common real-world compression
// extensions; strict mode checks RFC 9990-style XML or XML.GZ names.
func ValidateReportFilename(info ReportFilename, mode ValidationMode) []ValidationFinding {
	var findings []ValidationFinding
	add := func(severity ValidationSeverity, path, message string) {
		findings = append(findings, ValidationFinding{Severity: severity, Path: path, Message: message})
	}

	if strings.TrimSpace(info.Reporter) == "" {
		add(ValidationError, "filename.reporter", "missing reporting organization")
	}
	if strings.TrimSpace(info.PolicyDomain) == "" {
		add(ValidationError, "filename.policy_domain", "missing policy domain")
	}
	if _, err := epochStringToTime(info.Begin); err != nil {
		add(ValidationError, "filename.begin", "begin must be Unix epoch seconds")
	}
	if _, err := epochStringToTime(info.End); err != nil {
		add(ValidationError, "filename.end", "end must be Unix epoch seconds")
	}
	if begin, beginErr := epochStringToTime(info.Begin); beginErr == nil {
		if end, endErr := epochStringToTime(info.End); endErr == nil && end.Before(begin) {
			add(ValidationError, "filename.date_range", "end must be greater than or equal to begin")
		}
	}

	extension := strings.ToLower(strings.TrimSpace(info.Extension))
	switch mode {
	case ValidationModeStrictRFC9990:
		if extension != ".xml" && extension != ".xml.gz" {
			add(ValidationError, "filename.extension", "strict RFC 9990 filenames must end in .xml or .xml.gz")
		}
	default:
		if extension == "" {
			add(ValidationWarning, "filename.extension", "filename has no recognized report extension")
		}
	}

	return findings
}
