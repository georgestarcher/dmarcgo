package dmarcgo

import "strings"

// ReportIdentity is a stable identity tuple for deduplicating aggregate reports.
type ReportIdentity struct {
	ReportID     string `json:"report_id"`
	ReportingOrg string `json:"reporting_org,omitempty"`
	PolicyDomain string `json:"policy_domain"`
	Begin        string `json:"begin"`
	End          string `json:"end"`
}

// String returns a stable pipe-separated report identity.
func (k ReportIdentity) String() string {
	return strings.Join([]string{k.ReportingOrg, k.PolicyDomain, k.Begin, k.End, k.ReportID}, "|")
}

// IsZero reports whether no identity fields were populated.
func (k ReportIdentity) IsZero() bool {
	return k.ReportID == "" && k.ReportingOrg == "" && k.PolicyDomain == "" && k.Begin == "" && k.End == ""
}

// ReportKey returns a stable identity tuple for report. Nil reports return a
// zero identity.
func ReportKey(report *AggregateReport) ReportIdentity {
	if report == nil {
		return ReportIdentity{}
	}
	return ReportIdentity{
		ReportID:     report.ReportMetadata.ReportID,
		ReportingOrg: report.ReportMetadata.OrgName,
		PolicyDomain: report.PolicyPublished.Domain,
		Begin:        report.ReportMetadata.DateRange.Begin,
		End:          report.ReportMetadata.DateRange.End,
	}
}

// FilenameReportKey returns a stable identity tuple from a common DMARC report
// attachment filename.
func FilenameReportKey(path string) (ReportIdentity, error) {
	info, err := ParseReportFilename(path)
	if err != nil {
		return ReportIdentity{}, err
	}
	return ReportIdentity{
		ReportID:     info.UniqueID,
		ReportingOrg: info.Reporter,
		PolicyDomain: info.PolicyDomain,
		Begin:        info.Begin,
		End:          info.End,
	}, nil
}

// SameReport reports whether two reports have the same non-zero identity.
func SameReport(a, b *AggregateReport) bool {
	left := ReportKey(a)
	right := ReportKey(b)
	return !left.IsZero() && left == right
}

// DeduplicateReports returns reports with duplicate non-zero identities removed.
// The first report for each identity is kept. Nil reports are skipped.
func DeduplicateReports(reports []*AggregateReport) []*AggregateReport {
	seen := map[ReportIdentity]struct{}{}
	out := make([]*AggregateReport, 0, len(reports))
	for _, report := range reports {
		if report == nil {
			continue
		}
		key := ReportKey(report)
		if !key.IsZero() {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
		}
		out = append(out, report)
	}
	return out
}
