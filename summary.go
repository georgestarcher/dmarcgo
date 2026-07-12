package dmarcgo

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReportSummary is an aggregate summary of one DMARC report.
type ReportSummary struct {
	ReportID            string          `json:"report_id"`
	ReportingOrg        string          `json:"reporting_org"`
	TargetDomain        string          `json:"target_domain"`
	Begin               string          `json:"begin"`
	End                 string          `json:"end"`
	BeginTime           time.Time       `json:"begin_time,omitempty"`
	EndTime             time.Time       `json:"end_time,omitempty"`
	TotalRecords        int             `json:"total_records"`
	InvalidRecords      int             `json:"invalid_records"`
	TotalMessages       int             `json:"total_messages"`
	PassedMessages      int             `json:"passed_messages"`
	FailedMessages      int             `json:"failed_messages"`
	RejectedMessages    int             `json:"rejected_messages"`
	QuarantinedMessages int             `json:"quarantined_messages"`
	NoneMessages        int             `json:"none_messages"`
	DKIMPassMessages    int             `json:"dkim_pass_messages"`
	DKIMFailMessages    int             `json:"dkim_fail_messages"`
	SPFPassMessages     int             `json:"spf_pass_messages"`
	SPFFailMessages     int             `json:"spf_fail_messages"`
	PassRate            float64         `json:"pass_rate"`
	FailureRate         float64         `json:"failure_rate"`
	BySourceIP          []SourceSummary `json:"by_source_ip,omitempty"`
	ByDisposition       map[string]int  `json:"by_disposition,omitempty"`
	ByHeaderFrom        map[string]int  `json:"by_header_from,omitempty"`
}

// SourceSummary summarizes records for a single source IP.
type SourceSummary struct {
	SourceIP            string         `json:"source_ip"`
	Records             int            `json:"records"`
	Messages            int            `json:"messages"`
	RejectedMessages    int            `json:"rejected_messages"`
	QuarantinedMessages int            `json:"quarantined_messages"`
	NoneMessages        int            `json:"none_messages"`
	PassedMessages      int            `json:"passed_messages"`
	FailedMessages      int            `json:"failed_messages"`
	DKIMFailMessages    int            `json:"dkim_fail_messages"`
	SPFFailMessages     int            `json:"spf_fail_messages"`
	PassRate            float64        `json:"pass_rate"`
	FailureRate         float64        `json:"failure_rate"`
	HeaderFrom          map[string]int `json:"header_from,omitempty"`
	DKIMDomains         map[string]int `json:"dkim_domains,omitempty"`
	SPFDomains          map[string]int `json:"spf_domains,omitempty"`
	Reporters           map[string]int `json:"reporters,omitempty"`
}

// SuspiciousSource describes unauthenticated traffic using a target Header From domain.
type SuspiciousSource struct {
	SourceIP            string         `json:"source_ip"`
	Messages            int            `json:"messages"`
	Records             int            `json:"records"`
	RejectedMessages    int            `json:"rejected_messages"`
	QuarantinedMessages int            `json:"quarantined_messages"`
	NoneMessages        int            `json:"none_messages"`
	HeaderFrom          map[string]int `json:"header_from,omitempty"`
	SPFDomains          map[string]int `json:"spf_domains,omitempty"`
	DKIMDomains         map[string]int `json:"dkim_domains,omitempty"`
}

// Summary returns message counts and grouped source-IP information for a report.
// Records with invalid or negative counts are included in TotalRecords and
// InvalidRecords but excluded from all message totals and source groupings.
func (r AggregateReport) Summary() ReportSummary {
	summary := ReportSummary{
		ReportID:      r.ReportMetadata.ReportID,
		ReportingOrg:  r.ReportMetadata.OrgName,
		TargetDomain:  r.PolicyPublished.Domain,
		Begin:         r.ReportMetadata.DateRange.Begin,
		End:           r.ReportMetadata.DateRange.End,
		ByDisposition: map[string]int{},
		ByHeaderFrom:  map[string]int{},
	}
	summary.BeginTime, _ = r.ReportMetadata.DateRange.BeginTime()
	summary.EndTime, _ = r.ReportMetadata.DateRange.EndTime()

	byIP := map[string]*SourceSummary{}
	for _, record := range r.Record {
		count := parseCount(record.Row.Count)
		summary.TotalRecords++
		if count == InvalidMailCount {
			summary.InvalidRecords++
			continue
		}
		summary.TotalMessages += count
		summary.ByDisposition[record.Row.PolicyEvaluated.Disposition] += count
		summary.ByHeaderFrom[record.Identifiers.HeaderFrom] += count

		source := byIP[record.Row.SourceIP]
		if source == nil {
			source = &SourceSummary{
				SourceIP:    record.Row.SourceIP,
				HeaderFrom:  map[string]int{},
				DKIMDomains: map[string]int{},
				SPFDomains:  map[string]int{},
				Reporters:   map[string]int{},
			}
			byIP[record.Row.SourceIP] = source
		}
		source.Records++
		source.Messages += count
		source.HeaderFrom[record.Identifiers.HeaderFrom] += count
		source.Reporters[r.ReportMetadata.OrgName] += count

		switch record.Row.PolicyEvaluated.Disposition {
		case "reject":
			summary.RejectedMessages += count
			source.RejectedMessages += count
		case "quarantine":
			summary.QuarantinedMessages += count
			source.QuarantinedMessages += count
		case "none", "pass":
			summary.NoneMessages += count
			source.NoneMessages += count
		}
		if dmarcPassed(record) {
			summary.PassedMessages += count
			source.PassedMessages += count
		} else {
			summary.FailedMessages += count
			source.FailedMessages += count
		}
		switch record.Row.PolicyEvaluated.DKIM {
		case "pass":
			summary.DKIMPassMessages += count
		case "fail":
			summary.DKIMFailMessages += count
			source.DKIMFailMessages += count
		}
		switch record.Row.PolicyEvaluated.SPF {
		case "pass":
			summary.SPFPassMessages += count
		case "fail":
			summary.SPFFailMessages += count
			source.SPFFailMessages += count
		}
		for _, dkim := range record.AuthResults.DKIM {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.SPF != nil && record.AuthResults.SPF.Domain != "" {
			source.SPFDomains[record.AuthResults.SPF.Domain] += count
		}
	}

	for _, source := range byIP {
		source.PassRate = ratio(source.PassedMessages, source.Messages)
		source.FailureRate = ratio(source.FailedMessages, source.Messages)
		summary.BySourceIP = append(summary.BySourceIP, *source)
	}
	summary.PassRate = ratio(summary.PassedMessages, summary.TotalMessages)
	summary.FailureRate = ratio(summary.FailedMessages, summary.TotalMessages)
	sort.Slice(summary.BySourceIP, func(i, j int) bool {
		if summary.BySourceIP[i].Messages == summary.BySourceIP[j].Messages {
			return summary.BySourceIP[i].SourceIP < summary.BySourceIP[j].SourceIP
		}
		return summary.BySourceIP[i].Messages > summary.BySourceIP[j].Messages
	})
	return summary
}

// UnauthenticatedSources returns source IPs that used domain in header_from while
// both DMARC DKIM and SPF alignment failed.
func (r AggregateReport) UnauthenticatedSources(domain string) []SuspiciousSource {
	return r.unauthenticatedSources(domain, "")
}

// RejectedUnauthenticatedSources returns unauthenticated sources whose reported
// disposition was reject.
func (r AggregateReport) RejectedUnauthenticatedSources(domain string) []SuspiciousSource {
	return r.unauthenticatedSources(domain, "reject")
}

// PassingSources returns source IPs that used domain in header_from and passed
// at least one DMARC alignment mechanism.
func (r AggregateReport) PassingSources(domain string) []SourceSummary {
	byIP := map[string]*SourceSummary{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, record := range r.Record {
		if domain != "" && strings.ToLower(record.Identifiers.HeaderFrom) != domain {
			continue
		}
		if record.Row.PolicyEvaluated.DKIM != "pass" && record.Row.PolicyEvaluated.SPF != "pass" {
			continue
		}
		count := parseCount(record.Row.Count)
		if count == InvalidMailCount {
			continue
		}
		source := byIP[record.Row.SourceIP]
		if source == nil {
			source = &SourceSummary{SourceIP: record.Row.SourceIP, HeaderFrom: map[string]int{}, DKIMDomains: map[string]int{}, SPFDomains: map[string]int{}, Reporters: map[string]int{}}
			byIP[record.Row.SourceIP] = source
		}
		source.Records++
		source.Messages += count
		source.PassedMessages += count
		source.HeaderFrom[record.Identifiers.HeaderFrom] += count
		for _, dkim := range record.AuthResults.DKIM {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.SPF != nil && record.AuthResults.SPF.Domain != "" {
			source.SPFDomains[record.AuthResults.SPF.Domain] += count
		}
	}
	out := make([]SourceSummary, 0, len(byIP))
	for _, source := range byIP {
		source.PassRate = ratio(source.PassedMessages, source.Messages)
		source.FailureRate = ratio(source.FailedMessages, source.Messages)
		out = append(out, *source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages == out[j].Messages {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Messages > out[j].Messages
	})
	return out
}

// SuspiciousSources returns source IPs that used domain in header_from while both
// DMARC DKIM and SPF alignment failed. Prefer UnauthenticatedSources for new code.
func (r AggregateReport) SuspiciousSources(domain string) []SuspiciousSource {
	return r.UnauthenticatedSources(domain)
}

func (r AggregateReport) unauthenticatedSources(domain, disposition string) []SuspiciousSource {
	byIP := map[string]*SuspiciousSource{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, record := range r.Record {
		if domain != "" && strings.ToLower(record.Identifiers.HeaderFrom) != domain {
			continue
		}
		if disposition != "" && record.Row.PolicyEvaluated.Disposition != disposition {
			continue
		}
		if record.Row.PolicyEvaluated.DKIM != "fail" || record.Row.PolicyEvaluated.SPF != "fail" {
			continue
		}

		count := parseCount(record.Row.Count)
		if count == InvalidMailCount {
			continue
		}
		source := byIP[record.Row.SourceIP]
		if source == nil {
			source = &SuspiciousSource{SourceIP: record.Row.SourceIP, HeaderFrom: map[string]int{}, SPFDomains: map[string]int{}, DKIMDomains: map[string]int{}}
			byIP[record.Row.SourceIP] = source
		}
		source.Records++
		source.Messages += count
		source.HeaderFrom[record.Identifiers.HeaderFrom] += count
		switch record.Row.PolicyEvaluated.Disposition {
		case "reject":
			source.RejectedMessages += count
		case "quarantine":
			source.QuarantinedMessages += count
		case "none", "pass":
			source.NoneMessages += count
		}
		for _, dkim := range record.AuthResults.DKIM {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.SPF != nil && record.AuthResults.SPF.Domain != "" {
			source.SPFDomains[record.AuthResults.SPF.Domain] += count
		}
	}

	out := make([]SuspiciousSource, 0, len(byIP))
	for _, source := range byIP {
		out = append(out, *source)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Messages == out[j].Messages {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Messages > out[j].Messages
	})
	return out
}

// BeginTime returns the report begin time as UTC.
func (d DateRange) BeginTime() (time.Time, error) {
	return epochStringToTime(d.Begin)
}

// EndTime returns the report end time as UTC.
func (d DateRange) EndTime() (time.Time, error) {
	return epochStringToTime(d.End)
}

func parseCount(raw string) int {
	count, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || count < 0 {
		return InvalidMailCount
	}
	return count
}

func dmarcPassed(record Record) bool {
	return record.Row.PolicyEvaluated.DKIM == "pass" || record.Row.PolicyEvaluated.SPF == "pass"
}

func ratio(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func epochStringToTime(raw string) (time.Time, error) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0).UTC(), nil
}
