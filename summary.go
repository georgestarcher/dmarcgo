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
	TotalMessages       int             `json:"total_messages"`
	PassedMessages      int             `json:"passed_messages"`
	RejectedMessages    int             `json:"rejected_messages"`
	QuarantinedMessages int             `json:"quarantined_messages"`
	DKIMPassMessages    int             `json:"dkim_pass_messages"`
	DKIMFailMessages    int             `json:"dkim_fail_messages"`
	SPFPassMessages     int             `json:"spf_pass_messages"`
	SPFFailMessages     int             `json:"spf_fail_messages"`
	BySourceIP          []SourceSummary `json:"by_source_ip,omitempty"`
	ByDisposition       map[string]int  `json:"by_disposition,omitempty"`
	ByHeaderFrom        map[string]int  `json:"by_header_from,omitempty"`
}

// SourceSummary summarizes records for a single source IP.
type SourceSummary struct {
	SourceIP         string         `json:"source_ip"`
	Records          int            `json:"records"`
	Messages         int            `json:"messages"`
	RejectedMessages int            `json:"rejected_messages"`
	PassedMessages   int            `json:"passed_messages"`
	DKIMFailMessages int            `json:"dkim_fail_messages"`
	SPFFailMessages  int            `json:"spf_fail_messages"`
	HeaderFrom       map[string]int `json:"header_from,omitempty"`
	DKIMDomains      map[string]int `json:"dkim_domains,omitempty"`
	SPFDomains       map[string]int `json:"spf_domains,omitempty"`
	Reporters        map[string]int `json:"reporters,omitempty"`
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
func (r DmarcReport) Summary() ReportSummary {
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
		summary.TotalMessages += count
		summary.ByDisposition[record.Row.PolicyEvaluated.Disposition] += count
		summary.ByHeaderFrom[record.Identifiers.HeaderFrom] += count

		source := byIP[record.Row.SourceIp]
		if source == nil {
			source = &SourceSummary{
				SourceIP:    record.Row.SourceIp,
				HeaderFrom:  map[string]int{},
				DKIMDomains: map[string]int{},
				SPFDomains:  map[string]int{},
				Reporters:   map[string]int{},
			}
			byIP[record.Row.SourceIp] = source
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
		case "none", "pass":
			summary.PassedMessages += count
			source.PassedMessages += count
		}
		if record.Row.PolicyEvaluated.Dkim == "pass" {
			summary.DKIMPassMessages += count
		} else if record.Row.PolicyEvaluated.Dkim == "fail" {
			summary.DKIMFailMessages += count
			source.DKIMFailMessages += count
		}
		if record.Row.PolicyEvaluated.Spf == "pass" {
			summary.SPFPassMessages += count
		} else if record.Row.PolicyEvaluated.Spf == "fail" {
			summary.SPFFailMessages += count
			source.SPFFailMessages += count
		}
		for _, dkim := range record.AuthResults.Dkim {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.Spf != nil && record.AuthResults.Spf.Domain != "" {
			source.SPFDomains[record.AuthResults.Spf.Domain] += count
		}
	}

	for _, source := range byIP {
		summary.BySourceIP = append(summary.BySourceIP, *source)
	}
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
func (r DmarcReport) UnauthenticatedSources(domain string) []SuspiciousSource {
	return r.unauthenticatedSources(domain, "")
}

// RejectedUnauthenticatedSources returns unauthenticated sources whose reported
// disposition was reject.
func (r DmarcReport) RejectedUnauthenticatedSources(domain string) []SuspiciousSource {
	return r.unauthenticatedSources(domain, "reject")
}

// PassingSources returns source IPs that used domain in header_from and passed
// at least one DMARC alignment mechanism.
func (r DmarcReport) PassingSources(domain string) []SourceSummary {
	byIP := map[string]*SourceSummary{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, record := range r.Record {
		if domain != "" && strings.ToLower(record.Identifiers.HeaderFrom) != domain {
			continue
		}
		if record.Row.PolicyEvaluated.Dkim != "pass" && record.Row.PolicyEvaluated.Spf != "pass" {
			continue
		}
		count := parseCount(record.Row.Count)
		source := byIP[record.Row.SourceIp]
		if source == nil {
			source = &SourceSummary{SourceIP: record.Row.SourceIp, HeaderFrom: map[string]int{}, DKIMDomains: map[string]int{}, SPFDomains: map[string]int{}, Reporters: map[string]int{}}
			byIP[record.Row.SourceIp] = source
		}
		source.Records++
		source.Messages += count
		source.PassedMessages += count
		source.HeaderFrom[record.Identifiers.HeaderFrom] += count
		for _, dkim := range record.AuthResults.Dkim {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.Spf != nil && record.AuthResults.Spf.Domain != "" {
			source.SPFDomains[record.AuthResults.Spf.Domain] += count
		}
	}
	out := make([]SourceSummary, 0, len(byIP))
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

// SuspiciousSources returns source IPs that used domain in header_from while both
// DMARC DKIM and SPF alignment failed. Prefer UnauthenticatedSources for new code.
func (r DmarcReport) SuspiciousSources(domain string) []SuspiciousSource {
	return r.UnauthenticatedSources(domain)
}

func (r DmarcReport) unauthenticatedSources(domain, disposition string) []SuspiciousSource {
	byIP := map[string]*SuspiciousSource{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, record := range r.Record {
		if domain != "" && strings.ToLower(record.Identifiers.HeaderFrom) != domain {
			continue
		}
		if disposition != "" && record.Row.PolicyEvaluated.Disposition != disposition {
			continue
		}
		if record.Row.PolicyEvaluated.Dkim != "fail" || record.Row.PolicyEvaluated.Spf != "fail" {
			continue
		}

		count := parseCount(record.Row.Count)
		source := byIP[record.Row.SourceIp]
		if source == nil {
			source = &SuspiciousSource{SourceIP: record.Row.SourceIp, HeaderFrom: map[string]int{}, SPFDomains: map[string]int{}, DKIMDomains: map[string]int{}}
			byIP[record.Row.SourceIp] = source
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
		for _, dkim := range record.AuthResults.Dkim {
			if dkim.Domain != "" {
				source.DKIMDomains[dkim.Domain] += count
			}
		}
		if record.AuthResults.Spf != nil && record.AuthResults.Spf.Domain != "" {
			source.SPFDomains[record.AuthResults.Spf.Domain] += count
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
	if err != nil {
		return 0
	}
	return count
}

func epochStringToTime(raw string) (time.Time, error) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0).UTC(), nil
}
