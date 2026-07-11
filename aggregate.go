package dmarcgo

import "sort"

// AggregateSummary combines summary counts across many reports.
type AggregateSummary struct {
	Reports             int             `json:"reports"`
	TotalRecords        int             `json:"total_records"`
	TotalMessages       int             `json:"total_messages"`
	PassedMessages      int             `json:"passed_messages"`
	RejectedMessages    int             `json:"rejected_messages"`
	QuarantinedMessages int             `json:"quarantined_messages"`
	DKIMPassMessages    int             `json:"dkim_pass_messages"`
	DKIMFailMessages    int             `json:"dkim_fail_messages"`
	SPFPassMessages     int             `json:"spf_pass_messages"`
	SPFFailMessages     int             `json:"spf_fail_messages"`
	ByReporter          map[string]int  `json:"by_reporter,omitempty"`
	ByTargetDomain      map[string]int  `json:"by_target_domain,omitempty"`
	ByDisposition       map[string]int  `json:"by_disposition,omitempty"`
	ByHeaderFrom        map[string]int  `json:"by_header_from,omitempty"`
	BySourceIP          []SourceSummary `json:"by_source_ip,omitempty"`
}

// SummarizeReports combines message counts across parsed AggregateReport values. Nil
// reports are skipped.
func SummarizeReports(reports []*AggregateReport) AggregateSummary {
	summaries := make([]ReportSummary, 0, len(reports))
	for _, report := range reports {
		if report == nil {
			continue
		}
		summaries = append(summaries, report.Summary())
	}
	return MergeSummaries(summaries)
}

// MergeSummaries combines per-report summaries into one aggregate summary.
func MergeSummaries(summaries []ReportSummary) AggregateSummary {
	agg := AggregateSummary{
		ByReporter:     map[string]int{},
		ByTargetDomain: map[string]int{},
		ByDisposition:  map[string]int{},
		ByHeaderFrom:   map[string]int{},
	}
	byIP := map[string]*SourceSummary{}
	for _, summary := range summaries {
		agg.Reports++
		agg.TotalRecords += summary.TotalRecords
		agg.TotalMessages += summary.TotalMessages
		agg.PassedMessages += summary.PassedMessages
		agg.RejectedMessages += summary.RejectedMessages
		agg.QuarantinedMessages += summary.QuarantinedMessages
		agg.DKIMPassMessages += summary.DKIMPassMessages
		agg.DKIMFailMessages += summary.DKIMFailMessages
		agg.SPFPassMessages += summary.SPFPassMessages
		agg.SPFFailMessages += summary.SPFFailMessages
		if summary.ReportingOrg != "" {
			agg.ByReporter[summary.ReportingOrg] += summary.TotalMessages
		}
		if summary.TargetDomain != "" {
			agg.ByTargetDomain[summary.TargetDomain] += summary.TotalMessages
		}
		mergeCounts(agg.ByDisposition, summary.ByDisposition)
		mergeCounts(agg.ByHeaderFrom, summary.ByHeaderFrom)
		for _, source := range summary.BySourceIP {
			target := byIP[source.SourceIP]
			if target == nil {
				copySource := SourceSummary{SourceIP: source.SourceIP, HeaderFrom: map[string]int{}, DKIMDomains: map[string]int{}, SPFDomains: map[string]int{}, Reporters: map[string]int{}}
				target = &copySource
				byIP[source.SourceIP] = target
			}
			target.Records += source.Records
			target.Messages += source.Messages
			target.RejectedMessages += source.RejectedMessages
			target.PassedMessages += source.PassedMessages
			target.DKIMFailMessages += source.DKIMFailMessages
			target.SPFFailMessages += source.SPFFailMessages
			mergeCounts(target.HeaderFrom, source.HeaderFrom)
			mergeCounts(target.DKIMDomains, source.DKIMDomains)
			mergeCounts(target.SPFDomains, source.SPFDomains)
			mergeCounts(target.Reporters, source.Reporters)
		}
	}
	for _, source := range byIP {
		agg.BySourceIP = append(agg.BySourceIP, *source)
	}
	sort.Slice(agg.BySourceIP, func(i, j int) bool {
		if agg.BySourceIP[i].Messages == agg.BySourceIP[j].Messages {
			return agg.BySourceIP[i].SourceIP < agg.BySourceIP[j].SourceIP
		}
		return agg.BySourceIP[i].Messages > agg.BySourceIP[j].Messages
	})
	return agg
}

func mergeCounts(target, source map[string]int) {
	for key, value := range source {
		target[key] += value
	}
}
