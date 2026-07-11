package dmarcgo

import (
	"fmt"
	"net/netip"
	"strings"
)

// AnonymizeOptions controls deterministic report anonymization.
type AnonymizeOptions struct {
	PolicyDomain       string
	ReportingOrg       string
	ReportEmail        string
	ReportID           string
	PreserveExtensions bool
}

// AnonymizeReport returns a copy of report with domains, source IPs, reporter
// identity, contact metadata, and report ID replaced by deterministic
// documentation-safe values. Counts, dispositions, date ranges, and
// authentication pass/fail shape are preserved. Raw extension XML is removed by
// default because extensions can contain provider-specific or sensitive data;
// set PreserveExtensions only after reviewing the source report.
func AnonymizeReport(report AggregateReport, options AnonymizeOptions) AggregateReport {
	if options.PolicyDomain == "" {
		options.PolicyDomain = "example.com"
	}
	if options.ReportingOrg == "" {
		options.ReportingOrg = "Example Reporter"
	}
	if options.ReportEmail == "" {
		options.ReportEmail = "dmarc@example.net"
	}
	if options.ReportID == "" {
		options.ReportID = "example-report-id"
	}

	out := report
	out.ReportMetadata.OrgName = options.ReportingOrg
	out.ReportMetadata.Email = options.ReportEmail
	out.ReportMetadata.ReportID = options.ReportID
	out.ReportMetadata.ExtraContactInfo = LangString{}
	out.ReportMetadata.Error = LangString{}
	out.PolicyPublished.Domain = options.PolicyDomain
	out.Extension.Elements = nil
	if options.PreserveExtensions {
		out.Extension.Elements = copyRawElements(report.Extension.Elements)
	}
	out.Record = make([]Record, len(report.Record))

	domains := map[string]string{}
	ips := map[string]string{}
	nextDomain := 1
	nextIPv4 := 1
	nextIPv6 := 1
	mapDomain := func(domain string) string {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return ""
		}
		if strings.EqualFold(domain, report.PolicyPublished.Domain) {
			return options.PolicyDomain
		}
		if mapped, ok := domains[strings.ToLower(domain)]; ok {
			return mapped
		}
		mapped := fmt.Sprintf("domain-%d.example.net", nextDomain)
		nextDomain++
		domains[strings.ToLower(domain)] = mapped
		return mapped
	}
	mapIP := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return ""
		}
		if mapped, ok := ips[raw]; ok {
			return mapped
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return "192.0.2.254"
		}
		var mapped string
		if addr.Is6() {
			mapped = fmt.Sprintf("2001:db8::%x", nextIPv6)
			nextIPv6++
		} else {
			mapped = fmt.Sprintf("192.0.2.%d", nextIPv4)
			nextIPv4++
		}
		ips[raw] = mapped
		return mapped
	}

	for i, record := range report.Record {
		copied := record
		copied.Row.SourceIP = mapIP(record.Row.SourceIP)
		copied.Row.PolicyEvaluated.Reasons = append([]PolicyOverrideReason(nil), record.Row.PolicyEvaluated.Reasons...)
		copied.Identifiers.HeaderFrom = mapDomain(record.Identifiers.HeaderFrom)
		copied.Identifiers.EnvelopeFrom = mapDomain(record.Identifiers.EnvelopeFrom)
		copied.Identifiers.EnvelopeTo = mapDomain(record.Identifiers.EnvelopeTo)
		copied.AuthResults.DKIM = append([]DKIMAuthResult(nil), record.AuthResults.DKIM...)
		for j := range copied.AuthResults.DKIM {
			copied.AuthResults.DKIM[j].Domain = mapDomain(copied.AuthResults.DKIM[j].Domain)
		}
		if record.AuthResults.SPF != nil {
			spf := *record.AuthResults.SPF
			spf.Domain = mapDomain(spf.Domain)
			copied.AuthResults.SPF = &spf
		}
		copied.Extensions = nil
		if options.PreserveExtensions {
			copied.Extensions = copyRawElements(record.Extensions)
		}
		out.Record[i] = copied
	}
	return out
}

func copyRawElements(elements []RawElement) []RawElement {
	if len(elements) == 0 {
		return nil
	}
	return append([]RawElement(nil), elements...)
}
