package dmarcgo

import (
	"encoding/csv"
	"io"
	"strconv"
)

type featureColumn struct {
	Header string
	Value  func(DmarcReportFeatures) string
}

var featureColumns = []featureColumn{
	{"reporting_org", func(f DmarcReportFeatures) string { return f.ReportingOrg }},
	{"reporting_addr", func(f DmarcReportFeatures) string { return f.ReportingEmail }},
	{"report_id", func(f DmarcReportFeatures) string { return f.ReportID }},
	{"begin_date", func(f DmarcReportFeatures) string { return f.BeginDate }},
	{"end_date", func(f DmarcReportFeatures) string { return f.EndDate }},
	{"target_domain", func(f DmarcReportFeatures) string { return f.TargetDomain }},
	{"requested_handling_policy", func(f DmarcReportFeatures) string { return f.RequestedHandlingPolicy }},
	{"subdomain_policy_published", func(f DmarcReportFeatures) string { return f.SubdomainPolicyPublished }},
	{"nonexistent_subdomain_policy", func(f DmarcReportFeatures) string { return f.NonexistentSubdomainPolicy }},
	{"source_ip", func(f DmarcReportFeatures) string { return f.SrcIp }},
	{"mail_count", func(f DmarcReportFeatures) string { return strconv.Itoa(f.MailCount) }},
	{"vendor_action", func(f DmarcReportFeatures) string { return f.VendorAction }},
	{"dkim_policy_evaluated", func(f DmarcReportFeatures) string { return f.DkimPolicyEvaluated }},
	{"spf_policy_evaluated", func(f DmarcReportFeatures) string { return f.SpfPolicyEvaluated }},
	{"header_from", func(f DmarcReportFeatures) string { return f.HeaderFrom }},
	{"envelope_from", func(f DmarcReportFeatures) string { return f.EnvelopeFrom }},
	{"envelope_to", func(f DmarcReportFeatures) string { return f.EnvelopeTo }},
	{"dkim_domain", func(f DmarcReportFeatures) string { return f.DkimDomain }},
	{"dkim_selector", func(f DmarcReportFeatures) string { return f.DkimSelector }},
	{"dkim_result", func(f DmarcReportFeatures) string { return f.DkimResult }},
	{"spf_domain", func(f DmarcReportFeatures) string { return f.SpfDomain }},
	{"spf_scope", func(f DmarcReportFeatures) string { return f.SpfScope }},
	{"spf_result", func(f DmarcReportFeatures) string { return f.SpfResult }},
}

// FeatureCSVHeaders returns the CSV headers used by WriteFeaturesCSV.
func FeatureCSVHeaders() []string {
	headers := make([]string, 0, len(featureColumns))
	for _, column := range featureColumns {
		headers = append(headers, column.Header)
	}
	return headers
}

// WriteFeaturesCSV writes flattened feature rows as CSV with a header row.
func WriteFeaturesCSV(writer io.Writer, features []DmarcReportFeatures) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(FeatureCSVHeaders()); err != nil {
		return err
	}
	for _, feature := range features {
		row := make([]string, 0, len(featureColumns))
		for _, column := range featureColumns {
			row = append(row, column.Value(feature))
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}
