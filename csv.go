package dmarcgo

import (
	"encoding/csv"
	"io"
	"strconv"
)

type featureColumn struct {
	Header string
	Value  func(FeatureRow) string
}

var featureColumns = []featureColumn{
	{"reporting_org", func(f FeatureRow) string { return f.ReportingOrg }},
	{"reporting_addr", func(f FeatureRow) string { return f.ReportingEmail }},
	{"report_id", func(f FeatureRow) string { return f.ReportID }},
	{"begin_date", func(f FeatureRow) string { return f.BeginDate }},
	{"end_date", func(f FeatureRow) string { return f.EndDate }},
	{"target_domain", func(f FeatureRow) string { return f.TargetDomain }},
	{"requested_handling_policy", func(f FeatureRow) string { return f.RequestedHandlingPolicy }},
	{"subdomain_policy_published", func(f FeatureRow) string { return f.SubdomainPolicyPublished }},
	{"nonexistent_subdomain_policy", func(f FeatureRow) string { return f.NonexistentSubdomainPolicy }},
	{"source_ip", func(f FeatureRow) string { return f.SourceIP }},
	{"mail_count", func(f FeatureRow) string { return strconv.Itoa(f.MailCount) }},
	{"vendor_action", func(f FeatureRow) string { return f.VendorAction }},
	{"dkim_policy_evaluated", func(f FeatureRow) string { return f.DKIMPolicyEvaluated }},
	{"spf_policy_evaluated", func(f FeatureRow) string { return f.SPFPolicyEvaluated }},
	{"header_from", func(f FeatureRow) string { return f.HeaderFrom }},
	{"envelope_from", func(f FeatureRow) string { return f.EnvelopeFrom }},
	{"envelope_to", func(f FeatureRow) string { return f.EnvelopeTo }},
	{"dkim_domain", func(f FeatureRow) string { return f.DKIMDomain }},
	{"dkim_selector", func(f FeatureRow) string { return f.DKIMSelector }},
	{"dkim_result", func(f FeatureRow) string { return f.DKIMResult }},
	{"spf_domain", func(f FeatureRow) string { return f.SPFDomain }},
	{"spf_scope", func(f FeatureRow) string { return f.SPFScope }},
	{"spf_result", func(f FeatureRow) string { return f.SPFResult }},
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
func WriteFeaturesCSV(writer io.Writer, features []FeatureRow) error {
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
