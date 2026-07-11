package dmarcgo

import (
	"encoding/csv"
	"io"
	"strconv"
)

var featureCSVHeader = []string{
	"reporting_org",
	"reporting_addr",
	"report_id",
	"begin_date",
	"end_date",
	"target_domain",
	"requested_handling_policy",
	"subdomain_policy_published",
	"nonexistent_subdomain_policy",
	"source_ip",
	"mail_count",
	"vendor_action",
	"dkim_policy_evaluated",
	"spf_policy_evaluated",
	"header_from",
	"envelope_from",
	"envelope_to",
	"dkim_domain",
	"dkim_selector",
	"dkim_result",
	"spf_domain",
	"spf_scope",
	"spf_result",
}

// WriteFeaturesCSV writes flattened feature rows as CSV with a header row.
func WriteFeaturesCSV(writer io.Writer, features []DmarcReportFeatures) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(featureCSVHeader); err != nil {
		return err
	}
	for _, feature := range features {
		if err := csvWriter.Write([]string{
			feature.ReportingOrg,
			feature.ReportingEmail,
			feature.ReportID,
			feature.BeginDate,
			feature.EndDate,
			feature.TargetDomain,
			feature.RequestedHandlingPolicy,
			feature.SubdomainPolicyPublished,
			feature.NonexistentSubdomainPolicy,
			feature.SrcIp,
			strconv.Itoa(feature.MailCount),
			feature.VendorAction,
			feature.DkimPolicyEvaluated,
			feature.SpfPolicyEvaluated,
			feature.HeaderFrom,
			feature.EnvelopeFrom,
			feature.EnvelopeTo,
			feature.DkimDomain,
			feature.DkimSelector,
			feature.DkimResult,
			feature.SpfDomain,
			feature.SpfScope,
			feature.SpfResult,
		}); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}
