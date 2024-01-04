package dmarcgo

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"utilities"
)

// DMARC Report
// https://dmarc.org/dmarc-xml/0.1/
type DmarcReport struct {
	XMLName        xml.Name `xml:"feedback"`
	Text           string   `xml:",chardata"`
	ReportMetadata struct {
		Text    string `xml:",chardata"`
		OrgName string `xml:"org_name"`
		Email   string `xml:"email"`
		// ExtraContactInfo string `xml:"extra_contact_info"`
		ReportID  string `xml:"report_id"`
		DateRange struct {
			Text  string `xml:",chardata"`
			Begin string `xml:"begin"`
			End   string `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	PolicyPublished struct {
		Text   string `xml:",chardata"`
		Domain string `xml:"domain"`
		Adkim  string `xml:"adkim"`
		Aspf   string `xml:"aspf"`
		P      string `xml:"p"`
		Sp     string `xml:"sp"`
		Pct    string `xml:"pct"`
		Fo     string `xml:"fo"`
	} `xml:"policy_published"`
	Record []struct {
		Text string `xml:",chardata"`
		Row  struct {
			Text            string `xml:",chardata"`
			SourceIp        string `xml:"source_ip"`
			Count           string `xml:"count"`
			PolicyEvaluated struct {
				Text        string `xml:",chardata"`
				Disposition string `xml:"disposition"`
				Dkim        string `xml:"dkim"`
				Spf         string `xml:"spf"`
				Reason      struct {
					Text    string `xml:",chardata"`
					Type    string `xml:"type"`
					Comment string `xml:"comment"`
				} `xml:"reason"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		Identifiers struct {
			Text       string `xml:",chardata"`
			HeaderFrom string `xml:"header_from"`
		} `xml:"identifiers"`
		AuthResults struct {
			Text string `xml:",chardata"`
			Spf  struct {
				Text   string `xml:",chardata"`
				Domain string `xml:"domain"`
				Result string `xml:"result"`
			} `xml:"spf"`
			Dkim struct {
				Text        string `xml:",chardata"`
				Domain      string `xml:"domain"`
				Result      string `xml:"result"`
				HumanResult string `xml:"human_result"`
			} `xml:"dkim"`
		} `xml:"auth_results"`
	} `xml:"record"`
}

type DmarcReportFeatures struct {
	ReportingOrg   string `json:"reporting_org"`
	ReportingEmail string `json:"reporting_addr"`
	// ExtraContactInfo           string `json:"extra_contact_info",`
	ReportID                string `json:"report_id"`
	BeginDate               string `json:"beginDate"`
	EndDate                 string `json:"endDate"`
	TargetDomain            string `json:"target_domain"`
	SpfPolicyPublished      string `json:"spf_policy_published"`
	DkimPolicyPublished     string `json:"dkim_policy_published"`
	RequestedHandlingPolicy string `json:"requested_handling_policy"`
	SamplingPercentage      string `json:"sampling_percentage"`
	FailureReportingOptions string `json:"failure_reporting_options,omitempty"`
	SrcIp                   string `json:"src_ip"`
	MailCount               int    `json:"mail_count"`
	VendorAction            string `json:"vendor_action"`
	DkimPolicyEvaluated     string `json:"dkim_policy_evaluated"`
	SpfPolicyEvaluated      string `json:"spf_policy_evaluated"`
	Type                    string `json:"type,omitempty"`
	Comment                 string `json:"comment,omitempty"`
	HeaderFrom              string `json:"header_from,omitempty"`
	DkimDomain              string `json:"dkim_domain,omitempty"`
	DkimResult              string `json:"dkim_result,omitempty"`
	DkimHumanResult         string `json:"dkim_human_result,omitempty"`
	SpfDomain               string `json:"spf_domain,omitempty"`
	SpfResult               string `json:"spf_result,omitempty"`
}

func (r DmarcReport) Features() []DmarcReportFeatures {

	var returnFeatures []DmarcReportFeatures
	var baseReport DmarcReportFeatures

	baseReport.ReportID = r.ReportMetadata.ReportID
	baseReport.ReportingOrg = r.ReportMetadata.OrgName
	baseReport.ReportingEmail = r.ReportMetadata.Email
	// baseReport.ExtraContactInfo = r.ReportMetadata.Text
	baseReport.BeginDate = r.ReportMetadata.DateRange.Begin
	baseReport.EndDate = r.ReportMetadata.DateRange.End
	baseReport.TargetDomain = r.PolicyPublished.Domain
	baseReport.SpfPolicyPublished = r.PolicyPublished.Aspf
	baseReport.DkimPolicyPublished = r.PolicyPublished.Adkim
	baseReport.RequestedHandlingPolicy = r.PolicyPublished.P
	baseReport.SamplingPercentage = r.PolicyPublished.Pct
	baseReport.FailureReportingOptions = r.PolicyPublished.Fo

	returnFeatures = append(returnFeatures, baseReport)
	for _, record := range r.Record {
		tempReport := baseReport
		tempReport.SrcIp = record.Row.SourceIp
		tempReport.MailCount, _ = strconv.Atoi(record.Row.Count)
		tempReport.VendorAction = record.Row.PolicyEvaluated.Disposition
		tempReport.DkimPolicyEvaluated = record.Row.PolicyEvaluated.Dkim
		tempReport.SpfPolicyEvaluated = record.Row.PolicyEvaluated.Spf
		tempReport.Type = record.Row.PolicyEvaluated.Reason.Type
		tempReport.Comment = record.Row.PolicyEvaluated.Reason.Comment
		tempReport.HeaderFrom = record.Identifiers.HeaderFrom
		tempReport.DkimDomain = record.AuthResults.Dkim.Domain
		tempReport.DkimResult = record.AuthResults.Dkim.Result
		tempReport.DkimHumanResult = record.AuthResults.Dkim.HumanResult
		tempReport.SpfDomain = record.AuthResults.Spf.Domain
		tempReport.SpfResult = record.AuthResults.Spf.Result

		returnFeatures = append(returnFeatures, tempReport)
	}

	return returnFeatures
}

// Dmarc File Object
type Report struct {
	FilePath string
	Content  DmarcReport
}

// Load the DMARC report file contents from gzip file
func (r *Report) LoadReportFile() error {
	tryZlib := false
	tryZip := false

	s, err := utilities.ReadGZ(r.FilePath)
	if err != nil {
		tryZip = true
	} else {
		xml.Unmarshal(s, &r.Content)
		return nil
	}

	if tryZip {
		s, err := utilities.ReadZip(r.FilePath)
		if err != nil {
			tryZlib = true

		} else {
			xml.Unmarshal(s, &r.Content)
			return nil
		}
	}

	if tryZlib {
		s, err := utilities.ReadZZ(r.FilePath)
		if err != nil {
			return fmt.Errorf("failed to read file:%+v", r.FilePath)
		} else {
			xml.Unmarshal(s, &r.Content)
			return nil
		}
	}

	return nil
}
