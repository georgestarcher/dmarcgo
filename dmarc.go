package dmarcgo

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/georgestarcher/dmarcgo/utilities"
)

// Known DMARC aggregate report XML namespaces.
const (
	LegacyDMARCNamespace = "http://dmarc.org/dmarc-xml/0.1"
	RFC9990Namespace     = "urn:ietf:params:xml:ns:dmarc-2.0"
)

// InvalidMailCount is used when a DMARC row has a non-numeric or malformed <count>.
const InvalidMailCount = -1

var ErrNoFilePath = errors.New("report file path is empty")

// DmarcReport is a DMARC aggregate feedback report.
//
// The model accepts legacy aggregate reports as well as RFC 9990 reports. Unknown
// extension elements are retained as raw XML rather than interpreted.
type DmarcReport struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Extension       Extension       `xml:"extension"`
	Record          []Record        `xml:"record"`
}

// ReportMetadata describes the organization that generated the report.
type ReportMetadata struct {
	OrgName          string     `xml:"org_name" json:"org_name"`
	Email            string     `xml:"email" json:"email"`
	ExtraContactInfo LangString `xml:"extra_contact_info" json:"extra_contact_info,omitempty"`
	ReportID         string     `xml:"report_id" json:"report_id"`
	DateRange        DateRange  `xml:"date_range" json:"date_range"`
	Error            LangString `xml:"error" json:"error,omitempty"`
	Generator        string     `xml:"generator" json:"generator,omitempty"`
}

// LangString is a string value with the optional RFC 9990 lang attribute.
type LangString struct {
	Lang  string `xml:"lang,attr" json:"lang,omitempty"`
	Value string `xml:",chardata" json:"value,omitempty"`
}

// DateRange is the UTC reporting period, represented as epoch seconds in XML.
type DateRange struct {
	Begin string `xml:"begin" json:"begin"`
	End   string `xml:"end" json:"end"`
}

// PolicyPublished is the discovered DMARC policy applied by the reporter.
type PolicyPublished struct {
	Domain          string `xml:"domain" json:"domain"`
	Adkim           string `xml:"adkim" json:"adkim,omitempty"`
	Aspf            string `xml:"aspf" json:"aspf,omitempty"`
	P               string `xml:"p" json:"p"`
	Sp              string `xml:"sp" json:"sp,omitempty"`
	Np              string `xml:"np" json:"np,omitempty"`
	Pct             string `xml:"pct" json:"pct,omitempty"`
	Fo              string `xml:"fo" json:"fo,omitempty"`
	DiscoveryMethod string `xml:"discovery_method" json:"discovery_method,omitempty"`
	Testing         string `xml:"testing" json:"testing,omitempty"`
}

// Extension stores unrecognized namespaced extension elements.
type Extension struct {
	Elements []RawElement `xml:",any" json:"elements,omitempty"`
}

// RawElement preserves extension XML without assigning semantic meaning to it.
type RawElement struct {
	XMLName  xml.Name `json:"xml_name"`
	InnerXML string   `xml:",innerxml" json:"inner_xml,omitempty"`
}

// Record is one aggregate report tuple for a source IP and authentication result set.
type Record struct {
	Row         Row          `xml:"row" json:"row"`
	Identifiers Identifiers  `xml:"identifiers" json:"identifiers"`
	AuthResults AuthResults  `xml:"auth_results" json:"auth_results"`
	Extensions  []RawElement `xml:",any" json:"extensions,omitempty"`
}

// Row contains the reported source and DMARC policy evaluation.
type Row struct {
	SourceIp        string          `xml:"source_ip" json:"source_ip"`
	Count           string          `xml:"count" json:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated" json:"policy_evaluated"`
}

// PolicyEvaluated contains the final DMARC disposition and alignment outcomes.
type PolicyEvaluated struct {
	Disposition string                 `xml:"disposition" json:"disposition"`
	Dkim        string                 `xml:"dkim" json:"dkim"`
	Spf         string                 `xml:"spf" json:"spf"`
	Reasons     []PolicyOverrideReason `xml:"reason" json:"reasons,omitempty"`
}

// PolicyOverrideReason describes why the applied disposition differed from policy.
type PolicyOverrideReason struct {
	Type    string     `xml:"type" json:"type"`
	Comment LangString `xml:"comment" json:"comment,omitempty"`
}

// Identifiers contains the message identifiers used for policy evaluation.
type Identifiers struct {
	HeaderFrom   string `xml:"header_from" json:"header_from"`
	EnvelopeFrom string `xml:"envelope_from" json:"envelope_from,omitempty"`
	EnvelopeTo   string `xml:"envelope_to" json:"envelope_to,omitempty"`
}

// AuthResults contains uninterpreted DKIM and SPF authentication results.
type AuthResults struct {
	Dkim []DKIMAuthResult `xml:"dkim" json:"dkim,omitempty"`
	Spf  *SPFAuthResult   `xml:"spf" json:"spf,omitempty"`
}

// DKIMAuthResult is one DKIM authentication result from auth_results.
type DKIMAuthResult struct {
	Domain      string     `xml:"domain" json:"domain"`
	Selector    string     `xml:"selector" json:"selector,omitempty"`
	Result      string     `xml:"result" json:"result"`
	HumanResult LangString `xml:"human_result" json:"human_result,omitempty"`
}

// SPFAuthResult is the SPF authentication result from auth_results.
type SPFAuthResult struct {
	Domain      string     `xml:"domain" json:"domain"`
	Scope       string     `xml:"scope" json:"scope,omitempty"`
	Result      string     `xml:"result" json:"result"`
	HumanResult LangString `xml:"human_result" json:"human_result,omitempty"`
}

// DmarcReportFeatures is a flattened representation of report and record data.
type DmarcReportFeatures struct {
	ReportingOrg               string                 `json:"reporting_org"`
	ReportingEmail             string                 `json:"reporting_addr"`
	ExtraContactInfo           string                 `json:"extra_contact_info,omitempty"`
	ExtraContactInfoLang       string                 `json:"extra_contact_info_lang,omitempty"`
	ReportID                   string                 `json:"report_id"`
	ReportVersion              string                 `json:"report_version,omitempty"`
	ReportError                string                 `json:"report_error,omitempty"`
	ReportErrorLang            string                 `json:"report_error_lang,omitempty"`
	ReportGenerator            string                 `json:"report_generator,omitempty"`
	BeginDate                  string                 `json:"beginDate"`
	EndDate                    string                 `json:"endDate"`
	TargetDomain               string                 `json:"target_domain"`
	SpfPolicyPublished         string                 `json:"spf_policy_published"`
	DkimPolicyPublished        string                 `json:"dkim_policy_published"`
	RequestedHandlingPolicy    string                 `json:"requested_handling_policy"`
	SubdomainPolicyPublished   string                 `json:"subdomain_policy_published,omitempty"`
	NonexistentSubdomainPolicy string                 `json:"nonexistent_subdomain_policy,omitempty"`
	SamplingPercentage         string                 `json:"sampling_percentage,omitempty"`
	FailureReportingOptions    string                 `json:"failure_reporting_options,omitempty"`
	PolicyDiscoveryMethod      string                 `json:"policy_discovery_method,omitempty"`
	Testing                    string                 `json:"testing,omitempty"`
	SrcIp                      string                 `json:"src_ip,omitempty"`
	MailCount                  int                    `json:"mail_count"`
	VendorAction               string                 `json:"vendor_action,omitempty"`
	DkimPolicyEvaluated        string                 `json:"dkim_policy_evaluated,omitempty"`
	SpfPolicyEvaluated         string                 `json:"spf_policy_evaluated,omitempty"`
	Type                       string                 `json:"type,omitempty"`
	Comment                    string                 `json:"comment,omitempty"`
	HeaderFrom                 string                 `json:"header_from,omitempty"`
	EnvelopeFrom               string                 `json:"envelope_from,omitempty"`
	EnvelopeTo                 string                 `json:"envelope_to,omitempty"`
	DkimDomain                 string                 `json:"dkim_domain,omitempty"`
	DkimSelector               string                 `json:"dkim_selector,omitempty"`
	DkimResult                 string                 `json:"dkim_result,omitempty"`
	DkimHumanResult            string                 `json:"dkim_human_result,omitempty"`
	SpfDomain                  string                 `json:"spf_domain,omitempty"`
	SpfScope                   string                 `json:"spf_scope,omitempty"`
	SpfResult                  string                 `json:"spf_result,omitempty"`
	SpfHumanResult             string                 `json:"spf_human_result,omitempty"`
	DkimAuthResults            []DKIMAuthResult       `json:"dkim_auth_results,omitempty"`
	SpfAuthResult              *SPFAuthResult         `json:"spf_auth_result,omitempty"`
	PolicyOverrideReasons      []PolicyOverrideReason `json:"policy_override_reasons,omitempty"`
	ExtensionCount             int                    `json:"extension_count,omitempty"`
}

// Features returns flattened report rows.
//
// The first returned element contains report-level metadata. Subsequent elements
// contain one item per record, combining report-level fields with row-level data.
func (r DmarcReport) Features() []DmarcReportFeatures {
	returnFeatures := make([]DmarcReportFeatures, 0, len(r.Record)+1)

	baseReport := DmarcReportFeatures{
		ReportID:                   r.ReportMetadata.ReportID,
		ReportVersion:              r.Version,
		ReportingOrg:               r.ReportMetadata.OrgName,
		ReportingEmail:             r.ReportMetadata.Email,
		ExtraContactInfo:           r.ReportMetadata.ExtraContactInfo.Value,
		ExtraContactInfoLang:       r.ReportMetadata.ExtraContactInfo.Lang,
		ReportError:                r.ReportMetadata.Error.Value,
		ReportErrorLang:            r.ReportMetadata.Error.Lang,
		ReportGenerator:            r.ReportMetadata.Generator,
		BeginDate:                  r.ReportMetadata.DateRange.Begin,
		EndDate:                    r.ReportMetadata.DateRange.End,
		TargetDomain:               r.PolicyPublished.Domain,
		SpfPolicyPublished:         r.PolicyPublished.Aspf,
		DkimPolicyPublished:        r.PolicyPublished.Adkim,
		RequestedHandlingPolicy:    r.PolicyPublished.P,
		SubdomainPolicyPublished:   r.PolicyPublished.Sp,
		NonexistentSubdomainPolicy: r.PolicyPublished.Np,
		SamplingPercentage:         r.PolicyPublished.Pct,
		FailureReportingOptions:    r.PolicyPublished.Fo,
		PolicyDiscoveryMethod:      r.PolicyPublished.DiscoveryMethod,
		Testing:                    r.PolicyPublished.Testing,
		ExtensionCount:             len(r.Extension.Elements),
	}

	returnFeatures = append(returnFeatures, baseReport)
	for _, record := range r.Record {
		tempReport := baseReport
		tempReport.SrcIp = record.Row.SourceIp
		countString := strings.TrimSpace(record.Row.Count)
		if mailCount, err := strconv.Atoi(countString); err == nil {
			tempReport.MailCount = mailCount
		} else {
			tempReport.MailCount = InvalidMailCount
		}
		tempReport.VendorAction = record.Row.PolicyEvaluated.Disposition
		tempReport.DkimPolicyEvaluated = record.Row.PolicyEvaluated.Dkim
		tempReport.SpfPolicyEvaluated = record.Row.PolicyEvaluated.Spf
		tempReport.PolicyOverrideReasons = record.Row.PolicyEvaluated.Reasons
		if len(record.Row.PolicyEvaluated.Reasons) > 0 {
			tempReport.Type = record.Row.PolicyEvaluated.Reasons[0].Type
			tempReport.Comment = record.Row.PolicyEvaluated.Reasons[0].Comment.Value
		}
		tempReport.HeaderFrom = record.Identifiers.HeaderFrom
		tempReport.EnvelopeFrom = record.Identifiers.EnvelopeFrom
		tempReport.EnvelopeTo = record.Identifiers.EnvelopeTo
		tempReport.DkimAuthResults = record.AuthResults.Dkim
		if len(record.AuthResults.Dkim) > 0 {
			tempReport.DkimDomain = record.AuthResults.Dkim[0].Domain
			tempReport.DkimSelector = record.AuthResults.Dkim[0].Selector
			tempReport.DkimResult = record.AuthResults.Dkim[0].Result
			tempReport.DkimHumanResult = record.AuthResults.Dkim[0].HumanResult.Value
		}
		tempReport.SpfAuthResult = record.AuthResults.Spf
		if record.AuthResults.Spf != nil {
			tempReport.SpfDomain = record.AuthResults.Spf.Domain
			tempReport.SpfScope = record.AuthResults.Spf.Scope
			tempReport.SpfResult = record.AuthResults.Spf.Result
			tempReport.SpfHumanResult = record.AuthResults.Spf.HumanResult.Value
		}
		tempReport.ExtensionCount += len(record.Extensions)

		returnFeatures = append(returnFeatures, tempReport)
	}

	return returnFeatures
}

// Report is a loadable DMARC aggregate report file.
type Report struct {
	FilePath string
	Content  DmarcReport
	// MaxDecompressedBytes limits decompressed archive payload size. If zero,
	// utilities.DefaultMaxDecompressedBytes is used.
	MaxDecompressedBytes int64
}

// LoadReportFile parses the configured report file as gzip, zip, then zlib.
//
// It tries each supported encoding in that order and returns an error if:
//   - no supported decoder can read the file, or
//   - the decoder succeeds but the XML payload is invalid.
//
// For row count parsing behavior, invalid <count> values in record rows are surfaced
// in Features() as MailCount == InvalidMailCount instead of being silently converted to zero.
func (r *Report) LoadReportFile() error {
	if r == nil {
		return fmt.Errorf("report receiver is nil")
	}
	r.Content = DmarcReport{}

	if r.FilePath == "" {
		return ErrNoFilePath
	}

	var parseError error
	limit := r.MaxDecompressedBytes
	readers := []func(string, int64) ([]byte, error){
		utilities.ReadGZWithLimit,
		utilities.ReadZipWithLimit,
		utilities.ReadZZWithLimit,
	}

	for _, reader := range readers {
		s, err := reader(r.FilePath, limit)
		if err != nil {
			continue
		}

		if err := decodeDMARCXML(s, &r.Content); err != nil {
			parseError = fmt.Errorf("%w: failed to parse DMARC XML from %q: %w", ErrMalformedXML, r.FilePath, err)
			continue
		}

		return nil
	}

	if parseError != nil {
		return parseError
	}

	return fmt.Errorf("failed to read file: %q", r.FilePath)
}

// LoadReportFileFromPath validates file path and loads report contents.
func (r *Report) LoadReportFileFromPath(filePath string) error {
	if r == nil {
		return fmt.Errorf("report receiver is nil")
	}
	if filePath == "" {
		return ErrNoFilePath
	}
	r.FilePath = filePath
	return r.LoadReportFile()
}

func decodeDMARCXML(payload []byte, report *DmarcReport) error {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	decoder.CharsetReader = dmarcCharsetReader
	return decoder.Decode(report)
}

func dmarcCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "utf-8", "utf8", "":
		return input, nil
	case "iso-8859-1", "latin1", "latin-1":
		return decodeSingleByte(input, nil)
	case "windows-1252", "cp1252":
		return decodeSingleByte(input, windows1252Overrides)
	default:
		return nil, fmt.Errorf("unsupported XML charset %q", charset)
	}
}

func decodeSingleByte(input io.Reader, overrides map[byte]rune) (io.Reader, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	var output strings.Builder
	output.Grow(len(data))
	for _, b := range data {
		if replacement, ok := overrides[b]; ok {
			output.WriteRune(replacement)
			continue
		}
		output.WriteRune(rune(b))
	}
	return strings.NewReader(output.String()), nil
}

var windows1252Overrides = map[byte]rune{
	0x80: '\u20ac',
	0x82: '\u201a',
	0x83: '\u0192',
	0x84: '\u201e',
	0x85: '\u2026',
	0x86: '\u2020',
	0x87: '\u2021',
	0x88: '\u02c6',
	0x89: '\u2030',
	0x8a: '\u0160',
	0x8b: '\u2039',
	0x8c: '\u0152',
	0x8e: '\u017d',
	0x91: '\u2018',
	0x92: '\u2019',
	0x93: '\u201c',
	0x94: '\u201d',
	0x95: '\u2022',
	0x96: '\u2013',
	0x97: '\u2014',
	0x98: '\u02dc',
	0x99: '\u2122',
	0x9a: '\u0161',
	0x9b: '\u203a',
	0x9c: '\u0153',
	0x9e: '\u017e',
	0x9f: '\u0178',
}
