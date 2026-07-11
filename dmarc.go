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

// AggregateReport is a DMARC aggregate feedback report.
//
// The model accepts legacy aggregate reports as well as RFC 9990 reports. Unknown
// extension elements are retained as raw XML rather than interpreted.
type AggregateReport struct {
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
	ADKIM           string `xml:"adkim" json:"adkim,omitempty"`
	ASPF            string `xml:"aspf" json:"aspf,omitempty"`
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
	SourceIP        string          `xml:"source_ip" json:"source_ip"`
	Count           string          `xml:"count" json:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated" json:"policy_evaluated"`
}

// PolicyEvaluated contains the final DMARC disposition and alignment outcomes.
type PolicyEvaluated struct {
	Disposition string                 `xml:"disposition" json:"disposition"`
	DKIM        string                 `xml:"dkim" json:"dkim"`
	SPF         string                 `xml:"spf" json:"spf"`
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
	DKIM []DKIMAuthResult `xml:"dkim" json:"dkim,omitempty"`
	SPF  *SPFAuthResult   `xml:"spf" json:"spf,omitempty"`
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

// FeatureRow is a flattened representation of report and record data.
type FeatureRow struct {
	ReportingOrg               string                 `json:"reporting_org"`
	ReportingEmail             string                 `json:"reporting_addr"`
	ExtraContactInfo           string                 `json:"extra_contact_info,omitempty"`
	ExtraContactInfoLang       string                 `json:"extra_contact_info_lang,omitempty"`
	ReportID                   string                 `json:"report_id"`
	ReportVersion              string                 `json:"report_version,omitempty"`
	ReportError                string                 `json:"report_error,omitempty"`
	ReportErrorLang            string                 `json:"report_error_lang,omitempty"`
	ReportGenerator            string                 `json:"report_generator,omitempty"`
	BeginDate                  string                 `json:"begin_date"`
	EndDate                    string                 `json:"end_date"`
	TargetDomain               string                 `json:"target_domain"`
	SPFPolicyPublished         string                 `json:"spf_policy_published"`
	DKIMPolicyPublished        string                 `json:"dkim_policy_published"`
	RequestedHandlingPolicy    string                 `json:"requested_handling_policy"`
	SubdomainPolicyPublished   string                 `json:"subdomain_policy_published,omitempty"`
	NonexistentSubdomainPolicy string                 `json:"nonexistent_subdomain_policy,omitempty"`
	SamplingPercentage         string                 `json:"sampling_percentage,omitempty"`
	FailureReportingOptions    string                 `json:"failure_reporting_options,omitempty"`
	PolicyDiscoveryMethod      string                 `json:"policy_discovery_method,omitempty"`
	Testing                    string                 `json:"testing,omitempty"`
	SourceIP                   string                 `json:"source_ip,omitempty"`
	MailCount                  int                    `json:"mail_count"`
	VendorAction               string                 `json:"vendor_action,omitempty"`
	DKIMPolicyEvaluated        string                 `json:"dkim_policy_evaluated,omitempty"`
	SPFPolicyEvaluated         string                 `json:"spf_policy_evaluated,omitempty"`
	Type                       string                 `json:"type,omitempty"`
	Comment                    string                 `json:"comment,omitempty"`
	HeaderFrom                 string                 `json:"header_from,omitempty"`
	EnvelopeFrom               string                 `json:"envelope_from,omitempty"`
	EnvelopeTo                 string                 `json:"envelope_to,omitempty"`
	DKIMDomain                 string                 `json:"dkim_domain,omitempty"`
	DKIMSelector               string                 `json:"dkim_selector,omitempty"`
	DKIMResult                 string                 `json:"dkim_result,omitempty"`
	DKIMHumanResult            string                 `json:"dkim_human_result,omitempty"`
	SPFDomain                  string                 `json:"spf_domain,omitempty"`
	SPFScope                   string                 `json:"spf_scope,omitempty"`
	SPFResult                  string                 `json:"spf_result,omitempty"`
	SPFHumanResult             string                 `json:"spf_human_result,omitempty"`
	DKIMAuthResults            []DKIMAuthResult       `json:"dkim_auth_results,omitempty"`
	SPFAuthResult              *SPFAuthResult         `json:"spf_auth_result,omitempty"`
	PolicyOverrideReasons      []PolicyOverrideReason `json:"policy_override_reasons,omitempty"`
	ExtensionCount             int                    `json:"extension_count,omitempty"`
}

func (r AggregateReport) baseFeatureRow() FeatureRow {
	return FeatureRow{
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
		SPFPolicyPublished:         r.PolicyPublished.ASPF,
		DKIMPolicyPublished:        r.PolicyPublished.ADKIM,
		RequestedHandlingPolicy:    r.PolicyPublished.P,
		SubdomainPolicyPublished:   r.PolicyPublished.Sp,
		NonexistentSubdomainPolicy: r.PolicyPublished.Np,
		SamplingPercentage:         r.PolicyPublished.Pct,
		FailureReportingOptions:    r.PolicyPublished.Fo,
		PolicyDiscoveryMethod:      r.PolicyPublished.DiscoveryMethod,
		Testing:                    r.PolicyPublished.Testing,
		ExtensionCount:             len(r.Extension.Elements),
	}
}

// FeatureRows returns one flattened row per DMARC record.
func (r AggregateReport) FeatureRows() []FeatureRow {
	baseReport := r.baseFeatureRow()
	rows := make([]FeatureRow, 0, len(r.Record))
	for _, record := range r.Record {
		tempReport := baseReport
		tempReport.SourceIP = record.Row.SourceIP
		countString := strings.TrimSpace(record.Row.Count)
		if mailCount, err := strconv.Atoi(countString); err == nil {
			tempReport.MailCount = mailCount
		} else {
			tempReport.MailCount = InvalidMailCount
		}
		tempReport.VendorAction = record.Row.PolicyEvaluated.Disposition
		tempReport.DKIMPolicyEvaluated = record.Row.PolicyEvaluated.DKIM
		tempReport.SPFPolicyEvaluated = record.Row.PolicyEvaluated.SPF
		tempReport.PolicyOverrideReasons = record.Row.PolicyEvaluated.Reasons
		if len(record.Row.PolicyEvaluated.Reasons) > 0 {
			tempReport.Type = record.Row.PolicyEvaluated.Reasons[0].Type
			tempReport.Comment = record.Row.PolicyEvaluated.Reasons[0].Comment.Value
		}
		tempReport.HeaderFrom = record.Identifiers.HeaderFrom
		tempReport.EnvelopeFrom = record.Identifiers.EnvelopeFrom
		tempReport.EnvelopeTo = record.Identifiers.EnvelopeTo
		tempReport.DKIMAuthResults = record.AuthResults.DKIM
		if len(record.AuthResults.DKIM) > 0 {
			tempReport.DKIMDomain = record.AuthResults.DKIM[0].Domain
			tempReport.DKIMSelector = record.AuthResults.DKIM[0].Selector
			tempReport.DKIMResult = record.AuthResults.DKIM[0].Result
			tempReport.DKIMHumanResult = record.AuthResults.DKIM[0].HumanResult.Value
		}
		tempReport.SPFAuthResult = record.AuthResults.SPF
		if record.AuthResults.SPF != nil {
			tempReport.SPFDomain = record.AuthResults.SPF.Domain
			tempReport.SPFScope = record.AuthResults.SPF.Scope
			tempReport.SPFResult = record.AuthResults.SPF.Result
			tempReport.SPFHumanResult = record.AuthResults.SPF.HumanResult.Value
		}
		tempReport.ExtensionCount += len(record.Extensions)
		rows = append(rows, tempReport)
	}
	return rows
}

// Rows is an alias for FeatureRows.
func (r AggregateReport) Rows() []FeatureRow {
	return r.FeatureRows()
}

// Features returns a legacy flattened view with a metadata-only row at index 0.
// Prefer FeatureRows or Rows for new code.
func (r AggregateReport) Features() []FeatureRow {
	rows := make([]FeatureRow, 0, len(r.Record)+1)
	rows = append(rows, r.baseFeatureRow())
	rows = append(rows, r.FeatureRows()...)
	return rows
}

// FileReport is a loadable DMARC aggregate report file.
type FileReport struct {
	FilePath string
	Content  AggregateReport
	// MaxDecompressedBytes limits decompressed archive payload size. If zero,
	// utilities.DefaultMaxDecompressedBytes is used.
	MaxDecompressedBytes int64
}

// Load parses the configured report file as gzip XML, gzip-compressed tar, zip,
// tar, then zlib.
//
// It tries each supported encoding in that order and returns an error if:
//   - no supported decoder can read the file, or
//   - the decoder succeeds but the XML payload is invalid.
//
// For row count parsing behavior, invalid <count> values in record rows are surfaced
// in Rows() as MailCount == InvalidMailCount instead of being silently converted to zero.
func (r *FileReport) Load() error {
	if r == nil {
		return fmt.Errorf("report receiver is nil")
	}
	r.Content = AggregateReport{}

	if r.FilePath == "" {
		return ErrNoFilePath
	}

	var parseError error
	limit := r.MaxDecompressedBytes
	readers := []func(string, int64) ([]byte, error){
		utilities.ReadGZWithLimit,
		utilities.ReadTarGZWithLimit,
		utilities.ReadZipWithLimit,
		utilities.ReadTarWithLimit,
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

// LoadFile validates file path and loads report contents.
func (r *FileReport) LoadFile(path string) error {
	if r == nil {
		return fmt.Errorf("report receiver is nil")
	}
	if path == "" {
		return ErrNoFilePath
	}
	r.FilePath = path
	return r.Load()
}

// Report is a deprecated alias for FileReport.
type Report = FileReport

// LoadReportFile is a deprecated alias for Load.
func (r *FileReport) LoadReportFile() error { return r.Load() }

// LoadReportFileFromPath is a deprecated alias for LoadFile.
func (r *FileReport) LoadReportFileFromPath(path string) error { return r.LoadFile(path) }

func decodeDMARCXML(payload []byte, report *AggregateReport) error {
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
