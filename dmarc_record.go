package dmarcgo

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// DMARCAlignmentMode controls relaxed or strict identifier alignment.
type DMARCAlignmentMode string

const (
	DMARCAlignmentRelaxed DMARCAlignmentMode = "relaxed"
	DMARCAlignmentStrict  DMARCAlignmentMode = "strict"
)

// DMARCPolicy is a domain-owner assessment policy.
type DMARCPolicy string

const (
	DMARCPolicyNone       DMARCPolicy = "none"
	DMARCPolicyQuarantine DMARCPolicy = "quarantine"
	DMARCPolicyReject     DMARCPolicy = "reject"
)

// DMARCReportURI is a syntactically parsed, still-untrusted reporting destination.
type DMARCReportURI struct {
	Raw        string `json:"raw"`
	Scheme     string `json:"scheme"`
	Address    string `json:"address"`
	Domain     string `json:"domain,omitempty"`
	LegacySize string `json:"legacy_size,omitempty"`
}

// DMARCPolicyRecord is a semantic parse of one RFC 9989 policy record.
type DMARCPolicyRecord struct {
	Raw                 string                     `json:"raw"`
	Status              AuthenticationRecordStatus `json:"status"`
	Version             string                     `json:"version"`
	Policy              DMARCPolicy                `json:"policy,omitempty"`
	EffectivePolicy     DMARCPolicy                `json:"effective_policy,omitempty"`
	SubdomainPolicy     DMARCPolicy                `json:"subdomain_policy,omitempty"`
	NonexistentPolicy   DMARCPolicy                `json:"nonexistent_policy,omitempty"`
	DKIMAlignment       DMARCAlignmentMode         `json:"dkim_alignment"`
	SPFAlignment        DMARCAlignmentMode         `json:"spf_alignment"`
	Testing             bool                       `json:"testing"`
	PSD                 string                     `json:"psd,omitempty"`
	AggregateReports    []DMARCReportURI           `json:"aggregate_reports"`
	FailureReports      []DMARCReportURI           `json:"failure_reports"`
	FailureOptions      []string                   `json:"failure_options"`
	UnknownTags         []string                   `json:"unknown_tags"`
	RemovedLegacyTags   []string                   `json:"removed_legacy_tags"`
	PolicyDomain        string                     `json:"policy_domain,omitempty"`
	RecoveredMonitoring bool                       `json:"recovered_monitoring"`
}

// ParseDMARCPolicyRecord parses one supplied TXT value using RFC 9989 tag semantics.
func ParseDMARCPolicyRecord(value string) (DMARCPolicyRecord, []AuthenticationDiagnostic) {
	record := DMARCPolicyRecord{
		Raw:           value,
		DKIMAlignment: DMARCAlignmentRelaxed, SPFAlignment: DMARCAlignmentRelaxed,
		AggregateReports: []DMARCReportURI{}, FailureReports: []DMARCReportURI{},
		FailureOptions: []string{"0"}, UnknownTags: []string{}, RemovedLegacyTags: []string{},
	}
	if len(value) > maxAuthenticationRecordBytes {
		diagnostic := parserDiagnostic("dmarc.malformed_record_size", FindingSeverityHigh, "record", 0, "The DMARC policy record exceeds the parser size limit.", dmarcStandardReference)
		record.Status = AuthenticationRecordMalformed
		return record, []AuthenticationDiagnostic{diagnostic}
	}
	tags, diagnostics := parseAuthenticationTags(value, dmarcStandardReference)
	if len(tags) == 0 || tags[0].name != "v" || tags[0].value != "DMARC1" {
		diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_version", FindingSeverityHigh, "version", 0, "The DMARC version tag must be first and exactly DMARC1.", dmarcStandardReference))
	} else {
		record.Version = "DMARC1"
	}
	policyPresent := false
	domainPolicyInvalid := false
	validAggregateURI := false
	var failureOptionsTag *authenticationTag
	for _, tag := range tags {
		if tag.name == "p" {
			policyPresent = true
		}
		if tag.value == "" {
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.malformed_empty_value", FindingSeverityHigh, "tags."+tag.name, tag.offset, "A DMARC tag has an empty value.", dmarcStandardReference))
			continue
		}
		switch tag.name {
		case "v":
			continue
		case "p":
			policy, ok := parseDMARCPolicy(tag.value)
			if !ok {
				domainPolicyInvalid = true
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_policy", FindingSeverityHigh, "policy", tag.offset, "The DMARC domain policy is invalid.", dmarcStandardReference))
			} else {
				record.Policy = policy
				record.EffectivePolicy = policy
			}
		case "sp":
			policy, ok := parseDMARCPolicy(tag.value)
			if !ok {
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_subdomain_policy", FindingSeverityHigh, "subdomain_policy", tag.offset, "The DMARC subdomain policy is invalid.", dmarcStandardReference))
			} else {
				record.SubdomainPolicy = policy
			}
		case "np":
			policy, ok := parseDMARCPolicy(tag.value)
			if !ok {
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_nonexistent_policy", FindingSeverityHigh, "nonexistent_policy", tag.offset, "The DMARC non-existent-domain policy is invalid.", dmarcStandardReference))
			} else {
				record.NonexistentPolicy = policy
			}
		case "adkim":
			record.DKIMAlignment, diagnostics = parseDMARCAlignment(tag.value, "dkim_alignment", tag.offset, diagnostics)
		case "aspf":
			record.SPFAlignment, diagnostics = parseDMARCAlignment(tag.value, "spf_alignment", tag.offset, diagnostics)
		case "t":
			testing := strings.ToLower(tag.value)
			if testing != "y" && testing != "n" {
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_testing_mode", FindingSeverityHigh, "testing", tag.offset, "The DMARC policy-test value is invalid.", dmarcStandardReference))
			} else if testing == "y" {
				record.Testing = true
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.weak_testing_mode", FindingSeverityMedium, "testing", tag.offset, "DMARC policy testing requests enforcement one level below the published policy.", dmarcStandardReference))
			}
		case "psd":
			psd := strings.ToLower(tag.value)
			if psd != "y" && psd != "n" && psd != "u" {
				diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_psd", FindingSeverityHigh, "psd", tag.offset, "The DMARC public-suffix indicator is invalid.", dmarcStandardReference))
			} else {
				record.PSD = psd
			}
		case "rua":
			uris, uriDiagnostics := parseDMARCURIList(tag.value, "aggregate_reports", tag.offset)
			record.AggregateReports = uris
			diagnostics = append(diagnostics, uriDiagnostics...)
			validAggregateURI = len(uris) > 0
		case "ruf":
			uris, uriDiagnostics := parseDMARCURIList(tag.value, "failure_reports", tag.offset)
			record.FailureReports = uris
			diagnostics = append(diagnostics, uriDiagnostics...)
		case "fo":
			tagCopy := tag
			failureOptionsTag = &tagCopy
		case "pct", "ri", "rf":
			record.RemovedLegacyTags = append(record.RemovedLegacyTags, tag.name)
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.deprecated_removed_tag", FindingSeverityMedium, "removed_legacy_tags", tag.offset, "A tag removed from RFC 9989 is preserved but ignored.", dmarcStandardReference))
		default:
			record.UnknownTags = append(record.UnknownTags, tag.name)
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.unknown_tag", FindingSeverityInfo, "unknown_tags", tag.offset, "An unknown DMARC tag is preserved and ignored as required by RFC 9989.", dmarcStandardReference))
		}
	}
	if failureOptionsTag != nil && len(record.FailureReports) > 0 {
		record.FailureOptions, diagnostics = parseDMARCFailureOptions(failureOptionsTag.value, failureOptionsTag.offset, diagnostics)
	}
	if !policyPresent {
		record.EffectivePolicy = DMARCPolicyNone
		record.RecoveredMonitoring = true
	} else if domainPolicyInvalid || record.Policy == "" {
		if validAggregateURI {
			record.EffectivePolicy = DMARCPolicyNone
			record.RecoveredMonitoring = true
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.weak_recovered_monitoring", FindingSeverityMedium, "effective_policy", 0, "An absent or invalid policy with a valid aggregate-report URI is treated as monitoring only.", dmarcStandardReference))
		} else {
			record.EffectivePolicy = ""
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.missing_required_policy", FindingSeverityHigh, "policy", 0, "The DMARC record has no usable policy and no aggregate-report destination for monitoring fallback.", dmarcStandardReference))
		}
	}
	if record.Testing && record.EffectivePolicy != "" {
		record.EffectivePolicy = testingDMARCPolicy(record.EffectivePolicy)
	}
	record.Status = statusFromDiagnostics(diagnostics)
	return record, diagnostics
}

// DMARCPolicyDiscoveryNames returns the bounded RFC 9989 DNS tree-walk owner
// names for an Author Domain. It only computes names and performs no lookup.
func DMARCPolicyDiscoveryNames(authorDomain string) ([]string, error) {
	normalized, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(authorDomain)), "."))
	if err != nil || normalized == "" || strings.Contains(normalized, "..") {
		return nil, ErrInvalidAuthenticationRecord
	}
	labels := strings.Split(normalized, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return nil, ErrInvalidAuthenticationRecord
		}
	}
	result := []string{"_dmarc." + normalized}
	start := 1
	if len(labels) > 8 {
		start = len(labels) - 7
	}
	for index := start; index < len(labels) && len(result) < 8; index++ {
		name := "_dmarc." + strings.Join(labels[index:], ".")
		if name != result[len(result)-1] {
			result = append(result, name)
		}
	}
	return result, nil
}

func parseDMARCPolicy(value string) (DMARCPolicy, bool) {
	value = strings.ToLower(value)
	switch DMARCPolicy(value) {
	case DMARCPolicyNone, DMARCPolicyQuarantine, DMARCPolicyReject:
		return DMARCPolicy(value), true
	default:
		return "", false
	}
}

func testingDMARCPolicy(policy DMARCPolicy) DMARCPolicy {
	switch policy {
	case DMARCPolicyReject:
		return DMARCPolicyQuarantine
	case DMARCPolicyQuarantine, DMARCPolicyNone:
		return DMARCPolicyNone
	default:
		return policy
	}
}

func parseDMARCAlignment(value, path string, offset int, diagnostics []AuthenticationDiagnostic) (DMARCAlignmentMode, []AuthenticationDiagnostic) {
	switch strings.ToLower(value) {
	case "r":
		return DMARCAlignmentRelaxed, diagnostics
	case "s":
		return DMARCAlignmentStrict, diagnostics
	default:
		diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_alignment", FindingSeverityHigh, path, offset, "A DMARC alignment mode is invalid; the RFC default is retained.", dmarcStandardReference))
		return DMARCAlignmentRelaxed, diagnostics
	}
}

func parseDMARCURIList(value, path string, offset int) ([]DMARCReportURI, []AuthenticationDiagnostic) {
	parts := strings.SplitN(value, ",", maxAuthenticationListItems+1)
	result := make([]DMARCReportURI, 0, len(parts))
	diagnostics := make([]AuthenticationDiagnostic, 0)
	if len(parts) > maxAuthenticationListItems {
		parts = parts[:maxAuthenticationListItems]
		diagnostics = append(diagnostics, parserDiagnostic("dmarc.malformed_reporting_uri_limit", FindingSeverityHigh, path, offset, "The DMARC reporting URI list contains too many values.", dmarcStandardReference))
	}
	for _, part := range parts {
		raw := strings.TrimSpace(part)
		uri, ok := parseDMARCURI(raw)
		if !ok {
			diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_reporting_uri", FindingSeverityHigh, path, offset, "A DMARC reporting URI is syntactically invalid.", dmarcStandardReference))
			continue
		}
		result = append(result, uri)
	}
	return result, diagnostics
}

func parseDMARCURI(raw string) (DMARCReportURI, bool) {
	result := DMARCReportURI{Raw: raw}
	uriValue := raw
	if bang := strings.LastIndexByte(uriValue, '!'); bang > 0 {
		legacy := uriValue[bang+1:]
		if validLegacyReportSize(legacy) {
			result.LegacySize = legacy
			uriValue = uriValue[:bang]
		}
	}
	if strings.Contains(uriValue, "!") {
		return result, false
	}
	parsed, err := url.Parse(uriValue)
	if err != nil || parsed.Scheme == "" {
		return result, false
	}
	result.Scheme = strings.ToLower(parsed.Scheme)
	if result.Scheme == "mailto" {
		address := parsed.Opaque
		if address == "" {
			address = strings.TrimPrefix(parsed.Path, "//")
		}
		at := strings.LastIndexByte(address, '@')
		if at <= 0 || at == len(address)-1 {
			return result, false
		}
		domain, err := idna.Lookup.ToASCII(strings.ToLower(address[at+1:]))
		if err != nil || domain == "" {
			return result, false
		}
		result.Address = address[:at+1] + domain
		result.Domain = domain
		return result, true
	}
	if parsed.Host == "" && parsed.Opaque == "" {
		return result, false
	}
	result.Address = uriValue
	host := strings.ToLower(parsed.Hostname())
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			result.Domain = ip.String()
		} else {
			domain, err := idna.Lookup.ToASCII(host)
			if err != nil || domain == "" {
				return result, false
			}
			result.Domain = domain
		}
	}
	return result, true
}

func validLegacyReportSize(value string) bool {
	if value == "" {
		return false
	}
	if suffix := value[len(value)-1] | 0x20; suffix == 'k' || suffix == 'm' || suffix == 'g' || suffix == 't' {
		value = value[:len(value)-1]
	}
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseDMARCFailureOptions(value string, offset int, diagnostics []AuthenticationDiagnostic) ([]string, []AuthenticationDiagnostic) {
	values := strings.SplitN(value, ":", maxAuthenticationListItems+1)
	if len(values) > maxAuthenticationListItems {
		diagnostics = append(diagnostics, parserDiagnostic("dmarc.malformed_failure_option_limit", FindingSeverityHigh, "failure_options", offset, "The DMARC failure-option list contains too many values.", dmarcStandardReference))
		return []string{"0"}, diagnostics
	}
	seen := map[string]bool{}
	valid := true
	for index, option := range values {
		option = strings.ToLower(strings.TrimSpace(option))
		values[index] = option
		if option == "" || seen[option] || (option != "0" && option != "1" && option != "d" && option != "s") {
			valid = false
		}
		seen[option] = true
	}
	if seen["0"] && seen["1"] {
		valid = false
	}
	if len(values) == 0 || !valid {
		diagnostics = append(diagnostics, parserDiagnostic("dmarc.invalid_failure_options", FindingSeverityHigh, "failure_options", offset, "The DMARC failure-report option list is invalid.", dmarcStandardReference))
		return []string{"0"}, diagnostics
	}
	return values, diagnostics
}

func cloneDMARCPolicyRecord(value DMARCPolicyRecord) DMARCPolicyRecord {
	value.AggregateReports = append([]DMARCReportURI(nil), value.AggregateReports...)
	value.FailureReports = append([]DMARCReportURI(nil), value.FailureReports...)
	value.FailureOptions = cloneStrings(value.FailureOptions)
	value.UnknownTags = cloneStrings(value.UnknownTags)
	value.RemovedLegacyTags = cloneStrings(value.RemovedLegacyTags)
	return value
}
