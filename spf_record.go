package dmarcgo

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// SPFQualifier is the result returned when an SPF mechanism matches.
type SPFQualifier string

const (
	SPFQualifierPass     SPFQualifier = "pass"
	SPFQualifierFail     SPFQualifier = "fail"
	SPFQualifierSoftFail SPFQualifier = "softfail"
	SPFQualifierNeutral  SPFQualifier = "neutral"
)

// SPFTerm is one normalized mechanism or modifier in evaluation order.
type SPFTerm struct {
	Position  int          `json:"position"`
	Raw       string       `json:"raw"`
	Qualifier SPFQualifier `json:"qualifier,omitempty"`
	Mechanism string       `json:"mechanism,omitempty"`
	Modifier  string       `json:"modifier,omitempty"`
	Value     string       `json:"value,omitempty"`
	Domain    string       `json:"domain,omitempty"`
	Dynamic   bool         `json:"dynamic"`
	IPv4CIDR  int          `json:"ipv4_cidr,omitempty"`
	IPv6CIDR  int          `json:"ipv6_cidr,omitempty"`
	CausesDNS bool         `json:"causes_dns"`
}

// SPFRelationship records an include or redirect dependency without resolving it.
type SPFRelationship struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Dynamic bool   `json:"dynamic"`
}

// SPFLookupEvidence describes the bounded lookup facts derivable from supplied TXT data.
type SPFLookupEvidence struct {
	DirectTerms       int  `json:"direct_terms"`
	ExpandedTerms     int  `json:"expanded_terms"`
	ExpandedAvailable bool `json:"expanded_available"`
	Limit             int  `json:"limit"`
	Exceeded          bool `json:"exceeded"`
	VoidLookups       int  `json:"void_lookups"`
	VoidAvailable     bool `json:"void_available"`
	VoidLimit         int  `json:"void_limit"`
}

// SPFRecord is a side-effect-free semantic parse of one SPF TXT value.
type SPFRecord struct {
	Raw           string                     `json:"raw"`
	Status        AuthenticationRecordStatus `json:"status"`
	Version       string                     `json:"version"`
	Terms         []SPFTerm                  `json:"terms"`
	Relationships []SPFRelationship          `json:"relationships"`
	Lookup        SPFLookupEvidence          `json:"lookup"`
}

// ParseSPFRecord parses one supplied TXT value without performing DNS queries.
func ParseSPFRecord(value string) (SPFRecord, []AuthenticationDiagnostic) {
	record := SPFRecord{
		Raw:   value,
		Terms: []SPFTerm{}, Relationships: []SPFRelationship{},
		Lookup: SPFLookupEvidence{Limit: 10, VoidLimit: 2},
	}
	diagnostics := make([]AuthenticationDiagnostic, 0)
	if len(value) > maxAuthenticationRecordBytes {
		diagnostics = append(diagnostics, parserDiagnostic("spf.malformed_record_size", FindingSeverityHigh, "record", 0, "The SPF record exceeds the parser size limit.", spfStandardReference))
		record.Status = AuthenticationRecordMalformed
		return record, diagnostics
	}
	fields := strings.Fields(value)
	if len(fields) > maxAuthenticationTerms+1 {
		diagnostics = append(diagnostics, parserDiagnostic("spf.malformed_term_limit", FindingSeverityHigh, "terms", 0, "The SPF record contains too many terms.", spfStandardReference))
		record.Status = AuthenticationRecordMalformed
		return record, diagnostics
	}
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		diagnostics = append(diagnostics, parserDiagnostic("spf.missing_required_version", FindingSeverityHigh, "version", 0, "The SPF version term is missing or invalid.", spfStandardReference))
		record.Status = statusFromDiagnostics(diagnostics)
		return record, diagnostics
	}
	record.Version = "spf1"
	seenModifiers := map[string]bool{}
	searchOffset := strings.Index(value, fields[0]) + len(fields[0])
	for index, field := range fields[1:] {
		fieldOffset := searchOffset + strings.Index(value[searchOffset:], field)
		searchOffset = fieldOffset + len(field)
		term, termDiagnostics := parseSPFTerm(field, index)
		record.Terms = append(record.Terms, term)
		for diagnosticIndex := range termDiagnostics {
			termDiagnostics[diagnosticIndex].Path = "terms[" + itoa(index) + "]." + termDiagnostics[diagnosticIndex].Path
			termDiagnostics[diagnosticIndex].Offset += fieldOffset
		}
		diagnostics = append(diagnostics, termDiagnostics...)
		if term.Modifier != "" {
			if seenModifiers[term.Modifier] {
				diagnostics = append(diagnostics, parserDiagnostic("spf.duplicate_modifier", FindingSeverityHigh, "terms["+itoa(index)+"].modifier", 0, "An SPF modifier appears more than once.", spfStandardReference))
			}
			seenModifiers[term.Modifier] = true
		}
		if term.CausesDNS {
			record.Lookup.DirectTerms++
		}
		if term.Mechanism == "include" || term.Modifier == "redirect" {
			record.Relationships = append(record.Relationships, SPFRelationship{Type: firstNonEmpty(term.Mechanism, term.Modifier), Target: term.Domain, Dynamic: term.Dynamic})
		}
	}
	if record.Lookup.DirectTerms > record.Lookup.Limit {
		record.Lookup.Exceeded = true
		diagnostics = append(diagnostics, parserDiagnostic("spf.lookup_limit_invalid", FindingSeverityHigh, "lookup.direct_terms", 0, "The SPF record exceeds the ten-term DNS lookup limit before recursive evaluation.", spfStandardReference))
	}
	record.Status = statusFromDiagnostics(diagnostics)
	return record, diagnostics
}

func parseSPFTerm(raw string, position int) (SPFTerm, []AuthenticationDiagnostic) {
	term := SPFTerm{Position: position, Raw: raw, Qualifier: SPFQualifierPass}
	diagnostics := make([]AuthenticationDiagnostic, 0)
	if raw == "" {
		return term, []AuthenticationDiagnostic{parserDiagnostic("spf.malformed_term", FindingSeverityHigh, "raw", 0, "An SPF term is empty.", spfStandardReference)}
	}
	hadQualifier := false
	if qualifier, ok := spfQualifier(raw[0]); ok {
		hadQualifier = true
		term.Qualifier = qualifier
		raw = raw[1:]
		if raw == "" {
			return term, []AuthenticationDiagnostic{parserDiagnostic("spf.malformed_term", FindingSeverityHigh, "raw", 0, "An SPF qualifier has no mechanism.", spfStandardReference)}
		}
	}
	if equals := strings.IndexByte(raw, '='); equals > 0 && !strings.ContainsAny(raw[:equals], ":/") {
		term.Modifier = strings.ToLower(raw[:equals])
		term.Value = raw[equals+1:]
		if !validSPFName(term.Modifier) {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_modifier_name", FindingSeverityHigh, "modifier", 0, "The SPF modifier name is malformed.", spfStandardReference))
		}
		if hadQualifier {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_modifier_qualifier", FindingSeverityHigh, "qualifier", 0, "An SPF modifier cannot have a qualifier.", spfStandardReference))
		}
		switch term.Modifier {
		case "redirect", "exp":
			if term.Value == "" {
				diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_modifier", FindingSeverityHigh, "value", equals+1, "A known SPF modifier has no value.", spfStandardReference))
				return term, diagnostics
			}
			term.Domain, term.Dynamic, diagnostics = normalizeSPFDomain(term.Value, diagnostics)
			term.CausesDNS = term.Modifier == "redirect"
		default:
			diagnostics = append(diagnostics, parserDiagnostic("spf.unknown_modifier", FindingSeverityInfo, "modifier", 0, "An unknown SPF modifier is preserved and ignored as required by SPF.", spfStandardReference))
		}
		return term, diagnostics
	}

	nameEnd := len(raw)
	if separator := strings.IndexAny(raw, ":/"); separator >= 0 {
		nameEnd = separator
	}
	term.Mechanism = strings.ToLower(raw[:nameEnd])
	if !validSPFName(term.Mechanism) {
		diagnostics = append(diagnostics, parserDiagnostic("spf.malformed_mechanism_name", FindingSeverityHigh, "mechanism", 0, "The SPF mechanism name is malformed.", spfStandardReference))
		return term, diagnostics
	}
	remainder := raw[nameEnd:]
	switch term.Mechanism {
	case "all":
		if remainder != "" {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_mechanism", FindingSeverityHigh, "mechanism", nameEnd, "The all mechanism cannot have an argument or CIDR.", spfStandardReference))
		}
	case "include", "exists":
		term.CausesDNS = true
		if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_mechanism", FindingSeverityHigh, "value", nameEnd, "This SPF mechanism requires a domain-spec argument.", spfStandardReference))
			break
		}
		term.Value = remainder[1:]
		term.Domain, term.Dynamic, diagnostics = normalizeSPFDomain(term.Value, diagnostics)
	case "a", "mx":
		term.CausesDNS = true
		term.Domain, term.Dynamic, term.IPv4CIDR, term.IPv6CIDR, diagnostics = parseSPFDomainCIDR(remainder, diagnostics)
	case "ptr":
		term.CausesDNS = true
		diagnostics = append(diagnostics, parserDiagnostic("spf.ptr_deprecated", FindingSeverityMedium, "mechanism", 0, "The SPF ptr mechanism is deprecated and should not be used.", spfStandardReference))
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
				diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_mechanism", FindingSeverityHigh, "value", nameEnd, "The ptr mechanism argument is invalid.", spfStandardReference))
			} else {
				term.Value = remainder[1:]
				term.Domain, term.Dynamic, diagnostics = normalizeSPFDomain(term.Value, diagnostics)
			}
		}
	case "ip4", "ip6":
		if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 || !validSPFNetwork(term.Mechanism, remainder[1:]) {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_network", FindingSeverityHigh, "value", nameEnd, "The SPF IP mechanism has an invalid address or CIDR.", spfStandardReference))
		} else {
			term.Value = remainder[1:]
		}
	case "":
		diagnostics = append(diagnostics, parserDiagnostic("spf.malformed_term", FindingSeverityHigh, "mechanism", 0, "An SPF mechanism name is missing.", spfStandardReference))
	default:
		diagnostics = append(diagnostics, parserDiagnostic("spf.unknown_mechanism", FindingSeverityHigh, "mechanism", 0, "An unknown SPF mechanism makes evaluation unsupported.", spfStandardReference))
	}
	return term, diagnostics
}

func spfQualifier(value byte) (SPFQualifier, bool) {
	switch value {
	case '+':
		return SPFQualifierPass, true
	case '-':
		return SPFQualifierFail, true
	case '~':
		return SPFQualifierSoftFail, true
	case '?':
		return SPFQualifierNeutral, true
	default:
		return SPFQualifierPass, false
	}
}

func parseSPFDomainCIDR(value string, diagnostics []AuthenticationDiagnostic) (string, bool, int, int, []AuthenticationDiagnostic) {
	explicitDomain := strings.HasPrefix(value, ":")
	domainPart := value
	ipv4CIDR, ipv6CIDR := 0, 0
	domainPart = strings.TrimPrefix(domainPart, ":")
	if slash := strings.IndexByte(domainPart, '/'); slash >= 0 {
		cidrPart := domainPart[slash:]
		domainPart = domainPart[:slash]
		var ok bool
		ipv4CIDR, ipv6CIDR, ok = parseDualCIDR(cidrPart)
		if !ok {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_cidr", FindingSeverityHigh, "cidr", 0, "The SPF mechanism has an invalid IPv4 or IPv6 CIDR length.", spfStandardReference))
		}
	}
	if domainPart == "" {
		if explicitDomain {
			diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_domain", FindingSeverityHigh, "domain", 0, "An explicit SPF mechanism domain is empty.", spfStandardReference))
		}
		return "", false, ipv4CIDR, ipv6CIDR, diagnostics
	}
	domain, dynamic, diagnostics := normalizeSPFDomain(domainPart, diagnostics)
	return domain, dynamic, ipv4CIDR, ipv6CIDR, diagnostics
}

func validSPFName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func parseDualCIDR(value string) (int, int, bool) {
	if !strings.HasPrefix(value, "/") {
		return 0, 0, false
	}
	value = value[1:]
	parts := strings.Split(value, "//")
	if len(parts) > 2 {
		return 0, 0, false
	}
	ipv4, ipv6 := 0, 0
	if parts[0] != "" {
		parsed, err := strconv.Atoi(parts[0])
		if err != nil || parsed < 0 || parsed > 32 {
			return 0, 0, false
		}
		ipv4 = parsed
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return 0, 0, false
		}
		parsed, err := strconv.Atoi(parts[1])
		if err != nil || parsed < 0 || parsed > 128 {
			return 0, 0, false
		}
		ipv6 = parsed
	}
	return ipv4, ipv6, true
}

func validSPFNetwork(mechanism, value string) bool {
	address := value
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		return ip != nil && ((mechanism == "ip4" && ip.To4() != nil) || (mechanism == "ip6" && ip.To4() == nil))
	}
	ip, _, err := net.ParseCIDR(address)
	return err == nil && ((mechanism == "ip4" && ip.To4() != nil) || (mechanism == "ip6" && ip.To4() == nil))
}

func normalizeSPFDomain(value string, diagnostics []AuthenticationDiagnostic) (string, bool, []AuthenticationDiagnostic) {
	if strings.Contains(value, "%{") {
		return value, true, diagnostics
	}
	if strings.ContainsAny(value, "% ") {
		diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_domain", FindingSeverityHigh, "domain", 0, "The SPF domain-spec is malformed.", spfStandardReference))
		return value, false, diagnostics
	}
	normalized, err := normalizeSPFDNSName(value)
	if err != nil {
		diagnostics = append(diagnostics, parserDiagnostic("spf.invalid_domain", FindingSeverityHigh, "domain", 0, "The SPF domain-spec cannot be normalized to a DNS A-label.", eaiStandardReference))
		return value, false, diagnostics
	}
	return normalized, false, diagnostics
}

func normalizeSPFDNSName(value string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(value), "."), ".")
	if len(labels) == 0 {
		return "", ErrInvalidAuthenticationRecord
	}
	for index, label := range labels {
		if label == "" {
			return "", ErrInvalidAuthenticationRecord
		}
		ascii := true
		for _, character := range label {
			if character > 127 {
				ascii = false
				break
			}
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return "", ErrInvalidAuthenticationRecord
			}
		}
		if !ascii {
			normalized, err := idna.Lookup.ToASCII(label)
			if err != nil {
				return "", err
			}
			label = normalized
		}
		if len(label) > 63 {
			return "", ErrInvalidAuthenticationRecord
		}
		labels[index] = label
	}
	result := strings.Join(labels, ".")
	if len(result) > 253 {
		return "", ErrInvalidAuthenticationRecord
	}
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func cloneSPFRecord(value SPFRecord) SPFRecord {
	value.Terms = append([]SPFTerm(nil), value.Terms...)
	value.Relationships = append([]SPFRelationship(nil), value.Relationships...)
	return value
}

func applySPFGraphEvidence(recordSets []AuthenticationRecordSet, diagnostics *[]AuthenticationDiagnostic) {
	records := map[string]*SPFRecord{}
	evidence := map[string]EvidenceID{}
	for setIndex := range recordSets {
		set := &recordSets[setIndex]
		if set.Type != DNSRecordSPF || len(set.Records) != 1 || set.Records[0].SPF == nil {
			continue
		}
		records[set.Name] = set.Records[0].SPF
		evidence[set.Name] = set.Records[0].EvidenceID
	}
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		expanded, available, cycle := expandedSPFLookups(name, records, map[string]bool{})
		record := records[name]
		record.Lookup.ExpandedTerms = expanded
		record.Lookup.ExpandedAvailable = available && !cycle
		if expanded > record.Lookup.Limit {
			record.Lookup.Exceeded = true
			*diagnostics = append(*diagnostics, AuthenticationDiagnostic{
				Code: "spf.lookup_limit_invalid", Severity: FindingSeverityHigh, Name: name, RecordType: DNSRecordSPF,
				EvidenceID: evidence[name], Path: "lookup.expanded_terms", Message: "The supplied SPF dependency graph exceeds the ten-term DNS lookup limit.", Standard: spfStandardReference,
			})
			record.Status = strongerAuthenticationStatus(record.Status, AuthenticationRecordInvalid)
		}
		if cycle {
			*diagnostics = append(*diagnostics, AuthenticationDiagnostic{
				Code: "spf.include_cycle_invalid", Severity: FindingSeverityHigh, Name: name, RecordType: DNSRecordSPF,
				EvidenceID: evidence[name], Path: "relationships", Message: "The supplied SPF dependency graph contains an include or redirect cycle.", Standard: spfStandardReference,
			})
			record.Status = strongerAuthenticationStatus(record.Status, AuthenticationRecordInvalid)
		}
		for setIndex := range recordSets {
			set := &recordSets[setIndex]
			if set.Name == name && set.Type == DNSRecordSPF && len(set.Records) == 1 {
				set.Records[0].Status = record.Status
				set.Status = record.Status
				for diagnosticIndex := range *diagnostics {
					diagnostic := &(*diagnostics)[diagnosticIndex]
					if diagnostic.Name == name && diagnostic.RecordType == DNSRecordSPF && diagnostic.ObservedAt.IsZero() {
						diagnostic.ObservedAt = set.ObservedAt
					}
				}
			}
		}
	}
}

func expandedSPFLookups(name string, records map[string]*SPFRecord, visiting map[string]bool) (int, bool, bool) {
	return expandedSPFLookupsBounded(name, records, visiting, 0)
}

func expandedSPFLookupsBounded(name string, records map[string]*SPFRecord, visiting map[string]bool, depth int) (int, bool, bool) {
	if depth > 128 {
		return 0, false, false
	}
	if visiting[name] {
		return 0, false, true
	}
	record := records[name]
	if record == nil {
		return 0, false, false
	}
	visiting[name] = true
	total := record.Lookup.DirectTerms
	available := true
	cycle := false
	for _, relationship := range record.Relationships {
		if relationship.Dynamic || relationship.Target == "" {
			available = false
			continue
		}
		child, childAvailable, childCycle := expandedSPFLookupsBounded(relationship.Target, records, visiting, depth+1)
		total += child
		available = available && childAvailable
		cycle = cycle || childCycle
		if total > record.Lookup.Limit {
			total = record.Lookup.Limit + 1
			break
		}
	}
	delete(visiting, name)
	return total, available, cycle
}
