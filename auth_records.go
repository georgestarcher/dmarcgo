package dmarcgo

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	maxAuthenticationRecordBytes = 65535
	maxAuthenticationTerms       = 1024
	maxAuthenticationListItems   = 256
	spfStandardReference         = "https://www.rfc-editor.org/rfc/rfc7208.html"
	dkimStandardReference        = "https://www.rfc-editor.org/rfc/rfc6376.html"
	dkimCryptoReference          = "https://www.rfc-editor.org/rfc/rfc8301.html"
	dkimEd25519Reference         = "https://www.rfc-editor.org/rfc/rfc8463.html"
	dmarcStandardReference       = "https://www.rfc-editor.org/rfc/rfc9989.html"
	eaiStandardReference         = "https://www.rfc-editor.org/rfc/rfc8616.html"
)

// ErrInvalidAuthenticationRecord identifies an invalid owner/domain input to
// a pure authentication-record helper.
var ErrInvalidAuthenticationRecord = errors.New("invalid authentication record input")

// AuthenticationRecordStatus classifies supplied DNS authentication evidence.
type AuthenticationRecordStatus string

const (
	AuthenticationRecordValid         AuthenticationRecordStatus = "valid"
	AuthenticationRecordMissing       AuthenticationRecordStatus = "missing"
	AuthenticationRecordMalformed     AuthenticationRecordStatus = "malformed"
	AuthenticationRecordInvalid       AuthenticationRecordStatus = "invalid"
	AuthenticationRecordUnsupported   AuthenticationRecordStatus = "unsupported"
	AuthenticationRecordWeak          AuthenticationRecordStatus = "weak"
	AuthenticationRecordConflicting   AuthenticationRecordStatus = "conflicting"
	AuthenticationRecordIndeterminate AuthenticationRecordStatus = "indeterminate"
)

// AuthenticationDiagnostic describes a parser conclusion. Message and
// Standard are library-controlled; raw DNS text remains in evidence fields.
type AuthenticationDiagnostic struct {
	Code       DiagnosticCode  `json:"code"`
	Severity   FindingSeverity `json:"severity"`
	Name       string          `json:"name,omitempty"`
	RecordType DNSRecordType   `json:"record_type,omitempty"`
	EvidenceID EvidenceID      `json:"evidence_id,omitempty"`
	Path       string          `json:"path,omitempty"`
	Offset     int             `json:"offset,omitempty"`
	Message    string          `json:"message"`
	Standard   string          `json:"standard"`
	ObservedAt time.Time       `json:"observed_at,omitempty"`
}

// ParsedAuthenticationRecord preserves one candidate TXT record and exactly
// one typed semantic representation.
type ParsedAuthenticationRecord struct {
	EvidenceID         EvidenceID                 `json:"evidence_id"`
	Status             AuthenticationRecordStatus `json:"status"`
	Raw                string                     `json:"raw"`
	Fragments          []string                   `json:"fragments"`
	FragmentsAvailable bool                       `json:"fragments_available"`
	TTL                DNSDurationEvidence        `json:"ttl"`
	SPF                *SPFRecord                 `json:"spf,omitempty"`
	DKIM               *DKIMKeyRecord             `json:"dkim,omitempty"`
	DMARC              *DMARCPolicyRecord         `json:"dmarc,omitempty"`
}

// AuthenticationRecordSet is the parsed result for one owner name and record type.
type AuthenticationRecordSet struct {
	Name              string                       `json:"name"`
	Type              DNSRecordType                `json:"type"`
	Status            AuthenticationRecordStatus   `json:"status"`
	ObservationStatus DNSObservationStatus         `json:"observation_status"`
	ObservedAt        time.Time                    `json:"observed_at"`
	TTL               DNSDurationEvidence          `json:"ttl"`
	NegativeTTL       DNSDurationEvidence          `json:"negative_ttl"`
	SOA               *DNSSOAEvidence              `json:"soa,omitempty"`
	Resolver          string                       `json:"resolver,omitempty"`
	AnswerSource      DNSAnswerSource              `json:"answer_source"`
	RCode             DNSRCodeEvidence             `json:"rcode"`
	CanonicalName     string                       `json:"canonical_name,omitempty"`
	CNAMEPath         []string                     `json:"cname_path"`
	Attempts          int                          `json:"attempts"`
	References        []DNSRecordReference         `json:"references"`
	Records           []ParsedAuthenticationRecord `json:"records"`
}

// DNSAuthenticationResult is an immutable, reusable parse of a DNS snapshot.
// Accessors return defensive copies and never perform DNS or other I/O.
type DNSAuthenticationResult struct {
	metadata       ResultMetadata
	snapshotDigest AnalysisID
	digest         AnalysisID
	recordSets     []AuthenticationRecordSet
	diagnostics    []AuthenticationDiagnostic
}

// ResultMetadata returns authentication-record metadata without performing work.
func (result DNSAuthenticationResult) ResultMetadata() ResultMetadata { return result.metadata }

// SnapshotDigest identifies the exact DNS snapshot supplied to the parser.
func (result DNSAuthenticationResult) SnapshotDigest() AnalysisID { return result.snapshotDigest }

// Digest identifies the canonical parsed contents.
func (result DNSAuthenticationResult) Digest() AnalysisID { return result.digest }

// RecordSets returns deterministic owner-name and type ordered results.
func (result DNSAuthenticationResult) RecordSets() []AuthenticationRecordSet {
	return cloneAuthenticationRecordSets(result.recordSets)
}

// Diagnostics returns deterministic parser diagnostics.
func (result DNSAuthenticationResult) Diagnostics() []AuthenticationDiagnostic {
	return append([]AuthenticationDiagnostic(nil), result.diagnostics...)
}

// ParseAuthenticationRecords parses only values already present in snapshot.
// It performs no DNS lookups, report processing, filesystem access, or other I/O.
func ParseAuthenticationRecords(snapshot DNSSnapshot) (DNSAuthenticationResult, error) {
	metadata := snapshot.ResultMetadata()
	if metadata.Mode != AnalysisModeDNSSnapshot || metadata.ContractVersion != AnalysisContractVersion || snapshot.Digest() == "" {
		return DNSAuthenticationResult{}, ErrInvalidAnalysisResult
	}

	recordSets := make([]AuthenticationRecordSet, 0)
	diagnostics := make([]AuthenticationDiagnostic, 0)
	for _, observation := range snapshot.Observations() {
		types := recordTypesForObservation(observation)
		for _, recordType := range types {
			set, setDiagnostics := parseAuthenticationRecordSet(observation, recordType, metadata.GeneratedAt)
			recordSets = append(recordSets, set)
			diagnostics = append(diagnostics, setDiagnostics...)
		}
	}
	sort.Slice(recordSets, func(i, j int) bool {
		if recordSets[i].Name != recordSets[j].Name {
			return recordSets[i].Name < recordSets[j].Name
		}
		return recordSets[i].Type < recordSets[j].Type
	})
	applySPFGraphEvidence(recordSets, &diagnostics)
	sortAuthenticationDiagnostics(diagnostics)

	canonical, err := json.Marshal(struct {
		SnapshotDigest AnalysisID                 `json:"snapshot_digest"`
		RecordSets     []AuthenticationRecordSet  `json:"record_sets"`
		Diagnostics    []AuthenticationDiagnostic `json:"diagnostics"`
	}{snapshot.Digest(), recordSets, diagnostics})
	if err != nil {
		return DNSAuthenticationResult{}, errors.Join(ErrInvalidAnalysisResult, err)
	}
	return DNSAuthenticationResult{
		metadata: ResultMetadata{
			ContractVersion: AnalysisContractVersion,
			Mode:            AnalysisModeDNSAuthentication,
			GeneratedAt:     metadata.GeneratedAt,
			Evaluation:      Evaluation{State: EvaluationStateEvaluated},
		},
		snapshotDigest: snapshot.Digest(),
		digest:         StableAnalysisID("dns_authentication_records", string(canonical)),
		recordSets:     cloneAuthenticationRecordSets(recordSets),
		diagnostics:    append([]AuthenticationDiagnostic(nil), diagnostics...),
	}, nil
}

func recordTypesForObservation(observation DNSObservation) []DNSRecordType {
	present := map[DNSRecordType]bool{}
	for _, reference := range observation.References {
		present[reference.Type] = true
	}
	result := make([]DNSRecordType, 0, len(present))
	for _, recordType := range []DNSRecordType{DNSRecordSPF, DNSRecordDKIM, DNSRecordDMARC} {
		if present[recordType] {
			result = append(result, recordType)
		}
	}
	return result
}

func parseAuthenticationRecordSet(observation DNSObservation, recordType DNSRecordType, observedAt time.Time) (AuthenticationRecordSet, []AuthenticationDiagnostic) {
	set := AuthenticationRecordSet{
		Name: observation.Name, Type: recordType, ObservationStatus: observation.Status,
		ObservedAt: observedAt, TTL: observation.TTL, NegativeTTL: observation.NegativeTTL, SOA: cloneSOA(observation.SOA),
		Resolver: observation.Resolver, AnswerSource: observation.AnswerSource, RCode: observation.RCode,
		CanonicalName: observation.CanonicalName, CNAMEPath: cloneStrings(observation.CNAMEPath), Attempts: observation.Attempts,
		References: referencesForRecordType(observation.References, recordType), Records: []ParsedAuthenticationRecord{},
	}
	if observation.Status != DNSObservationSuccess {
		set.Status = authenticationStatusForObservation(observation.Status)
		return set, []AuthenticationDiagnostic{recordSetDiagnostic(set, "dns.authentication.evidence_unavailable", "The supplied DNS snapshot does not contain usable TXT evidence for this record.")}
	}

	candidates := candidateTXTRecords(observation.Records, recordType)
	if len(candidates) == 0 {
		set.Status = AuthenticationRecordMissing
		return set, []AuthenticationDiagnostic{recordSetDiagnostic(set, "dns.authentication.record_missing", "No candidate authentication record was present in the supplied TXT RRset.")}
	}

	diagnostics := make([]AuthenticationDiagnostic, 0)
	for index, candidate := range candidates {
		evidenceID := EvidenceID(StableAnalysisID("dns_authentication_record", string(recordType), observation.Name, candidate.Joined))
		parsed, recordDiagnostics := parseAuthenticationCandidate(recordType, candidate.Joined)
		applyAuthenticationOwnerMetadata(&parsed, observation.Name)
		parsed.EvidenceID = evidenceID
		parsed.Raw = candidate.Joined
		parsed.Fragments = cloneStrings(candidate.Fragments)
		parsed.FragmentsAvailable = candidate.FragmentsAvailable
		parsed.TTL = candidate.TTL
		set.Records = append(set.Records, parsed)
		for diagnosticIndex := range recordDiagnostics {
			diagnostic := &recordDiagnostics[diagnosticIndex]
			diagnostic.Name = observation.Name
			diagnostic.RecordType = recordType
			diagnostic.EvidenceID = evidenceID
			diagnostic.ObservedAt = observedAt
			if diagnostic.Path != "" {
				diagnostic.Path = "records[" + itoa(index) + "]." + diagnostic.Path
			}
		}
		diagnostics = append(diagnostics, recordDiagnostics...)
	}

	if len(set.Records) > 1 {
		set.Status = AuthenticationRecordConflicting
		diagnostics = append(diagnostics, recordSetDiagnostic(set, "dns.authentication.multiple_records", "Multiple candidate policy records make this owner name invalid."))
	} else {
		set.Status = set.Records[0].Status
	}
	return set, diagnostics
}

func referencesForRecordType(values []DNSRecordReference, recordType DNSRecordType) []DNSRecordReference {
	result := make([]DNSRecordReference, 0)
	for _, value := range values {
		if value.Type == recordType {
			result = append(result, value)
		}
	}
	sortDNSReferences(result)
	return result
}

func applyAuthenticationOwnerMetadata(record *ParsedAuthenticationRecord, name string) {
	if record.DKIM != nil {
		selector, domain, ok := strings.Cut(name, "._domainkey.")
		if ok {
			record.DKIM.Selector = selector
			record.DKIM.Domain = domain
		}
	}
	if record.DMARC != nil {
		record.DMARC.PolicyDomain = strings.TrimPrefix(name, "_dmarc.")
	}
}

func candidateTXTRecords(records []TXTRecord, recordType DNSRecordType) []TXTRecord {
	result := make([]TXTRecord, 0)
	for _, record := range records {
		value := strings.TrimSpace(record.Joined)
		switch recordType {
		case DNSRecordSPF:
			if hasVersionPrefix(value, "v=spf1") {
				result = append(result, record)
			}
		case DNSRecordDKIM:
			result = append(result, record)
		case DNSRecordDMARC:
			if hasDMARCVersionTag(value) {
				result = append(result, record)
			}
		}
	}
	return result
}

func hasDMARCVersionTag(value string) bool {
	first, _, _ := strings.Cut(value, ";")
	name, tagValue, found := strings.Cut(first, "=")
	return found && strings.EqualFold(strings.TrimSpace(name), "v") && strings.EqualFold(strings.TrimSpace(tagValue), "DMARC1")
}

func parseAuthenticationCandidate(recordType DNSRecordType, value string) (ParsedAuthenticationRecord, []AuthenticationDiagnostic) {
	switch recordType {
	case DNSRecordSPF:
		record, diagnostics := ParseSPFRecord(value)
		return ParsedAuthenticationRecord{Status: record.Status, SPF: &record}, diagnostics
	case DNSRecordDKIM:
		record, diagnostics := ParseDKIMKeyRecord(value)
		return ParsedAuthenticationRecord{Status: record.Status, DKIM: &record}, diagnostics
	case DNSRecordDMARC:
		record, diagnostics := ParseDMARCPolicyRecord(value)
		return ParsedAuthenticationRecord{Status: record.Status, DMARC: &record}, diagnostics
	default:
		return ParsedAuthenticationRecord{Status: AuthenticationRecordUnsupported}, nil
	}
}

func authenticationStatusForObservation(status DNSObservationStatus) AuthenticationRecordStatus {
	switch status {
	case DNSObservationNXDOMAIN, DNSObservationNoData, DNSObservationNotFound:
		return AuthenticationRecordMissing
	default:
		return AuthenticationRecordIndeterminate
	}
}

func recordSetDiagnostic(set AuthenticationRecordSet, code, message string) AuthenticationDiagnostic {
	severity := FindingSeverityMedium
	switch set.Status {
	case AuthenticationRecordConflicting:
		severity = FindingSeverityHigh
	case AuthenticationRecordIndeterminate:
		severity = FindingSeverityLow
	}
	return AuthenticationDiagnostic{
		Code: DiagnosticCode(code), Severity: severity, Name: set.Name, RecordType: set.Type,
		Message: message, Standard: standardForRecordType(set.Type), ObservedAt: set.ObservedAt,
	}
}

func standardForRecordType(recordType DNSRecordType) string {
	switch recordType {
	case DNSRecordSPF:
		return spfStandardReference
	case DNSRecordDKIM:
		return dkimStandardReference
	case DNSRecordDMARC:
		return dmarcStandardReference
	default:
		return ""
	}
}

func sortAuthenticationDiagnostics(values []AuthenticationDiagnostic) {
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.RecordType != right.RecordType {
			return left.RecordType < right.RecordType
		}
		if left.EvidenceID != right.EvidenceID {
			return left.EvidenceID < right.EvidenceID
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.Code < right.Code
	})
}

func cloneAuthenticationRecordSets(values []AuthenticationRecordSet) []AuthenticationRecordSet {
	result := make([]AuthenticationRecordSet, len(values))
	for index, value := range values {
		result[index] = value
		result[index].References = cloneDNSReferences(value.References)
		result[index].SOA = cloneSOA(value.SOA)
		result[index].CNAMEPath = cloneStrings(value.CNAMEPath)
		result[index].Records = make([]ParsedAuthenticationRecord, len(value.Records))
		for recordIndex, record := range value.Records {
			result[index].Records[recordIndex] = record
			result[index].Records[recordIndex].Fragments = cloneStrings(record.Fragments)
			if record.SPF != nil {
				copy := cloneSPFRecord(*record.SPF)
				result[index].Records[recordIndex].SPF = &copy
			}
			if record.DKIM != nil {
				copy := cloneDKIMKeyRecord(*record.DKIM)
				result[index].Records[recordIndex].DKIM = &copy
			}
			if record.DMARC != nil {
				copy := cloneDMARCPolicyRecord(*record.DMARC)
				result[index].Records[recordIndex].DMARC = &copy
			}
		}
	}
	return result
}

func hasVersionPrefix(value, version string) bool {
	if len(value) < len(version) || !strings.EqualFold(value[:len(version)], version) {
		return false
	}
	return len(value) == len(version) || value[len(version)] == ' ' || value[len(version)] == '\t'
}

type authenticationTag struct {
	name   string
	value  string
	offset int
}

func parseAuthenticationTags(raw, standard string) ([]authenticationTag, []AuthenticationDiagnostic) {
	parts := strings.SplitN(raw, ";", maxAuthenticationTerms+1)
	tags := make([]authenticationTag, 0, len(parts))
	diagnostics := make([]AuthenticationDiagnostic, 0)
	if len(parts) > maxAuthenticationTerms {
		parts = parts[:maxAuthenticationTerms]
		diagnostics = append(diagnostics, parserDiagnostic("dns.authentication.malformed_term_limit", FindingSeverityHigh, "tags", 0, "The authentication record contains too many tags.", standard))
	}
	seen := map[string]bool{}
	offset := 0
	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		partOffset := offset + strings.Index(part, trimmed)
		offset += len(part) + 1
		if trimmed == "" {
			if index != len(parts)-1 {
				diagnostics = append(diagnostics, parserDiagnostic("dns.authentication.empty_tag", FindingSeverityMedium, "tags", partOffset, "An empty tag is not valid.", standard))
			}
			continue
		}
		name, value, found := strings.Cut(trimmed, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if !found || !validAuthenticationTagName(name) {
			diagnostics = append(diagnostics, parserDiagnostic("dns.authentication.malformed_tag", FindingSeverityHigh, "tags", partOffset, "A tag has invalid syntax.", standard))
			continue
		}
		if seen[name] {
			diagnostics = append(diagnostics, parserDiagnostic("dns.authentication.duplicate_tag", FindingSeverityHigh, "tags", partOffset, "A tag appears more than once.", standard))
			continue
		}
		seen[name] = true
		tags = append(tags, authenticationTag{name: name, value: value, offset: partOffset})
	}
	return tags, diagnostics
}

func validAuthenticationTagName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func parserDiagnostic(code string, severity FindingSeverity, path string, offset int, message, standard string) AuthenticationDiagnostic {
	return AuthenticationDiagnostic{Code: DiagnosticCode(code), Severity: severity, Path: path, Offset: offset, Message: message, Standard: standard}
}

func statusFromDiagnostics(diagnostics []AuthenticationDiagnostic) AuthenticationRecordStatus {
	status := AuthenticationRecordValid
	for _, diagnostic := range diagnostics {
		code := string(diagnostic.Code)
		switch {
		case strings.Contains(code, "malformed") || strings.Contains(code, "empty_tag"):
			return AuthenticationRecordMalformed
		case strings.Contains(code, "invalid") || strings.Contains(code, "missing_required") || strings.Contains(code, "duplicate"):
			status = strongerAuthenticationStatus(status, AuthenticationRecordInvalid)
		case strings.Contains(code, ".unsupported") || strings.Contains(code, "unsupported_") || strings.Contains(code, "unknown_mechanism"):
			status = strongerAuthenticationStatus(status, AuthenticationRecordUnsupported)
		case strings.Contains(code, "weak") || strings.Contains(code, "revoked") || strings.Contains(code, "deprecated"):
			status = strongerAuthenticationStatus(status, AuthenticationRecordWeak)
		}
	}
	return status
}

func strongerAuthenticationStatus(left, right AuthenticationRecordStatus) AuthenticationRecordStatus {
	rank := map[AuthenticationRecordStatus]int{
		AuthenticationRecordValid: 0, AuthenticationRecordWeak: 1, AuthenticationRecordUnsupported: 2,
		AuthenticationRecordInvalid: 3, AuthenticationRecordMalformed: 4,
	}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}
