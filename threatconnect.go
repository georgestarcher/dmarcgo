package dmarcgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// ThreatConnectAPIContractVersion identifies the vendor API contract used by
	// the encoder. It is independent of the Go module and mapping versions.
	ThreatConnectAPIContractVersion = "v3"

	// ThreatConnectExportVersion identifies the dmarcgo-to-ThreatConnect
	// mapping. It is independent of the vendor API and Go module versions.
	ThreatConnectExportVersion = "1"

	// ThreatConnectIndicatorsEndpoint is the relative API endpoint that accepts
	// each encoded request. The library never calls it.
	ThreatConnectIndicatorsEndpoint = "/api/v3/indicators"

	maxThreatConnectMetadataItems = 64

	threatConnectAddressDescription = "DMARC aggregate authentication-failure source selected for human review. This payload does not assert malicious activity or authorize blocking."
	threatConnectASNDescription     = "DMARC aggregate ASN context selected for human review. This payload does not assert malicious activity or authorize blocking."
)

var (
	// ErrInvalidThreatConnectExportOptions identifies an invalid selection,
	// option, timestamp, owner, metadata value, or mismatched completed input.
	ErrInvalidThreatConnectExportOptions = errors.New("invalid ThreatConnect export options")
	// ErrInvalidThreatConnectIndicatorPayload identifies a malformed or
	// internally inconsistent supported ThreatConnect v3 request payload.
	ErrInvalidThreatConnectIndicatorPayload = errors.New("invalid ThreatConnect indicator payload")
	// ErrUnsupportedThreatConnectIndicatorType identifies an input candidate
	// type for which this encoder has no reviewed vendor mapping.
	ErrUnsupportedThreatConnectIndicatorType = errors.New("unsupported ThreatConnect indicator type")
)

// ThreatConnectIndicatorType is a supported ThreatConnect v3 Indicator type.
type ThreatConnectIndicatorType string

const (
	ThreatConnectIndicatorAddress ThreatConnectIndicatorType = "Address"
	ThreatConnectIndicatorASN     ThreatConnectIndicatorType = "ASN"
)

// ThreatConnectOwner selects an explicit Organization, Community, or Source.
// Set either ID or Name, never both. A zero value omits both fields so the
// eventual API call uses the API user's Organization according to the vendor
// contract.
type ThreatConnectOwner struct {
	ID   int64
	Name string
}

// ThreatConnectTag is either a standard Tag name or an ATT&CK technique ID.
// Exactly one field must be set. Values are caller-controlled tenant data.
type ThreatConnectTag struct {
	Name        string
	TechniqueID string
}

// ThreatConnectAttribute configures one tenant-supported Indicator Attribute.
// Type must be valid for the target Indicator type in the caller's instance.
// Value, Source, and SecurityLabels are untrusted data and are never converted
// into library-generated explanations or instructions.
type ThreatConnectAttribute struct {
	Type           string
	Value          string
	Source         string
	Default        bool
	Pinned         bool
	SecurityLabels []string
}

// ThreatConnectIndicatorSettings controls common vendor fields. Nil booleans
// select review-oriented defaults: active=false and privateFlag=true.
// MapEvidenceConfidence is opt-in because dmarcgo confidence describes the
// strength of review evidence, not confidence that a source is malicious. An
// explicit Confidence and MapEvidenceConfidence=true are mutually exclusive.
// Rating is always explicit because candidate score is not a Threat Rating.
type ThreatConnectIndicatorSettings struct {
	Active                *bool
	PrivateFlag           *bool
	MapEvidenceConfidence *bool
	Confidence            *int
	Rating                *int
	ExternalDateExpires   *time.Time
	Description           string
	Source                string
	Tags                  []ThreatConnectTag
	SecurityLabels        []string
	Attributes            []ThreatConnectAttribute
}

// ThreatConnectCandidateSelection is an explicit caller decision to encode one
// review-eligible, non-excluded source candidate as an Address request.
type ThreatConnectCandidateSelection struct {
	CandidateID AnalysisID
	Settings    ThreatConnectIndicatorSettings
}

// ThreatConnectASNSelection is an explicit caller decision to encode one ASN
// rollup from matching source enrichment. The rollup must retain candidate,
// source-IP, and assertion evidence.
type ThreatConnectASNSelection struct {
	ASN      uint32
	Settings ThreatConnectIndicatorSettings
}

// ThreatConnectExportOptions controls pure request encoding. GeneratedAt
// defaults to the latest completed-input timestamp and never consults the
// system clock. Defaults apply to every selected item; per-selection Settings
// override scalar values and append metadata collections.
type ThreatConnectExportOptions struct {
	GeneratedAt         time.Time
	Owner               ThreatConnectOwner
	Defaults            ThreatConnectIndicatorSettings
	CandidateSelections []ThreatConnectCandidateSelection
	ASNSelections       []ThreatConnectASNSelection
}

// ThreatConnectIndicatorSource retains the normalized evidence behind one
// native request without adding non-vendor fields to its JSON. Applications
// can map these references into tenant-specific Attributes or retain them as
// caller-owned export metadata.
type ThreatConnectIndicatorSource struct {
	MappingVersion         string                          `json:"mapping_version"`
	GeneratedAt            time.Time                       `json:"generated_at"`
	ThreatCandidateDigest  AnalysisID                      `json:"threat_candidate_digest"`
	SourceEnrichmentDigest AnalysisID                      `json:"source_enrichment_digest,omitempty"`
	EnrichmentStatuses     []ThreatConnectEnrichmentStatus `json:"enrichment_statuses"`
	CandidateIDs           []AnalysisID                    `json:"candidate_ids"`
	ObservationIDs         []EvidenceID                    `json:"observation_ids"`
	ReportEvidenceIDs      []EvidenceID                    `json:"report_evidence_ids"`
	CorrelationFindingIDs  []FindingID                     `json:"correlation_finding_ids"`
	AssertionIDs           []AnalysisID                    `json:"assertion_ids"`
	SourceIPs              []string                        `json:"source_ips"`
	StaleSourceIPs         []string                        `json:"stale_source_ips"`
	ConflictingSourceIPs   []string                        `json:"conflicting_source_ips"`
}

// ThreatConnectEnrichmentStatus preserves one source-enrichment outcome in
// export metadata. It is not added to the vendor request automatically.
type ThreatConnectEnrichmentStatus struct {
	SourceIP string                 `json:"source_ip"`
	Status   SourceEnrichmentStatus `json:"status"`
}

// ThreatConnectIndicatorPayload is one immutable, vendor-native v3 POST
// body. MarshalJSON returns only vendor fields; source references are available
// separately through Source.
type ThreatConnectIndicatorPayload struct {
	indicatorType ThreatConnectIndicatorType
	summary       string
	source        ThreatConnectIndicatorSource
	raw           []byte
}

// Type returns the supported vendor Indicator type.
func (payload ThreatConnectIndicatorPayload) Type() ThreatConnectIndicatorType {
	return payload.indicatorType
}

// Summary returns the owner-unique vendor summary value: a canonical IP or an
// ASN-prefixed number.
func (payload ThreatConnectIndicatorPayload) Summary() string { return payload.summary }

// Source returns a defensive copy of the evidence references behind a request.
func (payload ThreatConnectIndicatorPayload) Source() ThreatConnectIndicatorSource {
	return cloneThreatConnectIndicatorSource(payload.source)
}

// MarshalJSON implements json.Marshaler and returns one validated native v3
// Indicator request body.
func (payload ThreatConnectIndicatorPayload) MarshalJSON() ([]byte, error) {
	if err := ValidateThreatConnectIndicatorPayload(payload); err != nil {
		return nil, err
	}
	return append([]byte(nil), payload.raw...), nil
}

// ThreatConnectUnsupportedTypeError preserves a stable candidate identifier
// and the unsupported normalized type without copying the source address.
type ThreatConnectUnsupportedTypeError struct {
	CandidateID AnalysisID
	Type        ThreatCandidateIPType
}

func (err *ThreatConnectUnsupportedTypeError) Error() string {
	return fmt.Sprintf("%s for candidate %s: %s", ErrUnsupportedThreatConnectIndicatorType, err.CandidateID, err.Type)
}

func (err *ThreatConnectUnsupportedTypeError) Unwrap() error {
	return ErrUnsupportedThreatConnectIndicatorType
}

// WriteThreatConnectIndicatorPayload writes one validated native request body
// followed by a newline. It performs no HTTP request, lookup, retry, analysis,
// enrichment, credential access, or submission.
func WriteThreatConnectIndicatorPayload(writer io.Writer, payload ThreatConnectIndicatorPayload) error {
	if writer == nil {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	encoded, err := payload.MarshalJSON()
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	written, err := writer.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

// BuildThreatConnectIndicatorPayloads converts explicit candidate and ASN
// selections into deterministic native ThreatConnect v3 request bodies. It is
// pure and performs no DNS, HTTP, PTR, SMTP, ICMP, filesystem, enrichment,
// credential, system-clock, submission, retry, or direct subject-IP activity.
func BuildThreatConnectIndicatorPayloads(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, options ThreatConnectExportOptions) ([]ThreatConnectIndicatorPayload, error) {
	for _, candidate := range candidates.Candidates() {
		if candidate.IPType != ThreatCandidateIPv4 && candidate.IPType != ThreatCandidateIPv6 {
			return nil, &ThreatConnectUnsupportedTypeError{CandidateID: candidate.ID, Type: candidate.IPType}
		}
	}
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return nil, errors.Join(ErrInvalidThreatConnectExportOptions, err)
	}
	normalized, err := normalizeThreatConnectExportOptions(candidates, enrichment, options)
	if err != nil {
		return nil, err
	}

	candidateByID := make(map[AnalysisID]ThreatCandidate, len(candidates.candidates))
	assertionIDsByCandidate := map[AnalysisID][]AnalysisID{}
	enrichmentStatusByCandidate := map[AnalysisID]SourceEnrichmentStatus{}
	staleAssertionByCandidate := map[AnalysisID]bool{}
	for _, candidate := range candidates.Candidates() {
		candidateByID[candidate.ID] = candidate
	}
	var enrichmentDigest AnalysisID
	var asnByNumber map[uint32]ASNEnrichment
	if enrichment != nil {
		enrichmentDigest = enrichment.Digest()
		for _, value := range enrichment.Candidates() {
			candidateByID[value.Candidate.ID] = value.Candidate
			enrichmentStatusByCandidate[value.Candidate.ID] = value.Status
			staleAssertionByCandidate[value.Candidate.ID] = slices.ContainsFunc(value.Metadata.Assertions, func(assertion IPMetadataAssertion) bool {
				return assertion.Freshness == SourceEnrichmentFreshnessStale
			})
			for _, assertion := range value.Metadata.Assertions {
				assertionIDsByCandidate[value.Candidate.ID] = append(assertionIDsByCandidate[value.Candidate.ID], assertion.ID)
			}
			assertionIDsByCandidate[value.Candidate.ID] = compactSortedAnalysisIDs(assertionIDsByCandidate[value.Candidate.ID])
		}
		asnByNumber = make(map[uint32]ASNEnrichment, len(enrichment.asns))
		for _, asn := range enrichment.ASNs() {
			asnByNumber[asn.ASN] = asn
		}
	}

	payloads := make([]ThreatConnectIndicatorPayload, 0, len(normalized.CandidateSelections)+len(normalized.ASNSelections))
	for _, selection := range normalized.CandidateSelections {
		candidate, exists := candidateByID[selection.CandidateID]
		if !exists || !sourceEnrichmentEligible(candidate) || !candidate.FirstSeen.Available || !candidate.LastSeen.Available ||
			candidate.FirstSeen.Value.After(candidate.LastSeen.Value) || candidate.DualFailureMessages < 1 {
			return nil, errors.Join(ErrInvalidThreatConnectExportOptions, ErrInvalidAnalysisResult)
		}
		address, parseErr := netip.ParseAddr(candidate.SourceIP)
		if parseErr != nil || address != address.Unmap() || address.String() != candidate.SourceIP {
			return nil, errors.Join(ErrInvalidThreatConnectExportOptions, ErrInvalidAnalysisResult)
		}
		source := ThreatConnectIndicatorSource{
			MappingVersion: ThreatConnectExportVersion, GeneratedAt: normalized.GeneratedAt,
			ThreatCandidateDigest: candidates.Digest(), SourceEnrichmentDigest: enrichmentDigest,
			EnrichmentStatuses: []ThreatConnectEnrichmentStatus{}, CandidateIDs: []AnalysisID{candidate.ID},
			ObservationIDs:        append([]EvidenceID{}, candidate.ObservationIDs...),
			ReportEvidenceIDs:     append([]EvidenceID{}, candidate.ReportEvidenceIDs...),
			CorrelationFindingIDs: append([]FindingID{}, candidate.CorrelationFindingIDs...),
			AssertionIDs:          append([]AnalysisID{}, assertionIDsByCandidate[candidate.ID]...), SourceIPs: []string{candidate.SourceIP},
			StaleSourceIPs: []string{}, ConflictingSourceIPs: []string{},
		}
		if status, available := enrichmentStatusByCandidate[candidate.ID]; available {
			source.EnrichmentStatuses = []ThreatConnectEnrichmentStatus{{SourceIP: candidate.SourceIP, Status: status}}
			if staleAssertionByCandidate[candidate.ID] {
				source.StaleSourceIPs = []string{candidate.SourceIP}
			}
			if status == SourceEnrichmentConflicting {
				source.ConflictingSourceIPs = []string{candidate.SourceIP}
			}
		}
		settings := mergeThreatConnectSettings(normalized.Defaults, selection.Settings)
		payload, buildErr := buildThreatConnectPayload(ThreatConnectIndicatorAddress, candidate.SourceIP, candidate.FirstSeen.Value,
			candidate.LastSeen.Value, candidate.DualFailureMessages, candidate.Confidence, normalized.Owner, settings, source)
		if buildErr != nil {
			return nil, buildErr
		}
		payloads = append(payloads, payload)
	}

	for _, selection := range normalized.ASNSelections {
		asn, exists := asnByNumber[selection.ASN]
		if !exists || asn.ASN == 0 || len(asn.CandidateIDs) == 0 || len(asn.SourceIPs) == 0 || len(asn.AssertionIDs) == 0 {
			return nil, errors.Join(ErrInvalidThreatConnectExportOptions, ErrInvalidAnalysisResult)
		}
		firstSeen, lastSeen, observations, confidence, aggregateErr := aggregateThreatConnectASNEvidence(asn, candidateByID)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		source := threatConnectASNSource(normalized.GeneratedAt, candidates.Digest(), enrichmentDigest, asn, candidateByID, enrichmentStatusByCandidate)
		settings := mergeThreatConnectSettings(normalized.Defaults, selection.Settings)
		payload, buildErr := buildThreatConnectPayload(ThreatConnectIndicatorASN, "ASN"+strconv.FormatUint(uint64(asn.ASN), 10), firstSeen,
			lastSeen, observations, confidence, normalized.Owner, settings, source)
		if buildErr != nil {
			return nil, buildErr
		}
		payloads = append(payloads, payload)
	}

	sort.Slice(payloads, func(i, j int) bool {
		if payloads[i].indicatorType != payloads[j].indicatorType {
			return payloads[i].indicatorType < payloads[j].indicatorType
		}
		return payloads[i].summary < payloads[j].summary
	})
	return payloads, nil
}

func normalizeThreatConnectExportOptions(candidates ThreatCandidateResult, enrichment *SourceEnrichmentResult, options ThreatConnectExportOptions) (ThreatConnectExportOptions, error) {
	latestInput := candidates.ResultMetadata().GeneratedAt
	if enrichment != nil {
		if err := validateMatchingSourceEnrichment(candidates, *enrichment); err != nil {
			return ThreatConnectExportOptions{}, errors.Join(ErrInvalidThreatConnectExportOptions, err)
		}
		if enrichment.ResultMetadata().GeneratedAt.After(latestInput) {
			latestInput = enrichment.ResultMetadata().GeneratedAt
		}
	}
	if len(options.CandidateSelections)+len(options.ASNSelections) == 0 || len(options.ASNSelections) > 0 && enrichment == nil {
		return ThreatConnectExportOptions{}, ErrInvalidThreatConnectExportOptions
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = latestInput
	} else {
		options.GeneratedAt = options.GeneratedAt.UTC()
	}
	if options.GeneratedAt.IsZero() || !sourceEnrichmentTimeMarshalable(options.GeneratedAt) || options.GeneratedAt.Before(latestInput) {
		return ThreatConnectExportOptions{}, ErrInvalidThreatConnectExportOptions
	}
	options.GeneratedAt = options.GeneratedAt.UTC()
	options.Owner.Name = strings.TrimSpace(options.Owner.Name)
	if options.Owner.ID < 0 || options.Owner.ID > 0 && options.Owner.Name != "" || !validThreatConnectOptionalText(options.Owner.Name) {
		return ThreatConnectExportOptions{}, ErrInvalidThreatConnectExportOptions
	}
	options.Defaults = cloneThreatConnectSettings(options.Defaults)
	options.CandidateSelections = append([]ThreatConnectCandidateSelection(nil), options.CandidateSelections...)
	for index := range options.CandidateSelections {
		options.CandidateSelections[index].Settings = cloneThreatConnectSettings(options.CandidateSelections[index].Settings)
	}
	sort.Slice(options.CandidateSelections, func(i, j int) bool {
		return options.CandidateSelections[i].CandidateID < options.CandidateSelections[j].CandidateID
	})
	for index, selection := range options.CandidateSelections {
		if selection.CandidateID == "" || index > 0 && options.CandidateSelections[index-1].CandidateID == selection.CandidateID {
			return ThreatConnectExportOptions{}, ErrInvalidThreatConnectExportOptions
		}
	}
	options.ASNSelections = append([]ThreatConnectASNSelection(nil), options.ASNSelections...)
	for index := range options.ASNSelections {
		options.ASNSelections[index].Settings = cloneThreatConnectSettings(options.ASNSelections[index].Settings)
	}
	sort.Slice(options.ASNSelections, func(i, j int) bool { return options.ASNSelections[i].ASN < options.ASNSelections[j].ASN })
	for index, selection := range options.ASNSelections {
		if selection.ASN == 0 || index > 0 && options.ASNSelections[index-1].ASN == selection.ASN {
			return ThreatConnectExportOptions{}, ErrInvalidThreatConnectExportOptions
		}
	}
	return options, nil
}

func buildThreatConnectPayload(indicatorType ThreatConnectIndicatorType, summary string, firstSeen, lastSeen time.Time, observations int64, evidenceConfidence int,
	owner ThreatConnectOwner, settings ThreatConnectIndicatorSettings, source ThreatConnectIndicatorSource,
) (ThreatConnectIndicatorPayload, error) {
	active, privateFlag := false, true
	if settings.Active != nil {
		active = *settings.Active
	}
	if settings.PrivateFlag != nil {
		privateFlag = *settings.PrivateFlag
	}
	confidence, err := threatConnectConfidence(settings, evidenceConfidence)
	if err != nil {
		return ThreatConnectIndicatorPayload{}, err
	}
	if settings.Rating != nil && (*settings.Rating < 1 || *settings.Rating > 5) {
		return ThreatConnectIndicatorPayload{}, ErrInvalidThreatConnectExportOptions
	}
	firstSeen = firstSeen.UTC()
	lastSeen = lastSeen.UTC()
	if observations < 1 || firstSeen.After(lastSeen) || !sourceEnrichmentTimeMarshalable(firstSeen) || !sourceEnrichmentTimeMarshalable(lastSeen) {
		return ThreatConnectIndicatorPayload{}, ErrInvalidThreatConnectExportOptions
	}
	expires := cloneTimePointer(settings.ExternalDateExpires)
	if expires != nil {
		*expires = expires.UTC()
		if !sourceEnrichmentTimeMarshalable(*expires) || !expires.After(source.GeneratedAt) {
			return ThreatConnectIndicatorPayload{}, ErrInvalidThreatConnectExportOptions
		}
	}
	attributes, tags, securityLabels, err := normalizeThreatConnectMetadata(indicatorType, settings)
	if err != nil {
		return ThreatConnectIndicatorPayload{}, err
	}
	request := threatConnectIndicatorRequest{
		Type: indicatorType, Active: &active, PrivateFlag: &privateFlag, Confidence: confidence, Rating: cloneIntPointer(settings.Rating),
		FirstSeen: &firstSeen, LastSeen: &lastSeen, Observations: observations, OwnerID: owner.ID, OwnerName: owner.Name,
		ExternalDateExpires: expires, Attributes: &threatConnectAttributeCollection{Data: attributes},
		Tags: &threatConnectTagCollection{Data: tags}, SecurityLabels: threatConnectSecurityLabelCollectionPointer(securityLabels),
	}
	switch indicatorType {
	case ThreatConnectIndicatorAddress:
		request.IP = summary
	case ThreatConnectIndicatorASN:
		request.ASNumber = summary
	default:
		return ThreatConnectIndicatorPayload{}, ErrUnsupportedThreatConnectIndicatorType
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return ThreatConnectIndicatorPayload{}, errors.Join(ErrInvalidThreatConnectIndicatorPayload, err)
	}
	payload := ThreatConnectIndicatorPayload{indicatorType: indicatorType, summary: summary, source: cloneThreatConnectIndicatorSource(source), raw: raw}
	if err := ValidateThreatConnectIndicatorPayload(payload); err != nil {
		return ThreatConnectIndicatorPayload{}, err
	}
	return payload, nil
}

func threatConnectConfidence(settings ThreatConnectIndicatorSettings, evidenceConfidence int) (*int, error) {
	mapEvidence := settings.MapEvidenceConfidence != nil && *settings.MapEvidenceConfidence
	if mapEvidence && settings.Confidence != nil {
		return nil, ErrInvalidThreatConnectExportOptions
	}
	if settings.Confidence != nil {
		if *settings.Confidence < 1 || *settings.Confidence > 100 {
			return nil, ErrInvalidThreatConnectExportOptions
		}
		return cloneIntPointer(settings.Confidence), nil
	}
	if !mapEvidence {
		return nil, nil
	}
	if evidenceConfidence < 1 || evidenceConfidence > 100 {
		return nil, ErrInvalidThreatConnectExportOptions
	}
	return &evidenceConfidence, nil
}

func normalizeThreatConnectMetadata(indicatorType ThreatConnectIndicatorType, settings ThreatConnectIndicatorSettings) ([]threatConnectAttributeRequest, []threatConnectTagRequest, []threatConnectNameRequest, error) {
	description := strings.TrimSpace(settings.Description)
	if description == "" {
		description = threatConnectAddressDescription
		if indicatorType == ThreatConnectIndicatorASN {
			description = threatConnectASNDescription
		}
	}
	source := strings.TrimSpace(settings.Source)
	if source == "" {
		source = "dmarcgo"
	}
	attributes := []ThreatConnectAttribute{
		{Type: "Description", Value: description, Default: true},
		{Type: "Source", Value: source, Default: true},
	}
	attributes = append(attributes, settings.Attributes...)
	if len(attributes) > maxThreatConnectMetadataItems {
		return nil, nil, nil, ErrInvalidThreatConnectExportOptions
	}
	attributeRequests := make([]threatConnectAttributeRequest, 0, len(attributes))
	defaultTypes := map[string]struct{}{}
	seenAttributes := map[string]struct{}{}
	for _, attribute := range attributes {
		attribute.Type = strings.TrimSpace(attribute.Type)
		attribute.Source = strings.TrimSpace(attribute.Source)
		if attribute.Type == "" || strings.TrimSpace(attribute.Value) == "" || !validSourceEnrichmentText(attribute.Type) ||
			!validSourceEnrichmentText(attribute.Value) || !validThreatConnectOptionalText(attribute.Source) {
			return nil, nil, nil, ErrInvalidThreatConnectExportOptions
		}
		labels, labelErr := normalizeThreatConnectNames(attribute.SecurityLabels)
		if labelErr != nil {
			return nil, nil, nil, labelErr
		}
		if attribute.Default {
			if _, exists := defaultTypes[attribute.Type]; exists {
				return nil, nil, nil, ErrInvalidThreatConnectExportOptions
			}
			defaultTypes[attribute.Type] = struct{}{}
		}
		request := threatConnectAttributeRequest{Type: attribute.Type, Value: attribute.Value, Source: attribute.Source, Default: attribute.Default, Pinned: attribute.Pinned,
			SecurityLabels: threatConnectSecurityLabelCollectionPointer(labels)}
		keyBytes, _ := json.Marshal(request)
		key := string(keyBytes)
		if _, duplicate := seenAttributes[key]; duplicate {
			continue
		}
		seenAttributes[key] = struct{}{}
		attributeRequests = append(attributeRequests, request)
	}
	sort.Slice(attributeRequests, func(i, j int) bool {
		return threatConnectAttributeSortKey(attributeRequests[i]) < threatConnectAttributeSortKey(attributeRequests[j])
	})

	tags := append([]ThreatConnectTag{{Name: "DMARC Aggregate"}, {Name: "Human Review Required"}, {Name: "dmarcgo"}}, settings.Tags...)
	if len(tags) > maxThreatConnectMetadataItems {
		return nil, nil, nil, ErrInvalidThreatConnectExportOptions
	}
	tagRequests := make([]threatConnectTagRequest, 0, len(tags))
	seenTags := map[string]struct{}{}
	for _, tag := range tags {
		tag.Name = strings.TrimSpace(tag.Name)
		tag.TechniqueID = strings.TrimSpace(tag.TechniqueID)
		if (tag.Name == "") == (tag.TechniqueID == "") || !validThreatConnectOptionalText(tag.Name) || !validThreatConnectOptionalText(tag.TechniqueID) {
			return nil, nil, nil, ErrInvalidThreatConnectExportOptions
		}
		request := threatConnectTagRequest(tag)
		key := request.Name + "\x00" + request.TechniqueID
		if _, duplicate := seenTags[key]; duplicate {
			continue
		}
		seenTags[key] = struct{}{}
		tagRequests = append(tagRequests, request)
	}
	sort.Slice(tagRequests, func(i, j int) bool {
		return tagRequests[i].Name+"\x00"+tagRequests[i].TechniqueID < tagRequests[j].Name+"\x00"+tagRequests[j].TechniqueID
	})
	securityLabels, err := normalizeThreatConnectNames(settings.SecurityLabels)
	if err != nil {
		return nil, nil, nil, err
	}
	return attributeRequests, tagRequests, securityLabels, nil
}

func aggregateThreatConnectASNEvidence(asn ASNEnrichment, candidates map[AnalysisID]ThreatCandidate) (time.Time, time.Time, int64, int, error) {
	var firstSeen, lastSeen time.Time
	var observations int64
	confidence := 101
	for _, candidateID := range asn.CandidateIDs {
		candidate, exists := candidates[candidateID]
		if !exists || !sourceEnrichmentEligible(candidate) || !candidate.FirstSeen.Available || !candidate.LastSeen.Available ||
			candidate.FirstSeen.Value.After(candidate.LastSeen.Value) || candidate.DualFailureMessages < 1 {
			return time.Time{}, time.Time{}, 0, 0, errors.Join(ErrInvalidThreatConnectExportOptions, ErrInvalidAnalysisResult)
		}
		if firstSeen.IsZero() || candidate.FirstSeen.Value.Before(firstSeen) {
			firstSeen = candidate.FirstSeen.Value
		}
		if lastSeen.IsZero() || candidate.LastSeen.Value.After(lastSeen) {
			lastSeen = candidate.LastSeen.Value
		}
		var err error
		observations, err = checkedThreatCandidateAdd(observations, candidate.DualFailureMessages)
		if err != nil {
			return time.Time{}, time.Time{}, 0, 0, errors.Join(ErrInvalidThreatConnectExportOptions, err)
		}
		if candidate.Confidence < confidence {
			confidence = candidate.Confidence
		}
	}
	if firstSeen.IsZero() || lastSeen.IsZero() || observations < 1 || confidence < 0 || confidence > 100 {
		return time.Time{}, time.Time{}, 0, 0, errors.Join(ErrInvalidThreatConnectExportOptions, ErrInvalidAnalysisResult)
	}
	return firstSeen, lastSeen, observations, confidence, nil
}

func threatConnectASNSource(generatedAt time.Time, candidateDigest, enrichmentDigest AnalysisID, asn ASNEnrichment, candidates map[AnalysisID]ThreatCandidate,
	statuses map[AnalysisID]SourceEnrichmentStatus,
) ThreatConnectIndicatorSource {
	source := ThreatConnectIndicatorSource{
		MappingVersion: ThreatConnectExportVersion, GeneratedAt: generatedAt, ThreatCandidateDigest: candidateDigest,
		SourceEnrichmentDigest: enrichmentDigest, EnrichmentStatuses: []ThreatConnectEnrichmentStatus{}, CandidateIDs: append([]AnalysisID{}, asn.CandidateIDs...),
		ObservationIDs: []EvidenceID{}, ReportEvidenceIDs: []EvidenceID{}, CorrelationFindingIDs: []FindingID{}, AssertionIDs: append([]AnalysisID{}, asn.AssertionIDs...),
		SourceIPs: append([]string{}, asn.SourceIPs...), StaleSourceIPs: append([]string{}, asn.StaleSourceIPs...), ConflictingSourceIPs: append([]string{}, asn.ConflictingSourceIPs...),
	}
	for _, candidateID := range asn.CandidateIDs {
		candidate := candidates[candidateID]
		source.EnrichmentStatuses = append(source.EnrichmentStatuses, ThreatConnectEnrichmentStatus{SourceIP: candidate.SourceIP, Status: statuses[candidateID]})
		source.ObservationIDs = append(source.ObservationIDs, candidate.ObservationIDs...)
		source.ReportEvidenceIDs = append(source.ReportEvidenceIDs, candidate.ReportEvidenceIDs...)
		source.CorrelationFindingIDs = append(source.CorrelationFindingIDs, candidate.CorrelationFindingIDs...)
	}
	source.CandidateIDs = compactSortedAnalysisIDs(source.CandidateIDs)
	source.ObservationIDs = compactSortedEvidenceIDs(source.ObservationIDs)
	source.ReportEvidenceIDs = compactSortedEvidenceIDs(source.ReportEvidenceIDs)
	source.CorrelationFindingIDs = compactSortedFindingIDs(source.CorrelationFindingIDs)
	source.AssertionIDs = compactSortedAnalysisIDs(source.AssertionIDs)
	sort.Slice(source.EnrichmentStatuses, func(i, j int) bool {
		return source.EnrichmentStatuses[i].SourceIP < source.EnrichmentStatuses[j].SourceIP
	})
	sort.Strings(source.SourceIPs)
	sort.Strings(source.StaleSourceIPs)
	sort.Strings(source.ConflictingSourceIPs)
	return source
}

// ValidateThreatConnectIndicatorPayload validates the exact supported native
// request shape, vendor field ranges, review defaults, source references, and
// type-specific required fields.
func ValidateThreatConnectIndicatorPayload(payload ThreatConnectIndicatorPayload) error {
	if payload.indicatorType == "" || payload.summary == "" || len(payload.raw) == 0 || validateThreatConnectSource(payload.source) != nil {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	var request threatConnectIndicatorRequest
	decoder := json.NewDecoder(bytes.NewReader(payload.raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if request.Type != payload.indicatorType || request.Active == nil || request.PrivateFlag == nil || request.FirstSeen == nil || request.LastSeen == nil ||
		request.Observations < 1 || request.FirstSeen.After(*request.LastSeen) || !sourceEnrichmentTimeMarshalable(*request.FirstSeen) ||
		!sourceEnrichmentTimeMarshalable(*request.LastSeen) || request.OwnerID < 0 || request.OwnerID > 0 && request.OwnerName != "" ||
		!validThreatConnectOptionalText(request.OwnerName) || request.Attributes == nil || request.Tags == nil ||
		validateThreatConnectRequestMetadata(request) != nil {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if request.Confidence != nil && (*request.Confidence < 1 || *request.Confidence > 100) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if request.Rating != nil && (*request.Rating < 1 || *request.Rating > 5) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if request.ExternalDateExpires != nil && (!sourceEnrichmentTimeMarshalable(*request.ExternalDateExpires) || !request.ExternalDateExpires.After(payload.source.GeneratedAt)) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	switch request.Type {
	case ThreatConnectIndicatorAddress:
		address, err := netip.ParseAddr(request.IP)
		if err != nil || address != address.Unmap() || address.String() != request.IP || request.ASNumber != "" || request.IP != payload.summary ||
			len(payload.source.CandidateIDs) != 1 || !slices.Equal(payload.source.SourceIPs, []string{request.IP}) {
			return ErrInvalidThreatConnectIndicatorPayload
		}
	case ThreatConnectIndicatorASN:
		if request.IP != "" || request.ASNumber != payload.summary || !validThreatConnectASN(request.ASNumber) || len(payload.source.CandidateIDs) == 0 ||
			len(payload.source.SourceIPs) == 0 || len(payload.source.AssertionIDs) == 0 || payload.source.SourceEnrichmentDigest == "" {
			return ErrInvalidThreatConnectIndicatorPayload
		}
	default:
		return ErrUnsupportedThreatConnectIndicatorType
	}
	return nil
}

func validateThreatConnectRequestMetadata(request threatConnectIndicatorRequest) error {
	if len(request.Attributes.Data) < 2 || len(request.Attributes.Data) > maxThreatConnectMetadataItems || len(request.Tags.Data) < 3 || len(request.Tags.Data) > maxThreatConnectMetadataItems {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	foundDescription, foundSource := false, false
	defaultTypes := map[string]struct{}{}
	previousAttribute := ""
	for index, attribute := range request.Attributes.Data {
		if attribute.Type == "" || strings.TrimSpace(attribute.Value) == "" || !validSourceEnrichmentText(attribute.Type) ||
			!validSourceEnrichmentText(attribute.Value) || !validThreatConnectOptionalText(attribute.Source) {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		if attribute.Default {
			if _, exists := defaultTypes[attribute.Type]; exists {
				return ErrInvalidThreatConnectIndicatorPayload
			}
			defaultTypes[attribute.Type] = struct{}{}
		}
		if attribute.Type == "Description" && attribute.Default {
			foundDescription = true
		}
		if attribute.Type == "Source" && attribute.Default {
			foundSource = true
		}
		if attribute.SecurityLabels != nil && validateThreatConnectNameRequests(attribute.SecurityLabels.Data) != nil {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		key := threatConnectAttributeSortKey(attribute)
		if index > 0 && key <= previousAttribute {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		previousAttribute = key
	}
	if !foundDescription || !foundSource {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	previousTag := ""
	foundDMARC, foundReview, foundLibrary := false, false, false
	for index, tag := range request.Tags.Data {
		if (tag.Name == "") == (tag.TechniqueID == "") || !validThreatConnectOptionalText(tag.Name) || !validThreatConnectOptionalText(tag.TechniqueID) {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		key := tag.Name + "\x00" + tag.TechniqueID
		if index > 0 && key <= previousTag {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		previousTag = key
		foundDMARC = foundDMARC || tag.Name == "DMARC Aggregate"
		foundReview = foundReview || tag.Name == "Human Review Required"
		foundLibrary = foundLibrary || tag.Name == "dmarcgo"
	}
	if !foundDMARC || !foundReview || !foundLibrary {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if request.SecurityLabels != nil && validateThreatConnectNameRequests(request.SecurityLabels.Data) != nil {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	return nil
}

func validateThreatConnectSource(source ThreatConnectIndicatorSource) error {
	if source.MappingVersion != ThreatConnectExportVersion || source.GeneratedAt.IsZero() || !sourceEnrichmentTimeMarshalable(source.GeneratedAt) ||
		source.ThreatCandidateDigest == "" || len(source.CandidateIDs) == 0 || len(source.SourceIPs) == 0 ||
		!sortedUniqueThreatConnectAnalysisIDs(source.CandidateIDs) || !sortedUniqueThreatConnectEvidenceIDs(source.ObservationIDs) ||
		!sortedUniqueThreatConnectEvidenceIDs(source.ReportEvidenceIDs) || !sortedUniqueThreatConnectFindingIDs(source.CorrelationFindingIDs) ||
		!sortedUniqueThreatConnectAnalysisIDs(source.AssertionIDs) || !sortedUniqueThreatConnectStrings(source.SourceIPs) ||
		!sortedUniqueThreatConnectStrings(source.StaleSourceIPs) || !sortedUniqueThreatConnectStrings(source.ConflictingSourceIPs) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if source.SourceEnrichmentDigest == "" {
		if len(source.EnrichmentStatuses) != 0 || len(source.AssertionIDs) != 0 || len(source.StaleSourceIPs) != 0 || len(source.ConflictingSourceIPs) != 0 {
			return ErrInvalidThreatConnectIndicatorPayload
		}
	} else if !validThreatConnectEnrichmentStatuses(source.EnrichmentStatuses, source.SourceIPs) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	if !validThreatConnectSourceIPSubset(source.StaleSourceIPs, source.SourceIPs) ||
		!validThreatConnectSourceIPSubset(source.ConflictingSourceIPs, source.SourceIPs) {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	for _, sourceIP := range source.SourceIPs {
		address, err := netip.ParseAddr(sourceIP)
		if err != nil || address != address.Unmap() || address.String() != sourceIP {
			return ErrInvalidThreatConnectIndicatorPayload
		}
	}
	return nil
}

func validThreatConnectEnrichmentStatuses(values []ThreatConnectEnrichmentStatus, sourceIPs []string) bool {
	if len(values) != len(sourceIPs) {
		return false
	}
	for index, value := range values {
		if value.SourceIP != sourceIPs[index] || !slices.Contains(sourceEnrichmentStatusOrder(), value.Status) {
			return false
		}
	}
	return true
}

func validThreatConnectSourceIPSubset(values, sourceIPs []string) bool {
	for _, value := range values {
		if _, found := slices.BinarySearch(sourceIPs, value); !found {
			return false
		}
	}
	return true
}

func validThreatConnectASN(value string) bool {
	if !strings.HasPrefix(value, "ASN") || len(value) <= 3 || value[3] == '0' {
		return false
	}
	number, err := strconv.ParseUint(value[3:], 10, 32)
	return err == nil && number > 0 && value == "ASN"+strconv.FormatUint(number, 10)
}

func validThreatConnectOptionalText(value string) bool {
	return value == "" || validSourceEnrichmentText(value)
}

func mergeThreatConnectSettings(defaults, override ThreatConnectIndicatorSettings) ThreatConnectIndicatorSettings {
	result := cloneThreatConnectSettings(defaults)
	if override.Active != nil {
		result.Active = cloneBoolPointer(override.Active)
	}
	if override.PrivateFlag != nil {
		result.PrivateFlag = cloneBoolPointer(override.PrivateFlag)
	}
	if override.MapEvidenceConfidence != nil {
		result.MapEvidenceConfidence = cloneBoolPointer(override.MapEvidenceConfidence)
		if *override.MapEvidenceConfidence {
			result.Confidence = nil
		}
	}
	if override.Confidence != nil {
		result.Confidence = cloneIntPointer(override.Confidence)
		if override.MapEvidenceConfidence == nil {
			value := false
			result.MapEvidenceConfidence = &value
		}
	}
	if override.Rating != nil {
		result.Rating = cloneIntPointer(override.Rating)
	}
	if override.ExternalDateExpires != nil {
		result.ExternalDateExpires = cloneTimePointer(override.ExternalDateExpires)
	}
	if override.Description != "" {
		result.Description = override.Description
	}
	if override.Source != "" {
		result.Source = override.Source
	}
	result.Tags = append(result.Tags, override.Tags...)
	result.SecurityLabels = append(result.SecurityLabels, override.SecurityLabels...)
	result.Attributes = append(result.Attributes, override.Attributes...)
	return result
}

func cloneThreatConnectSettings(value ThreatConnectIndicatorSettings) ThreatConnectIndicatorSettings {
	value.Active = cloneBoolPointer(value.Active)
	value.PrivateFlag = cloneBoolPointer(value.PrivateFlag)
	value.MapEvidenceConfidence = cloneBoolPointer(value.MapEvidenceConfidence)
	value.Confidence = cloneIntPointer(value.Confidence)
	value.Rating = cloneIntPointer(value.Rating)
	value.ExternalDateExpires = cloneTimePointer(value.ExternalDateExpires)
	value.Tags = append([]ThreatConnectTag(nil), value.Tags...)
	value.SecurityLabels = cloneStrings(value.SecurityLabels)
	value.Attributes = append([]ThreatConnectAttribute(nil), value.Attributes...)
	for index := range value.Attributes {
		value.Attributes[index].SecurityLabels = cloneStrings(value.Attributes[index].SecurityLabels)
	}
	return value
}

func cloneThreatConnectIndicatorSource(value ThreatConnectIndicatorSource) ThreatConnectIndicatorSource {
	value.EnrichmentStatuses = append([]ThreatConnectEnrichmentStatus{}, value.EnrichmentStatuses...)
	value.CandidateIDs = append([]AnalysisID{}, value.CandidateIDs...)
	value.ObservationIDs = append([]EvidenceID{}, value.ObservationIDs...)
	value.ReportEvidenceIDs = append([]EvidenceID{}, value.ReportEvidenceIDs...)
	value.CorrelationFindingIDs = append([]FindingID{}, value.CorrelationFindingIDs...)
	value.AssertionIDs = append([]AnalysisID{}, value.AssertionIDs...)
	value.SourceIPs = append([]string{}, value.SourceIPs...)
	value.StaleSourceIPs = append([]string{}, value.StaleSourceIPs...)
	value.ConflictingSourceIPs = append([]string{}, value.ConflictingSourceIPs...)
	return value
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func normalizeThreatConnectNames(values []string) ([]threatConnectNameRequest, error) {
	if len(values) > maxThreatConnectMetadataItems {
		return nil, ErrInvalidThreatConnectExportOptions
	}
	seen := map[string]struct{}{}
	result := make([]threatConnectNameRequest, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !validSourceEnrichmentText(value) {
			return nil, ErrInvalidThreatConnectExportOptions
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, threatConnectNameRequest{Name: value})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func threatConnectSecurityLabelCollectionPointer(values []threatConnectNameRequest) *threatConnectNameCollection {
	if len(values) == 0 {
		return nil
	}
	return &threatConnectNameCollection{Data: values}
}

func threatConnectAttributeSortKey(value threatConnectAttributeRequest) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func validateThreatConnectNameRequests(values []threatConnectNameRequest) error {
	if len(values) == 0 || len(values) > maxThreatConnectMetadataItems {
		return ErrInvalidThreatConnectIndicatorPayload
	}
	previous := ""
	for index, value := range values {
		if value.Name == "" || !validSourceEnrichmentText(value.Name) || index > 0 && value.Name <= previous {
			return ErrInvalidThreatConnectIndicatorPayload
		}
		previous = value.Name
	}
	return nil
}

func sortedUniqueThreatConnectStrings(values []string) bool {
	return sort.StringsAreSorted(values) && !hasAdjacentDuplicate(values)
}

func sortedUniqueThreatConnectAnalysisIDs(values []AnalysisID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func sortedUniqueThreatConnectEvidenceIDs(values []EvidenceID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

func sortedUniqueThreatConnectFindingIDs(values []FindingID) bool {
	return slices.IsSorted(values) && !hasAdjacentDuplicate(values)
}

type threatConnectIndicatorRequest struct {
	Type                ThreatConnectIndicatorType        `json:"type"`
	IP                  string                            `json:"ip,omitempty"`
	ASNumber            string                            `json:"AS Number,omitempty"`
	Active              *bool                             `json:"active"`
	PrivateFlag         *bool                             `json:"privateFlag"`
	Confidence          *int                              `json:"confidence,omitempty"`
	Rating              *int                              `json:"rating,omitempty"`
	FirstSeen           *time.Time                        `json:"firstSeen"`
	LastSeen            *time.Time                        `json:"lastSeen"`
	Observations        int64                             `json:"observations"`
	OwnerID             int64                             `json:"ownerId,omitempty"`
	OwnerName           string                            `json:"ownerName,omitempty"`
	ExternalDateExpires *time.Time                        `json:"externalDateExpires,omitempty"`
	Attributes          *threatConnectAttributeCollection `json:"attributes"`
	Tags                *threatConnectTagCollection       `json:"tags"`
	SecurityLabels      *threatConnectNameCollection      `json:"securityLabels,omitempty"`
}

type threatConnectAttributeCollection struct {
	Data []threatConnectAttributeRequest `json:"data"`
}

type threatConnectAttributeRequest struct {
	Type           string                       `json:"type"`
	Value          string                       `json:"value"`
	Source         string                       `json:"source,omitempty"`
	Default        bool                         `json:"default,omitempty"`
	Pinned         bool                         `json:"pinned,omitempty"`
	SecurityLabels *threatConnectNameCollection `json:"securityLabels,omitempty"`
}

type threatConnectTagCollection struct {
	Data []threatConnectTagRequest `json:"data"`
}

type threatConnectTagRequest struct {
	Name        string `json:"name,omitempty"`
	TechniqueID string `json:"techniqueId,omitempty"`
}

type threatConnectNameCollection struct {
	Data []threatConnectNameRequest `json:"data"`
}

type threatConnectNameRequest struct {
	Name string `json:"name"`
}
