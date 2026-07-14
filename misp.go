package dmarcgo

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- UUIDv5 requires SHA-1; it is not used for security.
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
	"unicode"
	"unicode/utf8"
)

const (
	// MISPAPIContractVersion identifies the reviewed upstream API family. The
	// target instance version is retained separately in caller capabilities.
	MISPAPIContractVersion = "2.5"

	// MISPExportVersion identifies the dmarcgo-to-MISP mapping.
	MISPExportVersion = "1"

	// MISPAddEventEndpoint accepts a complete event request. The library never
	// calls it.
	MISPAddEventEndpoint = "/events/add"

	mispAddAttributeEndpointPrefix = "/attributes/add/"
	mispReviewComment              = "DMARC aggregate authentication-failure source selected for human review. This attribute does not assert malicious activity or authorize blocking."
	maxMISPTextBytes               = 4096
)

var (
	// ErrInvalidMISPExportOptions identifies incomplete event context, invalid
	// tenant capabilities, selections, timestamps, or review settings.
	ErrInvalidMISPExportOptions = errors.New("invalid MISP export options")
	// ErrInvalidMISPAttributePayload identifies a malformed or internally
	// inconsistent supported MISP Attribute request.
	ErrInvalidMISPAttributePayload = errors.New("invalid MISP attribute payload")
	// ErrInvalidMISPEventPayload identifies a malformed or internally
	// inconsistent supported MISP Event request.
	ErrInvalidMISPEventPayload = errors.New("invalid MISP event payload")
	// ErrUnsupportedMISPAttributeMapping identifies a selected type/category
	// pair that was not declared in the caller's target-instance capabilities.
	ErrUnsupportedMISPAttributeMapping = errors.New("unsupported MISP attribute mapping")
)

// MISPAttributeType is a supported target-instance Attribute type. A caller
// must deliberately choose whether an observed source address is represented
// with source or destination semantics.
type MISPAttributeType string

const (
	MISPAttributeTypeIPSource      MISPAttributeType = "ip-src"
	MISPAttributeTypeIPDestination MISPAttributeType = "ip-dst"
)

// MISPDistribution is a MISP distribution level. Inherit Event is valid only
// for Attributes; Events must select one of the other values.
type MISPDistribution string

const (
	MISPDistributionOrganizationOnly     MISPDistribution = "0"
	MISPDistributionCommunityOnly        MISPDistribution = "1"
	MISPDistributionConnectedCommunities MISPDistribution = "2"
	MISPDistributionAllCommunities       MISPDistribution = "3"
	MISPDistributionSharingGroup         MISPDistribution = "4"
	MISPDistributionInheritEvent         MISPDistribution = "5"
)

// MISPThreatLevel is explicit Event context. Candidate severity is never
// converted into a MISP threat level.
type MISPThreatLevel string

const (
	MISPThreatLevelHigh      MISPThreatLevel = "1"
	MISPThreatLevelMedium    MISPThreatLevel = "2"
	MISPThreatLevelLow       MISPThreatLevel = "3"
	MISPThreatLevelUndefined MISPThreatLevel = "4"
)

// MISPAnalysisLevel is explicit Event analysis maturity.
type MISPAnalysisLevel string

const (
	MISPAnalysisInitial  MISPAnalysisLevel = "0"
	MISPAnalysisOngoing  MISPAnalysisLevel = "1"
	MISPAnalysisComplete MISPAnalysisLevel = "2"
)

// MISPAttributeMapping is one type/category combination reported as valid by
// the target instance. The encoder supports only ip-src and ip-dst types.
type MISPAttributeMapping struct {
	Type     MISPAttributeType `json:"type"`
	Category string            `json:"category"`
}

// MISPInstanceCapabilities records caller-supplied target-instance metadata.
// Populate AttributeMappings from that instance's describeTypes response. The
// encoder performs no capability discovery.
type MISPInstanceCapabilities struct {
	ContractVersion   string
	AttributeMappings []MISPAttributeMapping
}

// MISPEventReference identifies an existing destination Event by canonical
// numeric ID or UUID. The encoder never searches for or creates this Event.
type MISPEventReference struct {
	Identifier string
}

// MISPAttributeSettings controls native Attribute fields. Nil booleans select
// review-oriented defaults: to_ids=false and disable_correlation=true.
// FirstSeen and LastSeen default to the candidate's report-period bounds.
// Comment and Tags are caller-controlled untrusted data.
type MISPAttributeSettings struct {
	ToIDS              *bool
	DisableCorrelation *bool
	Distribution       MISPDistribution
	SharingGroupID     string
	Comment            string
	Tags               []string
	FirstSeen          *time.Time
	LastSeen           *time.Time
}

// MISPAttributeSelection is an explicit caller decision to encode one
// review-eligible, non-excluded candidate with one direction/category mapping.
type MISPAttributeSelection struct {
	CandidateID AnalysisID
	Mapping     MISPAttributeMapping
	Settings    MISPAttributeSettings
}

// MISPAttributeExportOptions controls native Attribute requests for one
// existing Event. GeneratedAt defaults to the completed candidate timestamp
// and never reads the system clock. Attributes default to organization-only
// distribution unless the caller selects another level.
type MISPAttributeExportOptions struct {
	GeneratedAt  time.Time
	Event        MISPEventReference
	Capabilities MISPInstanceCapabilities
	Defaults     MISPAttributeSettings
	Selections   []MISPAttributeSelection
}

// MISPEventDefinition is the complete caller-owned lifecycle context required
// to construct one offline Event request. UUID, Info, Date, Distribution,
// ThreatLevel, Analysis, Published, and DisableCorrelation are mandatory.
// Event text and tags are untrusted data and are never treated as instructions.
type MISPEventDefinition struct {
	UUID               string
	Info               string
	Date               time.Time
	Distribution       MISPDistribution
	SharingGroupID     string
	ThreatLevel        MISPThreatLevel
	Analysis           MISPAnalysisLevel
	Published          *bool
	DisableCorrelation *bool
	Tags               []string
}

// MISPEventExportOptions controls one complete offline Event request. Selected
// Attributes inherit the explicit Event distribution unless overridden.
type MISPEventExportOptions struct {
	GeneratedAt  time.Time
	Capabilities MISPInstanceCapabilities
	Event        MISPEventDefinition
	Defaults     MISPAttributeSettings
	Selections   []MISPAttributeSelection
}

// MISPAttributeSource retains normalized evidence behind one native request
// without adding non-vendor fields to its JSON.
type MISPAttributeSource struct {
	MappingVersion          string               `json:"mapping_version"`
	APIContractVersion      string               `json:"api_contract_version"`
	InstanceContractVersion string               `json:"instance_contract_version"`
	GeneratedAt             time.Time            `json:"generated_at"`
	ThreatCandidateDigest   AnalysisID           `json:"threat_candidate_digest"`
	EventIdentifier         string               `json:"event_identifier"`
	CandidateID             AnalysisID           `json:"candidate_id"`
	Mapping                 MISPAttributeMapping `json:"mapping"`
	SourceIP                string               `json:"source_ip"`
	CandidateFirstSeen      time.Time            `json:"candidate_first_seen"`
	CandidateLastSeen       time.Time            `json:"candidate_last_seen"`
	PayloadFirstSeen        time.Time            `json:"payload_first_seen"`
	PayloadLastSeen         time.Time            `json:"payload_last_seen"`
	ObservationIDs          []EvidenceID         `json:"observation_ids"`
	ReportEvidenceIDs       []EvidenceID         `json:"report_evidence_ids"`
	CorrelationFindingIDs   []FindingID          `json:"correlation_finding_ids"`
}

// MISPEventSource retains the source references behind a complete Event body.
type MISPEventSource struct {
	MappingVersion          string                `json:"mapping_version"`
	APIContractVersion      string                `json:"api_contract_version"`
	InstanceContractVersion string                `json:"instance_contract_version"`
	GeneratedAt             time.Time             `json:"generated_at"`
	ThreatCandidateDigest   AnalysisID            `json:"threat_candidate_digest"`
	EventUUID               string                `json:"event_uuid"`
	Attributes              []MISPAttributeSource `json:"attributes"`
}

// MISPAttributePayload is one immutable native request body for an existing
// Event. MarshalJSON returns vendor fields only.
type MISPAttributePayload struct {
	eventIdentifier string
	uuid            string
	candidateID     AnalysisID
	source          MISPAttributeSource
	raw             []byte
}

// Endpoint returns the relative target endpoint containing the validated Event
// ID or UUID. The library never calls it.
func (payload MISPAttributePayload) Endpoint() string {
	return mispAddAttributeEndpointPrefix + payload.eventIdentifier
}

// UUID returns the deterministic MISP Attribute UUID.
func (payload MISPAttributePayload) UUID() string { return payload.uuid }

// CandidateID returns the selected normalized candidate identifier.
func (payload MISPAttributePayload) CandidateID() AnalysisID { return payload.candidateID }

// Source returns a defensive copy of the evidence behind the request.
func (payload MISPAttributePayload) Source() MISPAttributeSource {
	return cloneMISPAttributeSource(payload.source)
}

// MarshalJSON implements json.Marshaler and emits only native MISP fields.
func (payload MISPAttributePayload) MarshalJSON() ([]byte, error) {
	if err := ValidateMISPAttributePayload(payload); err != nil {
		return nil, err
	}
	return append([]byte(nil), payload.raw...), nil
}

// MISPEventPayload is one immutable complete native Event request body.
type MISPEventPayload struct {
	uuid   string
	source MISPEventSource
	raw    []byte
}

// Endpoint returns the relative Event creation endpoint. The library never
// calls it.
func (payload MISPEventPayload) Endpoint() string { return MISPAddEventEndpoint }

// UUID returns the caller-supplied Event UUID.
func (payload MISPEventPayload) UUID() string { return payload.uuid }

// Source returns a defensive copy of the Event's evidence references.
func (payload MISPEventPayload) Source() MISPEventSource { return cloneMISPEventSource(payload.source) }

// MarshalJSON implements json.Marshaler and emits only native MISP fields.
func (payload MISPEventPayload) MarshalJSON() ([]byte, error) {
	if err := ValidateMISPEventPayload(payload); err != nil {
		return nil, err
	}
	return append([]byte(nil), payload.raw...), nil
}

// MISPUnsupportedMappingError preserves structured mapping evidence without
// interpolating the caller-controlled category into generated error text.
type MISPUnsupportedMappingError struct {
	CandidateID AnalysisID
	Mapping     MISPAttributeMapping
}

func (err *MISPUnsupportedMappingError) Error() string {
	return fmt.Sprintf("%s for candidate %s", ErrUnsupportedMISPAttributeMapping, err.CandidateID)
}

func (err *MISPUnsupportedMappingError) Unwrap() error { return ErrUnsupportedMISPAttributeMapping }

// BuildMISPAttributePayloads converts explicit selections into deterministic
// native Attribute request bodies for one existing Event. It performs no DNS,
// HTTP, report parsing, scoring, enrichment, filesystem, credential, clock,
// submission, retry, warning-list, or subject-IP activity.
func BuildMISPAttributePayloads(candidates ThreatCandidateResult, options MISPAttributeExportOptions) ([]MISPAttributePayload, error) {
	eventIdentifier, err := normalizeMISPIdentifier(options.Event.Identifier)
	if err != nil {
		return nil, ErrInvalidMISPExportOptions
	}
	normalized, err := normalizeMISPExport(candidates, options.GeneratedAt, options.Capabilities, options.Defaults, options.Selections)
	if err != nil {
		return nil, err
	}
	built, err := buildMISPAttributes(candidates, normalized, eventIdentifier, MISPDistributionOrganizationOnly)
	if err != nil {
		return nil, err
	}
	result := make([]MISPAttributePayload, len(built))
	for index, value := range built {
		raw, marshalErr := json.Marshal(value.request)
		if marshalErr != nil {
			return nil, errors.Join(ErrInvalidMISPAttributePayload, marshalErr)
		}
		result[index] = MISPAttributePayload{
			eventIdentifier: eventIdentifier,
			uuid:            value.request.UUID,
			candidateID:     value.source.CandidateID,
			source:          value.source,
			raw:             raw,
		}
		if validateErr := ValidateMISPAttributePayload(result[index]); validateErr != nil {
			return nil, validateErr
		}
	}
	return result, nil
}

// BuildMISPEventPayload builds one complete deterministic native Event body.
// It requires explicit caller-owned Event lifecycle context and performs none
// of the I/O or upstream analysis activities excluded from the Attribute
// builder.
func BuildMISPEventPayload(candidates ThreatCandidateResult, options MISPEventExportOptions) (MISPEventPayload, error) {
	normalized, err := normalizeMISPExport(candidates, options.GeneratedAt, options.Capabilities, options.Defaults, options.Selections)
	if err != nil {
		return MISPEventPayload{}, err
	}
	event, err := normalizeMISPEventDefinition(options.Event, normalized.GeneratedAt)
	if err != nil {
		return MISPEventPayload{}, err
	}
	built, err := buildMISPAttributes(candidates, normalized, event.UUID, MISPDistributionInheritEvent)
	if err != nil {
		return MISPEventPayload{}, err
	}
	attributes := make([]mispAttributeRequest, len(built))
	sources := make([]MISPAttributeSource, len(built))
	for index, value := range built {
		attributes[index] = value.request
		sources[index] = value.source
	}
	request := mispEventRequest{
		UUID: event.UUID, Info: event.Info, Date: event.Date.UTC().Format(time.DateOnly),
		Published: *event.Published, Analysis: event.Analysis, Distribution: event.Distribution,
		SharingGroupID: event.SharingGroupID, ThreatLevel: event.ThreatLevel,
		Timestamp: strconv.FormatInt(normalized.GeneratedAt.Unix(), 10), DisableCorrelation: *event.DisableCorrelation,
		Tags: mispTagRequests(event.Tags), Attributes: attributes,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return MISPEventPayload{}, errors.Join(ErrInvalidMISPEventPayload, err)
	}
	payload := MISPEventPayload{
		uuid: event.UUID,
		source: MISPEventSource{
			MappingVersion: MISPExportVersion, APIContractVersion: MISPAPIContractVersion,
			InstanceContractVersion: normalized.Capabilities.ContractVersion,
			GeneratedAt:             normalized.GeneratedAt, ThreatCandidateDigest: candidates.Digest(), EventUUID: event.UUID,
			Attributes: sources,
		},
		raw: raw,
	}
	if err := ValidateMISPEventPayload(payload); err != nil {
		return MISPEventPayload{}, err
	}
	return payload, nil
}

// WriteMISPAttributePayload validates and writes one native request followed by
// a newline.
func WriteMISPAttributePayload(writer io.Writer, payload MISPAttributePayload) error {
	return writeMISPJSON(writer, payload, ErrInvalidMISPAttributePayload)
}

// WriteMISPEventPayload validates and writes one native request followed by a
// newline.
func WriteMISPEventPayload(writer io.Writer, payload MISPEventPayload) error {
	return writeMISPJSON(writer, payload, ErrInvalidMISPEventPayload)
}

func writeMISPJSON(writer io.Writer, value json.Marshaler, invalid error) error {
	if writer == nil {
		return invalid
	}
	encoded, err := value.MarshalJSON()
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

type normalizedMISPExport struct {
	GeneratedAt  time.Time
	Capabilities MISPInstanceCapabilities
	Defaults     MISPAttributeSettings
	Selections   []MISPAttributeSelection
}

func normalizeMISPExport(candidates ThreatCandidateResult, generatedAt time.Time, capabilities MISPInstanceCapabilities,
	defaults MISPAttributeSettings, selections []MISPAttributeSelection,
) (normalizedMISPExport, error) {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return normalizedMISPExport{}, errors.Join(ErrInvalidMISPExportOptions, err)
	}
	inputTime := candidates.ResultMetadata().GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = inputTime
	} else {
		generatedAt = generatedAt.UTC()
	}
	if generatedAt.IsZero() || generatedAt.Unix() < 0 || generatedAt.Before(inputTime) || !sourceEnrichmentTimeMarshalable(generatedAt) {
		return normalizedMISPExport{}, ErrInvalidMISPExportOptions
	}
	normalizedCapabilities, err := normalizeMISPCapabilities(capabilities)
	if err != nil {
		return normalizedMISPExport{}, err
	}
	if len(selections) == 0 {
		return normalizedMISPExport{}, ErrInvalidMISPExportOptions
	}
	result := normalizedMISPExport{
		GeneratedAt: generatedAt.UTC(), Capabilities: normalizedCapabilities,
		Defaults: cloneMISPAttributeSettings(defaults), Selections: append([]MISPAttributeSelection(nil), selections...),
	}
	for index := range result.Selections {
		result.Selections[index].Mapping.Type = MISPAttributeType(strings.TrimSpace(string(result.Selections[index].Mapping.Type)))
		result.Selections[index].Mapping.Category = strings.TrimSpace(result.Selections[index].Mapping.Category)
		result.Selections[index].Settings = cloneMISPAttributeSettings(result.Selections[index].Settings)
	}
	sort.Slice(result.Selections, func(i, j int) bool {
		if result.Selections[i].CandidateID != result.Selections[j].CandidateID {
			return result.Selections[i].CandidateID < result.Selections[j].CandidateID
		}
		return mispMappingKey(result.Selections[i].Mapping) < mispMappingKey(result.Selections[j].Mapping)
	})
	for index, selection := range result.Selections {
		if selection.CandidateID == "" || index > 0 && result.Selections[index-1].CandidateID == selection.CandidateID &&
			result.Selections[index-1].Mapping == selection.Mapping {
			return normalizedMISPExport{}, ErrInvalidMISPExportOptions
		}
		if _, found := slices.BinarySearchFunc(result.Capabilities.AttributeMappings, selection.Mapping, func(left, right MISPAttributeMapping) int {
			return strings.Compare(mispMappingKey(left), mispMappingKey(right))
		}); !found {
			return normalizedMISPExport{}, &MISPUnsupportedMappingError{CandidateID: selection.CandidateID, Mapping: selection.Mapping}
		}
	}
	return result, nil
}

func normalizeMISPCapabilities(value MISPInstanceCapabilities) (MISPInstanceCapabilities, error) {
	value.ContractVersion = strings.TrimSpace(value.ContractVersion)
	if value.ContractVersion == "" || !validMISPText(value.ContractVersion) || len(value.AttributeMappings) == 0 {
		return MISPInstanceCapabilities{}, ErrInvalidMISPExportOptions
	}
	value.AttributeMappings = append([]MISPAttributeMapping(nil), value.AttributeMappings...)
	for index := range value.AttributeMappings {
		value.AttributeMappings[index].Type = MISPAttributeType(strings.TrimSpace(string(value.AttributeMappings[index].Type)))
		value.AttributeMappings[index].Category = strings.TrimSpace(value.AttributeMappings[index].Category)
		if !validMISPAttributeType(value.AttributeMappings[index].Type) || value.AttributeMappings[index].Category == "" ||
			len(value.AttributeMappings[index].Category) > 255 || !validMISPText(value.AttributeMappings[index].Category) {
			return MISPInstanceCapabilities{}, ErrInvalidMISPExportOptions
		}
	}
	sort.Slice(value.AttributeMappings, func(i, j int) bool {
		return mispMappingKey(value.AttributeMappings[i]) < mispMappingKey(value.AttributeMappings[j])
	})
	for index := 1; index < len(value.AttributeMappings); index++ {
		if value.AttributeMappings[index] == value.AttributeMappings[index-1] {
			return MISPInstanceCapabilities{}, ErrInvalidMISPExportOptions
		}
	}
	return value, nil
}

type builtMISPAttribute struct {
	request mispAttributeRequest
	source  MISPAttributeSource
}

func buildMISPAttributes(candidates ThreatCandidateResult, options normalizedMISPExport, eventIdentifier string,
	defaultDistribution MISPDistribution,
) ([]builtMISPAttribute, error) {
	candidateByID := make(map[AnalysisID]ThreatCandidate, len(candidates.candidates))
	for _, candidate := range candidates.Candidates() {
		candidateByID[candidate.ID] = candidate
	}
	result := make([]builtMISPAttribute, 0, len(options.Selections))
	for _, selection := range options.Selections {
		candidate, found := candidateByID[selection.CandidateID]
		if !found || !sourceEnrichmentEligible(candidate) || !candidate.FirstSeen.Available || !candidate.LastSeen.Available ||
			candidate.FirstSeen.Value.After(candidate.LastSeen.Value) || candidate.DualFailureMessages < 1 {
			return nil, errors.Join(ErrInvalidMISPExportOptions, ErrInvalidAnalysisResult)
		}
		address, parseErr := netip.ParseAddr(candidate.SourceIP)
		if parseErr != nil || address != address.Unmap() || address.String() != candidate.SourceIP {
			return nil, errors.Join(ErrInvalidMISPExportOptions, ErrInvalidAnalysisResult)
		}
		settings, err := normalizeMISPAttributeSettings(candidate, options.Defaults, selection.Settings, defaultDistribution, options.GeneratedAt)
		if err != nil {
			return nil, err
		}
		uuid := mispAttributeUUID(eventIdentifier, selection.Mapping, candidate.SourceIP)
		request := mispAttributeRequest{
			Type: selection.Mapping.Type, Category: selection.Mapping.Category, Value: candidate.SourceIP,
			ToIDS: settings.ToIDS, UUID: uuid, Timestamp: strconv.FormatInt(options.GeneratedAt.Unix(), 10),
			Distribution: settings.Distribution, SharingGroupID: settings.SharingGroupID, Comment: settings.Comment,
			DisableCorrelation: settings.DisableCorrelation, FirstSeen: settings.FirstSeen, LastSeen: settings.LastSeen,
			Tags: mispTagRequests(settings.Tags),
		}
		source := MISPAttributeSource{
			MappingVersion: MISPExportVersion, APIContractVersion: MISPAPIContractVersion,
			InstanceContractVersion: options.Capabilities.ContractVersion,
			GeneratedAt:             options.GeneratedAt, ThreatCandidateDigest: candidates.Digest(), EventIdentifier: eventIdentifier,
			CandidateID: candidate.ID, Mapping: selection.Mapping, SourceIP: candidate.SourceIP,
			CandidateFirstSeen: candidate.FirstSeen.Value.UTC(), CandidateLastSeen: candidate.LastSeen.Value.UTC(),
			PayloadFirstSeen: settings.FirstSeen, PayloadLastSeen: settings.LastSeen,
			ObservationIDs:        append([]EvidenceID{}, compactSortedEvidenceIDs(candidate.ObservationIDs)...),
			ReportEvidenceIDs:     append([]EvidenceID{}, compactSortedEvidenceIDs(candidate.ReportEvidenceIDs)...),
			CorrelationFindingIDs: append([]FindingID{}, compactSortedFindingIDs(candidate.CorrelationFindingIDs)...),
		}
		result = append(result, builtMISPAttribute{request: request, source: source})
	}
	sort.Slice(result, func(i, j int) bool { return mispAttributeRequestLess(result[i].request, result[j].request) })
	return result, nil
}

type normalizedMISPAttributeSettings struct {
	ToIDS, DisableCorrelation bool
	Distribution              MISPDistribution
	SharingGroupID, Comment   string
	Tags                      []string
	FirstSeen, LastSeen       time.Time
}

func normalizeMISPAttributeSettings(candidate ThreatCandidate, defaults, override MISPAttributeSettings,
	defaultDistribution MISPDistribution, generatedAt time.Time,
) (normalizedMISPAttributeSettings, error) {
	settings := mergeMISPAttributeSettings(defaults, override)
	result := normalizedMISPAttributeSettings{
		ToIDS: false, DisableCorrelation: true, Distribution: settings.Distribution,
		SharingGroupID: strings.TrimSpace(settings.SharingGroupID), Comment: strings.TrimSpace(settings.Comment),
		FirstSeen: candidate.FirstSeen.Value.UTC(), LastSeen: candidate.LastSeen.Value.UTC(),
	}
	if settings.ToIDS != nil {
		result.ToIDS = *settings.ToIDS
	}
	if settings.DisableCorrelation != nil {
		result.DisableCorrelation = *settings.DisableCorrelation
	}
	if result.Distribution == "" {
		result.Distribution = defaultDistribution
	}
	if settings.FirstSeen != nil {
		result.FirstSeen = settings.FirstSeen.UTC()
	}
	if settings.LastSeen != nil {
		result.LastSeen = settings.LastSeen.UTC()
	}
	if result.Comment == "" {
		result.Comment = mispReviewComment
	}
	var err error
	result.Tags, err = normalizeMISPTagNames(settings.Tags)
	if err != nil || !validMISPAttributeDistribution(result.Distribution) ||
		!validMISPSharingGroup(result.Distribution, result.SharingGroupID) || !validMISPText(result.Comment) ||
		result.FirstSeen.IsZero() || result.LastSeen.IsZero() || result.FirstSeen.After(result.LastSeen) || result.LastSeen.After(generatedAt) ||
		!sourceEnrichmentTimeMarshalable(result.FirstSeen) || !sourceEnrichmentTimeMarshalable(result.LastSeen) {
		return normalizedMISPAttributeSettings{}, ErrInvalidMISPExportOptions
	}
	return result, nil
}

func normalizeMISPEventDefinition(value MISPEventDefinition, generatedAt time.Time) (MISPEventDefinition, error) {
	uuid, err := normalizeMISPUUID(value.UUID)
	if err != nil {
		return MISPEventDefinition{}, ErrInvalidMISPExportOptions
	}
	value.UUID = uuid
	value.Info = strings.TrimSpace(value.Info)
	value.SharingGroupID = strings.TrimSpace(value.SharingGroupID)
	year, month, day := value.Date.Date()
	value.Date = time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	value.Published = cloneMISPBoolPointer(value.Published)
	value.DisableCorrelation = cloneMISPBoolPointer(value.DisableCorrelation)
	value.Tags, err = normalizeMISPTagNames(value.Tags)
	if err != nil || value.Info == "" || !validMISPText(value.Info) || value.Date.IsZero() || value.Date.After(generatedAt) ||
		!sourceEnrichmentTimeMarshalable(value.Date) || !validMISPEventDistribution(value.Distribution) ||
		!validMISPSharingGroup(value.Distribution, value.SharingGroupID) || !validMISPThreatLevel(value.ThreatLevel) ||
		!validMISPAnalysisLevel(value.Analysis) || value.Published == nil || value.DisableCorrelation == nil {
		return MISPEventDefinition{}, ErrInvalidMISPExportOptions
	}
	return value, nil
}

// ValidateMISPAttributePayload validates the supported native Attribute shape,
// deterministic identity, and detached source metadata.
func ValidateMISPAttributePayload(payload MISPAttributePayload) error {
	eventIdentifier, err := normalizeMISPIdentifier(payload.eventIdentifier)
	if err != nil || eventIdentifier != payload.eventIdentifier || len(payload.raw) == 0 {
		return ErrInvalidMISPAttributePayload
	}
	var request mispAttributeRequest
	if err := decodeMISPStrict(payload.raw, &request); err != nil || !validMISPAttributeRequest(request) {
		return ErrInvalidMISPAttributePayload
	}
	if payload.uuid != request.UUID || payload.candidateID == "" || payload.candidateID != payload.source.CandidateID ||
		request.UUID != mispAttributeUUID(eventIdentifier, MISPAttributeMapping{Type: request.Type, Category: request.Category}, request.Value) ||
		request.Timestamp != strconv.FormatInt(payload.source.GeneratedAt.Unix(), 10) || !request.FirstSeen.Equal(payload.source.PayloadFirstSeen) ||
		!request.LastSeen.Equal(payload.source.PayloadLastSeen) || request.Value != payload.source.SourceIP ||
		request.Type != payload.source.Mapping.Type || request.Category != payload.source.Mapping.Category ||
		payload.source.EventIdentifier != eventIdentifier || !validMISPAttributeSource(payload.source) {
		return ErrInvalidMISPAttributePayload
	}
	return nil
}

// ValidateMISPEventPayload validates the supported complete Event shape and
// every embedded Attribute/source pair.
func ValidateMISPEventPayload(payload MISPEventPayload) error {
	var request mispEventRequest
	if len(payload.raw) == 0 || decodeMISPStrict(payload.raw, &request) != nil || !validMISPEventRequest(request) ||
		payload.uuid != request.UUID || payload.uuid != payload.source.EventUUID || len(request.Attributes) != len(payload.source.Attributes) ||
		payload.source.MappingVersion != MISPExportVersion || payload.source.APIContractVersion != MISPAPIContractVersion ||
		payload.source.InstanceContractVersion == "" ||
		!validMISPText(payload.source.InstanceContractVersion) || payload.source.GeneratedAt.IsZero() ||
		request.Timestamp != strconv.FormatInt(payload.source.GeneratedAt.Unix(), 10) || payload.source.ThreatCandidateDigest == "" {
		return ErrInvalidMISPEventPayload
	}
	if uuid, err := normalizeMISPUUID(request.UUID); err != nil || uuid != request.UUID {
		return ErrInvalidMISPEventPayload
	}
	if date, err := time.Parse(time.DateOnly, request.Date); err != nil || date.After(payload.source.GeneratedAt) {
		return ErrInvalidMISPEventPayload
	}
	for index, attribute := range request.Attributes {
		raw, err := json.Marshal(attribute)
		if err != nil {
			return ErrInvalidMISPEventPayload
		}
		source := payload.source.Attributes[index]
		if source.EventIdentifier != request.UUID || source.GeneratedAt != payload.source.GeneratedAt ||
			source.APIContractVersion != payload.source.APIContractVersion ||
			source.InstanceContractVersion != payload.source.InstanceContractVersion || source.ThreatCandidateDigest != payload.source.ThreatCandidateDigest {
			return ErrInvalidMISPEventPayload
		}
		attributePayload := MISPAttributePayload{
			eventIdentifier: request.UUID, uuid: attribute.UUID, candidateID: source.CandidateID, source: source, raw: raw,
		}
		if err := ValidateMISPAttributePayload(attributePayload); err != nil {
			return ErrInvalidMISPEventPayload
		}
	}
	return nil
}

func validMISPAttributeRequest(value mispAttributeRequest) bool {
	address, err := netip.ParseAddr(value.Value)
	if err != nil || address != address.Unmap() || address.String() != value.Value || !validMISPAttributeType(value.Type) ||
		value.Category == "" || len(value.Category) > 255 || !validMISPText(value.Category) || !validMISPText(value.Comment) || value.Comment == "" ||
		!validMISPAttributeDistribution(value.Distribution) || !validMISPSharingGroup(value.Distribution, value.SharingGroupID) ||
		value.FirstSeen.IsZero() || value.LastSeen.IsZero() || value.FirstSeen.After(value.LastSeen) || !validMISPTags(value.Tags) {
		return false
	}
	uuid, err := normalizeMISPUUID(value.UUID)
	if err != nil || uuid != value.UUID {
		return false
	}
	timestamp, err := strconv.ParseInt(value.Timestamp, 10, 64)
	return err == nil && timestamp >= 0 && value.Timestamp == strconv.FormatInt(timestamp, 10)
}

func validMISPEventRequest(value mispEventRequest) bool {
	if value.Info == "" || !validMISPText(value.Info) || !validMISPEventDistribution(value.Distribution) ||
		!validMISPSharingGroup(value.Distribution, value.SharingGroupID) || !validMISPThreatLevel(value.ThreatLevel) ||
		!validMISPAnalysisLevel(value.Analysis) || !validMISPTags(value.Tags) || len(value.Attributes) == 0 {
		return false
	}
	if date, err := time.Parse(time.DateOnly, value.Date); err != nil || date.Format(time.DateOnly) != value.Date {
		return false
	}
	timestamp, err := strconv.ParseInt(value.Timestamp, 10, 64)
	if err != nil || timestamp < 0 || value.Timestamp != strconv.FormatInt(timestamp, 10) {
		return false
	}
	for index, attribute := range value.Attributes {
		if !validMISPAttributeRequest(attribute) || index > 0 && !mispAttributeRequestLess(value.Attributes[index-1], attribute) {
			return false
		}
	}
	return true
}

func validMISPAttributeSource(value MISPAttributeSource) bool {
	address, err := netip.ParseAddr(value.SourceIP)
	if err != nil || address != address.Unmap() || address.String() != value.SourceIP || value.MappingVersion != MISPExportVersion ||
		value.APIContractVersion != MISPAPIContractVersion ||
		value.InstanceContractVersion == "" || !validMISPText(value.InstanceContractVersion) || value.ThreatCandidateDigest == "" ||
		value.EventIdentifier == "" || value.CandidateID == "" || !validMISPAttributeType(value.Mapping.Type) || value.Mapping.Category == "" ||
		!validMISPText(value.Mapping.Category) || value.GeneratedAt.IsZero() || value.CandidateFirstSeen.IsZero() || value.CandidateLastSeen.IsZero() ||
		value.PayloadFirstSeen.IsZero() || value.PayloadLastSeen.IsZero() || value.CandidateFirstSeen.After(value.CandidateLastSeen) ||
		value.PayloadFirstSeen.After(value.PayloadLastSeen) || value.PayloadLastSeen.After(value.GeneratedAt) ||
		value.ObservationIDs == nil || value.ReportEvidenceIDs == nil || value.CorrelationFindingIDs == nil {
		return false
	}
	return sortedUniqueMISPStrings(value.ObservationIDs) && sortedUniqueMISPStrings(value.ReportEvidenceIDs) && sortedUniqueMISPStrings(value.CorrelationFindingIDs)
}

func normalizeMISPIdentifier(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalidMISPExportOptions
	}
	if number, err := strconv.ParseUint(value, 10, 32); err == nil && number > 0 && len(value) <= 10 && value == strconv.FormatUint(number, 10) {
		return value, nil
	}
	return normalizeMISPUUID(value)
}

func normalizeMISPUUID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", ErrInvalidMISPExportOptions
	}
	if strings.ReplaceAll(value, "-", "") == strings.Repeat("0", 32) {
		return "", ErrInvalidMISPExportOptions
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return "", ErrInvalidMISPExportOptions
		}
	}
	return value, nil
}

func normalizeMISPTagNames(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 255 || !validMISPText(value) {
			return nil, ErrInvalidMISPExportOptions
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return slices.Compact(result), nil
}

func mergeMISPAttributeSettings(defaults, override MISPAttributeSettings) MISPAttributeSettings {
	result := cloneMISPAttributeSettings(defaults)
	if override.ToIDS != nil {
		result.ToIDS = cloneMISPBoolPointer(override.ToIDS)
	}
	if override.DisableCorrelation != nil {
		result.DisableCorrelation = cloneMISPBoolPointer(override.DisableCorrelation)
	}
	if override.Distribution != "" {
		result.Distribution = override.Distribution
		if override.SharingGroupID == "" {
			result.SharingGroupID = ""
		}
	}
	if override.SharingGroupID != "" {
		result.SharingGroupID = override.SharingGroupID
	}
	if override.Comment != "" {
		result.Comment = override.Comment
	}
	result.Tags = append(result.Tags, override.Tags...)
	if override.FirstSeen != nil {
		result.FirstSeen = cloneMISPTimePointer(override.FirstSeen)
	}
	if override.LastSeen != nil {
		result.LastSeen = cloneMISPTimePointer(override.LastSeen)
	}
	return result
}

func cloneMISPAttributeSettings(value MISPAttributeSettings) MISPAttributeSettings {
	value.ToIDS = cloneMISPBoolPointer(value.ToIDS)
	value.DisableCorrelation = cloneMISPBoolPointer(value.DisableCorrelation)
	value.Tags = append([]string(nil), value.Tags...)
	value.FirstSeen = cloneMISPTimePointer(value.FirstSeen)
	value.LastSeen = cloneMISPTimePointer(value.LastSeen)
	return value
}

func cloneMISPAttributeSource(value MISPAttributeSource) MISPAttributeSource {
	value.ObservationIDs = append([]EvidenceID{}, value.ObservationIDs...)
	value.ReportEvidenceIDs = append([]EvidenceID{}, value.ReportEvidenceIDs...)
	value.CorrelationFindingIDs = append([]FindingID{}, value.CorrelationFindingIDs...)
	return value
}

func cloneMISPEventSource(value MISPEventSource) MISPEventSource {
	value.Attributes = append([]MISPAttributeSource(nil), value.Attributes...)
	for index := range value.Attributes {
		value.Attributes[index] = cloneMISPAttributeSource(value.Attributes[index])
	}
	return value
}

func cloneMISPBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneMISPTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func validMISPAttributeType(value MISPAttributeType) bool {
	return value == MISPAttributeTypeIPSource || value == MISPAttributeTypeIPDestination
}

func validMISPAttributeDistribution(value MISPDistribution) bool {
	switch value {
	case MISPDistributionOrganizationOnly, MISPDistributionCommunityOnly, MISPDistributionConnectedCommunities,
		MISPDistributionAllCommunities, MISPDistributionSharingGroup, MISPDistributionInheritEvent:
		return true
	default:
		return false
	}
}

func validMISPEventDistribution(value MISPDistribution) bool {
	switch value {
	case MISPDistributionOrganizationOnly, MISPDistributionCommunityOnly, MISPDistributionConnectedCommunities,
		MISPDistributionAllCommunities, MISPDistributionSharingGroup:
		return true
	default:
		return false
	}
}

func validMISPThreatLevel(value MISPThreatLevel) bool {
	switch value {
	case MISPThreatLevelHigh, MISPThreatLevelMedium, MISPThreatLevelLow, MISPThreatLevelUndefined:
		return true
	default:
		return false
	}
}

func validMISPAnalysisLevel(value MISPAnalysisLevel) bool {
	switch value {
	case MISPAnalysisInitial, MISPAnalysisOngoing, MISPAnalysisComplete:
		return true
	default:
		return false
	}
}

func validMISPSharingGroup(distribution MISPDistribution, identifier string) bool {
	if distribution != MISPDistributionSharingGroup {
		return identifier == ""
	}
	normalized, err := normalizeMISPIdentifier(identifier)
	return err == nil && normalized == identifier
}

func validMISPText(value string) bool {
	return len(value) <= maxMISPTextBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validMISPTags(values []mispTagRequest) bool {
	previous := ""
	for index, value := range values {
		if value.Name == "" || len(value.Name) > 255 || !validMISPText(value.Name) || index > 0 && value.Name <= previous {
			return false
		}
		previous = value.Name
	}
	return true
}

func sortedUniqueMISPStrings[T ~string](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] <= values[index-1] {
			return false
		}
	}
	return true
}

func mispMappingKey(value MISPAttributeMapping) string {
	return string(value.Type) + "\x00" + value.Category
}

func mispAttributeRequestLess(left, right mispAttributeRequest) bool {
	if left.Value != right.Value {
		return left.Value < right.Value
	}
	if left.Type != right.Type {
		return left.Type < right.Type
	}
	return left.Category < right.Category
}

func mispTagRequests(values []string) []mispTagRequest {
	result := make([]mispTagRequest, len(values))
	for index, value := range values {
		result[index] = mispTagRequest{Name: value}
	}
	return result
}

func decodeMISPStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidMISPExportOptions
	}
	return nil
}

// UUIDv5 uses the standard URL namespace with a dmarcgo-specific name. These
// UUIDs are stable correlation identifiers, not security tokens.
func mispAttributeUUID(eventIdentifier string, mapping MISPAttributeMapping, sourceIP string) string {
	name := strings.Join([]string{
		"https://github.com/georgestarcher/dmarcgo/v2/misp/attribute/" + MISPExportVersion,
		eventIdentifier, string(mapping.Type), mapping.Category, sourceIP,
	}, "\x00")
	namespace := [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	hash := sha1.New() // #nosec G401 -- UUIDv5 is a namespacing algorithm, not a security hash.
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write([]byte(name))
	var value [16]byte
	copy(value[:], hash.Sum(nil))
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

type mispTagRequest struct {
	Name string `json:"name"`
}

type mispAttributeRequest struct {
	Type               MISPAttributeType `json:"type"`
	Category           string            `json:"category"`
	Value              string            `json:"value"`
	ToIDS              bool              `json:"to_ids"`
	UUID               string            `json:"uuid"`
	Timestamp          string            `json:"timestamp"`
	Distribution       MISPDistribution  `json:"distribution"`
	SharingGroupID     string            `json:"sharing_group_id,omitempty"`
	Comment            string            `json:"comment"`
	DisableCorrelation bool              `json:"disable_correlation"`
	FirstSeen          time.Time         `json:"first_seen"`
	LastSeen           time.Time         `json:"last_seen"`
	Tags               []mispTagRequest  `json:"Tag,omitempty"`
}

type mispEventRequest struct {
	UUID               string                 `json:"uuid"`
	Info               string                 `json:"info"`
	Date               string                 `json:"date"`
	Published          bool                   `json:"published"`
	Analysis           MISPAnalysisLevel      `json:"analysis"`
	Distribution       MISPDistribution       `json:"distribution"`
	SharingGroupID     string                 `json:"sharing_group_id,omitempty"`
	ThreatLevel        MISPThreatLevel        `json:"threat_level_id"`
	Timestamp          string                 `json:"timestamp"`
	DisableCorrelation bool                   `json:"disable_correlation"`
	Tags               []mispTagRequest       `json:"Tag,omitempty"`
	Attributes         []mispAttributeRequest `json:"Attribute"`
}
