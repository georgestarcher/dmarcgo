package dmarcgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// ThreatStreamExportVersion identifies the dmarcgo-to-ThreatStream
	// mapping. The tenant contract version is supplied separately because
	// Anomali does not publish one universal ingestion schema.
	ThreatStreamExportVersion = "1"

	maxThreatStreamFieldNameBytes = 128
	maxThreatStreamEndpointBytes  = 2048
	maxThreatStreamContractBytes  = 256
	maxThreatStreamLimit          = 1 << 20
)

var (
	// ErrInvalidThreatStreamExportOptions identifies invalid tenant
	// capabilities, selections, settings, timestamps, or limits.
	ErrInvalidThreatStreamExportOptions = errors.New("invalid ThreatStream export options")
	// ErrInvalidThreatStreamPayload identifies a malformed or internally
	// inconsistent native request payload.
	ErrInvalidThreatStreamPayload = errors.New("invalid ThreatStream payload")
	// ErrUnsupportedThreatStreamCapability identifies a selected mapping or
	// value that the supplied tenant contract does not support.
	ErrUnsupportedThreatStreamCapability = errors.New("unsupported ThreatStream capability")
)

// ThreatStreamPayloadVariant selects one tenant-confirmed request shape.
type ThreatStreamPayloadVariant string

const (
	// ThreatStreamDirectObservable encodes one flat observable request.
	ThreatStreamDirectObservable ThreatStreamPayloadVariant = "direct_observable"
	// ThreatStreamReviewedImport encodes one observable inside a tenant-named
	// import collection with an explicit pending-review state.
	ThreatStreamReviewedImport ThreatStreamPayloadVariant = "reviewed_import"
)

// ThreatStreamFieldScope identifies whether a reviewed-import field belongs
// on the request envelope or the observable item. Direct-observable fields
// must all use the root scope.
type ThreatStreamFieldScope string

const (
	ThreatStreamFieldRoot ThreatStreamFieldScope = "root"
	ThreatStreamFieldItem ThreatStreamFieldScope = "item"
)

// ThreatStreamTagEncoding records the tenant-confirmed JSON representation.
type ThreatStreamTagEncoding string

const (
	ThreatStreamTagsStringArray    ThreatStreamTagEncoding = "string_array"
	ThreatStreamTagsCommaSeparated ThreatStreamTagEncoding = "comma_separated"
)

// ThreatStreamTimestampEncoding records the tenant-confirmed JSON timestamp
// representation used for expiration.
type ThreatStreamTimestampEncoding string

const (
	ThreatStreamTimestampRFC3339     ThreatStreamTimestampEncoding = "rfc3339"
	ThreatStreamTimestampUnixSeconds ThreatStreamTimestampEncoding = "unix_seconds"
)

// ThreatStreamResponseMode records a caller-confirmed response style. It is
// metadata only: the library never sends a request or parses a response.
type ThreatStreamResponseMode string

const (
	ThreatStreamResponseSynchronous  ThreatStreamResponseMode = "synchronous"
	ThreatStreamResponseAsynchronous ThreatStreamResponseMode = "asynchronous"
)

// ThreatStreamCapability identifies one fail-closed tenant mapping decision.
type ThreatStreamCapability string

const (
	ThreatStreamCapabilityIType          ThreatStreamCapability = "itype"
	ThreatStreamCapabilityConfidence     ThreatStreamCapability = "confidence"
	ThreatStreamCapabilitySeverity       ThreatStreamCapability = "severity"
	ThreatStreamCapabilityClassification ThreatStreamCapability = "classification"
	ThreatStreamCapabilityTLP            ThreatStreamCapability = "tlp"
	ThreatStreamCapabilityReviewState    ThreatStreamCapability = "review_state"
)

// ThreatStreamJSONField maps one semantic value to a tenant-confirmed JSON
// property. Names and scopes are data and never become generated guidance.
type ThreatStreamJSONField struct {
	Name  string
	Scope ThreatStreamFieldScope
}

// ThreatStreamFieldMappings declares the exact request property names. Every
// field except ReviewState is required. ReviewState is required for the
// reviewed-import variant and optional for the direct variant.
type ThreatStreamFieldMappings struct {
	Observable     ThreatStreamJSONField
	IType          ThreatStreamJSONField
	Confidence     ThreatStreamJSONField
	Severity       ThreatStreamJSONField
	Classification ThreatStreamJSONField
	TLP            ThreatStreamJSONField
	Tags           ThreatStreamJSONField
	Expiration     ThreatStreamJSONField
	ReviewState    ThreatStreamJSONField
}

// ThreatStreamITypeCapability declares one exact tenant itype and the address
// families for which the caller confirmed it is valid.
type ThreatStreamITypeCapability struct {
	Value   string
	IPTypes []ThreatCandidateIPType
}

// ThreatStreamSeverityMapping is an explicit opt-in mapping from dmarcgo
// review severity to one tenant-supported ThreatStream value.
type ThreatStreamSeverityMapping struct {
	CandidateSeverity FindingSeverity
	Value             string
}

// ThreatStreamValueRange declares the tenant-confirmed inclusive confidence
// range. Both values must remain within 0 through 100.
type ThreatStreamValueRange struct {
	Minimum int
	Maximum int
}

// ThreatStreamReviewDefaults are tenant-confirmed conservative defaults.
// PrivateClassification and, for reviewed imports, PendingReviewState are
// mandatory so a zero per-selection Settings value cannot invent a malicious
// or public classification. Confidence is a caller-chosen platform value; it
// is not automatically derived from evidence confidence.
type ThreatStreamReviewDefaults struct {
	Confidence            int
	Severity              string
	PrivateClassification string
	TLP                   string
	PendingReviewState    string
	Tags                  []string
	ExpirationAfter       time.Duration
}

// ThreatStreamResponseAssumptions record tenant-confirmed response metadata.
// They do not cause response parsing. Applications own HTTP, asynchronous job
// handling, success interpretation, and audit storage.
type ThreatStreamResponseAssumptions struct {
	ContractVersion  string
	Mode             ThreatStreamResponseMode
	IdentifierField  string
	StatusField      string
	AcceptedStatuses []string
}

// ThreatStreamTenantCapabilities is the complete caller-supplied request
// contract for one payload variant. Endpoint must be a relative path without
// credentials, query parameters, or a fragment. ItemsField is empty for a
// direct request and mandatory for a reviewed import.
type ThreatStreamTenantCapabilities struct {
	ContractVersion     string
	Variant             ThreatStreamPayloadVariant
	Endpoint            string
	ItemsField          string
	Fields              ThreatStreamFieldMappings
	ITypes              []ThreatStreamITypeCapability
	Confidence          ThreatStreamValueRange
	Severities          []string
	SeverityMappings    []ThreatStreamSeverityMapping
	Classifications     []string
	TLPs                []string
	ReviewStates        []string
	TagEncoding         ThreatStreamTagEncoding
	TimestampEncoding   ThreatStreamTimestampEncoding
	MaximumStringBytes  int
	MaximumTags         int
	MaximumPayloadBytes int
	ReviewDefaults      ThreatStreamReviewDefaults
	Response            ThreatStreamResponseAssumptions
}

// ThreatStreamObservableSettings overrides tenant review defaults for one
// selection. Evidence confidence and candidate severity are mapped only when
// their corresponding boolean is explicitly true. Explicit values and mapping
// the same semantic value are mutually exclusive. Tags are caller-controlled
// untrusted data and are added to the tenant defaults.
type ThreatStreamObservableSettings struct {
	MapEvidenceConfidence *bool
	Confidence            *int
	MapCandidateSeverity  *bool
	Severity              string
	Classification        string
	TLP                   string
	ReviewState           string
	Tags                  []string
	ExpiresAt             *time.Time
}

// ThreatStreamCandidateSelection is an explicit decision to encode one
// review-eligible, non-excluded source address with one tenant-confirmed itype.
type ThreatStreamCandidateSelection struct {
	CandidateID AnalysisID
	IType       string
	Settings    ThreatStreamObservableSettings
}

// ThreatStreamExportOptions controls deterministic native request encoding.
// GeneratedAt defaults to the completed candidate result time and never reads
// the system clock. Defaults apply before per-selection Settings.
type ThreatStreamExportOptions struct {
	GeneratedAt  time.Time
	Capabilities ThreatStreamTenantCapabilities
	Defaults     ThreatStreamObservableSettings
	Selections   []ThreatStreamCandidateSelection
}

// ThreatStreamPayloadSource retains normalized evidence references outside the
// vendor-native JSON body.
type ThreatStreamPayloadSource struct {
	MappingVersion          string                     `json:"mapping_version"`
	TenantContractVersion   string                     `json:"tenant_contract_version"`
	ResponseContractVersion string                     `json:"response_contract_version"`
	ResponseMode            ThreatStreamResponseMode   `json:"response_mode"`
	GeneratedAt             time.Time                  `json:"generated_at"`
	Variant                 ThreatStreamPayloadVariant `json:"variant"`
	Endpoint                string                     `json:"endpoint"`
	ThreatCandidateDigest   AnalysisID                 `json:"threat_candidate_digest"`
	CandidateID             AnalysisID                 `json:"candidate_id"`
	IType                   string                     `json:"itype"`
	SourceIP                string                     `json:"source_ip"`
	CandidateFirstSeen      time.Time                  `json:"candidate_first_seen"`
	CandidateLastSeen       time.Time                  `json:"candidate_last_seen"`
	ObservationIDs          []EvidenceID               `json:"observation_ids"`
	ReportEvidenceIDs       []EvidenceID               `json:"report_evidence_ids"`
	CorrelationFindingIDs   []FindingID                `json:"correlation_finding_ids"`
}

// ThreatStreamPayload is one immutable tenant-native request body. MarshalJSON
// emits only native fields; defensive evidence metadata remains available
// through Source.
type ThreatStreamPayload struct {
	capabilities ThreatStreamTenantCapabilities
	settings     resolvedThreatStreamSettings
	source       ThreatStreamPayloadSource
	raw          []byte
}

// Variant returns the selected request shape.
func (payload ThreatStreamPayload) Variant() ThreatStreamPayloadVariant {
	return payload.source.Variant
}

// Endpoint returns the tenant-confirmed relative endpoint. The library never
// calls it.
func (payload ThreatStreamPayload) Endpoint() string { return payload.source.Endpoint }

// CandidateID returns the stable selected candidate identifier.
func (payload ThreatStreamPayload) CandidateID() AnalysisID { return payload.source.CandidateID }

// ResponseAssumptions returns a defensive copy of caller-supplied response
// metadata. The encoder never interprets a live response.
func (payload ThreatStreamPayload) ResponseAssumptions() ThreatStreamResponseAssumptions {
	return cloneThreatStreamResponse(payload.capabilities.Response)
}

// Source returns a defensive copy of the evidence references behind the
// native request.
func (payload ThreatStreamPayload) Source() ThreatStreamPayloadSource {
	return cloneThreatStreamSource(payload.source)
}

// MarshalJSON implements json.Marshaler and returns one validated native
// request body.
func (payload ThreatStreamPayload) MarshalJSON() ([]byte, error) {
	if err := ValidateThreatStreamPayload(payload); err != nil {
		return nil, err
	}
	return append([]byte(nil), payload.raw...), nil
}

// ThreatStreamUnsupportedCapabilityError identifies the selected semantic
// mapping without copying its potentially untrusted value into Error output.
type ThreatStreamUnsupportedCapabilityError struct {
	CandidateID AnalysisID
	Variant     ThreatStreamPayloadVariant
	Capability  ThreatStreamCapability
	Value       string
}

func (err *ThreatStreamUnsupportedCapabilityError) Error() string {
	return fmt.Sprintf("%s for candidate %s: %s", ErrUnsupportedThreatStreamCapability, err.CandidateID, err.Capability)
}

func (err *ThreatStreamUnsupportedCapabilityError) Unwrap() error {
	return ErrUnsupportedThreatStreamCapability
}

// BuildThreatStreamPayloads converts explicit candidate selections into
// deterministic direct-observable or reviewed-import request bodies. It is
// pure and performs no DNS, HTTP, PTR, SMTP, ICMP, filesystem, credential,
// response parsing, polling, approval, retry, clock, or source-IP activity.
func BuildThreatStreamPayloads(candidates ThreatCandidateResult, options ThreatStreamExportOptions) ([]ThreatStreamPayload, error) {
	if err := validateSourceEnrichmentInput(candidates); err != nil {
		return nil, errors.Join(ErrInvalidThreatStreamExportOptions, err)
	}
	capabilities, err := normalizeThreatStreamCapabilities(options.Capabilities)
	if err != nil {
		return nil, err
	}
	generatedAt := options.GeneratedAt
	inputGeneratedAt := candidates.ResultMetadata().GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = inputGeneratedAt
	} else {
		generatedAt = generatedAt.UTC()
	}
	generatedAt = generatedAt.UTC()
	if generatedAt.IsZero() || generatedAt.Before(inputGeneratedAt) || !sourceEnrichmentTimeMarshalable(generatedAt) || len(options.Selections) == 0 {
		return nil, ErrInvalidThreatStreamExportOptions
	}
	selections := cloneThreatStreamSelections(options.Selections)
	sort.Slice(selections, func(i, j int) bool { return selections[i].CandidateID < selections[j].CandidateID })
	for index, selection := range selections {
		selection.IType = strings.TrimSpace(selection.IType)
		selections[index] = selection
		if selection.CandidateID == "" || selection.IType == "" || index > 0 && selections[index-1].CandidateID == selection.CandidateID {
			return nil, ErrInvalidThreatStreamExportOptions
		}
	}

	candidateByID := make(map[AnalysisID]ThreatCandidate, len(candidates.candidates))
	for _, candidate := range candidates.Candidates() {
		candidateByID[candidate.ID] = candidate
	}
	payloads := make([]ThreatStreamPayload, 0, len(selections))
	for _, selection := range selections {
		candidate, exists := candidateByID[selection.CandidateID]
		if !exists || !sourceEnrichmentEligible(candidate) || !candidate.FirstSeen.Available || !candidate.LastSeen.Available ||
			candidate.FirstSeen.Value.After(candidate.LastSeen.Value) || candidate.DualFailureMessages < 1 {
			return nil, errors.Join(ErrInvalidThreatStreamExportOptions, ErrInvalidAnalysisResult)
		}
		address, parseErr := netip.ParseAddr(candidate.SourceIP)
		if parseErr != nil || address != address.Unmap() || address.String() != candidate.SourceIP {
			return nil, errors.Join(ErrInvalidThreatStreamExportOptions, ErrInvalidAnalysisResult)
		}
		if !threatStreamSupportsIType(capabilities, selection.IType, candidate.IPType) {
			return nil, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilityIType, selection.IType)
		}
		settings, settingsErr := resolveThreatStreamSettings(candidate, generatedAt, capabilities, options.Defaults, selection.Settings)
		if settingsErr != nil {
			return nil, settingsErr
		}
		source := ThreatStreamPayloadSource{
			MappingVersion: ThreatStreamExportVersion, TenantContractVersion: capabilities.ContractVersion,
			ResponseContractVersion: capabilities.Response.ContractVersion, ResponseMode: capabilities.Response.Mode,
			GeneratedAt: generatedAt, Variant: capabilities.Variant, Endpoint: capabilities.Endpoint,
			ThreatCandidateDigest: candidates.Digest(), CandidateID: candidate.ID, IType: selection.IType, SourceIP: candidate.SourceIP,
			CandidateFirstSeen: candidate.FirstSeen.Value.UTC(), CandidateLastSeen: candidate.LastSeen.Value.UTC(),
			ObservationIDs: append([]EvidenceID{}, candidate.ObservationIDs...), ReportEvidenceIDs: append([]EvidenceID{}, candidate.ReportEvidenceIDs...),
			CorrelationFindingIDs: append([]FindingID{}, candidate.CorrelationFindingIDs...),
		}
		raw, buildErr := buildThreatStreamRequest(capabilities, settings, source.SourceIP, source.IType)
		if buildErr != nil {
			return nil, buildErr
		}
		payload := ThreatStreamPayload{
			capabilities: cloneThreatStreamCapabilities(capabilities), settings: cloneResolvedThreatStreamSettings(settings),
			source: cloneThreatStreamSource(source), raw: raw,
		}
		if validateErr := ValidateThreatStreamPayload(payload); validateErr != nil {
			return nil, validateErr
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

// ValidateThreatStreamPayload validates the configured contract, evidence
// metadata, exact native shape, limits, and internal consistency.
func ValidateThreatStreamPayload(payload ThreatStreamPayload) error {
	capabilities, err := normalizeThreatStreamCapabilities(payload.capabilities)
	if err != nil || !reflect.DeepEqual(capabilities, payload.capabilities) || validateThreatStreamSource(payload.source) != nil || len(payload.raw) == 0 {
		return ErrInvalidThreatStreamPayload
	}
	if payload.source.TenantContractVersion != capabilities.ContractVersion || payload.source.ResponseContractVersion != capabilities.Response.ContractVersion ||
		payload.source.ResponseMode != capabilities.Response.Mode || payload.source.Variant != capabilities.Variant || payload.source.Endpoint != capabilities.Endpoint ||
		!threatStreamSupportsIType(capabilities, payload.source.IType, threatStreamIPType(payload.source.SourceIP)) ||
		validateResolvedThreatStreamSettings(payload.settings, capabilities) != nil || !payload.settings.ExpiresAt.After(payload.source.GeneratedAt) {
		return ErrInvalidThreatStreamPayload
	}
	want, err := buildThreatStreamRequest(capabilities, payload.settings, payload.source.SourceIP, payload.source.IType)
	if err != nil || !bytes.Equal(want, payload.raw) {
		return ErrInvalidThreatStreamPayload
	}
	return nil
}

// WriteThreatStreamPayload writes one validated native request body followed
// by a newline.
func WriteThreatStreamPayload(writer io.Writer, payload ThreatStreamPayload) error {
	if writer == nil {
		return ErrInvalidThreatStreamPayload
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

type resolvedThreatStreamSettings struct {
	Confidence     int
	Severity       string
	Classification string
	TLP            string
	ReviewState    string
	Tags           []string
	ExpiresAt      time.Time
}

func resolveThreatStreamSettings(candidate ThreatCandidate, generatedAt time.Time, capabilities ThreatStreamTenantCapabilities,
	defaults, override ThreatStreamObservableSettings,
) (resolvedThreatStreamSettings, error) {
	mapConfidence := false
	if defaults.MapEvidenceConfidence != nil {
		mapConfidence = *defaults.MapEvidenceConfidence
	}
	if override.MapEvidenceConfidence != nil {
		mapConfidence = *override.MapEvidenceConfidence
	}
	explicitConfidence := defaults.Confidence
	if override.Confidence != nil {
		explicitConfidence = override.Confidence
	}
	if mapConfidence && explicitConfidence != nil {
		return resolvedThreatStreamSettings{}, ErrInvalidThreatStreamExportOptions
	}
	confidence := capabilities.ReviewDefaults.Confidence
	if mapConfidence {
		confidence = candidate.Confidence
	} else if explicitConfidence != nil {
		confidence = *explicitConfidence
	}
	if confidence < capabilities.Confidence.Minimum || confidence > capabilities.Confidence.Maximum {
		return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilityConfidence, fmt.Sprint(confidence))
	}

	mapSeverity := false
	if defaults.MapCandidateSeverity != nil {
		mapSeverity = *defaults.MapCandidateSeverity
	}
	if override.MapCandidateSeverity != nil {
		mapSeverity = *override.MapCandidateSeverity
	}
	explicitSeverity := strings.TrimSpace(defaults.Severity)
	if strings.TrimSpace(override.Severity) != "" {
		explicitSeverity = strings.TrimSpace(override.Severity)
	}
	if mapSeverity && explicitSeverity != "" {
		return resolvedThreatStreamSettings{}, ErrInvalidThreatStreamExportOptions
	}
	severity := capabilities.ReviewDefaults.Severity
	if mapSeverity {
		var matched bool
		for _, mapping := range capabilities.SeverityMappings {
			if mapping.CandidateSeverity == candidate.Severity {
				severity, matched = mapping.Value, true
				break
			}
		}
		if !matched {
			return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilitySeverity, string(candidate.Severity))
		}
	} else if explicitSeverity != "" {
		severity = explicitSeverity
	}
	if !slices.Contains(capabilities.Severities, severity) {
		return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilitySeverity, severity)
	}

	classification := capabilities.ReviewDefaults.PrivateClassification
	if strings.TrimSpace(defaults.Classification) != "" {
		classification = strings.TrimSpace(defaults.Classification)
	}
	if strings.TrimSpace(override.Classification) != "" {
		classification = strings.TrimSpace(override.Classification)
	}
	if !slices.Contains(capabilities.Classifications, classification) {
		return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilityClassification, classification)
	}
	tlp := capabilities.ReviewDefaults.TLP
	if strings.TrimSpace(defaults.TLP) != "" {
		tlp = strings.TrimSpace(defaults.TLP)
	}
	if strings.TrimSpace(override.TLP) != "" {
		tlp = strings.TrimSpace(override.TLP)
	}
	if !slices.Contains(capabilities.TLPs, tlp) {
		return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilityTLP, tlp)
	}
	reviewState := capabilities.ReviewDefaults.PendingReviewState
	if strings.TrimSpace(defaults.ReviewState) != "" {
		reviewState = strings.TrimSpace(defaults.ReviewState)
	}
	if strings.TrimSpace(override.ReviewState) != "" {
		reviewState = strings.TrimSpace(override.ReviewState)
	}
	if capabilities.Fields.ReviewState.Name == "" {
		if reviewState != "" {
			return resolvedThreatStreamSettings{}, ErrInvalidThreatStreamExportOptions
		}
	} else if !slices.Contains(capabilities.ReviewStates, reviewState) {
		return resolvedThreatStreamSettings{}, unsupportedThreatStream(candidate.ID, capabilities.Variant, ThreatStreamCapabilityReviewState, reviewState)
	}

	tags, err := normalizeThreatStreamTags(append(append(append([]string{}, capabilities.ReviewDefaults.Tags...), defaults.Tags...), override.Tags...), capabilities)
	if err != nil {
		return resolvedThreatStreamSettings{}, err
	}
	expiresAt := generatedAt.Add(capabilities.ReviewDefaults.ExpirationAfter)
	if defaults.ExpiresAt != nil {
		expiresAt = defaults.ExpiresAt.UTC()
	}
	if override.ExpiresAt != nil {
		expiresAt = override.ExpiresAt.UTC()
	}
	settings := resolvedThreatStreamSettings{
		Confidence: confidence, Severity: severity, Classification: classification, TLP: tlp,
		ReviewState: reviewState, Tags: tags, ExpiresAt: expiresAt,
	}
	if err := validateResolvedThreatStreamSettings(settings, capabilities); err != nil || !expiresAt.After(generatedAt) {
		return resolvedThreatStreamSettings{}, ErrInvalidThreatStreamExportOptions
	}
	return settings, nil
}

func buildThreatStreamRequest(capabilities ThreatStreamTenantCapabilities, settings resolvedThreatStreamSettings, sourceIP, itype string) ([]byte, error) {
	root := map[string]any{}
	item := root
	if capabilities.Variant == ThreatStreamReviewedImport {
		item = map[string]any{}
	}
	set := func(field ThreatStreamJSONField, value any) {
		if field.Name == "" {
			return
		}
		if field.Scope == ThreatStreamFieldItem {
			item[field.Name] = value
		} else {
			root[field.Name] = value
		}
	}
	set(capabilities.Fields.Observable, sourceIP)
	set(capabilities.Fields.IType, itype)
	set(capabilities.Fields.Confidence, settings.Confidence)
	set(capabilities.Fields.Severity, settings.Severity)
	set(capabilities.Fields.Classification, settings.Classification)
	set(capabilities.Fields.TLP, settings.TLP)
	if capabilities.TagEncoding == ThreatStreamTagsCommaSeparated {
		set(capabilities.Fields.Tags, strings.Join(settings.Tags, ","))
	} else {
		set(capabilities.Fields.Tags, append([]string{}, settings.Tags...))
	}
	if capabilities.TimestampEncoding == ThreatStreamTimestampUnixSeconds {
		set(capabilities.Fields.Expiration, settings.ExpiresAt.Unix())
	} else {
		set(capabilities.Fields.Expiration, settings.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	set(capabilities.Fields.ReviewState, settings.ReviewState)
	var request json.Marshaler
	if capabilities.Variant == ThreatStreamReviewedImport {
		root[capabilities.ItemsField] = []any{item}
		request = threatStreamReviewedImportRequest{Envelope: root}
	} else {
		request = threatStreamDirectObservableRequest{Fields: root}
	}
	raw, err := request.MarshalJSON()
	if err != nil {
		return nil, errors.Join(ErrInvalidThreatStreamPayload, err)
	}
	if len(raw) > capabilities.MaximumPayloadBytes {
		return nil, ErrInvalidThreatStreamExportOptions
	}
	return raw, nil
}

// These DTOs deliberately remain separate even though tenant capabilities
// control their property names. A direct request is flat; a reviewed import is
// an envelope containing exactly one observable item.
type threatStreamDirectObservableRequest struct {
	Fields map[string]any
}

func (request threatStreamDirectObservableRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(request.Fields)
}

type threatStreamReviewedImportRequest struct {
	Envelope map[string]any
}

func (request threatStreamReviewedImportRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(request.Envelope)
}

func normalizeThreatStreamCapabilities(value ThreatStreamTenantCapabilities) (ThreatStreamTenantCapabilities, error) {
	value = cloneThreatStreamCapabilities(value)
	value.ContractVersion = strings.TrimSpace(value.ContractVersion)
	value.Endpoint = strings.TrimSpace(value.Endpoint)
	value.ItemsField = strings.TrimSpace(value.ItemsField)
	value.Response.ContractVersion = strings.TrimSpace(value.Response.ContractVersion)
	value.Response.IdentifierField = strings.TrimSpace(value.Response.IdentifierField)
	value.Response.StatusField = strings.TrimSpace(value.Response.StatusField)
	if !validThreatStreamContract(value.ContractVersion) || !validThreatStreamEndpoint(value.Endpoint) ||
		value.MaximumStringBytes < 1 || value.MaximumStringBytes > maxThreatStreamLimit || value.MaximumTags < 1 || value.MaximumTags > maxThreatStreamLimit ||
		value.MaximumPayloadBytes < 1 || value.MaximumPayloadBytes > maxThreatStreamLimit || value.Confidence.Minimum < 0 ||
		value.Confidence.Maximum > 100 || value.Confidence.Minimum > value.Confidence.Maximum ||
		(value.TagEncoding != ThreatStreamTagsStringArray && value.TagEncoding != ThreatStreamTagsCommaSeparated) ||
		(value.TimestampEncoding != ThreatStreamTimestampRFC3339 && value.TimestampEncoding != ThreatStreamTimestampUnixSeconds) {
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}
	fields := []*ThreatStreamJSONField{
		&value.Fields.Observable, &value.Fields.IType, &value.Fields.Confidence, &value.Fields.Severity,
		&value.Fields.Classification, &value.Fields.TLP, &value.Fields.Tags, &value.Fields.Expiration, &value.Fields.ReviewState,
	}
	for _, field := range fields {
		field.Name = strings.TrimSpace(field.Name)
		if field.Name != "" && !validThreatStreamFieldName(field.Name) {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
	}
	required := fields[:8]
	for _, field := range required {
		if field.Name == "" {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
	}
	switch value.Variant {
	case ThreatStreamDirectObservable:
		if value.ItemsField != "" {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
		for _, field := range fields {
			if field.Name != "" && field.Scope != ThreatStreamFieldRoot {
				return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
			}
		}
	case ThreatStreamReviewedImport:
		if !validThreatStreamFieldName(value.ItemsField) || value.Fields.Observable.Scope != ThreatStreamFieldItem || value.Fields.IType.Scope != ThreatStreamFieldItem ||
			value.Fields.ReviewState.Name == "" {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
		for _, field := range fields {
			if field.Name != "" && field.Scope != ThreatStreamFieldRoot && field.Scope != ThreatStreamFieldItem {
				return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
			}
		}
	default:
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}
	if !uniqueThreatStreamFields(value) {
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}

	var err error
	value.Severities, err = normalizeThreatStreamStrings(value.Severities, value.MaximumStringBytes, false)
	if err != nil {
		return ThreatStreamTenantCapabilities{}, err
	}
	value.Classifications, err = normalizeThreatStreamStrings(value.Classifications, value.MaximumStringBytes, false)
	if err != nil {
		return ThreatStreamTenantCapabilities{}, err
	}
	value.TLPs, err = normalizeThreatStreamStrings(value.TLPs, value.MaximumStringBytes, false)
	if err != nil {
		return ThreatStreamTenantCapabilities{}, err
	}
	value.ReviewStates, err = normalizeThreatStreamStrings(value.ReviewStates, value.MaximumStringBytes, value.Fields.ReviewState.Name == "")
	if err != nil {
		return ThreatStreamTenantCapabilities{}, err
	}
	if value.Fields.ReviewState.Name == "" && len(value.ReviewStates) != 0 {
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}
	value.ReviewDefaults.Severity = strings.TrimSpace(value.ReviewDefaults.Severity)
	value.ReviewDefaults.PrivateClassification = strings.TrimSpace(value.ReviewDefaults.PrivateClassification)
	value.ReviewDefaults.TLP = strings.TrimSpace(value.ReviewDefaults.TLP)
	value.ReviewDefaults.PendingReviewState = strings.TrimSpace(value.ReviewDefaults.PendingReviewState)
	value.ReviewDefaults.Tags, err = normalizeThreatStreamTags(value.ReviewDefaults.Tags, value)
	if err != nil || value.ReviewDefaults.ExpirationAfter <= 0 || value.ReviewDefaults.ExpirationAfter > 100*365*24*time.Hour ||
		value.ReviewDefaults.Confidence < value.Confidence.Minimum || value.ReviewDefaults.Confidence > value.Confidence.Maximum ||
		!slices.Contains(value.Severities, value.ReviewDefaults.Severity) ||
		!slices.Contains(value.Classifications, value.ReviewDefaults.PrivateClassification) || !slices.Contains(value.TLPs, value.ReviewDefaults.TLP) ||
		(value.Fields.ReviewState.Name == "" && value.ReviewDefaults.PendingReviewState != "") ||
		(value.Fields.ReviewState.Name != "" && !slices.Contains(value.ReviewStates, value.ReviewDefaults.PendingReviewState)) {
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}

	if len(value.ITypes) == 0 {
		return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
	}
	for index := range value.ITypes {
		value.ITypes[index].Value = strings.TrimSpace(value.ITypes[index].Value)
		value.ITypes[index].IPTypes = append([]ThreatCandidateIPType{}, value.ITypes[index].IPTypes...)
		sort.Slice(value.ITypes[index].IPTypes, func(i, j int) bool { return value.ITypes[index].IPTypes[i] < value.ITypes[index].IPTypes[j] })
		value.ITypes[index].IPTypes = slices.Compact(value.ITypes[index].IPTypes)
		if value.ITypes[index].Value == "" || !validThreatStreamValue(value.ITypes[index].Value, value.MaximumStringBytes) || len(value.ITypes[index].IPTypes) == 0 {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
		for _, ipType := range value.ITypes[index].IPTypes {
			if ipType != ThreatCandidateIPv4 && ipType != ThreatCandidateIPv6 {
				return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
			}
		}
	}
	sort.Slice(value.ITypes, func(i, j int) bool { return value.ITypes[i].Value < value.ITypes[j].Value })
	for index := 1; index < len(value.ITypes); index++ {
		if value.ITypes[index-1].Value == value.ITypes[index].Value {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
	}
	for index := range value.SeverityMappings {
		value.SeverityMappings[index].Value = strings.TrimSpace(value.SeverityMappings[index].Value)
		if !validFindingSeverity(value.SeverityMappings[index].CandidateSeverity) || !slices.Contains(value.Severities, value.SeverityMappings[index].Value) {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
	}
	sort.Slice(value.SeverityMappings, func(i, j int) bool {
		return value.SeverityMappings[i].CandidateSeverity < value.SeverityMappings[j].CandidateSeverity
	})
	for index := 1; index < len(value.SeverityMappings); index++ {
		if value.SeverityMappings[index-1].CandidateSeverity == value.SeverityMappings[index].CandidateSeverity {
			return ThreatStreamTenantCapabilities{}, ErrInvalidThreatStreamExportOptions
		}
	}
	response, err := normalizeThreatStreamResponse(value.Response, value.MaximumStringBytes)
	if err != nil {
		return ThreatStreamTenantCapabilities{}, err
	}
	value.Response = response
	return value, nil
}

func normalizeThreatStreamResponse(value ThreatStreamResponseAssumptions, maxBytes int) (ThreatStreamResponseAssumptions, error) {
	value.ContractVersion = strings.TrimSpace(value.ContractVersion)
	value.IdentifierField = strings.TrimSpace(value.IdentifierField)
	value.StatusField = strings.TrimSpace(value.StatusField)
	statuses, err := normalizeThreatStreamStrings(value.AcceptedStatuses, maxBytes, true)
	if err != nil || !validThreatStreamContract(value.ContractVersion) || !validOptionalThreatStreamFieldName(value.IdentifierField) ||
		!validOptionalThreatStreamFieldName(value.StatusField) || (value.Mode != ThreatStreamResponseSynchronous && value.Mode != ThreatStreamResponseAsynchronous) {
		return ThreatStreamResponseAssumptions{}, ErrInvalidThreatStreamExportOptions
	}
	if value.IdentifierField != "" && value.IdentifierField == value.StatusField {
		return ThreatStreamResponseAssumptions{}, ErrInvalidThreatStreamExportOptions
	}
	if value.Mode == ThreatStreamResponseAsynchronous && (value.IdentifierField == "" || value.StatusField == "" || len(statuses) == 0) {
		return ThreatStreamResponseAssumptions{}, ErrInvalidThreatStreamExportOptions
	}
	value.AcceptedStatuses = statuses
	return value, nil
}

func validateResolvedThreatStreamSettings(value resolvedThreatStreamSettings, capabilities ThreatStreamTenantCapabilities) error {
	if value.Confidence < capabilities.Confidence.Minimum || value.Confidence > capabilities.Confidence.Maximum ||
		!slices.Contains(capabilities.Severities, value.Severity) || !slices.Contains(capabilities.Classifications, value.Classification) ||
		!slices.Contains(capabilities.TLPs, value.TLP) || !sourceEnrichmentTimeMarshalable(value.ExpiresAt) || value.ExpiresAt.IsZero() {
		return ErrInvalidThreatStreamPayload
	}
	if capabilities.Fields.ReviewState.Name == "" {
		if value.ReviewState != "" {
			return ErrInvalidThreatStreamPayload
		}
	} else if !slices.Contains(capabilities.ReviewStates, value.ReviewState) {
		return ErrInvalidThreatStreamPayload
	}
	tags, err := normalizeThreatStreamTags(value.Tags, capabilities)
	if err != nil || !slices.Equal(tags, value.Tags) {
		return ErrInvalidThreatStreamPayload
	}
	return nil
}

func validateThreatStreamSource(source ThreatStreamPayloadSource) error {
	address, err := netip.ParseAddr(source.SourceIP)
	if err != nil || address != address.Unmap() || address.String() != source.SourceIP || source.MappingVersion != ThreatStreamExportVersion ||
		!validThreatStreamContract(source.TenantContractVersion) || !validThreatStreamContract(source.ResponseContractVersion) ||
		source.GeneratedAt.IsZero() || !sourceEnrichmentTimeMarshalable(source.GeneratedAt) || source.Endpoint == "" || source.ThreatCandidateDigest == "" ||
		source.CandidateID == "" || source.IType == "" || source.CandidateFirstSeen.IsZero() || source.CandidateLastSeen.IsZero() ||
		source.CandidateFirstSeen.After(source.CandidateLastSeen) || source.GeneratedAt.Before(source.CandidateLastSeen) || !sourceEnrichmentTimeMarshalable(source.CandidateFirstSeen) ||
		!sourceEnrichmentTimeMarshalable(source.CandidateLastSeen) || !sortedUniqueThreatStreamEvidenceIDs(source.ObservationIDs) ||
		!sortedUniqueThreatStreamEvidenceIDs(source.ReportEvidenceIDs) || !sortedUniqueThreatStreamFindingIDs(source.CorrelationFindingIDs) {
		return ErrInvalidThreatStreamPayload
	}
	return nil
}

func threatStreamSupportsIType(capabilities ThreatStreamTenantCapabilities, value string, ipType ThreatCandidateIPType) bool {
	for _, supported := range capabilities.ITypes {
		if supported.Value == value && slices.Contains(supported.IPTypes, ipType) {
			return true
		}
	}
	return false
}

func threatStreamIPType(value string) ThreatCandidateIPType {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	if address.Is4() {
		return ThreatCandidateIPv4
	}
	return ThreatCandidateIPv6
}

func normalizeThreatStreamTags(values []string, capabilities ThreatStreamTenantCapabilities) ([]string, error) {
	result, err := normalizeThreatStreamStrings(values, capabilities.MaximumStringBytes, true)
	if err != nil || len(result) > capabilities.MaximumTags {
		return nil, ErrInvalidThreatStreamExportOptions
	}
	if capabilities.TagEncoding == ThreatStreamTagsCommaSeparated {
		for _, value := range result {
			if strings.Contains(value, ",") {
				return nil, ErrInvalidThreatStreamExportOptions
			}
		}
	}
	return result, nil
}

func normalizeThreatStreamStrings(values []string, maxBytes int, allowEmpty bool) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validThreatStreamValue(value, maxBytes) {
			return nil, ErrInvalidThreatStreamExportOptions
		}
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	result = slices.Compact(result)
	if !allowEmpty && len(result) == 0 {
		return nil, ErrInvalidThreatStreamExportOptions
	}
	return result, nil
}

func uniqueThreatStreamFields(value ThreatStreamTenantCapabilities) bool {
	seenRoot := map[string]struct{}{}
	seenItem := map[string]struct{}{}
	if value.ItemsField != "" {
		seenRoot[value.ItemsField] = struct{}{}
	}
	fields := []ThreatStreamJSONField{
		value.Fields.Observable, value.Fields.IType, value.Fields.Confidence, value.Fields.Severity, value.Fields.Classification,
		value.Fields.TLP, value.Fields.Tags, value.Fields.Expiration, value.Fields.ReviewState,
	}
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		target := seenRoot
		if field.Scope == ThreatStreamFieldItem {
			target = seenItem
		}
		if _, exists := target[field.Name]; exists {
			return false
		}
		target[field.Name] = struct{}{}
	}
	return true
}

func validThreatStreamEndpoint(value string) bool {
	if len(value) == 0 || len(value) > maxThreatStreamEndpointBytes || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "?#") || strings.IndexFunc(value, unicode.IsSpace) >= 0 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "" && parsed.Host == "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validThreatStreamContract(value string) bool {
	return len(value) > 0 && len(value) <= maxThreatStreamContractBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validThreatStreamFieldName(value string) bool {
	return len(value) > 0 && len(value) <= maxThreatStreamFieldNameBytes && value == strings.TrimSpace(value) &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validOptionalThreatStreamFieldName(value string) bool {
	return value == "" || validThreatStreamFieldName(value)
}

func validThreatStreamValue(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validFindingSeverity(value FindingSeverity) bool {
	switch value {
	case FindingSeverityInfo, FindingSeverityLow, FindingSeverityMedium, FindingSeverityHigh, FindingSeverityCritical:
		return true
	default:
		return false
	}
}

func unsupportedThreatStream(candidateID AnalysisID, variant ThreatStreamPayloadVariant, capability ThreatStreamCapability, value string) error {
	return &ThreatStreamUnsupportedCapabilityError{CandidateID: candidateID, Variant: variant, Capability: capability, Value: value}
}

func cloneThreatStreamCapabilities(value ThreatStreamTenantCapabilities) ThreatStreamTenantCapabilities {
	value.ITypes = append([]ThreatStreamITypeCapability{}, value.ITypes...)
	for index := range value.ITypes {
		value.ITypes[index].IPTypes = append([]ThreatCandidateIPType{}, value.ITypes[index].IPTypes...)
	}
	value.Severities = append([]string{}, value.Severities...)
	value.SeverityMappings = append([]ThreatStreamSeverityMapping{}, value.SeverityMappings...)
	value.Classifications = append([]string{}, value.Classifications...)
	value.TLPs = append([]string{}, value.TLPs...)
	value.ReviewStates = append([]string{}, value.ReviewStates...)
	value.ReviewDefaults.Tags = append([]string{}, value.ReviewDefaults.Tags...)
	value.Response = cloneThreatStreamResponse(value.Response)
	return value
}

func cloneThreatStreamResponse(value ThreatStreamResponseAssumptions) ThreatStreamResponseAssumptions {
	value.AcceptedStatuses = append([]string{}, value.AcceptedStatuses...)
	return value
}

func cloneThreatStreamSettings(value ThreatStreamObservableSettings) ThreatStreamObservableSettings {
	value.MapEvidenceConfidence = cloneBoolPointer(value.MapEvidenceConfidence)
	value.Confidence = cloneIntPointer(value.Confidence)
	value.MapCandidateSeverity = cloneBoolPointer(value.MapCandidateSeverity)
	value.Tags = append([]string{}, value.Tags...)
	value.ExpiresAt = cloneTimePointer(value.ExpiresAt)
	return value
}

func cloneThreatStreamSelections(values []ThreatStreamCandidateSelection) []ThreatStreamCandidateSelection {
	result := append([]ThreatStreamCandidateSelection{}, values...)
	for index := range result {
		result[index].Settings = cloneThreatStreamSettings(result[index].Settings)
	}
	return result
}

func cloneResolvedThreatStreamSettings(value resolvedThreatStreamSettings) resolvedThreatStreamSettings {
	value.Tags = append([]string{}, value.Tags...)
	return value
}

func cloneThreatStreamSource(value ThreatStreamPayloadSource) ThreatStreamPayloadSource {
	value.ObservationIDs = append([]EvidenceID{}, value.ObservationIDs...)
	value.ReportEvidenceIDs = append([]EvidenceID{}, value.ReportEvidenceIDs...)
	value.CorrelationFindingIDs = append([]FindingID{}, value.CorrelationFindingIDs...)
	return value
}

func sortedUniqueThreatStreamEvidenceIDs(values []EvidenceID) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return values[i] < values[j] }) && !hasDuplicateEvidenceID(values)
}

func sortedUniqueThreatStreamFindingIDs(values []FindingID) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return values[i] < values[j] }) && !hasDuplicateFindingID(values)
}

func hasDuplicateEvidenceID(values []EvidenceID) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] == value {
			return true
		}
	}
	return false
}

func hasDuplicateFindingID(values []FindingID) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] == value {
			return true
		}
	}
	return false
}
